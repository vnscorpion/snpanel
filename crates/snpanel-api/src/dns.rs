//! The DNS Manager addon: zones on this server's PowerDNS, through its API.
//!
//! Not in the Python. PowerDNS listens for its API on 127.0.0.1 only
//! (`ops::dns` in the helper sets it up), with a key in a file the panel's
//! user can read. Nothing here needs root: the helper installs and starts
//! PowerDNS, and every zone and record is a request to that API.
//!
//! What is written is checked here first, type by type, so a customer's
//! record reaches PowerDNS in the one form it accepts, and whatever PowerDNS
//! still refuses (a CNAME beside another record, say) comes back as its own
//! message.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const API_KEY_FILE: &str = "/etc/snpanel/pdns-api-key";
const API_ADDR: (&str, u16) = ("127.0.0.1", 8081);
const ZONES: &str = "/api/v1/servers/localhost/zones";
const TIMEOUT: Duration = Duration::from_secs(10);

/// The record types the panel edits. SOA is PowerDNS's to keep (its serial
/// goes up with every change made through the API).
pub const TYPES: &[&str] = &["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS"];

pub const MIN_TTL: u32 = 60;
pub const MAX_TTL: u32 = 604_800;

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TemplateRecord {
    /// Relative to the zone: `@`, `www`, `mail`.
    pub name: String,
    #[serde(rename = "type")]
    pub rtype: String,
    /// `{domain}`, `{ip}` and `{ipv6}` are filled in; a record whose
    /// placeholder has nothing to fill it (no IPv6) is left out.
    pub content: String,
    #[serde(default)]
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsSettings {
    pub nameservers: Vec<String>,
    pub hostmaster: String,
    /// Empty: the server's first public IPv4 address.
    #[serde(default)]
    pub server_ip: String,
    /// Empty: no AAAA records from the template.
    #[serde(default)]
    pub server_ipv6: String,
    pub default_ttl: u32,
    pub template: Vec<TemplateRecord>,
}

fn t(name: &str, rtype: &str, content: &str) -> TemplateRecord {
    TemplateRecord {
        name: name.into(),
        rtype: rtype.into(),
        content: content.into(),
        ttl: None,
    }
}

/// The server's own address is named: `a` and `mx` only cover mail sent
/// from the domain's web or mail host, and many receivers want the IP.
pub const DEFAULT_SPF: &str = "\"v=spf1 a mx ip4:{ip} ~all\"";
/// What the template held before; a zone or saved template still holding
/// exactly this is brought up to [`DEFAULT_SPF`].
const OLD_SPF: &str = "v=spf1 a mx ~all";

fn is_old_spf(content: &str) -> bool {
    content.trim().trim_matches('"') == OLD_SPF
}

pub fn default_template() -> Vec<TemplateRecord> {
    vec![
        t("@", "A", "{ip}"),
        t("@", "AAAA", "{ipv6}"),
        t("www", "CNAME", "{domain}."),
        t("mail", "A", "{ip}"),
        t("@", "MX", "10 mail.{domain}."),
        t("@", "TXT", DEFAULT_SPF),
        t("@", "CAA", "0 issue \"letsencrypt.org\""),
    ]
}

/// The parent of the machine's name - `example.com` for `panel.example.com` - which is
/// where an administrator's nameservers usually are.
fn base_domain() -> String {
    let host = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    match labels.len() {
        0 | 1 => "example.com".to_string(),
        2 => labels.join("."),
        _ => labels[1..].join("."),
    }
}

impl DnsSettings {
    pub fn defaults() -> Self {
        let base = base_domain();
        Self {
            nameservers: vec![format!("ns1.{base}"), format!("ns2.{base}")],
            hostmaster: format!("hostmaster@{base}"),
            server_ip: String::new(),
            server_ipv6: String::new(),
            default_ttl: 3600,
            template: default_template(),
        }
    }

    /// Normalised and checked; the template is rendered against a sample
    /// zone so a record that could never be written is refused now, not when
    /// a website is created.
    pub fn validated(mut self) -> Result<Self, String> {
        self.nameservers = self
            .nameservers
            .iter()
            .map(|n| n.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|n| !n.is_empty())
            .collect();
        if self.nameservers.is_empty() || self.nameservers.len() > 6 {
            return Err("Give between one and six nameservers".into());
        }
        for ns in &self.nameservers {
            if !hostname_valid(ns) {
                return Err(format!("{ns} is not a host name"));
            }
        }
        self.hostmaster = self.hostmaster.trim().to_ascii_lowercase();
        if soa_mailbox(&self.hostmaster).is_none() {
            return Err("The hostmaster must be an e-mail address".into());
        }
        self.server_ip = self.server_ip.trim().to_string();
        if !self.server_ip.is_empty() && self.server_ip.parse::<Ipv4Addr>().is_err() {
            return Err("The server IP must be an IPv4 address".into());
        }
        self.server_ipv6 = self.server_ipv6.trim().to_string();
        if !self.server_ipv6.is_empty() && self.server_ipv6.parse::<Ipv6Addr>().is_err() {
            return Err("The server IPv6 must be an IPv6 address".into());
        }
        if !(MIN_TTL..=MAX_TTL).contains(&self.default_ttl) {
            return Err(format!("The TTL must be from {MIN_TTL} to {MAX_TTL} seconds"));
        }
        if self.template.len() > 50 {
            return Err("The template holds at most 50 records".into());
        }
        for record in &mut self.template {
            record.name = record.name.trim().to_ascii_lowercase();
            record.rtype = record.rtype.trim().to_ascii_uppercase();
            record.content = record.content.trim().to_string();
            if record.rtype == "NS" {
                return Err("The nameservers are added from the list above, not the template".into());
            }
            if let Some(ttl) = record.ttl {
                if !(MIN_TTL..=MAX_TTL).contains(&ttl) {
                    return Err(format!("The TTL must be from {MIN_TTL} to {MAX_TTL} seconds"));
                }
            }
            let sample = Placeholders {
                domain: "example.com",
                ip: "192.0.2.1",
                ipv6: "2001:db8::1",
            };
            let content = sample.fill(&record.content).unwrap_or_default();
            let name = record_name(&record.name, "example.com")
                .map_err(|e| format!("{} {}: {e}", record.name, record.rtype))?;
            normalize_content(&record.rtype, &content, "example.com")
                .map_err(|e| format!("{} {}: {e}", record.name, record.rtype))?;
            if record.rtype == "CNAME" && name == "example.com." {
                return Err("A CNAME cannot be at the zone's own name (@)".into());
            }
        }
        Ok(self)
    }
}

fn data_dir() -> PathBuf {
    PathBuf::from(std::env::var("SNPANEL_DATA_DIR").unwrap_or_else(|_| "/var/lib/snpanel".into()))
}

fn settings_file() -> PathBuf {
    data_dir().join("dns.json")
}

pub fn settings() -> DnsSettings {
    let mut s = std::fs::read_to_string(settings_file())
        .ok()
        .and_then(|t| serde_json::from_str::<DnsSettings>(&t).ok())
        .unwrap_or_else(DnsSettings::defaults);
    upgrade_template(&mut s);
    s
}

/// A saved template still holding the old default SPF gets the new one.
fn upgrade_template(settings: &mut DnsSettings) {
    for record in &mut settings.template {
        if record.rtype == "TXT" && is_old_spf(&record.content) {
            record.content = DEFAULT_SPF.to_string();
        }
    }
}

/// `set` (an RRset as PowerDNS lists it) with the old default SPF swapped
/// for the one naming `ip`; `None` when it has no such record.
fn spf_upgraded(set: &Value, ip: &str) -> Option<Value> {
    if set["type"] != "TXT" {
        return None;
    }
    let records = set["records"].as_array()?;
    if !records.iter().any(|r| r["content"].as_str().is_some_and(is_old_spf)) {
        return None;
    }
    let new = format!("\"v=spf1 a mx ip4:{ip} ~all\"");
    let records: Vec<Value> = records
        .iter()
        .map(|r| match r["content"].as_str() {
            Some(c) if is_old_spf(c) => json!({"content": new, "disabled": r["disabled"].as_bool().unwrap_or(false)}),
            _ => json!({"content": r["content"], "disabled": r["disabled"].as_bool().unwrap_or(false)}),
        })
        .collect();
    Some(json!({
        "name": set["name"], "type": "TXT", "ttl": set["ttl"], "changetype": "REPLACE",
        "records": records,
    }))
}

/// Every hosted zone whose SPF is still the old default, given the server's
/// IPv4 in it. Records anyone has changed are left alone. Returns how many
/// zones changed.
pub async fn upgrade_spf() -> usize {
    let Some(ip) = server_ip(&settings()) else { return 0 };
    let Ok(hosted) = zones().await else { return 0 };
    let mut changed = 0;
    for name in hosted {
        let Ok(Some(z)) = zone(&name).await else { continue };
        let sets: Vec<Value> = z["rrsets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|set| spf_upgraded(set, &ip))
            .collect();
        if sets.is_empty() {
            continue;
        }
        match patch_zone(&name, sets).await {
            Ok(()) => changed += 1,
            Err(e) => tracing::warn!("SPF of {name}: {e}"),
        }
    }
    if changed > 0 {
        tracing::info!("DNS: SPF given the server's IPv4 in {changed} zone(s)");
    }
    changed
}

pub fn save_settings(settings: &DnsSettings) -> std::io::Result<()> {
    let path = settings_file();
    let dir = path.parent().map(std::path::Path::to_path_buf).unwrap_or_else(|| ".".into());
    std::fs::create_dir_all(&dir)?;
    let mut text = serde_json::to_string_pretty(settings)?;
    text.push('\n');
    let temp = dir.join(format!(".dns.json.{}", std::process::id()));
    std::fs::write(&temp, text)?;
    std::fs::rename(&temp, &path)
}

/// The address the template's `{ip}` stands for.
pub fn server_ip(settings: &DnsSettings) -> Option<String> {
    if !settings.server_ip.is_empty() {
        return Some(settings.server_ip.clone());
    }
    let found = crate::routes::panel_settings::ipv4_addresses();
    let public = found.iter().find(|a| {
        a.parse::<Ipv4Addr>()
            .is_ok_and(|ip| !ip.is_private() && !ip.is_loopback() && !(ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64))
    });
    public.or(found.first()).cloned()
}

// ---------------------------------------------------------------------------
// Names and contents
// ---------------------------------------------------------------------------

fn label_valid(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// A host name, without the trailing dot.
pub fn hostname_valid(name: &str) -> bool {
    let name = name.trim_end_matches('.');
    name.len() <= 253 && name.contains('.') && name.split('.').all(label_valid)
}

/// A zone's name, as the panel stores domains: lower case, no trailing dot.
pub fn zone_name(raw: &str) -> Result<String, String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    snpanel_core::Domain::parse(&name)
        .map(|d| d.as_str().to_string())
        .map_err(|_| format!("{raw} is not a domain name"))
}

/// A record's owner as PowerDNS wants it: absolute, with the trailing dot.
/// `@` or nothing is the zone itself; a name that does not end in the zone
/// is taken as relative to it.
pub fn record_name(raw: &str, zone: &str) -> Result<String, String> {
    let name = raw.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name == "@" || name == zone {
        return Ok(format!("{zone}."));
    }
    let relative = name
        .strip_suffix(&format!(".{zone}"))
        .unwrap_or(&name)
        .to_string();
    let labels: Vec<&str> = relative.split('.').collect();
    for (i, label) in labels.iter().enumerate() {
        if !(label_valid(label) || (i == 0 && *label == "*")) {
            return Err(format!("{raw} is not a valid record name"));
        }
    }
    let full = format!("{relative}.{zone}.");
    if full.len() > 254 {
        return Err("The name is too long".into());
    }
    Ok(full)
}

/// The name relative to the zone, as the page shows it.
pub fn relative_name(fqdn: &str, zone: &str) -> String {
    let fqdn = fqdn.trim_end_matches('.');
    if fqdn == zone {
        "@".to_string()
    } else {
        fqdn.strip_suffix(&format!(".{zone}")).unwrap_or(fqdn).to_string()
    }
}

/// A target host: `@` is the zone, a name with a dot is absolute, a single
/// label is in the zone.
fn target(raw: &str, zone: &str) -> Result<String, String> {
    let raw = raw.trim().to_ascii_lowercase();
    if raw == "@" {
        return Ok(format!("{zone}."));
    }
    if raw == "." {
        return Ok(".".into());
    }
    let absolute = if raw.ends_with('.') || raw.contains('.') {
        raw.trim_end_matches('.').to_string()
    } else {
        format!("{raw}.{zone}")
    };
    if !hostname_valid(&absolute) {
        return Err(format!("{raw} is not a host name"));
    }
    Ok(format!("{absolute}."))
}

fn number<T: std::str::FromStr>(raw: Option<&str>, what: &str) -> Result<T, String> {
    raw.and_then(|s| s.parse::<T>().ok())
        .ok_or_else(|| format!("{what} must be a number"))
}

/// TXT content: kept when it is already quoted strings, quoted (and cut into
/// 255-byte strings) when it is plain text.
fn txt(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("The text is empty".into());
    }
    if raw.len() > 4000 {
        return Err("The text is too long".into());
    }
    if raw.starts_with('"') {
        if quoted_strings_valid(raw) {
            return Ok(raw.to_string());
        }
        return Err("The quotes in the text do not match".into());
    }
    if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("The text has a control character".into());
    }
    let mut parts = Vec::new();
    let mut chunk = String::new();
    for c in raw.chars() {
        if chunk.len() + c.len_utf8() > 255 {
            parts.push(std::mem::take(&mut chunk));
        }
        chunk.push(c);
    }
    parts.push(chunk);
    Ok(parts
        .iter()
        .map(|p| format!("\"{}\"", p.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(" "))
}

/// `"..." "..."`: strings in quotes, with `\` escaping, separated by spaces.
fn quoted_strings_valid(text: &str) -> bool {
    let mut chars = text.chars().peekable();
    let mut any = false;
    loop {
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        match chars.next() {
            None => return any,
            Some('"') => {}
            Some(_) => return false,
        }
        let mut closed = false;
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    if chars.next().is_none() {
                        return false;
                    }
                }
                '"' => {
                    closed = true;
                    break;
                }
                c if (c as u32) < 0x20 => return false,
                _ => {}
            }
        }
        if !closed {
            return false;
        }
        any = true;
        if !matches!(chars.peek(), None | Some(' ')) {
            return false;
        }
    }
}

/// One record's content, checked for its type and in PowerDNS's form.
pub fn normalize_content(rtype: &str, raw: &str, zone: &str) -> Result<String, String> {
    let raw = raw.trim();
    let mut fields = raw.split_whitespace();
    match rtype {
        "A" => raw
            .parse::<Ipv4Addr>()
            .map(|a| a.to_string())
            .map_err(|_| format!("{raw} is not an IPv4 address")),
        "AAAA" => raw
            .parse::<Ipv6Addr>()
            .map(|a| a.to_string())
            .map_err(|_| format!("{raw} is not an IPv6 address")),
        "CNAME" | "NS" => target(raw, zone),
        "MX" => {
            let priority: u16 = number(fields.next(), "The priority")?;
            let host = fields.next().ok_or("An MX record is a priority and a host")?;
            if fields.next().is_some() {
                return Err("An MX record is a priority and a host".into());
            }
            Ok(format!("{priority} {}", target(host, zone)?))
        }
        "SRV" => {
            let priority: u16 = number(fields.next(), "The priority")?;
            let weight: u16 = number(fields.next(), "The weight")?;
            let port: u16 = number(fields.next(), "The port")?;
            let host = fields
                .next()
                .ok_or("An SRV record is a priority, a weight, a port and a host")?;
            if fields.next().is_some() {
                return Err("An SRV record is a priority, a weight, a port and a host".into());
            }
            Ok(format!("{priority} {weight} {port} {}", target(host, zone)?))
        }
        "CAA" => {
            let flags: u8 = number(fields.next(), "The flag")?;
            let tag = fields.next().ok_or("A CAA record is a flag, a tag and a value")?;
            if !["issue", "issuewild", "iodef"].contains(&tag) {
                return Err("The CAA tag must be issue, issuewild or iodef".into());
            }
            let value = fields.collect::<Vec<_>>().join(" ");
            let value = value.trim_matches('"');
            if value.contains('"') || value.contains('\\') || value.len() > 255 {
                return Err("The CAA value cannot hold quotes".into());
            }
            Ok(format!("{flags} {tag} \"{value}\""))
        }
        "TXT" => txt(raw),
        _ => Err(format!("{rtype} records cannot be edited here")),
    }
}

/// `hostmaster@example.com` as SOA writes it: `hostmaster.example.com.`,
/// with any dot in the mailbox escaped.
pub fn soa_mailbox(email: &str) -> Option<String> {
    let (local, domain) = email.split_once('@')?;
    if local.is_empty()
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
        || !hostname_valid(domain)
    {
        return None;
    }
    Some(format!("{}.{domain}.", local.replace('.', "\\.")))
}

struct Placeholders<'a> {
    domain: &'a str,
    ip: &'a str,
    ipv6: &'a str,
}

impl Placeholders<'_> {
    /// `None` when the content needs a value there is none of.
    fn fill(&self, text: &str) -> Option<String> {
        if (text.contains("{ip}") && self.ip.is_empty())
            || (text.contains("{ipv6}") && self.ipv6.is_empty())
        {
            return None;
        }
        Some(
            text.replace("{domain}", self.domain)
                .replace("{ipv6}", self.ipv6)
                .replace("{ip}", self.ip),
        )
    }
}

/// A new zone's records: SOA, NS, a glue A for a nameserver inside the
/// zone, then the template - grouped the way PowerDNS takes them.
pub fn zone_rrsets(zone: &str, settings: &DnsSettings, ip: &str) -> Result<Vec<Value>, String> {
    let fill = Placeholders {
        domain: zone,
        ip,
        ipv6: &settings.server_ipv6,
    };
    let mailbox = soa_mailbox(&settings.hostmaster).ok_or("The hostmaster is not an e-mail address")?;
    let primary = settings.nameservers.first().ok_or("No nameservers are set")?;
    let serial = format!("{}01", chrono::Utc::now().format("%Y%m%d"));
    let mut sets: Vec<(String, String, u32, Vec<String>)> = vec![
        (
            format!("{zone}."),
            "SOA".into(),
            settings.default_ttl,
            vec![format!("{primary}. {mailbox} {serial} 10800 3600 604800 3600")],
        ),
        (
            format!("{zone}."),
            "NS".into(),
            settings.default_ttl,
            settings.nameservers.iter().map(|n| format!("{n}.")).collect(),
        ),
    ];
    let mut add = |name: String, rtype: String, ttl: u32, content: String| {
        match sets.iter_mut().find(|(n, t, _, _)| *n == name && *t == rtype) {
            Some(set) if !set.3.contains(&content) => set.3.push(content),
            Some(_) => {}
            None => sets.push((name, rtype, ttl, vec![content])),
        }
    };
    if !ip.is_empty() {
        for ns in &settings.nameservers {
            if ns.ends_with(&format!(".{zone}")) {
                add(format!("{ns}."), "A".into(), settings.default_ttl, ip.to_string());
            }
        }
    }
    for record in &settings.template {
        let Some(content) = fill.fill(&record.content) else {
            continue;
        };
        let name = record_name(&record.name, zone)?;
        let content = normalize_content(&record.rtype, &content, zone)?;
        add(name, record.rtype.clone(), record.ttl.unwrap_or(settings.default_ttl), content);
    }
    Ok(sets
        .into_iter()
        .map(|(name, rtype, ttl, contents)| {
            json!({
                "name": name,
                "type": rtype,
                "ttl": ttl,
                "changetype": "REPLACE",
                "records": contents.iter().map(|c| json!({"content": c, "disabled": false})).collect::<Vec<_>>(),
            })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// The PowerDNS API
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct PdnsError(pub String);

impl std::fmt::Display for PdnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn api_key() -> Result<String, PdnsError> {
    std::fs::read_to_string(API_KEY_FILE)
        .map(|k| k.trim().to_string())
        .map_err(|_| PdnsError("PowerDNS is not set up: install the DNS Manager addon again".into()))
}

/// One request; the status and the body as JSON (`null` when empty).
async fn call(method: &str, path: &str, body: Option<&Value>) -> Result<(u16, Value), PdnsError> {
    use http_body_util::BodyExt;
    use hyper_util::rt::TokioIo;

    let key = api_key()?;
    let text = body.map(Value::to_string).unwrap_or_default();
    let request = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header(hyper::header::HOST, "127.0.0.1")
        .header("X-API-Key", key)
        .header(hyper::header::CONTENT_TYPE, "application/json")
        .header(hyper::header::ACCEPT, "application/json")
        .body(axum::body::Body::from(text))
        .map_err(|_| PdnsError("PowerDNS API key is not a usable header".into()))?;
    let unreachable = |_| PdnsError("PowerDNS does not answer; start it from Services".into());
    let exchange = async {
        let tcp = tokio::net::TcpStream::connect(API_ADDR).await.map_err(unreachable)?;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tcp))
            .await
            .map_err(|e| PdnsError(format!("PowerDNS: {e}")))?;
        let pump = tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender
            .send_request(request)
            .await
            .map_err(|e| PdnsError(format!("PowerDNS: {e}")))?;
        let status = response.status().as_u16();
        let bytes = response
            .into_body()
            .collect()
            .await
            .map_err(|e| PdnsError(format!("PowerDNS: {e}")))?
            .to_bytes();
        pump.abort();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        Ok((status, value))
    };
    match tokio::time::timeout(TIMEOUT, exchange).await {
        Ok(result) => result,
        Err(_) => Err(PdnsError("PowerDNS did not answer in time".into())),
    }
}

/// A 2xx, or PowerDNS's own message.
async fn checked(method: &str, path: &str, body: Option<&Value>) -> Result<Value, PdnsError> {
    let (status, value) = call(method, path, body).await?;
    if (200..300).contains(&status) {
        return Ok(value);
    }
    let message = value["error"].as_str().unwrap_or("").trim().to_string();
    Err(PdnsError(if message.is_empty() {
        format!("PowerDNS answered HTTP {status}")
    } else {
        message
    }))
}

fn zone_path(zone: &str) -> String {
    format!("{ZONES}/{zone}.")
}

/// Every zone's name, without the trailing dot.
pub async fn zones() -> Result<Vec<String>, PdnsError> {
    let value = checked("GET", ZONES, None).await?;
    let mut names: Vec<String> = value
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|z| z["name"].as_str())
                .map(|n| n.trim_end_matches('.').to_string())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    Ok(names)
}

/// The zone with its RRsets, or `None` when there is no such zone.
pub async fn zone(zone: &str) -> Result<Option<Value>, PdnsError> {
    let (status, value) = call("GET", &zone_path(zone), None).await?;
    match status {
        200 => Ok(Some(value)),
        404 | 422 => Ok(None),
        _ => Err(PdnsError(
            value["error"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_else(|| format!("PowerDNS answered HTTP {status}")),
        )),
    }
}

pub async fn create_zone(zone: &str, rrsets: Vec<Value>) -> Result<(), PdnsError> {
    let body = json!({
        "name": format!("{zone}."),
        "kind": "Native",
        "soa_edit_api": "DEFAULT",
        "nameservers": [],
        "rrsets": rrsets,
    });
    checked("POST", ZONES, Some(&body)).await.map(drop)
}

pub async fn patch_zone(zone: &str, rrsets: Vec<Value>) -> Result<(), PdnsError> {
    checked("PATCH", &zone_path(zone), Some(&json!({ "rrsets": rrsets })))
        .await
        .map(drop)
}

pub async fn delete_zone(zone: &str) -> Result<(), PdnsError> {
    checked("DELETE", &zone_path(zone), None).await.map(drop)
}

/// The zone made from the template, with `settings` (the nameservers of
/// the domain's reseller, when it has one - see [`settings_for`]).
pub async fn create_from_template(zone: &str, settings: &DnsSettings) -> Result<(), PdnsError> {
    let ip = server_ip(settings).unwrap_or_default();
    let rrsets = zone_rrsets(zone, settings, &ip).map_err(PdnsError)?;
    create_zone(zone, rrsets).await
}

// ---------------------------------------------------------------------------
// Where the world is told to ask
// ---------------------------------------------------------------------------

/// The nameservers a public resolver (1.1.1.1, then 8.8.8.8) gives for
/// `zone`, lower case without the final dot; `None` when neither answered.
/// A plain NS query over UDP, two seconds each.
pub async fn public_nameservers(zone: &str) -> Option<Vec<String>> {
    for resolver in ["1.1.1.1:53", "8.8.8.8:53"] {
        if let Some(found) = ns_query(resolver, zone).await {
            return Some(found);
        }
    }
    None
}

fn ns_packet(zone: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + zone.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in zone.trim_end_matches('.').split('.') {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 2, 0, 1]);
    q
}

/// A name at `pos`, following compression pointers; the position after it.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let target = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            pos = target;
            continue;
        }
        labels.push(String::from_utf8_lossy(msg.get(pos + 1..pos + 1 + len)?).to_ascii_lowercase());
        pos += 1 + len;
    }
    None
}

fn parse_ns_answer(msg: &[u8], id: u16) -> Option<Vec<String>> {
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != id || msg[2] & 0x80 == 0 {
        return None;
    }
    let rcode = msg[3] & 0x0f;
    if rcode != 0 && rcode != 3 {
        return None;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qd {
        pos = read_name(msg, pos)?.1 + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        let (_, after) = read_name(msg, pos)?;
        let rtype = u16::from_be_bytes([*msg.get(after)?, *msg.get(after + 1)?]);
        let rdlen = u16::from_be_bytes([*msg.get(after + 8)?, *msg.get(after + 9)?]) as usize;
        let data = after + 10;
        if rtype == 2 {
            out.push(read_name(msg, data)?.0);
        }
        pos = data + rdlen;
    }
    out.sort();
    Some(out)
}

async fn ns_query(resolver: &str, zone: &str) -> Option<Vec<String>> {
    let id: u16 = rand::random();
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.send_to(&ns_packet(zone, id), resolver).await.ok()?;
    let mut buf = [0u8; 1500];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf)).await.ok()?.ok()?;
    parse_ns_answer(&buf[..n], id)
}

// ---------------------------------------------------------------------------
// Resellers' nameservers
// ---------------------------------------------------------------------------

fn reseller_ns_file() -> PathBuf {
    data_dir().join("dns-resellers.json")
}

fn reseller_ns_all() -> std::collections::BTreeMap<String, Vec<String>> {
    std::fs::read_to_string(reseller_ns_file())
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default()
}

/// A reseller's own nameservers, when it set them.
pub fn reseller_nameservers(reseller_id: i64) -> Option<Vec<String>> {
    reseller_ns_all().remove(&reseller_id.to_string()).filter(|n| !n.is_empty())
}

/// Checked names, or `None` for the server's defaults.
pub fn save_reseller_nameservers(reseller_id: i64, names: Option<Vec<String>>) -> Result<(), String> {
    let mut all = reseller_ns_all();
    match names {
        Some(names) => {
            all.insert(reseller_id.to_string(), names);
        }
        None => {
            all.remove(&reseller_id.to_string());
        }
    }
    let path = reseller_ns_file();
    let dir = path.parent().map(std::path::Path::to_path_buf).unwrap_or_else(|| ".".into());
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let temp = dir.join(format!(".dns-resellers.json.{}", std::process::id()));
    std::fs::write(&temp, serde_json::to_string_pretty(&all).map_err(|e| e.to_string())? + "\n")
        .and_then(|()| std::fs::rename(&temp, &path))
        .map_err(|e| e.to_string())
}

/// One to six host names, lower case, without the final dot.
pub fn nameservers_valid(raw: &[String]) -> Result<Vec<String>, String> {
    let names: Vec<String> = raw
        .iter()
        .map(|n| n.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|n| !n.is_empty())
        .collect();
    if names.is_empty() || names.len() > 6 {
        return Err("Give between one and six nameservers".into());
    }
    if let Some(bad) = names.iter().find(|n| !hostname_valid(n)) {
        return Err(format!("{bad} is not a host name"));
    }
    Ok(names)
}

/// The reseller whose nameservers an account's zones get, if any.
pub async fn reseller_for_owner(state: &crate::state::AppState, owner_id: i64) -> Option<i64> {
    crate::resellers::reseller_of(state, owner_id).await.ok().flatten().map(|(id, _)| id)
}

/// The settings a zone of `owner_id`'s is made with: the server's, with its
/// reseller's nameservers when it has set them.
pub async fn settings_for_owner(state: &crate::state::AppState, owner_id: Option<i64>) -> DnsSettings {
    let mut s = settings();
    if let Some(owner) = owner_id {
        if let Some(reseller) = reseller_for_owner(state, owner).await {
            if let Some(ns) = reseller_nameservers(reseller) {
                s.nameservers = ns;
            }
        }
    }
    s
}

/// Who owns each website domain and alias.
async fn owners(state: &crate::state::AppState) -> std::collections::BTreeMap<String, i64> {
    crate::mail::domains(state)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|d| (d.name, d.owner_id))
        .collect()
}

/// [`settings_for_owner`] for the owner of `domain`.
pub async fn settings_for(state: &crate::state::AppState, domain: &str) -> DnsSettings {
    let owner = owners(state).await.get(domain).copied();
    settings_for_owner(state, owner).await
}

/// A zone's NS and SOA pointed at `settings`' nameservers, with a glue
/// address for a nameserver inside the zone.
pub async fn apply_nameservers(zone: &str, settings: &DnsSettings) -> Result<(), PdnsError> {
    let Some(existing) = self::zone(zone).await? else {
        return Ok(());
    };
    let apex = format!("{zone}.");
    let soa = existing["rrsets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["name"] == apex.as_str() && s["type"] == "SOA")
        .and_then(|s| s["records"][0]["content"].as_str())
        .map(str::to_string);
    let primary = settings.nameservers.first().ok_or_else(|| PdnsError("No nameservers are set".into()))?;
    let mut rrsets = vec![json!({
        "name": apex, "type": "NS", "ttl": settings.default_ttl, "changetype": "REPLACE",
        "records": settings.nameservers.iter().map(|n| json!({"content": format!("{n}."), "disabled": false})).collect::<Vec<_>>(),
    })];
    if let Some(soa) = soa {
        let mut fields: Vec<&str> = soa.split_whitespace().collect();
        let mname = format!("{primary}.");
        if fields.len() == 7 && fields[0] != mname {
            fields[0] = &mname;
            rrsets.push(single(&apex, "SOA", settings.default_ttl, &fields.join(" ")));
        }
    }
    if let Some(ip) = server_ip(settings) {
        for ns in settings.nameservers.iter().filter(|n| n.ends_with(&format!(".{zone}"))) {
            let fqdn = format!("{ns}.");
            let has = existing["rrsets"].as_array().is_some_and(|sets| sets.iter().any(|s| s["name"] == fqdn.as_str() && s["type"] == "A"));
            if !has {
                rrsets.push(single(&fqdn, "A", settings.default_ttl, &ip));
            }
        }
    }
    patch_zone(zone, rrsets).await
}

/// Every zone of a reseller's (its own domains' and its accounts') given
/// its nameservers now. The number changed.
pub async fn apply_reseller_nameservers(state: &crate::state::AppState, reseller_id: i64) -> usize {
    let settings = settings_for_owner(state, Some(reseller_id)).await;
    let Ok(hosted) = zones().await else { return 0 };
    let mut members = state.db.resellers().children(reseller_id).await.unwrap_or_default();
    members.push(reseller_id);
    let mut changed = 0;
    for (domain, owner) in owners(state).await {
        if members.contains(&owner) && hosted.contains(&domain) {
            match apply_nameservers(&domain, &settings).await {
                Ok(()) => changed += 1,
                Err(e) => tracing::warn!("nameservers of {domain}: {e}"),
            }
        }
    }
    changed
}

/// The longest hosted zone `name` is under, other than `name` itself.
pub fn parent_zone<'a>(name: &str, zones: &'a [String]) -> Option<&'a String> {
    zones
        .iter()
        .filter(|z| name.ends_with(&format!(".{z}")))
        .max_by_key(|z| z.len())
}

// ---------------------------------------------------------------------------
// Websites
// ---------------------------------------------------------------------------

/// A website (or an alias) was created: its zone from the template, or -
/// when it is under a zone this server already has - its own A and AAAA in
/// that zone. Nothing is changed when the name already has records.
///
/// Every domain gets one: zones are not made by hand. [`ensure_all`] makes
/// the ones missing - websites from before the addon, or a create that
/// failed while PowerDNS was down.
pub async fn website_created(state: &crate::state::AppState, domain: &str) {
    if !crate::routes::addons::dns_installed() {
        return;
    }
    let settings = settings_for(state, &domain.to_ascii_lowercase()).await;
    if let Err(e) = website_created_inner(domain, &settings).await {
        tracing::warn!("DNS zone for {domain}: {e}");
    }
}

/// Every website domain and alias on the server, lower case.
pub async fn all_domains(state: &crate::state::AppState) -> Result<Vec<String>, String> {
    let sites = state.db.websites().all_by_id().await.map_err(|e| e.to_string())?;
    let ids: Vec<i64> = sites.iter().map(|s| s.id).collect();
    let aliases = state.db.websites().aliases_for(&ids).await.map_err(|e| e.to_string())?;
    let mut domains: Vec<String> = sites
        .into_iter()
        .map(|s| s.domain)
        .chain(aliases.into_iter().map(|a| a.domain))
        .map(|d| d.to_ascii_lowercase())
        .collect();
    domains.sort();
    domains.dedup();
    Ok(domains)
}

/// The order zones are made in: parents first, so `blog.example.com` lands
/// in `example.com`'s zone when both are websites here.
pub fn by_depth(mut domains: Vec<String>) -> Vec<String> {
    domains.sort_by_key(|d| (d.matches('.').count(), d.clone()));
    domains
}

/// Whether `domain` already answers from here: its own zone, or records in
/// a zone above it.
fn covered(domain: &str, hosted: &[String], parents_with_name: &[String]) -> bool {
    hosted.iter().any(|z| z == domain) || parents_with_name.iter().any(|d| d == domain)
}

/// A zone (or parent-zone records) for every domain that has none. Returns
/// how many were made. Cheap when there is nothing to do: one listing.
pub async fn ensure_domains(state: &crate::state::AppState, domains: Vec<String>) -> Result<usize, PdnsError> {
    let hosted = zones().await?;
    let missing: Vec<String> = domains
        .into_iter()
        .filter(|d| !hosted.contains(d))
        .collect();
    if missing.is_empty() {
        return Ok(0);
    }
    // Names already inside a parent zone count as covered; look once per
    // parent rather than once per name.
    let mut inside: Vec<String> = Vec::new();
    let mut seen_parents: Vec<String> = Vec::new();
    for d in &missing {
        if let Some(parent) = parent_zone(d, &hosted) {
            if !seen_parents.contains(parent) {
                seen_parents.push(parent.clone());
                if let Some(z) = zone(parent).await? {
                    for set in z["rrsets"].as_array().into_iter().flatten() {
                        if let Some(name) = set["name"].as_str() {
                            inside.push(name.trim_end_matches('.').to_string());
                        }
                    }
                }
            }
        }
    }
    let owners = owners(state).await;
    let mut made = 0;
    for d in by_depth(missing) {
        if covered(&d, &hosted, &inside) {
            continue;
        }
        let settings = settings_for_owner(state, owners.get(&d).copied()).await;
        match website_created_inner(&d, &settings).await {
            Ok(()) => made += 1,
            Err(e) => tracing::warn!("DNS zone for {d}: {e}"),
        }
    }
    Ok(made)
}

/// [`ensure_domains`] over every website and alias, when the addon is on.
pub async fn ensure_all(state: &crate::state::AppState) -> usize {
    if !crate::routes::addons::dns_installed() {
        return 0;
    }
    let domains = match all_domains(state).await {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("listing domains for DNS failed: {e}");
            return 0;
        }
    };
    match ensure_domains(state, domains).await {
        Ok(n) => {
            if n > 0 {
                tracing::info!("DNS: made {n} missing zone(s)");
            }
            n
        }
        Err(e) => {
            tracing::warn!("DNS zones not checked: {e}");
            0
        }
    }
}

/// At start: once PowerDNS has had time to come up, and then every ten
/// minutes, so a website added while it was down still gets its zone.
pub fn start(state: &crate::state::AppState) {
    let state = state.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(20)).await;
        if crate::routes::addons::dns_installed() {
            upgrade_spf().await;
        }
        loop {
            ensure_all(&state).await;
            tokio::time::sleep(Duration::from_secs(600)).await;
        }
    });
}

async fn website_created_inner(domain: &str, settings: &DnsSettings) -> Result<(), PdnsError> {
    let domain = zone_name(domain).map_err(PdnsError)?;
    let hosted = zones().await?;
    if hosted.contains(&domain) {
        return Ok(());
    }
    let Some(parent) = parent_zone(&domain, &hosted) else {
        return create_from_template(&domain, settings).await;
    };
    let existing = zone(parent).await?.unwrap_or(Value::Null);
    let fqdn = format!("{domain}.");
    let taken = existing["rrsets"]
        .as_array()
        .is_some_and(|sets| sets.iter().any(|s| s["name"] == fqdn.as_str()));
    if taken {
        return Ok(());
    }
    let mut rrsets = Vec::new();
    if let Some(ip) = server_ip(settings) {
        rrsets.push(single(&fqdn, "A", settings.default_ttl, &ip));
    }
    if !settings.server_ipv6.is_empty() {
        rrsets.push(single(&fqdn, "AAAA", settings.default_ttl, &settings.server_ipv6));
    }
    if rrsets.is_empty() {
        return Ok(());
    }
    patch_zone(parent, rrsets).await
}

fn single(name: &str, rtype: &str, ttl: u32, content: &str) -> Value {
    json!({
        "name": name, "type": rtype, "ttl": ttl, "changetype": "REPLACE",
        "records": [{"content": content, "disabled": false}],
    })
}

/// A website (or an alias) was deleted: its zone goes with it, or, under a
/// parent zone, the A and AAAA that point at this server.
pub async fn website_deleted(domain: &str) {
    if !crate::routes::addons::dns_installed() {
        return;
    }
    if let Err(e) = website_deleted_inner(domain).await {
        tracing::warn!("DNS zone for {domain}: {e}");
    }
}

async fn website_deleted_inner(domain: &str) -> Result<(), PdnsError> {
    let domain = zone_name(domain).map_err(PdnsError)?;
    let hosted = zones().await?;
    if hosted.contains(&domain) {
        return delete_zone(&domain).await;
    }
    let Some(parent) = parent_zone(&domain, &hosted) else {
        return Ok(());
    };
    let settings = settings();
    let ours: Vec<String> = server_ip(&settings)
        .into_iter()
        .chain((!settings.server_ipv6.is_empty()).then(|| settings.server_ipv6.clone()))
        .collect();
    let existing = zone(parent).await?.unwrap_or(Value::Null);
    let fqdn = format!("{domain}.");
    let mut deletes = Vec::new();
    for set in existing["rrsets"].as_array().into_iter().flatten() {
        let rtype = set["type"].as_str().unwrap_or("");
        if set["name"] != fqdn.as_str() || !["A", "AAAA"].contains(&rtype) {
            continue;
        }
        let all_ours = set["records"].as_array().is_some_and(|records| {
            records
                .iter()
                .all(|r| r["content"].as_str().is_some_and(|c| ours.iter().any(|o| o == c)))
        });
        if all_ours {
            deletes.push(json!({"name": fqdn, "type": rtype, "changetype": "DELETE"}));
        }
    }
    if deletes.is_empty() {
        return Ok(());
    }
    patch_zone(parent, deletes).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ns_answer_is_read_with_its_compressed_names() {
        // example.com NS -> ns1.example.net, ns2.example.com (compressed).
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0];
        m.extend_from_slice(&ns_packet("example.com", 0)[12..]);
        // answer 1: name pointer to 12, type NS, class IN, ttl, rdata ns1.example.net
        let rdata1: Vec<u8> = [&[3u8][..], b"ns1", &[7], b"example", &[3], b"net", &[0]].concat();
        m.extend_from_slice(&[0xc0, 12, 0, 2, 0, 1, 0, 0, 0x0e, 0x10, 0, rdata1.len() as u8]);
        m.extend_from_slice(&rdata1);
        // answer 2: rdata "ns2" + pointer to example.com at 12
        let rdata2: Vec<u8> = [&[3u8][..], b"ns2", &[0xc0, 12]].concat();
        m.extend_from_slice(&[0xc0, 12, 0, 2, 0, 1, 0, 0, 0x0e, 0x10, 0, rdata2.len() as u8]);
        m.extend_from_slice(&rdata2);
        assert_eq!(parse_ns_answer(&m, 0x1234).unwrap(), ["ns1.example.net", "ns2.example.com"]);
        assert!(parse_ns_answer(&m, 0x9999).is_none(), "another query's answer is not ours");
    }

    #[test]
    fn record_names_are_made_absolute_in_the_zone() {
        assert_eq!(record_name("@", "example.com").unwrap(), "example.com.");
        assert_eq!(record_name("", "example.com").unwrap(), "example.com.");
        assert_eq!(record_name("www", "example.com").unwrap(), "www.example.com.");
        assert_eq!(record_name("WWW.example.com.", "example.com").unwrap(), "www.example.com.");
        assert_eq!(record_name("*.dev", "example.com").unwrap(), "*.dev.example.com.");
        assert_eq!(
            record_name("_dmarc", "example.com").unwrap(),
            "_dmarc.example.com."
        );
        assert!(record_name("a b", "example.com").is_err());
        assert!(record_name("dev.*", "example.com").is_err());
        assert!(record_name("-x", "example.com").is_err());
        assert_eq!(relative_name("www.example.com.", "example.com"), "www");
        assert_eq!(relative_name("example.com.", "example.com"), "@");
    }

    #[test]
    fn contents_are_checked_for_their_type() {
        let z = "example.com";
        assert_eq!(normalize_content("A", " 192.0.2.1 ", z).unwrap(), "192.0.2.1");
        assert!(normalize_content("A", "192.0.2", z).is_err());
        assert!(normalize_content("A", "2001:db8::1", z).is_err());
        assert_eq!(normalize_content("AAAA", "2001:DB8::1", z).unwrap(), "2001:db8::1");
        assert_eq!(normalize_content("CNAME", "@", z).unwrap(), "example.com.");
        assert_eq!(normalize_content("CNAME", "host", z).unwrap(), "host.example.com.");
        assert_eq!(normalize_content("CNAME", "cdn.example.net", z).unwrap(), "cdn.example.net.");
        assert_eq!(normalize_content("MX", "10 mail", z).unwrap(), "10 mail.example.com.");
        assert!(normalize_content("MX", "mail.example.com", z).is_err());
        assert!(normalize_content("MX", "70000 mail", z).is_err());
        assert_eq!(
            normalize_content("SRV", "0 5 5060 sip.example.net.", z).unwrap(),
            "0 5 5060 sip.example.net."
        );
        assert_eq!(
            normalize_content("CAA", "0 issue letsencrypt.org", z).unwrap(),
            "0 issue \"letsencrypt.org\""
        );
        assert!(normalize_content("CAA", "0 bogus x", z).is_err());
        assert!(normalize_content("SOA", "x", z).is_err());
    }

    #[test]
    fn txt_is_quoted_and_split_or_kept_when_already_quoted() {
        assert_eq!(txt("v=spf1 a mx ~all").unwrap(), "\"v=spf1 a mx ~all\"");
        assert_eq!(txt("say \"hi\"").unwrap(), "\"say \\\"hi\\\"\"");
        assert_eq!(txt("\"a\" \"b\"").unwrap(), "\"a\" \"b\"");
        assert!(txt("\"open").is_err());
        assert!(txt("\"a\"b").is_err());
        let long = "k".repeat(300);
        let quoted = txt(&long).unwrap();
        assert_eq!(quoted, format!("\"{}\" \"{}\"", "k".repeat(255), "k".repeat(45)));
        assert!(txt("line\nbreak").is_err());
    }

    #[test]
    fn the_hostmaster_is_written_the_soa_way() {
        assert_eq!(soa_mailbox("hostmaster@example.com").unwrap(), "hostmaster.example.com.");
        assert_eq!(soa_mailbox("first.last@example.com").unwrap(), "first\\.last.example.com.");
        assert!(soa_mailbox("nobody").is_none());
        assert!(soa_mailbox("a b@example.com").is_none());
    }

    #[test]
    fn the_default_spf_names_the_server_ip() {
        let settings = DnsSettings::defaults();
        let sets = zone_rrsets("example.com", &settings, "192.0.2.1").unwrap();
        let txt = sets.iter().find(|s| s["type"] == "TXT").unwrap();
        assert_eq!(txt["records"][0]["content"], "\"v=spf1 a mx ip4:192.0.2.1 ~all\"");
        // No address: no SPF rather than one without it.
        let sets = zone_rrsets("example.com", &settings, "").unwrap();
        assert!(!sets.iter().any(|s| s["type"] == "TXT"));
    }

    #[test]
    fn the_old_default_spf_is_upgraded() {
        let mut s = DnsSettings::defaults();
        s.template = vec![t("@", "TXT", "\"v=spf1 a mx ~all\""), t("x", "TXT", "\"v=spf1 -all\"")];
        upgrade_template(&mut s);
        assert_eq!(s.template[0].content, DEFAULT_SPF);
        assert_eq!(s.template[1].content, "\"v=spf1 -all\"");

        let set = json!({"name": "a.test.", "type": "TXT", "ttl": 3600, "records": [
            {"content": "\"v=spf1 a mx ~all\"", "disabled": false},
            {"content": "\"google-site-verification=x\"", "disabled": false},
        ]});
        let up = spf_upgraded(&set, "192.0.2.1").unwrap();
        assert_eq!(up["records"][0]["content"], "\"v=spf1 a mx ip4:192.0.2.1 ~all\"");
        assert_eq!(up["records"][1]["content"], "\"google-site-verification=x\"");
        assert_eq!(up["changetype"], "REPLACE");
        let custom = json!({"name": "a.test.", "type": "TXT", "ttl": 3600, "records": [
            {"content": "\"v=spf1 include:_spf.google.com ~all\"", "disabled": false},
        ]});
        assert!(spf_upgraded(&custom, "192.0.2.1").is_none());
    }

    #[test]
    fn the_template_makes_a_whole_zone() {
        let mut settings = DnsSettings::defaults();
        settings.nameservers = vec!["ns1.example.com".into(), "ns2.example.net".into()];
        settings.hostmaster = "hostmaster@example.com".into();
        let sets = zone_rrsets("example.com", &settings, "192.0.2.1").unwrap();
        let find = |name: &str, rtype: &str| {
            sets.iter()
                .find(|s| s["name"] == name && s["type"] == rtype)
                .map(|s| {
                    s["records"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|r| r["content"].as_str().unwrap().to_string())
                        .collect::<Vec<_>>()
                })
        };
        assert!(find("example.com.", "SOA").unwrap()[0]
            .starts_with("ns1.example.com. hostmaster.example.com. "));
        assert_eq!(
            find("example.com.", "NS").unwrap(),
            ["ns1.example.com.", "ns2.example.net."]
        );
        // The nameserver inside the zone gets its glue; the other does not.
        assert_eq!(find("ns1.example.com.", "A").unwrap(), ["192.0.2.1"]);
        assert!(find("ns2.example.net.", "A").is_none());
        assert_eq!(find("example.com.", "A").unwrap(), ["192.0.2.1"]);
        assert_eq!(find("www.example.com.", "CNAME").unwrap(), ["example.com."]);
        assert_eq!(find("example.com.", "MX").unwrap(), ["10 mail.example.com."]);
        assert_eq!(find("example.com.", "CAA").unwrap(), ["0 issue \"letsencrypt.org\""]);
        // No IPv6 set: the AAAA line is left out.
        assert!(find("example.com.", "AAAA").is_none());
        settings.server_ipv6 = "2001:db8::1".into();
        let sets = zone_rrsets("example.com", &settings, "192.0.2.1").unwrap();
        assert!(sets.iter().any(|s| s["type"] == "AAAA"));
    }

    #[test]
    fn settings_are_checked_before_they_are_kept() {
        let base = DnsSettings::defaults();
        assert!(base.clone().validated().is_ok());
        let mut bad = base.clone();
        bad.nameservers = vec![];
        assert!(bad.validated().is_err());
        let mut bad = base.clone();
        bad.template.push(t("@", "CNAME", "other.example.net."));
        assert!(bad.validated().is_err());
        let mut bad = base.clone();
        bad.template.push(t("x", "NS", "ns.example.net."));
        assert!(bad.validated().is_err());
        let mut bad = base.clone();
        bad.template.push(t("x", "A", "not-an-ip"));
        assert!(bad.validated().is_err());
        let mut bad = base;
        bad.server_ip = "300.1.1.1".into();
        assert!(bad.validated().is_err());
    }

    #[test]
    fn parents_are_made_before_the_names_under_them() {
        let order = by_depth(vec![
            "blog.example.com".into(),
            "a.b.example.org".into(),
            "example.com".into(),
            "example.org".into(),
        ]);
        assert_eq!(order, ["example.com", "example.org", "blog.example.com", "a.b.example.org"]);
        let hosted = vec!["example.com".to_string()];
        assert!(covered("example.com", &hosted, &[]));
        assert!(covered("blog.example.com", &hosted, &["blog.example.com".into()]));
        assert!(!covered("shop.example.com", &hosted, &["blog.example.com".into()]));
    }

    #[test]
    fn the_parent_zone_is_the_longest_one_above() {
        let zones = vec!["example.com".to_string(), "shop.example.com".to_string()];
        assert_eq!(parent_zone("a.shop.example.com", &zones).unwrap(), "shop.example.com");
        assert_eq!(parent_zone("blog.example.com", &zones).unwrap(), "example.com");
        assert!(parent_zone("example.com", &zones).is_none());
        assert!(parent_zone("badexample.com", &zones).is_none());
    }
}
