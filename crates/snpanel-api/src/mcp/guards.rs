//! What the MCP tools refuse to do, as functions of their arguments: the
//! addresses `block_ip` will not block, the only WAF rules `add_waf_rule`
//! writes, and the paths `delete_file` leaves alone.

use std::collections::HashSet;
use std::net::IpAddr;

/// An address, or a network given as `address/prefix`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Network {
    /// The network's first address: `203.0.113.7/24` is `203.0.113.0/24`.
    pub addr: IpAddr,
    pub prefix: u8,
}

fn max_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() {
        32
    } else {
        128
    }
}

fn masked(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix))
            };
            IpAddr::V4((bits & mask).into())
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix))
            };
            IpAddr::V6((bits & mask).into())
        }
    }
}

impl Network {
    pub fn parse(text: &str) -> Option<Network> {
        let text = text.trim();
        let (addr, prefix) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let prefix = match prefix {
            None => max_prefix(addr),
            Some(raw) => {
                if raw.is_empty() || raw.len() > 3 || !raw.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let n: u8 = raw.parse().ok()?;
                if n > max_prefix(addr) {
                    return None;
                }
                n
            }
        };
        Some(Network {
            addr: masked(addr, prefix),
            prefix,
        })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        ip.is_ipv4() == self.addr.is_ipv4() && masked(ip, self.prefix) == self.addr
    }

    /// The network's last address.
    pub fn last(&self) -> IpAddr {
        match self.addr {
            IpAddr::V4(v4) => {
                let host = if self.prefix == 32 {
                    0
                } else {
                    u32::MAX >> self.prefix
                };
                IpAddr::V4((u32::from(v4) | host).into())
            }
            IpAddr::V6(v6) => {
                let host = if self.prefix == 128 {
                    0
                } else {
                    u128::MAX >> self.prefix
                };
                IpAddr::V6((u128::from(v6) | host).into())
            }
        }
    }
}

impl std::fmt::Display for Network {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

/// What an address is when it is not somebody on the Internet: private,
/// loopback, link-local, multicast, the documentation ranges, reserved.
pub fn special(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            if o[0] == 0 {
                Some("unspecified")
            } else if v4.is_loopback() {
                Some("loopback")
            } else if v4.is_private() {
                Some("private")
            } else if v4.is_link_local() {
                Some("link-local")
            } else if v4.is_multicast() {
                Some("multicast")
            } else if o[0] >= 240 {
                Some("reserved")
            } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
                Some("carrier-grade NAT")
            } else if matches!(
                (o[0], o[1], o[2]),
                (192, 0, 2) | (198, 51, 100) | (203, 0, 113)
            ) {
                Some("documentation")
            } else if o[0] == 198 && (o[1] & 0xfe) == 18 {
                Some("benchmarking")
            } else if (o[0], o[1], o[2]) == (192, 0, 0) {
                Some("protocol assignment")
            } else {
                None
            }
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return special(IpAddr::V4(v4));
            }
            let s = v6.segments();
            if v6.is_unspecified() {
                Some("unspecified")
            } else if v6.is_loopback() {
                Some("loopback")
            } else if (s[0] & 0xffc0) == 0xfe80 {
                Some("link-local")
            } else if (s[0] & 0xfe00) == 0xfc00 {
                Some("unique local")
            } else if (s[0] & 0xff00) == 0xff00 {
                Some("multicast")
            } else if s[0] == 0x2001 && s[1] == 0x0db8 {
                Some("documentation")
            } else {
                None
            }
        }
    }
}

/// The network `block_ip` would block, or why it will not: nothing wider
/// than a /16 (IPv4) or a /32 (IPv6), nothing that is not on the Internet,
/// and never this server or the address the assistant is calling from.
pub fn block_target(
    wanted: &str,
    server: &[IpAddr],
    client: Option<IpAddr>,
) -> Result<Network, String> {
    let net = Network::parse(wanted)
        .ok_or_else(|| format!("{} is not an IP address or a network", wanted.trim()))?;
    let widest = if net.addr.is_ipv4() { 16 } else { 32 };
    if net.prefix < widest {
        return Err(format!(
            "{net} is wider than a /{widest}; block smaller networks"
        ));
    }
    for end in [net.addr, net.last()] {
        if let Some(kind) = special(end) {
            return Err(format!(
                "{net} is a {kind} address, not somebody on the Internet"
            ));
        }
    }
    if let Some(own) = server.iter().find(|ip| net.contains(**ip)) {
        return Err(format!("{net} includes this server's own address {own}"));
    }
    if let Some(caller) = client.filter(|ip| net.contains(*ip)) {
        return Err(format!(
            "{net} includes the address this assistant is calling from ({caller})"
        ));
    }
    Ok(net)
}

/// Whether two ways of writing an address or network mean the same one:
/// `1.2.3.4` and `1.2.3.4/32`.
pub fn same_network(a: &str, b: &str) -> bool {
    match (Network::parse(a), Network::parse(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

// ------------------------------------------------------------------ WAF rules

/// The ids `add_waf_rule` gives its rules: a range of their own, so none
/// can collide with the panel's or a hand-written one's.
pub const RULE_ID_FIRST: u32 = 1_090_000;
pub const RULE_ID_LAST: u32 = 1_099_999;

/// What a rule matches on. The assistant chooses one of these and a value;
/// it never writes ModSecurity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleMatch {
    Ip,
    Path,
    UserAgent,
    Query,
}

impl RuleMatch {
    pub const NAMES: &'static [&'static str] = &["ip", "path", "user_agent", "query"];

    pub fn parse(name: &str) -> Option<RuleMatch> {
        match name {
            "ip" => Some(RuleMatch::Ip),
            "path" => Some(RuleMatch::Path),
            "user_agent" => Some(RuleMatch::UserAgent),
            "query" => Some(RuleMatch::Query),
            _ => None,
        }
    }

    fn variable(self) -> &'static str {
        match self {
            RuleMatch::Ip => "REMOTE_ADDR",
            RuleMatch::Path => "REQUEST_FILENAME",
            RuleMatch::UserAgent => "REQUEST_HEADERS:User-Agent",
            RuleMatch::Query => "QUERY_STRING",
        }
    }

    fn operator(self) -> &'static str {
        match self {
            RuleMatch::Ip => "@ipMatch",
            RuleMatch::Path => "@beginsWith",
            RuleMatch::UserAgent | RuleMatch::Query => "@contains",
        }
    }

    fn transforms(self) -> &'static str {
        match self {
            RuleMatch::Ip | RuleMatch::Path => "t:none",
            RuleMatch::UserAgent => "t:none,t:lowercase",
            RuleMatch::Query => "t:none,t:urlDecodeUni,t:lowercase",
        }
    }
}

/// A rule's value, checked for its kind and safe inside the rule's quotes:
/// no quote, backslash or control character can close the string, and no
/// `%{` can expand a macro. A user agent and a query are matched lower-cased,
/// so they are lower-cased here too.
pub fn rule_value(kind: RuleMatch, raw: &str) -> Result<String, String> {
    let value = raw.trim();
    if value.is_empty() || value.chars().count() > 200 {
        return Err("The value is 1 to 200 characters".to_string());
    }
    if value
        .chars()
        .any(|c| c.is_control() || matches!(c, '"' | '\'' | '\\' | '`'))
        || value.contains("%{")
    {
        return Err(
            "The value cannot hold quotes, backslashes, control characters or %{".to_string(),
        );
    }
    match kind {
        RuleMatch::Ip => Network::parse(value)
            .map(|net| net.to_string())
            .ok_or_else(|| format!("{value} is not an IP address or a network")),
        RuleMatch::Path => {
            if !value.starts_with('/') || value.chars().any(char::is_whitespace) {
                return Err("A path starts with / and has no spaces".to_string());
            }
            Ok(value.to_string())
        }
        RuleMatch::UserAgent | RuleMatch::Query => Ok(value.to_lowercase()),
    }
}

/// A note as both a comment and the rule's log message can carry it.
pub fn rule_note(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || " .,:;()/@#+-_".contains(c) {
                c
            } else {
                ' '
            }
        })
        .collect();
    let note: String = cleaned
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(80)
        .collect();
    if note.is_empty() {
        "added by an AI assistant".to_string()
    } else {
        note
    }
}

/// Every `id:N` in some rules.
fn rule_ids(text: &str) -> impl Iterator<Item = u32> + '_ {
    text.match_indices("id:").filter_map(move |(at, _)| {
        let digits: String = text[at + 3..]
            .trim_start()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        digits.parse().ok()
    })
}

/// The first id of the range no rule anywhere uses - the server's custom
/// rules and every site's are all passed in.
pub fn next_rule_id(rules: &[&str]) -> Option<u32> {
    let used: HashSet<u32> = rules
        .iter()
        .flat_map(|text| rule_ids(text))
        .filter(|id| (RULE_ID_FIRST..=RULE_ID_LAST).contains(id))
        .collect();
    (RULE_ID_FIRST..=RULE_ID_LAST).find(|id| !used.contains(id))
}

/// The rule, and the comment above it saying where it came from. Always
/// phase 1: the server does not read request bodies, so a phase 2 rule would
/// never run.
pub fn render_rule(
    kind: RuleMatch,
    value: &str,
    id: u32,
    note: &str,
    when: &str,
    by: &str,
) -> String {
    format!(
        "# snpanel-mcp: {note} (added {when} by {by})\n\
         SecRule {} \"{} {value}\" \"id:{id},phase:1,{},deny,status:403,log,msg:'snpanel mcp: {note}'\"",
        kind.variable(),
        kind.operator(),
        kind.transforms(),
    )
}

// ---------------------------------------------------------------------- files

/// Why `delete_file` will not delete a path: nothing named, the website
/// itself, or its web root.
pub fn delete_refusal(cleaned: &str, document_root: &str) -> Option<String> {
    let path = cleaned.trim_matches('/');
    if path.is_empty() || path == "." {
        return Some("Name a file or folder inside the website".to_string());
    }
    let web_root = match document_root.trim_matches('/') {
        "" => "public_html",
        root => root,
    };
    if path == web_root || path == "public_html" {
        return Some(format!(
            "{path} is the website's web root and cannot be deleted"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_network_is_its_first_address_and_prefix() {
        assert_eq!(Network::parse("1.2.3.4").unwrap().to_string(), "1.2.3.4/32");
        assert_eq!(
            Network::parse(" 1.2.3.4/24 ").unwrap().to_string(),
            "1.2.3.0/24"
        );
        assert_eq!(
            Network::parse("2a01:4f8::1/48").unwrap().to_string(),
            "2a01:4f8::/48"
        );
        for bad in [
            "",
            "1.2.3",
            "1.2.3.4/33",
            "1.2.3.4/",
            "1.2.3.4/-1",
            "::1/129",
            "host.example.com",
            "1.2.3.4/2x",
        ] {
            assert!(Network::parse(bad).is_none(), "{bad}");
        }
        let net = Network::parse("1.2.3.0/24").unwrap();
        assert!(
            net.contains(ip("1.2.3.200"))
                && !net.contains(ip("1.2.4.1"))
                && !net.contains(ip("::1"))
        );
        assert_eq!(net.last(), ip("1.2.3.255"));
        assert!(same_network("1.2.3.4", "1.2.3.4/32") && !same_network("1.2.3.4", "1.2.3.5"));
    }

    #[test]
    fn only_somebody_on_the_internet_is_blocked() {
        let server = [ip("5.6.7.8"), ip("2a01:4f8::10")];
        let caller = Some(ip("9.9.9.9"));
        assert_eq!(
            block_target("1.2.3.4", &server, caller)
                .unwrap()
                .to_string(),
            "1.2.3.4/32"
        );
        assert_eq!(
            block_target("1.2.0.0/16", &server, caller)
                .unwrap()
                .to_string(),
            "1.2.0.0/16"
        );
        for (wanted, why) in [
            ("1.2.0.0/15", "wider than a /16"),
            ("2a01::/31", "wider than a /32"),
            ("10.1.2.3", "private"),
            ("192.168.1.0/24", "private"),
            ("172.16.0.1", "private"),
            ("127.0.0.1", "loopback"),
            ("169.254.1.1", "link-local"),
            ("224.0.0.1", "multicast"),
            ("255.255.255.255", "reserved"),
            ("0.1.2.3", "unspecified"),
            ("100.64.0.1", "carrier-grade NAT"),
            ("192.0.2.10", "documentation"),
            ("198.51.100.10", "documentation"),
            ("203.0.113.7", "documentation"),
            ("198.18.0.1", "benchmarking"),
            ("::1", "loopback"),
            ("fe80::1", "link-local"),
            ("fd00::1", "unique local"),
            ("ff02::1", "multicast"),
            ("2001:db8::1", "documentation"),
            ("::ffff:10.0.0.1", "private"),
            ("5.6.7.8", "this server's own address"),
            ("5.6.0.0/16", "this server's own address"),
            ("2a01:4f8::/48", "this server's own address"),
            ("9.9.9.9", "calling from"),
            ("banana", "not an IP address"),
        ] {
            let refused = block_target(wanted, &server, caller).unwrap_err();
            assert!(refused.contains(why), "{wanted}: {refused}");
        }
    }

    #[test]
    fn a_rule_value_cannot_leave_its_quotes() {
        assert_eq!(
            rule_value(RuleMatch::Ip, "203.0.113.7").unwrap(),
            "203.0.113.7/32"
        );
        assert_eq!(
            rule_value(RuleMatch::Path, "/wp-login.php").unwrap(),
            "/wp-login.php"
        );
        assert_eq!(
            rule_value(RuleMatch::UserAgent, "  EvilBot/2.0 ").unwrap(),
            "evilbot/2.0"
        );
        assert_eq!(
            rule_value(RuleMatch::Query, "UNION SELECT").unwrap(),
            "union select"
        );
        for (kind, bad) in [
            (RuleMatch::UserAgent, "bot\" \"id:1"),
            (RuleMatch::UserAgent, "bot'"),
            (RuleMatch::UserAgent, "a\\b"),
            (RuleMatch::UserAgent, "%{REMOTE_ADDR}"),
            (RuleMatch::UserAgent, "line\nbreak"),
            (RuleMatch::UserAgent, ""),
            (RuleMatch::Path, "wp-login.php"),
            (RuleMatch::Path, "/a b"),
            (RuleMatch::Ip, "1.2.3.4/40"),
        ] {
            assert!(rule_value(kind, bad).is_err(), "{bad:?}");
        }
        assert!(rule_value(RuleMatch::Query, &"a".repeat(201)).is_err());
    }

    #[test]
    fn a_note_keeps_only_what_a_comment_and_a_message_can_hold() {
        assert_eq!(
            rule_note("scanner hitting wp-login"),
            "scanner hitting wp-login"
        );
        assert_eq!(rule_note("it's \"bad\"\n'); drop"), "it s bad ); drop");
        assert_eq!(rule_note("   "), "added by an AI assistant");
        assert_eq!(rule_note(&"x".repeat(100)).len(), 80);
    }

    #[test]
    fn a_rule_takes_the_first_id_nobody_uses() {
        assert_eq!(next_rule_id(&[]), Some(RULE_ID_FIRST));
        let server = "SecRule ARGS \"@rx x\" \"id:1090000,phase:1,deny\"\nSecRule X \"y\" \"id: 1090001,deny\"";
        let site =
            "SecRule ARGS \"@rx z\" \"id:1090003,phase:1,deny\"\nSecRule A \"b\" \"id:1000,deny\"";
        assert_eq!(next_rule_id(&[server, site]), Some(1_090_002));
        let full: String = (RULE_ID_FIRST..=RULE_ID_LAST)
            .map(|id| format!("id:{id}\n"))
            .collect();
        assert_eq!(next_rule_id(&[&full]), None);
    }

    #[test]
    fn the_rule_written_is_the_documented_one() {
        let rule = render_rule(
            RuleMatch::Ip,
            "203.0.113.7/32",
            1_090_000,
            "scanner hitting wp-login",
            "2026-09-23 16:01 UTC",
            "admin",
        );
        assert_eq!(
            rule,
            "# snpanel-mcp: scanner hitting wp-login (added 2026-09-23 16:01 UTC by admin)\n\
             SecRule REMOTE_ADDR \"@ipMatch 203.0.113.7/32\" \"id:1090000,phase:1,t:none,deny,status:403,log,msg:'snpanel mcp: scanner hitting wp-login'\""
        );
        let query = render_rule(
            RuleMatch::Query,
            "union select",
            1_090_001,
            "sqli",
            "now",
            "admin",
        );
        assert!(query.contains("SecRule QUERY_STRING \"@contains union select\" \"id:1090001,phase:1,t:none,t:urlDecodeUni,t:lowercase,deny"));
        let agent = render_rule(
            RuleMatch::UserAgent,
            "evilbot",
            1_090_002,
            "bot",
            "now",
            "admin",
        );
        assert!(agent.contains("SecRule REQUEST_HEADERS:User-Agent \"@contains evilbot\" \"id:1090002,phase:1,t:none,t:lowercase,deny"));
        let path = render_rule(
            RuleMatch::Path,
            "/xmlrpc.php",
            1_090_003,
            "x",
            "now",
            "admin",
        );
        assert!(path.contains("SecRule REQUEST_FILENAME \"@beginsWith /xmlrpc.php\""));
    }

    #[test]
    fn the_website_and_its_web_root_are_never_deleted() {
        assert!(delete_refusal("", "public_html").is_some());
        assert!(delete_refusal(".", "public_html").is_some());
        assert!(delete_refusal("/", "public_html").is_some());
        assert!(delete_refusal("public_html", "public_html").is_some());
        assert!(delete_refusal("public_html/", "").is_some());
        assert!(delete_refusal("web", "web").is_some());
        assert!(delete_refusal("public_html", "web").is_some());
        assert_eq!(delete_refusal("public_html/old.php", "public_html"), None);
        assert_eq!(delete_refusal("logs", "public_html"), None);
    }
}
