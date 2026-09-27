//! Where the panel will answer, and which SSH ports the firewall must keep
//! open.
//!
//! Source: `validate_port`, `is_domain_name`, `ask_panel_url` and
//! `detect_ssh_ports`.
//!
//! Two things here can lock an operator out of their own machine if they are
//! wrong, and both are parsing rather than doing. A panel URL that names the
//! wrong port is a panel nobody can reach; an SSH port list that misses the
//! port the operator is *currently connected on* is a firewall that closes
//! the door behind them.

/// `[[ "$1" =~ ^[0-9]{1,5}$ ]]` and then the range.
///
/// Two checks rather than one because they report differently: a value that
/// is not a number at all is "Invalid PANEL_PORT", and one that is a number
/// out of range is "PANEL_PORT out of range".
pub fn validate_port(raw: &str) -> Result<u16, String> {
    let digits = (1..=5).contains(&raw.len()) && raw.bytes().all(|b| b.is_ascii_digit());
    if !digits {
        return Err(format!("Invalid PANEL_PORT: {raw}"));
    }
    let value: u32 = raw
        .parse()
        .map_err(|_| format!("Invalid PANEL_PORT: {raw}"))?;
    if !(1..=65535).contains(&value) {
        return Err(format!("PANEL_PORT out of range: {raw}"));
    }
    Ok(value as u16)
}

/// `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`
///
/// Lower case only, and at least two labels — this is the name a certificate
/// will be issued for, and Let's Encrypt will not issue for a single label.
pub fn is_domain_name(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|label| label_ok(label))
}

fn label_ok(label: &str) -> bool {
    let bytes = label.as_bytes();
    let ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    match bytes.len() {
        0 => false,
        1 => ok(bytes[0]),
        n if n <= 63 => {
            ok(bytes[0]) && ok(bytes[n - 1]) && bytes[1..n - 1].iter().all(|b| ok(*b) || *b == b'-')
        }
        _ => false,
    }
}

/// Pull the hostname and port out of a `PANEL_URL`.
///
/// Source: the two `sed` pairs in `ask_panel_url`. The port group is
/// `([0-9]+)`, so **a non-numeric port is not a port**: `host:abc` yields no
/// port and the default is kept. The host is `[^/:]+` — up to the first
/// colon or slash — whether or not a scheme was given.
pub fn split_url(raw: &str) -> (String, Option<String>) {
    // `${PANEL_URL%/}` — one trailing slash, not all of them.
    let trimmed = raw.strip_suffix('/').unwrap_or(raw);
    let body = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host: String = body
        .chars()
        .take_while(|c| *c != ':' && *c != '/')
        .collect();
    let rest = &body[host.len()..];
    let port = rest.strip_prefix(':').and_then(|after| {
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        (!digits.is_empty()).then_some(digits)
    });
    (host, port)
}

/// Pull the hostname and port out of a `PANEL_HOSTNAME`.
///
/// Source: the parameter expansions after the prompt — `${H#http://}`,
/// `${H%%/*}`, then `${H%%:*}` and `${H##*:}`. Those last two are **not**
/// one split: the host is everything before the *first* colon and the port
/// everything after the *last*, so `a:b:c` gives `a` and `c`.
///
/// A port that is not a number is still taken here, and `validate_port` then
/// refuses it by name — which is a better answer than a host that silently
/// kept it and a panel URL nobody can reach.
pub fn split_hostname(raw: &str) -> (String, Option<String>) {
    let body = raw
        .strip_prefix("http://")
        .or_else(|| raw.strip_prefix("https://"))
        .unwrap_or(raw);
    let body = body.split('/').next().unwrap_or("");
    if !body.contains(':') {
        return (body.to_string(), None);
    }
    let host = body.split(':').next().unwrap_or("").to_string();
    let port = body.rsplit(':').next().unwrap_or("").to_string();
    (host, (!port.is_empty()).then_some(port))
}

/// Whether SSL was asked for, declined, or left to the installer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SslChoice {
    Auto,
    Yes,
    No,
}

impl SslChoice {
    pub fn parse(raw: &str) -> SslChoice {
        match raw {
            "yes" => SslChoice::Yes,
            "auto" => SslChoice::Auto,
            _ => SslChoice::No,
        }
    }
}

/// Where the panel will answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanelAddress {
    pub url: String,
    /// Empty when the panel is reached by address rather than by name.
    pub domain: String,
    pub port: u16,
    pub ssl: SslChoice,
}

/// Source: the tail of `ask_panel_url`, with the prompts taken out.
///
/// `answered_yes` is what the operator said to the Let's Encrypt question,
/// which is only asked when the choice was `auto` and the host is a name.
/// Everything else is decided from the values alone.
pub fn decide_address(
    hostname: &str,
    port: u16,
    ssl: SslChoice,
    server_ip: &str,
    answered_yes: bool,
) -> Result<PanelAddress, String> {
    if hostname.is_empty() {
        if server_ip.is_empty() {
            return Err("Cannot detect server IP. Set PANEL_HOSTNAME manually.".to_string());
        }
        // No name means no certificate anyone else would trust, so the panel
        // answers on its address over HTTP and `setup_selfsigned_ssl` gives
        // it a certificate of its own afterwards.
        return Ok(PanelAddress {
            url: format!("http://{server_ip}:{port}"),
            domain: String::new(),
            port,
            ssl: SslChoice::No,
        });
    }

    // An address, or `localhost`, cannot be certified by Let's Encrypt.
    if hostname == "localhost" || hostname == "127.0.0.1" || looks_numeric(hostname) {
        return Ok(PanelAddress {
            url: format!("http://{hostname}:{port}"),
            domain: hostname.to_string(),
            port,
            ssl: SslChoice::No,
        });
    }

    let wants_ssl = match ssl {
        SslChoice::Auto => {
            if !is_domain_name(hostname) {
                return Err(format!("Invalid panel domain: {hostname}"));
            }
            answered_yes
        }
        SslChoice::Yes => {
            if !is_domain_name(hostname) {
                return Err(format!("Invalid panel domain: {hostname}"));
            }
            true
        }
        SslChoice::No => false,
    };
    let scheme = if wants_ssl { "https" } else { "http" };
    Ok(PanelAddress {
        url: format!("{scheme}://{hostname}:{port}"),
        domain: hostname.to_string(),
        port,
        ssl: if wants_ssl {
            SslChoice::Yes
        } else {
            SslChoice::No
        },
    })
}

/// `[[ "$PANEL_DOMAIN" =~ ^[0-9.]+$ ]]` — digits and dots, nothing about
/// their arrangement. `1...2` passes it, and that is the shell's.
fn looks_numeric(host: &str) -> bool {
    !host.is_empty() && host.bytes().all(|b| b.is_ascii_digit() || b == b'.')
}

// --- SSH ports -------------------------------------------------------------

/// Every port an `sshd_config` mentions.
///
/// Source: the `awk` inside `detect_ssh_ports`. `sshd -T` is the primary
/// source and knows the effective configuration, but it **misses ports only
/// visible from the live session or a non-default config**, which is why the
/// file is read as well. A port missed here is a firewall that closes the
/// door behind the operator.
///
/// `ListenAddress` is read too, because `ListenAddress 0.0.0.0:2200` is a
/// port that never appears on a `Port` line. The bracketed IPv6 form
/// `[::]:2200` has its brackets stripped first, or the host part would
/// swallow the port.
pub fn ports_in_sshd_config(text: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(keyword) = fields.next() else {
            continue;
        };
        match keyword.to_ascii_lowercase().as_str() {
            "port" => {
                if let Some(value) = fields.next() {
                    if value.bytes().all(|b| b.is_ascii_digit()) && !value.is_empty() {
                        if let Ok(port) = value.parse::<u32>() {
                            out.push(port);
                        }
                    }
                }
            }
            "listenaddress" => {
                for value in fields {
                    let value = value.trim_start_matches('[');
                    let value = value.trim_end_matches(']');
                    // `value ~ /:[0-9]+$/` then `sub(/^.*:/, "")` — the
                    // **last** colon, so `[::]:2200` gives 2200 and a bare
                    // `::` gives nothing.
                    let Some((_, port)) = value.rsplit_once(':') else {
                        continue;
                    };
                    if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) {
                        if let Ok(port) = port.parse::<u32>() {
                            out.push(port);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    finish_ports(out)
}

/// `| awk '$1 >= 1 && $1 <= 65535' | sort -nu` — the range filter and the
/// numeric de-duplicating sort every source goes through.
pub fn finish_ports(ports: Vec<u32>) -> Vec<u16> {
    let mut kept: Vec<u16> = ports
        .into_iter()
        .filter(|port| (1..=65535).contains(port))
        .map(|port| port as u16)
        .collect();
    kept.sort_unstable();
    kept.dedup();
    kept
}

/// The port of the session this install is running over.
///
/// Source: `awk '{print $4}' <<<"$SSH_CONNECTION"` — client address, client
/// port, server address, **server port**. This is the one the operator is
/// using right now, and it is read from the environment because a config
/// that was edited since sshd started would not mention it.
pub fn port_from_ssh_connection(value: &str) -> Option<u32> {
    let field = value.split_whitespace().nth(3)?;
    field.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_port_is_digits_and_then_in_range() {
        assert_eq!(validate_port("2222"), Ok(2222));
        assert_eq!(validate_port("1"), Ok(1));
        assert_eq!(validate_port("65535"), Ok(65535));
        // Not a number at all, and a number out of range, report
        // differently — the shell has two messages and so does this.
        assert_eq!(
            validate_port("abc"),
            Err("Invalid PANEL_PORT: abc".to_string())
        );
        assert_eq!(
            validate_port("123456"),
            Err("Invalid PANEL_PORT: 123456".to_string())
        );
        assert_eq!(
            validate_port("0"),
            Err("PANEL_PORT out of range: 0".to_string())
        );
        assert_eq!(
            validate_port("99999"),
            Err("PANEL_PORT out of range: 99999".to_string())
        );
        assert!(validate_port("").is_err());
        assert!(validate_port(" 22").is_err());
    }

    #[test]
    fn a_domain_needs_two_labels_and_lower_case() {
        assert!(is_domain_name("panel.example.com"));
        assert!(is_domain_name("a.b"));
        assert!(is_domain_name("x-1.example.com"));
        // One label: Let's Encrypt will not issue for it.
        assert!(!is_domain_name("localhost"));
        assert!(!is_domain_name("example"));
        // Upper case, a leading or trailing dash, an empty label.
        assert!(!is_domain_name("Panel.example.com"));
        assert!(!is_domain_name("-a.example.com"));
        assert!(!is_domain_name("a-.example.com"));
        assert!(!is_domain_name("a..b"));
        assert!(!is_domain_name(""));
    }

    #[test]
    fn a_pasted_url_is_reduced_to_a_host_and_a_port() {
        let host = |s: &str| s.to_string();
        let port = |s: &str| Some(s.to_string());
        assert_eq!(
            split_url("https://panel.example.com:2222/"),
            (host("panel.example.com"), port("2222"))
        );
        assert_eq!(
            split_url("http://panel.example.com/login"),
            (host("panel.example.com"), None)
        );
        assert_eq!(
            split_url("panel.example.com:8443"),
            (host("panel.example.com"), port("8443"))
        );
        assert_eq!(
            split_url("panel.example.com"),
            (host("panel.example.com"), None)
        );
        assert_eq!(
            split_url("https://panel.example.com"),
            (host("panel.example.com"), None)
        );
    }

    /// The two paths are not one function, and this is where they part.
    ///
    /// A URL's port group is `([0-9]+)`, so `host:abc` has **no** port and
    /// the default is kept. A hostname's is `${H##*:}`, which takes whatever
    /// is there — and `validate_port` then refuses it by name, which is a
    /// better answer than a panel URL nobody can reach and no message
    /// saying why. Checked against bash, not reasoned about.
    #[test]
    fn a_url_and_a_hostname_split_by_different_rules() {
        assert_eq!(
            split_url("panel.example.com:abc"),
            ("panel.example.com".to_string(), None)
        );
        assert_eq!(
            split_hostname("panel.example.com:abc"),
            ("panel.example.com".to_string(), Some("abc".to_string()))
        );

        // `${H%%:*}` and `${H##*:}` are the first colon and the last, so a
        // value with two of them keeps neither middle piece.
        assert_eq!(
            split_hostname("a:b:c"),
            ("a".to_string(), Some("c".to_string()))
        );
        // The URL rule stops at the first colon and finds no digits.
        assert_eq!(split_url("a:b:c"), ("a".to_string(), None));
        assert_eq!(split_url("https://a:b:c/x"), ("a".to_string(), None));
    }

    #[test]
    fn no_hostname_means_the_panel_answers_on_its_address() {
        let address = decide_address("", 2222, SslChoice::Auto, "203.0.113.10", true).unwrap();
        assert_eq!(address.url, "http://203.0.113.10:2222");
        assert_eq!(address.domain, "");
        // No name, no certificate anyone else would trust. The self-signed
        // phase gives it one afterwards.
        assert_eq!(address.ssl, SslChoice::No);
    }

    #[test]
    fn no_hostname_and_no_address_is_refused_rather_than_guessed() {
        assert_eq!(
            decide_address("", 2222, SslChoice::Auto, "", true),
            Err("Cannot detect server IP. Set PANEL_HOSTNAME manually.".to_string())
        );
    }

    /// An address or `localhost` cannot be certified by Let's Encrypt, so
    /// the question is not asked and the answer is not used.
    #[test]
    fn an_address_never_gets_lets_encrypt_however_it_was_asked_for() {
        for host in ["localhost", "127.0.0.1", "203.0.113.10", "1...2"] {
            for choice in [SslChoice::Auto, SslChoice::Yes, SslChoice::No] {
                let address = decide_address(host, 2222, choice, "203.0.113.10", true).unwrap();
                assert_eq!(address.ssl, SslChoice::No, "{host} {choice:?}");
                assert!(address.url.starts_with("http://"), "{host} {choice:?}");
            }
        }
    }

    #[test]
    fn a_name_takes_the_answer_when_the_choice_was_left_open() {
        let yes = decide_address("panel.example.com", 2222, SslChoice::Auto, "", true).unwrap();
        assert_eq!(yes.url, "https://panel.example.com:2222");
        assert_eq!(yes.ssl, SslChoice::Yes);

        let no = decide_address("panel.example.com", 2222, SslChoice::Auto, "", false).unwrap();
        assert_eq!(no.url, "http://panel.example.com:2222");
        assert_eq!(no.ssl, SslChoice::No);
    }

    /// `ENABLE_SSL=no` does **not** validate the domain — the shell's `else`
    /// arm takes whatever it was given. Reproduced, because tightening it
    /// would refuse installs that work today.
    #[test]
    fn an_explicit_no_takes_the_host_as_given() {
        let address = decide_address("Not A Domain", 2222, SslChoice::No, "", false).unwrap();
        assert_eq!(address.url, "http://Not A Domain:2222");
        // Where `auto` and `yes` would have refused it.
        assert!(decide_address("Not A Domain", 2222, SslChoice::Auto, "", true).is_err());
        assert!(decide_address("Not A Domain", 2222, SslChoice::Yes, "", true).is_err());
    }

    /// A port missed here is a firewall that closes the door behind the
    /// operator, so both keywords are read and both IPv6 forms handled.
    #[test]
    fn every_port_an_sshd_config_mentions_is_found() {
        let config = "# a comment\n\
             Port 22\n\
             Port 2200\n\
             port 2201\n\
             ListenAddress 0.0.0.0:2202\n\
             ListenAddress [::]:2203\n\
             ListenAddress 192.0.2.1\n\
             ListenAddress ::\n\
             PermitRootLogin no\n\
             Port notanumber\n";
        assert_eq!(ports_in_sshd_config(config), [22, 2200, 2201, 2202, 2203]);
    }

    /// `sort -nu`: numeric, and de-duplicated.
    #[test]
    fn the_ports_come_back_sorted_numerically_and_once_each() {
        assert_eq!(finish_ports(vec![2200, 22, 2200, 9]), [9, 22, 2200]);
        // Out of range on either side is dropped, not clamped.
        assert_eq!(finish_ports(vec![0, 65536, 70000, 22]), [22]);
    }

    /// `SSH_CONNECTION` is *client address, client port, server address,
    /// server port* — the fourth field, and the one the operator is on.
    #[test]
    fn the_live_session_port_is_the_fourth_field() {
        assert_eq!(
            port_from_ssh_connection("203.0.113.5 51234 192.0.2.1 2200"),
            Some(2200)
        );
        assert_eq!(
            port_from_ssh_connection("203.0.113.5 51234 192.0.2.1"),
            None
        );
        assert_eq!(port_from_ssh_connection(""), None);
    }
}
