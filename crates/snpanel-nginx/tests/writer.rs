//! The write half of a vhost rewrite, against what Python actually wrote.
//!
//! The fixtures were produced by driving the real `rewrite_vhost` with
//! `nginx_sites_available` pointed at a temporary directory and the
//! privileged helper stubbed, then reading the finished file back. So these
//! are not "what the code looks like it does" - they are the bytes that
//! landed on disk.
//!
//! The case that matters most is `over_certbot_preserved`. A site whose
//! certificate certbot installed has its `ssl_certificate` lines in that file
//! and nowhere else, so a rewrite that drops them takes HTTPS off a working
//! site and the customer finds out before the panel does.

use std::path::{Path, PathBuf};

use serde_json::Value;
use snpanel_nginx::{plan_rewrite, CustomDirectives, VhostEnv, VhostInput};

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn every_captured_vhost_write_matches() {
    let path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/nginx/vhost_writes.json");
    let cases: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(&path).expect("the write fixtures"))
            .expect("the fixtures parse");
    assert!(
        cases.len() >= 15,
        "the write corpus shrank to {} cases",
        cases.len()
    );

    let mut failures: Vec<String> = Vec::new();
    for case in &cases {
        let name = case["name"].as_str().expect("a case name");
        let kwargs = &case["kwargs"];
        let domain = kwargs["domain"].as_str().expect("a domain");
        let parsed = snpanel_core::Domain::parse(domain).expect("a valid fixture domain");
        let root_path = PathBuf::from("/home")
            .join(parsed.linux_user().as_str())
            .join(domain);

        let custom = CustomDirectives::validate(
            kwargs
                .get("custom_directives")
                .and_then(Value::as_str)
                .unwrap_or(""),
        )
        .expect("valid custom directives");

        let aliases = strings(kwargs.get("aliases"));
        let redirects = strings(kwargs.get("redirects"));
        let bots = kwargs
            .get("blocked_bots")
            .filter(|v| !v.is_null())
            .map(|_| strings(kwargs.get("blocked_bots")));

        let mut input = VhostInput::new(domain, &root_path, &custom);
        input.app_type = kwargs["app_type"].as_str().unwrap_or("wordpress");
        input.php_version = kwargs.get("php_version").and_then(Value::as_str);
        input.waf_enabled = kwargs
            .get("waf_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(true);
        input.http_flood_enabled = kwargs
            .get("http_flood_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        input.rewrite_mode = kwargs.get("rewrite_mode").and_then(Value::as_str);
        input.ssl_cert_path = kwargs.get("ssl_cert_path").and_then(Value::as_str);
        input.ssl_key_path = kwargs.get("ssl_key_path").and_then(Value::as_str);
        input.ssl_ca_path = kwargs.get("ssl_ca_path").and_then(Value::as_str);
        input.aliases = &aliases;
        input.redirects = &redirects;
        input.app_port = kwargs.get("app_port").and_then(Value::as_i64);
        input.blocked_bots = bots.as_deref();

        let env = VhostEnv {
            ipv6: false,
            waf_engine: true,
            default_php_version: "8.4".to_string(),
            home_root: PathBuf::from("/home"),
        };
        let existing = case["existing"].as_str();
        let preserve = case["preserve_existing_ssl"].as_bool().unwrap_or(true);
        let expected = case["expected"].as_str().expect("expected bytes");

        match plan_rewrite(
            &input,
            &env,
            Path::new("/etc/nginx/sites-available"),
            existing,
            preserve,
        ) {
            Ok(plan) if plan.content == expected => {
                assert_eq!(
                    plan.previous.as_deref(),
                    existing,
                    "{name}: the plan must carry the old bytes for the rollback"
                );
            }
            Ok(plan) => failures.push(format!(
                "{name}: {}",
                first_difference(expected, &plan.content)
            )),
            Err(e) => failures.push(format!("{name}: planning failed: {e}")),
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} writes differ:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

fn first_difference(expected: &str, actual: &str) -> String {
    for (i, (e, a)) in expected.lines().zip(actual.lines()).enumerate() {
        if e != a {
            return format!(
                "line {} differs\n    python: {e:?}\n    rust:   {a:?}",
                i + 1
            );
        }
    }
    let (el, al) = (expected.lines().count(), actual.lines().count());
    if el != al {
        let longer = if el > al { expected } else { actual };
        let extra: Vec<&str> = longer.lines().skip(el.min(al)).take(2).collect();
        return format!(
            "python has {el} lines, rust has {al}; first extra: {:?}",
            extra.first().unwrap_or(&"")
        );
    }
    "the text matches but the bytes do not".to_string()
}
