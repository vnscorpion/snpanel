//! Contract C19: the rendered vhost must match Python's, byte for byte.
//!
//! The fixtures are produced by `tests/fixtures/generate.py`, which drives the
//! *real* `render_vhost` with the real Jinja2 and saves what came out. They
//! capture the finished file rather than the template output, so the four
//! steps that happen after the template - the bot block, the manual
//! certificate, the redirect vhosts, the trailing newline - are covered too.
//!
//! A vhost that differs by one line is a website that stops serving, and
//! nobody notices until a customer reports it. So this compares bytes and
//! prints the first differing line when it fails, rather than asserting a
//! length or a substring.

use std::path::{Path, PathBuf};

use serde_json::Value;
use snpanel_nginx::{CustomDirectives, HttpFloodConfig, VhostEnv, VhostInput};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

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
fn every_golden_vhost_renders_byte_for_byte() {
    let repo = repo();
    let manifest_path = repo.join("tests/golden/nginx/manifest.json");
    let manifest: Vec<Value> = serde_json::from_str(
        &std::fs::read_to_string(&manifest_path).expect("the golden manifest"),
    )
    .expect("the manifest parses");
    assert!(
        manifest.len() >= 20,
        "expected at least the twenty captured cases, found {}",
        manifest.len()
    );

    let mut failures: Vec<String> = Vec::new();
    for case in &manifest {
        let name = case["name"].as_str().expect("a case name");
        let kwargs = &case["kwargs"];
        let domain = kwargs["domain"].as_str().expect("a domain");

        // `root_path` is deliberately not in the manifest: the generator ran
        // under a sandbox home and rewrote the prefix, so the fixture records
        // the shape rather than the directory. It is rebuilt the same way the
        // generator built it.
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
        .expect("the fixture's custom directives are valid");

        let aliases = strings(kwargs.get("aliases"));
        let redirects = strings(kwargs.get("redirects"));
        let bots = kwargs
            .get("blocked_bots")
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
        input.http_flood_config = match kwargs.get("http_flood_config") {
            Some(v) if v.is_object() => HttpFloodConfig::from_json(v),
            _ => HttpFloodConfig::default(),
        };
        input.document_root = kwargs
            .get("document_root")
            .and_then(Value::as_str)
            .unwrap_or("public_html");
        input.rewrite_mode = kwargs.get("rewrite_mode").and_then(Value::as_str);
        input.ssl_cert_path = kwargs.get("ssl_cert_path").and_then(Value::as_str);
        input.ssl_key_path = kwargs.get("ssl_key_path").and_then(Value::as_str);
        input.ssl_ca_path = kwargs.get("ssl_ca_path").and_then(Value::as_str);
        input.aliases = &aliases;
        input.redirects = &redirects;
        input.app_port = kwargs.get("app_port").and_then(Value::as_i64);
        input.blocked_bots = bots.as_deref();

        // What the generator pinned: the WAF engine present, IPv6 off, and
        // the panel's own default PHP version.
        let env = VhostEnv {
            ipv6: false,
            waf_engine: true,
            default_php_version: "8.4".to_string(),
            home_root: PathBuf::from("/home"),
        };

        let expected_path = repo.join(case["expected"].as_str().expect("an expected path"));
        let expected = std::fs::read_to_string(&expected_path).expect("the expected vhost");

        match snpanel_nginx::render_vhost(&input, &env) {
            Ok(actual) if actual == expected => {}
            Ok(actual) => {
                let diff = first_difference(&expected, &actual);
                failures.push(format!("{name}: {diff}"));
            }
            Err(e) => failures.push(format!("{name}: render failed: {e}")),
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} golden vhosts differ:\n{}",
        failures.len(),
        manifest.len(),
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
        let extra: Vec<&str> = longer.lines().skip(el.min(al)).take(3).collect();
        return format!(
            "python has {el} lines, rust has {al}; first extra line: {:?}",
            extra.first().unwrap_or(&"")
        );
    }
    "the text matches but the bytes do not (trailing whitespace or newline)".to_string()
}
