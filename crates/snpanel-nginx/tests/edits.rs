//! The targeted vhost edits, against what Python produced from the same input.
//!
//! The inputs are the twenty golden vhosts rather than something synthetic:
//! `ensure_custom_include_position` moves `location /` around and only does
//! the interesting thing on a file with the shape a template produces.
//!
//! Outputs are compared by hash, because storing 295 pairs of full vhosts
//! made a two-megabyte fixture. A dozen representative cases keep their text,
//! so a disagreement has something to show rather than two hex strings.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};
use snpanel_nginx::{
    domain_from_vhost, ensure_custom_include_position, replace_bot_block, replace_http_flood_block,
    replace_waf_block, HttpFloodConfig,
};

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root")
}

fn sha256(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
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
fn every_targeted_edit_matches_python() {
    let repo = repo();
    let golden = repo.join("tests/golden/nginx");

    // The rendered vhosts the fixtures reference.
    let manifest: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(golden.join("manifest.json")).unwrap())
            .expect("the manifest parses");
    let mut sources: HashMap<String, String> = HashMap::new();
    for case in &manifest {
        let name = case["name"].as_str().expect("a name").to_string();
        let path = repo.join(case["expected"].as_str().expect("a path"));
        sources.insert(name, std::fs::read_to_string(path).expect("a golden vhost"));
    }

    let cases: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(golden.join("vhost_edits.json")).unwrap())
            .expect("the edit fixtures parse");
    assert!(cases.len() > 250, "the corpus shrank to {}", cases.len());

    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0usize;
    for case in &cases {
        let op = case["op"].as_str().expect("an op");
        let name = case["name"].as_str().expect("a name");
        let content = match case.get("content_ref").and_then(Value::as_str) {
            Some(r) => sources.get(r).cloned().expect("a referenced vhost"),
            None => case["content"]
                .as_str()
                .expect("inline content")
                .to_string(),
        };
        let domain = case.get("domain").and_then(Value::as_str);

        let produced: Result<String, String> = match op {
            "waf" => replace_waf_block(
                &content,
                case["enabled"].as_bool().unwrap_or(false),
                domain,
                true,
            )
            .map_err(|e| e.to_string()),
            "flood" => {
                let config = case
                    .get("config")
                    .map(HttpFloodConfig::from_json)
                    .unwrap_or_default();
                replace_http_flood_block(
                    &content,
                    case["enabled"].as_bool().unwrap_or(false),
                    domain,
                    &config,
                )
                .map_err(|e| e.to_string())
            }
            "bots" => {
                let bots = strings(case.get("bots"));
                replace_bot_block(&content, &bots).map_err(|e| e.to_string())
            }
            "custom_position" => {
                ensure_custom_include_position(&content, domain.expect("a domain"))
                    .map_err(|e| e.to_string())
            }
            "domain_from_vhost" => Ok(domain_from_vhost(&content)),
            other => {
                failures.push(format!("{other}:{name}: unknown op in the fixture"));
                continue;
            }
        };
        checked += 1;

        let python_ok = case["ok"].as_bool().unwrap_or(false);
        match (produced, python_ok) {
            (Ok(got), true) => {
                let want = case["sha256"].as_str().expect("a hash");
                if sha256(&got) != want {
                    let detail = match case.get("expected").and_then(Value::as_str) {
                        Some(expected) => first_difference(expected, &got),
                        None => "hashes differ (this case does not keep its text)".to_string(),
                    };
                    failures.push(format!("{op}:{name}: {detail}"));
                }
            }
            (Err(_), false) => {}
            (Ok(_), false) => failures.push(format!(
                "{op}:{name}: rust succeeded where python raised ({})",
                case["error"].as_str().unwrap_or("?")
            )),
            (Err(e), true) => failures.push(format!("{op}:{name}: rust failed: {e}")),
        }
    }

    assert_eq!(checked, cases.len(), "some cases were skipped");
    assert!(
        failures.is_empty(),
        "{} of {} edits differ:\n{}",
        failures.len(),
        cases.len(),
        failures
            .iter()
            .take(8)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
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
