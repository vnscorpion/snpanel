//! Contract C19: the nginx templates must render byte-identically.
//!
//! This is the highest-consequence golden test in the project. A vhost that
//! differs by one line is a website that stops serving, and nobody notices
//! until a customer reports it.
//!
//! The expected output is produced by the *real* Jinja2, driven by the real
//! `render_vhost`, in `tests/fixtures/generate.py`, and committed. The
//! contexts are captured from that same run rather than written by hand, so
//! they include the values Python computes (the flood zone name, the challenge
//! block, the resolved FPM socket) that no amount of reading the templates
//! would reveal.
//!
//! This task renders the same templates with minijinja against the same
//! contexts and diffs the bytes.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde_json::Value;

pub fn check(args: &[String]) -> Result<()> {
    let verbose = args.iter().any(|a| a == "--verbose");
    let repo = repo_root()?;
    let renders_path = repo.join("tests/golden/nginx/template_renders.json");

    if !renders_path.exists() {
        bail!(
            "no captured renders at {}.\n\
             Generate them first:\n\
             \n    python3 -m venv .venv\n\
                 .venv/bin/pip install -r backend/requirements.txt\n\
                 .venv/bin/python tests/fixtures/generate.py\n",
            renders_path.display()
        );
    }

    let renders: Vec<Value> = serde_json::from_str(
        &std::fs::read_to_string(&renders_path).context("reading the captured renders")?,
    )
    .context("parsing the captured renders")?;

    if renders.is_empty() {
        bail!("the captured renders file is empty");
    }

    let template_dir = repo.join("crates/snpanel-nginx/templates");
    let mut env = minijinja::Environment::new();
    env.set_loader(minijinja::path_loader(&template_dir));
    // Jinja2 is configured with autoescape=False in nginx.py: an nginx config
    // is not HTML, and escaping it would corrupt every regex in the file.
    env.set_auto_escape_callback(|_| minijinja::AutoEscape::None);

    let mut failures = Vec::new();

    for (i, entry) in renders.iter().enumerate() {
        let template = entry["template"].as_str().context("captured: template")?;
        let context = entry["context"].clone();
        let expected = entry["output"].as_str().context("captured: output")?;

        let tmpl = env
            .get_template(template)
            .with_context(|| format!("loading {template}"))?;

        let rendered = match tmpl.render(&context) {
            Ok(r) => r,
            Err(e) => {
                failures.push(format!(
                    "#{i} {template}\n  minijinja failed to render: {e:#}"
                ));
                continue;
            }
        };

        if rendered == expected {
            if verbose {
                println!("  ok  #{i} {template}");
            }
            continue;
        }

        failures.push(format!(
            "#{i} {template}\n{}",
            first_difference(expected, &rendered)
        ));
    }

    if !failures.is_empty() {
        bail!(
            "{} of {} renders differ from Jinja2:\n\n{}",
            failures.len(),
            renders.len(),
            failures.join("\n\n")
        );
    }

    println!(
        "golden-nginx: {} renders match Jinja2 byte for byte",
        renders.len()
    );
    Ok(())
}

/// Show the first line that differs, with a little context. A full diff of a
/// 200-line vhost buries the one line that matters.
fn first_difference(expected: &str, actual: &str) -> String {
    let e: Vec<&str> = expected.lines().collect();
    let a: Vec<&str> = actual.lines().collect();
    for (i, (el, al)) in e.iter().zip(a.iter()).enumerate() {
        if el != al {
            return format!(
                "  line {}:\n    jinja2:    {el:?}\n    minijinja: {al:?}",
                i + 1
            );
        }
    }
    format!(
        "  same prefix, different length: jinja2 has {} lines, minijinja {}",
        e.len(),
        a.len()
    )
}

fn repo_root() -> Result<PathBuf> {
    // CARGO_MANIFEST_DIR is <repo>/xtask.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest
        .parent()
        .context("xtask should live one level below the repository root")?;
    if !root.join("Cargo.toml").exists() {
        bail!("cannot find the workspace root from {}", manifest.display());
    }
    Ok(root.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_diff_points_at_the_first_differing_line() {
        let out = first_difference("a\nb\nc\n", "a\nX\nc\n");
        assert!(out.contains("line 2"));
        assert!(out.contains("\"b\""));
        assert!(out.contains("\"X\""));
    }

    #[test]
    fn a_length_difference_is_reported() {
        let out = first_difference("a\nb\n", "a\nb\nc\n");
        assert!(out.contains("different length"));
    }

    #[test]
    fn repo_root_is_findable() {
        let root = repo_root().unwrap();
        assert!(root.join("Cargo.toml").exists());
        assert!(root.join("crates").is_dir());
    }

    /// The spike itself, as a test so CI runs it without a separate step.
    #[test]
    fn minijinja_matches_jinja2_on_every_captured_render() {
        check(&[]).expect("C19: the nginx templates must render identically");
    }
}
