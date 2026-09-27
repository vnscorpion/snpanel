//! What the update tells the panel about itself while it runs.
//!
//! Source: `update_progress`, `finish_update_script`, `panel_healthcheck`.
//!
//! The panel's own update page reads this file, and the update is often the
//! reason the panel is down — so the file has to be written by something
//! that survives the panel, and it has to be readable afterwards whatever
//! went wrong. Both facts shape the whole module: every write merges into
//! whatever is already there, and the failure path is a trap that runs on
//! every exit rather than a branch somebody has to remember.

/// Where the state lives.
pub const FILE: &str = "/var/lib/snpanel/update-status.json";
/// `0640`, owned by `snpanel` — the panel reads it, and it records a version
/// and a failure message rather than anything secret.
pub const FILE_MODE: u32 = 0o640;
pub const DIR_MODE: u32 = 0o750;

/// One progress update, merged into the existing file.
///
/// Three rules, and each of them is about not losing what is already known:
///
/// * a file that cannot be parsed is replaced rather than read — a corrupt
///   file must not stop the update from reporting;
/// * a percentage that is not a number becomes `0` rather than being
///   dropped, so the field is always present and always an integer;
/// * an empty phase or message **does not overwrite** the one already
///   there, which is what lets a caller update only the percentage.
pub fn merge(existing: Option<&str>, percent: &str, phase: &str, message: &str) -> Progress {
    let mut state = existing
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default();

    state.insert(
        "progress_percent".into(),
        serde_json::Value::from(percent.parse::<i64>().unwrap_or(0)),
    );
    if !phase.is_empty() {
        state.insert("progress_phase".into(), serde_json::Value::from(phase));
    }
    if !message.is_empty() {
        state.insert("progress_message".into(), serde_json::Value::from(message));
    }
    Progress(state)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Progress(pub serde_json::Map<String, serde_json::Value>);

impl Progress {
    /// `json.dumps(..., indent=2, sort_keys=True) + "\n"`.
    ///
    /// Sorted and with a trailing newline because the file is read by a
    /// human as often as by the panel, and a diff between two runs should
    /// show what changed rather than what moved.
    pub fn render(&self) -> String {
        let mut out = serde_json::to_string_pretty(&serde_json::Value::Object(self.0.clone()))
            .unwrap_or_else(|_| "{}".into());
        out.push('\n');
        out
    }

    pub fn percent(&self) -> i64 {
        self.0
            .get("progress_percent")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
    }
}

/// The percentage already recorded, for the failure path to preserve.
///
/// An update that failed at 70% should say so; resetting to 0 would tell the
/// operator it never started, which sends them looking in the wrong place.
/// Anything unreadable is `0`, which is the honest answer when the file is
/// gone.
pub fn recorded_percent(existing: Option<&str>) -> i64 {
    existing
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
        .and_then(|v| v.get("progress_percent").and_then(|p| p.as_i64()))
        .unwrap_or(0)
}

pub fn failure_message(exit_code: i32) -> String {
    format!("Update failed with exit code {exit_code}")
}

/// Whether the panel is answering.
///
/// HTTPS first and HTTP second, because a box part-way through
/// [`super::panel_https`] may be on either. The HTTPS attempt passes `-k`,
/// and that is correct rather than lax: the request is to `127.0.0.1`, and
/// the certificate there is the panel's own — frequently self-signed, and
/// issued for the panel's hostname rather than for the loopback address it
/// is being reached on. Verifying it would fail on a healthy panel.
pub fn healthcheck_urls(port: u16) -> [String; 2] {
    [
        format!("https://127.0.0.1:{port}/api/health"),
        format!("http://127.0.0.1:{port}/api/health"),
    ]
}

/// `PANEL_PORT` with the default the shell falls back to.
pub const DEFAULT_PORT: u16 = 2222;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_progress_update_merges_into_what_is_there() {
        let existing = r#"{"status":"running","version":"1.2.3","progress_percent":10}"#;
        let merged = merge(Some(existing), "40", "building", "Building frontend");
        // The fields this call did not touch survive.
        assert_eq!(merged.0["status"], "running");
        assert_eq!(merged.0["version"], "1.2.3");
        // And the ones it did are updated.
        assert_eq!(merged.percent(), 40);
        assert_eq!(merged.0["progress_phase"], "building");
        assert_eq!(merged.0["progress_message"], "Building frontend");
    }

    /// A corrupt file must not stop the update from reporting — the whole
    /// point of the file is to be readable when something has gone wrong.
    #[test]
    fn a_file_that_cannot_be_parsed_is_replaced_rather_than_read() {
        for broken in ["", "not json", "{", "[1,2,3]", "null", "\"a string\""] {
            let merged = merge(Some(broken), "40", "building", "");
            assert_eq!(merged.percent(), 40, "{broken:?}");
            assert_eq!(merged.0["progress_phase"], "building");
        }
        assert_eq!(merge(None, "40", "x", "").percent(), 40);
    }

    /// The field is always present and always an integer, so a reader never
    /// has to handle its absence.
    #[test]
    fn a_percentage_that_is_not_a_number_becomes_zero() {
        for bad in ["", "abc", "40.5", "  ", "1e3", "-"] {
            assert_eq!(merge(None, bad, "", "").percent(), 0, "{bad:?}");
        }
        assert_eq!(merge(None, "0", "", "").percent(), 0);
        assert_eq!(merge(None, "100", "", "").percent(), 100);
        // A negative integer is a number, and is kept as one.
        assert_eq!(merge(None, "-5", "", "").percent(), -5);
    }

    /// An empty phase or message does not overwrite the one already there,
    /// which is what lets a caller update only the percentage.
    #[test]
    fn an_empty_phase_or_message_leaves_the_previous_one_alone() {
        let existing = r#"{"progress_phase":"building","progress_message":"Building frontend"}"#;
        let merged = merge(Some(existing), "50", "", "");
        assert_eq!(merged.0["progress_phase"], "building");
        assert_eq!(merged.0["progress_message"], "Building frontend");
        assert_eq!(merged.percent(), 50);
    }

    /// Sorted, indented, and newline-terminated: the file is read by a human
    /// as often as by the panel, and a diff between two runs should show
    /// what changed rather than what moved.
    #[test]
    fn the_file_is_written_in_a_stable_shape() {
        let rendered = merge(None, "40", "building", "msg").render();
        assert!(rendered.ends_with("}\n"));
        assert!(rendered.contains("\n  \"progress_percent\": 40"));
        let keys: Vec<&str> = rendered
            .lines()
            .filter_map(|l| l.trim().strip_prefix('"'))
            .filter_map(|l| l.split('"').next())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        assert_eq!(keys, sorted, "the keys are not in sorted order");
    }

    /// An update that failed at 70% should say so. Resetting to 0 would tell
    /// the operator it never started, which sends them looking in the wrong
    /// place.
    #[test]
    fn a_failure_keeps_the_percentage_it_got_to() {
        assert_eq!(recorded_percent(Some(r#"{"progress_percent":70}"#)), 70);
        // And an unreadable or absent file is honestly zero.
        assert_eq!(recorded_percent(Some("garbage")), 0);
        assert_eq!(recorded_percent(Some("{}")), 0);
        assert_eq!(recorded_percent(None), 0);
        assert_eq!(failure_message(3), "Update failed with exit code 3");
    }

    /// A box part-way through the HTTPS migration may be on either scheme,
    /// so both are tried — and the secure one first, so a panel that is
    /// already on TLS is not recorded as healthy by an HTTP probe that
    /// happened to answer.
    #[test]
    fn the_health_check_tries_https_first_and_falls_back() {
        let urls = healthcheck_urls(2222);
        assert_eq!(urls[0], "https://127.0.0.1:2222/api/health");
        assert_eq!(urls[1], "http://127.0.0.1:2222/api/health");
        // Always loopback: this asks whether the service is up, not whether
        // the firewall lets anyone in.
        assert!(urls.iter().all(|u| u.contains("//127.0.0.1:")));
        assert_eq!(DEFAULT_PORT, 2222);
    }

    /// The file records a version and a failure message, and the panel has
    /// to read it — but nothing else should.
    #[test]
    fn the_state_file_is_not_world_readable() {
        assert_eq!(FILE_MODE & 0o007, 0);
        assert_eq!(FILE_MODE & 0o040, 0o040);
        assert_eq!(DIR_MODE & 0o007, 0);
        assert!(FILE.starts_with("/var/lib/snpanel/"));
    }
}
