//! `ops::lve` - CloudLinux LVE limits.
//!
//! `lvectl` owns the default LVE; `cloudlinux-limits` owns per-user limits
//! (it resolves usernames through the panel's CPAPI integration). Both print
//! JSON with `--json`. The parsing is kept apart from the commands so it is
//! tested against output captured on a CloudLinux 10 machine.

use serde_json::{json, Value};
use snpanel_core::PanelUsername;
use snpanel_ipc::{HelperErrorKind, HelperResponse, LveLimits, LvePackageName};

use crate::exec;

/// Refuse early and plainly on a machine where LVE is not running.
fn require_lve() -> Result<(), HelperResponse> {
    match snpanel_osabi::hosting::cloudlinux() {
        Some(cl) if cl.lve_loaded => Ok(()),
        Some(_) => Err(HelperResponse::failed(
            HelperErrorKind::NotFound,
            "CloudLinux is installed but the LVE module is not loaded; reboot to finish the conversion"
                .to_string(),
        )),
        None => Err(HelperResponse::failed(
            HelperErrorKind::NotFound,
            "this server is not running CloudLinux".to_string(),
        )),
    }
}

/// A limit as the panel shows it: the number, and whether it is the user's
/// own (cloudlinux-limits marks those with a leading `*`) or the default's.
fn value(raw: &Value) -> (u64, bool) {
    let text = match raw {
        Value::String(s) => s.as_str(),
        Value::Object(o) => o.get("all").and_then(Value::as_str).unwrap_or(""),
        _ => "",
    };
    let custom = text.starts_with('*');
    let number = text
        .trim_start_matches('*')
        .trim()
        .parse::<u64>()
        .unwrap_or(0);
    (number, custom)
}

/// `lvectl list --json` sizes: "1024M", "2G", "0K", or bare numbers.
fn size_mb(text: &str) -> u64 {
    let t = text.trim();
    let (digits, unit) = t.split_at(t.find(|c: char| !c.is_ascii_digit()).unwrap_or(t.len()));
    let n = digits.parse::<u64>().unwrap_or(0);
    match unit.trim().to_ascii_uppercase().as_str() {
        "K" => n / 1024,
        "G" => n * 1024,
        "T" => n * 1024 * 1024,
        _ => n, // "M" or none
    }
}

/// The default LVE row out of `lvectl list --json`.
pub fn parse_default(lvectl_list: &str) -> Option<Value> {
    let v: Value = serde_json::from_str(lvectl_list).ok()?;
    let row = v["data"]
        .as_array()?
        .iter()
        .find(|r| r["ID"].as_str() == Some("default"))?;
    let n = |k: &str| {
        row[k]
            .as_str()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0)
    };
    Some(json!({
        "speed_percent": n("SPEED"),
        "pmem_mb": size_mb(row["PMEM"].as_str().unwrap_or("0")),
        "ep": n("EP"),
        "nproc": n("NPROC"),
        "io_kbps": n("IO"),
        "iops": n("IOPS"),
    }))
}

/// Every user out of `cloudlinux-limits get --json`, limits normalised to the
/// same units as [`LveLimits`] (PMEM arrives in bytes).
pub fn parse_users(limits_get: &str) -> Option<Vec<Value>> {
    let v: Value = serde_json::from_str(limits_get).ok()?;
    if v["result"].as_str() != Some("success") {
        return None;
    }
    let mut out = Vec::new();
    for u in v["users"].as_array()? {
        // cloudlinux-limits also lists LVEs no panel account owns, as "-".
        match u["username"].as_str() {
            Some(name) if !name.is_empty() && name != "-" => {}
            _ => continue,
        }
        let l = &u["limits"];
        let (speed, speed_c) = value(&l["cpu"]);
        let (pmem, pmem_c) = value(&l["pmem"]);
        let (ep, ep_c) = value(&l["ep"]);
        let (nproc, nproc_c) = value(&l["nproc"]);
        let (io, io_c) = value(&l["io"]);
        let (iops, iops_c) = value(&l["iops"]);
        let mut custom = Vec::new();
        for (name, is) in [
            ("speed_percent", speed_c),
            ("pmem_mb", pmem_c),
            ("ep", ep_c),
            ("nproc", nproc_c),
            ("io_kbps", io_c),
            ("iops", iops_c),
        ] {
            if is {
                custom.push(name);
            }
        }
        out.push(json!({
            "username": u["username"],
            "uid": u["id"],
            "domain": u["domain"],
            "cagefs": u["cageFS"].as_str() == Some("enabled"),
            "limits": {
                "speed_percent": speed,
                "pmem_mb": pmem / (1024 * 1024),
                "ep": ep,
                "nproc": nproc,
                "io_kbps": io,
                "iops": iops,
            },
            "custom": custom,
        }));
    }
    Some(out)
}

/// `cloudlinux-limits set --json` answers 0 with `"result": "No such user"`
/// and similar, so success is the JSON's word, not the exit code.
fn limits_result(label: &str, out: std::io::Result<exec::Output>) -> HelperResponse {
    let out = match out {
        Ok(o) => o,
        Err(e) => {
            return HelperResponse::failed(HelperErrorKind::CommandFailed, format!("{label}: {e}"))
        }
    };
    let stdout = out.stdout.clone();
    let result = serde_json::from_str::<Value>(stdout.trim())
        .ok()
        .and_then(|v| v["result"].as_str().map(str::to_string))
        .unwrap_or_default();
    if out.ok() && result == "success" {
        return HelperResponse::with_stdout("ok\n".to_string());
    }
    let detail = if result.is_empty() {
        out.stderr.trim().to_string()
    } else {
        result
    };
    let kind = if detail.starts_with("No such user") {
        HelperErrorKind::NotFound
    } else {
        HelperErrorKind::CommandFailed
    };
    HelperResponse::failed(kind, format!("{label}: {detail}"))
}

/// Where lvectl keeps the default's, packages' and LVEs' limits.
const VE_CFG: &str = "/etc/container/ve.cfg";

fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&#39;", "'")
        .replace("&amp;", "&")
}

/// The value of `attr="..."` inside one XML tag.
fn attr<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    let key = format!("{attr}=\"");
    let start = tag.find(&key)? + key.len();
    let len = tag[start..].find('"')?;
    Some(&tag[start..start + len])
}

/// Every `<package id="...">` block in ve.cfg: its (unescaped) name, and the
/// `lvectl package-set` flags that reproduce exactly the limits it sets. A
/// limit the package leaves to the default is left out, so a copy inherits
/// the same way the original did. Memory is stored in 4 KiB pages.
pub fn parse_ve_packages(ve_cfg: &str) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut rest = ve_cfg;
    while let Some(at) = rest.find("<package ") {
        rest = &rest[at..];
        let Some(open_end) = rest.find('>') else {
            break;
        };
        let open = &rest[..open_end];
        let Some(id) = attr(open, "id") else {
            rest = &rest[open_end..];
            continue;
        };
        let name = xml_unescape(id);
        let body_end = rest.find("</package>").unwrap_or(rest.len());
        let body = &rest[open_end + 1..body_end];
        let mut flags = Vec::new();
        let pages = |v: &str| v.trim().parse::<u64>().ok().map(|p| p * 4);
        for tag in body
            .split('<')
            .filter(|t| !t.trim().is_empty() && !t.starts_with('/'))
        {
            let element = tag.split_whitespace().next().unwrap_or("");
            match element {
                "cpu" => attr(tag, "limit").map(|v| flags.push(format!("--speed={v}"))),
                "ncpu" => attr(tag, "limit").map(|v| flags.push(format!("--ncpu={v}"))),
                "io" => attr(tag, "limit").map(|v| flags.push(format!("--io={v}"))),
                "iops" => attr(tag, "limit").map(|v| flags.push(format!("--iops={v}"))),
                "nproc" => attr(tag, "limit").map(|v| flags.push(format!("--nproc={v}"))),
                "pmem" => attr(tag, "limit")
                    .and_then(pages)
                    .map(|k| flags.push(format!("--pmem={k}K"))),
                "mem" => attr(tag, "limit")
                    .and_then(pages)
                    .map(|k| flags.push(format!("--vmem={k}K"))),
                "other" => {
                    attr(tag, "maxentryprocs").map(|v| flags.push(format!("--maxEntryProcs={v}")))
                }
                _ => None,
            };
        }
        out.push((name, flags));
        rest = &rest[body_end..];
    }
    out
}

fn ve_packages() -> Vec<(String, Vec<String>)> {
    std::fs::read_to_string(VE_CFG)
        .map(|s| parse_ve_packages(&s))
        .unwrap_or_default()
}

/// The packages out of `lvectl package-list --json` (the ones the CPAPI
/// snapshot reports), each marked with whether it has limits of its own.
pub fn parse_packages(package_list: &str, own: &[String]) -> Option<Vec<Value>> {
    let v: Value = serde_json::from_str(package_list).ok()?;
    let mut out = Vec::new();
    for row in v["data"].as_array()? {
        let Some(name) = row["ID"].as_str() else {
            continue;
        };
        if name == "VE_DEFAULT" {
            continue;
        }
        let n = |k: &str| {
            row[k]
                .as_str()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .unwrap_or(0)
        };
        out.push(json!({
            "name": name,
            "custom": own.iter().any(|o| o == name),
            "limits": {
                "speed_percent": n("SPEED"),
                "pmem_mb": size_mb(row["PMEM"].as_str().unwrap_or("0")),
                "ep": n("EP"),
                "nproc": n("NPROC"),
                "io_kbps": n("IO"),
                "iops": n("IOPS"),
            },
        }));
    }
    Some(out)
}

/// `lve-status`.
pub fn status() -> HelperResponse {
    if let Err(r) = require_lve() {
        return r;
    }
    let list = match exec::run(&["lvectl", "list", "--json"]) {
        Ok(o) if o.ok() => o.stdout.clone(),
        other => return exec::respond("lvectl list", other),
    };
    let users = match exec::run(&["cloudlinux-limits", "get", "--json"]) {
        Ok(o) if o.ok() => o.stdout.clone(),
        other => return exec::respond("cloudlinux-limits get", other),
    };
    let Some(default) = parse_default(&list) else {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            "lvectl list printed no default LVE".to_string(),
        );
    };
    let Some(users) = parse_users(&users) else {
        return HelperResponse::failed(
            HelperErrorKind::Internal,
            "cloudlinux-limits get did not succeed".to_string(),
        );
    };
    let own: Vec<String> = ve_packages().into_iter().map(|(n, _)| n).collect();
    let packages = match exec::run(&["lvectl", "package-list", "--json"]) {
        Ok(o) if o.ok() => parse_packages(&o.stdout, &own).unwrap_or_default(),
        _ => Vec::new(),
    };
    HelperResponse::with_stdout(format!(
        "{}\n",
        json!({ "default": default, "users": users, "packages": packages })
    ))
}

/// Package limits reach running LVEs only when they are re-applied.
fn apply_all(label: &str, out: std::io::Result<exec::Output>) -> HelperResponse {
    if !matches!(&out, Ok(o) if o.ok()) {
        return exec::respond(label, out);
    }
    exec::respond("lvectl apply all", exec::run(&["lvectl", "apply", "all"]))
}

/// `lve-package-set`.
pub fn package_set(package: &LvePackageName, limits: &LveLimits) -> HelperResponse {
    if let Err(r) = require_lve() {
        return r;
    }
    if let Err(m) = limits.validate() {
        return HelperResponse::failed(HelperErrorKind::BadRequest, m);
    }
    let flags = limits.flags();
    let mut argv = vec!["lvectl", "package-set", package.as_str()];
    argv.extend(flags.iter().map(String::as_str));
    apply_all("lvectl package-set", exec::run(&argv))
}

/// `lve-package-reset`. Deleting limits a package does not have succeeds.
pub fn package_reset(package: &LvePackageName) -> HelperResponse {
    if let Err(r) = require_lve() {
        return r;
    }
    apply_all(
        "lvectl package-delete",
        exec::run(&["lvectl", "package-delete", package.as_str()]),
    )
}

/// `lve-package-rename`. A package without limits of its own has nothing to
/// carry over; the new name inherits the default just as the old one did.
pub fn package_rename(from: &LvePackageName, to: &LvePackageName) -> HelperResponse {
    if let Err(r) = require_lve() {
        return r;
    }
    let Some((_, flags)) = ve_packages().into_iter().find(|(n, _)| n == from.as_str()) else {
        return HelperResponse::with_stdout("ok\n".to_string());
    };
    if !flags.is_empty() {
        let mut argv = vec!["lvectl", "package-set", to.as_str()];
        argv.extend(flags.iter().map(String::as_str));
        let out = exec::run(&argv);
        if !matches!(&out, Ok(o) if o.ok()) {
            return exec::respond("lvectl package-set", out);
        }
    }
    apply_all(
        "lvectl package-delete",
        exec::run(&["lvectl", "package-delete", from.as_str()]),
    )
}

/// `lve-set`.
pub fn set(user: Option<&PanelUsername>, limits: &LveLimits) -> HelperResponse {
    if let Err(r) = require_lve() {
        return r;
    }
    // Checked again here: the helper is also reachable through argv.
    if let Err(m) = limits.validate() {
        return HelperResponse::failed(HelperErrorKind::BadRequest, m);
    }
    let flags = limits.flags();
    match user {
        None => {
            let mut argv = vec!["lvectl", "set", "default"];
            argv.extend(flags.iter().map(String::as_str));
            let out = exec::run(&argv);
            if !matches!(&out, Ok(o) if o.ok()) {
                return exec::respond("lvectl set default", out);
            }
            // lvectl applies to LVEs created from now on; existing ones keep
            // their limits until re-applied.
            exec::respond("lvectl apply all", exec::run(&["lvectl", "apply", "all"]))
        }
        Some(u) => {
            let mut argv = vec![
                "cloudlinux-limits",
                "set",
                "--json",
                "--username",
                u.as_str(),
            ];
            argv.extend(flags.iter().map(String::as_str));
            limits_result("cloudlinux-limits set", exec::run(&argv))
        }
    }
}

/// `lve-reset`.
pub fn reset(user: &PanelUsername) -> HelperResponse {
    if let Err(r) = require_lve() {
        return r;
    }
    limits_result(
        "cloudlinux-limits set --default",
        exec::run(&[
            "cloudlinux-limits",
            "set",
            "--json",
            "--username",
            user.as_str(),
            "--default",
            "all",
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Captured on the CL-0 CloudLinux 10 machine (trimmed).
    const LVECTL_LIST: &str = r#"{"data":[{"ID":"default","SPEED":"100","CPU":"25","PMEM":"1024M","VMEM":"0K","EP":"20","NPROC":"100","IO":"1024","IOPS":"1024"},{"ID":"48","SPEED":"400","CPU":"100","PMEM":"2048000M","VMEM":"0K","EP":"0","NPROC":"0","IO":"0","IOPS":"0"}]}"#;

    const LIMITS_GET: &str = r#"{"cageFS": "enabled", "errors": {"quota": "Quotas not activated on this system"}, "items": 2, "result": "success", "users": [
        {"cageFS": "enabled", "domain": "wp2.alice.test", "id": 1001, "limits": {"cpu": {"all": "100"}, "ep": "20", "io": {"all": "1024"}, "iops": "1024", "nproc": "100", "pmem": "1073741824", "vmem": "0"}, "package": "None", "reseller": "admin", "username": "alice"},
        {"cageFS": "disabled", "domain": "php8.dave.test", "id": 1004, "limits": {"cpu": {"all": "*150"}, "ep": "*30", "io": {"all": "*2048"}, "iops": "*2048", "nproc": "*120", "pmem": "*1610612736", "vmem": "0"}, "package": "None", "reseller": "admin", "username": "dave"}]}"#;

    #[test]
    fn reads_the_default_lve_from_lvectl() {
        let d = parse_default(LVECTL_LIST).unwrap();
        assert_eq!(
            d,
            json!({"speed_percent":100,"pmem_mb":1024,"ep":20,"nproc":100,"io_kbps":1024,"iops":1024})
        );
        assert_eq!(parse_default(r#"{"data":[]}"#), None);
        assert_eq!(parse_default("not json"), None);
    }

    #[test]
    fn reads_users_and_marks_their_own_limits() {
        let users = parse_users(LIMITS_GET).unwrap();
        assert_eq!(users.len(), 2);
        let alice = &users[0];
        assert_eq!(alice["username"], "alice");
        assert_eq!(alice["limits"]["pmem_mb"], 1024);
        assert_eq!(alice["custom"], json!([]));
        assert_eq!(alice["cagefs"], true);

        let dave = &users[1];
        assert_eq!(dave["limits"]["speed_percent"], 150);
        assert_eq!(dave["limits"]["pmem_mb"], 1536);
        assert_eq!(dave["limits"]["io_kbps"], 2048);
        assert_eq!(dave["cagefs"], false);
        assert_eq!(
            dave["custom"],
            json!(["speed_percent", "pmem_mb", "ep", "nproc", "io_kbps", "iops"])
        );
    }

    #[test]
    fn lves_without_a_panel_account_are_left_out() {
        let get = r#"{"result": "success", "users": [
            {"username": "-", "domain": "-", "id": 991, "cageFS": "disabled", "limits": {"cpu": {"all": "100"}, "pmem": "1073741824"}},
            {"username": "alice", "domain": "a.test", "id": 1001, "cageFS": "enabled", "limits": {"cpu": {"all": "100"}, "pmem": "1073741824"}}]}"#;
        let users = parse_users(get).unwrap();
        assert_eq!(users.len(), 1);
        assert_eq!(users[0]["username"], "alice");
    }

    #[test]
    fn a_failed_get_is_not_an_empty_list() {
        assert_eq!(
            parse_users(r#"{"result": "No such user (%(user)s)", "users": []}"#),
            None
        );
    }

    // ve.cfg as lvectl wrote it on the CL-0 machine.
    const VE_CFG_SAMPLE: &str = r#"<?xml version="1.0" ?>
<lveconfig>
	<defaults>
		<cpu limit="100%"/>
		<pmem limit="262144"/>
	</defaults>
	<package id="Starter">
		<cpu limit="50%"/>
		<io limit="512"/>
		<pmem limit="131072"/>
		<nproc limit="50"/>
		<iops limit="512"/>
		<other maxentryprocs="10"/>
	</package>
	<package id="Gói Pro &amp; &lt;x&gt;">
		<cpu limit="20%"/>
	</package>
	<lve id="48">
		<cpu limit="400%"/>
	</lve>
</lveconfig>"#;

    #[test]
    fn package_limits_are_read_back_as_the_flags_that_set_them() {
        let pkgs = parse_ve_packages(VE_CFG_SAMPLE);
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0].0, "Starter");
        assert_eq!(
            pkgs[0].1,
            [
                "--speed=50%",
                "--io=512",
                "--pmem=524288K",
                "--nproc=50",
                "--iops=512",
                "--maxEntryProcs=10"
            ]
        );
        // Escaped names come back as the panel spells them, and a package
        // that sets one limit carries only that one.
        assert_eq!(pkgs[1].0, "Gói Pro & <x>");
        assert_eq!(pkgs[1].1, ["--speed=20%"]);
    }

    #[test]
    fn packages_are_marked_with_whether_they_have_their_own_limits() {
        let list = r#"{"data":[{"ID":"VE_DEFAULT","SPEED":"100","PMEM":"1024M","EP":"20","NPROC":"100","IO":"1024","IOPS":"1024"},{"ID":"Starter","SPEED":"50","PMEM":"512M","EP":"10","NPROC":"50","IO":"512","IOPS":"512"},{"ID":"Pro","SPEED":"100","PMEM":"1024M","EP":"20","NPROC":"100","IO":"1024","IOPS":"1024"}]}"#;
        let pkgs = parse_packages(list, &["Starter".to_string()]).unwrap();
        assert_eq!(pkgs.len(), 2);
        assert_eq!(pkgs[0]["name"], "Starter");
        assert_eq!(pkgs[0]["custom"], true);
        assert_eq!(pkgs[0]["limits"]["pmem_mb"], 512);
        assert_eq!(pkgs[1]["custom"], false);
    }

    #[test]
    fn sizes_convert_to_megabytes() {
        assert_eq!(size_mb("1024M"), 1024);
        assert_eq!(size_mb("2G"), 2048);
        assert_eq!(size_mb("0K"), 0);
        assert_eq!(size_mb("512"), 512);
    }
}
