import json
import os
import re
import subprocess
import time
from pathlib import Path

from app.core import platform
from app.core.version import APP_VERSION
from app.services.shell import shell


REPO_URL = os.environ.get("SNPANEL_REPO_URL", "https://github.com/vnscorpion/snpanel.git")
UPDATE_STATE_FILE = Path(os.environ.get("SNPANEL_UPDATE_STATE_FILE", "/var/lib/snpanel/update-status.json"))
SEMVER_TAG_RE = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
STATUS_CACHE_SECONDS = 300


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _semver_tuple(value: str):
    value = (value or "").strip()
    if value.startswith("v"):
        value = value[1:]
    parts = value.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        return None
    return tuple(int(part) for part in parts)


def _read_update_state() -> dict:
    try:
        if UPDATE_STATE_FILE.exists():
            return json.loads(UPDATE_STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {}


def _write_update_state(state: dict) -> None:
    try:
        UPDATE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = UPDATE_STATE_FILE.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp_path.replace(UPDATE_STATE_FILE)
    except Exception:
        # Update status should never break the Updates page itself.
        return


def _latest_release_from_git() -> tuple[str, str]:
    completed = subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", REPO_URL, "refs/tags/v*"],
        capture_output=True,
        text=True,
        check=False,
        timeout=12,
    )
    if completed.returncode != 0:
        raise RuntimeError((completed.stderr or completed.stdout or "Could not read release tags").strip())
    candidates = []
    for line in completed.stdout.splitlines():
        ref = line.rsplit("/", 1)[-1].strip()
        match = SEMVER_TAG_RE.match(ref)
        if match:
            candidates.append((tuple(int(part) for part in match.groups()), ref))
    if not candidates:
        raise RuntimeError("No release tags found")
    _, latest_tag = max(candidates, key=lambda item: item[0])
    return latest_tag, latest_tag[1:]


def panel_release_status(force_refresh: bool = False) -> dict:
    state = _read_update_state()
    now = _utc_now()
    current_version = APP_VERSION
    current_tuple = _semver_tuple(current_version)
    latest_version = state.get("latest_version") or ""
    latest_tag = state.get("latest_tag") or (f"v{latest_version}" if latest_version else "")
    check_error = ""

    checked_at = float(state.get("last_checked_epoch") or 0)
    should_refresh = force_refresh or not latest_version or (time.time() - checked_at > STATUS_CACHE_SECONDS)
    if should_refresh:
        try:
            latest_tag, latest_version = _latest_release_from_git()
            state.update(
                {
                    "current_version": current_version,
                    "latest_tag": latest_tag,
                    "latest_version": latest_version,
                    "last_checked_at": now,
                    "last_checked_epoch": time.time(),
                    "check_error": "",
                }
            )
        except Exception as exc:
            check_error = str(exc)
            state.update(
                {
                    "current_version": current_version,
                    "last_checked_at": now,
                    "last_checked_epoch": time.time(),
                    "check_error": check_error,
                }
            )
        _write_update_state(state)
    else:
        state["current_version"] = current_version

    latest_tuple = _semver_tuple(latest_version)
    update_available = None
    if current_tuple and latest_tuple:
        update_available = latest_tuple > current_tuple
    elif not check_error:
        check_error = state.get("check_error") or ""

    return {
        "current_version": current_version,
        "latest_version": latest_version,
        "latest_tag": latest_tag,
        "update_available": update_available,
        "last_checked_at": state.get("last_checked_at") or "",
        "last_update_started_at": state.get("last_update_started_at") or "",
        "last_update_finished_at": state.get("last_update_finished_at") or "",
        "last_update_status": state.get("last_update_status") or "",
        "last_update_ref": state.get("last_update_ref") or "",
        "check_error": check_error or state.get("check_error") or "",
        "progress_percent": state.get("progress_percent", 0),
        "progress_phase": state.get("progress_phase") or "",
        "progress_message": state.get("progress_message") or "",
        "state_file": str(UPDATE_STATE_FILE),
    }


def _read_panel_update_log(max_lines: int = 100) -> list[str]:
    """Return recent panel update log lines.

    Prefers the systemd journal for `snpanel-panel-update.service`; falls back to
    the flat log file at /var/log/snpanel-panel-update.log when journald is
    unavailable (e.g. containers without systemd).
    """
    lines: list[str] = []
    try:
        have_journal = subprocess.run(
            ["systemctl", "cat", "snpanel-panel-update.service"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        ).returncode == 0
        journal_ok = False
        if have_journal:
            completed = subprocess.run(
                ["journalctl", "-u", "snpanel-panel-update.service", "-n", str(max_lines), "--no-pager", "--output=cat"],
                capture_output=True,
                text=True,
                check=False,
                timeout=10,
            )
            if completed.returncode == 0 and completed.stdout.strip():
                lines = completed.stdout.splitlines()[-max_lines:]
                journal_ok = True
        if not journal_ok:
            log_path = Path("/var/log/snpanel-panel-update.log")
            if log_path.exists():
                with log_path.open("r", encoding="utf-8", errors="replace") as handle:
                    lines = handle.read().splitlines()[-max_lines:]
    except Exception:
        return []
    return lines


def status(force_refresh: bool = False):
    result = shell.privileged(
        "updates-status",
        check=False,
        fallback=["bash", "-lc", "apt list --upgradable 2>/dev/null | head -40"],
    )
    payload = result.__dict__
    payload["panel"] = panel_release_status(force_refresh=force_refresh)
    payload["panel_update_log"] = _read_panel_update_log()
    return payload


def run_os_update():
    return shell.privileged(
        "updates-os-run",
        check=False,
        fallback=[
            "bash",
            "-lc",
            f"nohup bash -lc '{platform.upgrade_command()}' >/tmp/snpanel-os-update.log 2>&1 "
            "& echo OS update started in background. Log: /tmp/snpanel-os-update.log",
        ],
    )


def configure_os_auto_update(enabled: bool, mode: str, auto_reboot: bool):
    if mode not in {"security", "all"}:
        raise ValueError("Unsupported OS auto-update mode")
    return shell.privileged(
        "updates-os-auto",
        helper_args=["on" if enabled else "off", mode, "on" if auto_reboot else "off"],
        check=False,
        fallback=["bash", "-lc", "echo unattended-upgrades helper is not installed"],
    )


def run_panel_update():
    state = _read_update_state()
    state.update(
        {
            "last_update_status": "checking",
            "last_update_started_at": _utc_now(),
            "last_update_message": "Starting panel update",
            "progress_percent": 0,
            "progress_phase": "starting",
            "progress_message": "Starting panel update",
        }
    )
    _write_update_state(state)
    result = shell.privileged(
        "updates-panel-run",
        check=False,
        fallback=["bash", "installer/update.sh"],
    )
    if result.returncode != 0:
        state = _read_update_state()
        state.update(
            {
                "last_update_status": "failed",
                "last_update_finished_at": _utc_now(),
                "last_update_message": (result.stderr or result.stdout or "Panel update could not be started").strip(),
                "progress_phase": "failed",
                "progress_message": "Panel update could not be started",
            }
        )
        _write_update_state(state)
    return result

