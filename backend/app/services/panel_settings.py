import json
import os
import re
import time
import uuid
from pathlib import Path
from tempfile import NamedTemporaryFile
from urllib.parse import urlparse

from fastapi import HTTPException, UploadFile, status

from app.core.config import settings
from app.services import panel_ipv6, server_network
from app.services.shell import shell


SETTINGS_DIR = Path(os.environ.get("SNPANEL_DATA_DIR", "/var/lib/snpanel"))
SETTINGS_FILE = SETTINGS_DIR / "panel-settings.json"
ASSETS_DIR = SETTINGS_DIR / "assets"
MAX_ASSET_SIZE = 1024 * 1024
ALLOWED_ASSET_TYPES = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
    "ico": "image/x-icon",
}
DOMAIN_RE = re.compile(r"^(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,}$")
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _read_raw() -> dict:
    try:
        if SETTINGS_FILE.exists():
            return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return {}


def _write_raw(data: dict) -> None:
    SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", encoding="utf-8", dir=str(SETTINGS_DIR), delete=False) as tmp:
        json.dump(data, tmp, ensure_ascii=True, indent=2, sort_keys=True)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    tmp_path.replace(SETTINGS_FILE)


def configured_panel_url() -> str:
    """The panel URL an admin set, without the cost of current_settings().

    Link builders need this on every request; refreshing the malware scan
    status to read one string would be a poor trade.
    """
    return (_read_raw().get("panel_url") or settings.panel_url or "").strip()


def global_blocked_bots() -> list[str]:
    """The server-wide bad-bot list.

    Read through _read_raw rather than current_settings(): that one refreshes
    the malware scan status, which is far too much work to answer "what bots
    are blocked" on every vhost render.
    """
    from app.services import nginx

    return nginx.normalize_blocked_bots(_read_raw().get("global_blocked_bots") or "")


def crs_mode() -> str:
    """The server-wide OWASP CRS mode an admin chose: off, detect, or block.

    Read through _read_raw for the same reason global_blocked_bots does: this is
    consulted on every vhost and site-rule render.
    """
    return (_read_raw().get("crs_mode") or "off").strip().lower()


def save_crs_mode(mode: str) -> str:
    """Store the CRS mode. Callers re-render the site rule files - see
    waf.set_crs_mode(), which is the only thing that should call this."""
    value = (mode or "off").strip().lower()
    data = _read_raw()
    data["crs_mode"] = value
    _write_raw(data)
    return value


def save_global_blocked_bots(raw) -> list[str]:
    """Store the server-wide list. Callers are responsible for re-rendering the
    vhosts afterwards - see waf.resync_bot_blocks()."""
    from app.services import nginx

    bots = nginx.normalize_blocked_bots(raw)
    data = _read_raw()
    data["global_blocked_bots"] = "\n".join(bots)
    _write_raw(data)
    return bots


def _asset_url(filename: str | None) -> str:
    if not filename:
        return ""
    path = ASSETS_DIR / filename
    if not path.exists():
        return ""
    stat = path.stat()
    version = f"{stat.st_mtime_ns}-{stat.st_size}"
    return f"/brand-assets/{filename}?v={version}"


def _is_ipv4(host: str) -> bool:
    if not IPV4_RE.fullmatch(host):
        return False
    return all(0 <= int(part) <= 255 for part in host.split("."))


def is_domain(host: str) -> bool:
    return bool(DOMAIN_RE.fullmatch((host or "").lower()))


def default_ssl_email(host: str) -> str:
    return f"admin@{host.lower()}" if is_domain(host) else ""


def normalize_panel_hostname(value: str) -> str:
    host = (value or "").strip().lower().rstrip(".")
    if not host:
        raise ValueError("Panel hostname is required")
    if "://" in host or "/" in host or ":" in host:
        raise ValueError("Panel hostname must not include a scheme, port, or path")
    if not is_domain(host) and not _is_ipv4(host) and host != "localhost":
        raise ValueError("Panel hostname must be a domain name or IPv4 address")
    return host


def normalize_panel_port(value: int | str | None) -> int:
    try:
        port = int(value or settings.panel_port or 2222)
    except (TypeError, ValueError) as exc:
        raise ValueError("Panel port is invalid") from exc
    if port < 1 or port > 65535:
        raise ValueError("Panel port is out of range")
    return port


def normalize_panel_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise ValueError("Panel URL is required")
    if "://" not in value:
        value = f"http://{value}"
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme not in {"http", "https"}:
        raise ValueError("Panel URL must start with http:// or https://")
    host = normalize_panel_hostname(host)
    port = normalize_panel_port(parsed.port or settings.panel_port or 2222)
    return f"{scheme}://{host}:{port}"


def panel_url_from_parts(hostname: str, port: int | str | None, scheme: str | None = None) -> str:
    safe_scheme = (scheme or "http").lower()
    if safe_scheme not in {"http", "https"}:
        raise ValueError("Panel URL scheme must be http or https")
    host = normalize_panel_hostname(hostname)
    safe_port = normalize_panel_port(port)
    return f"{safe_scheme}://{host}:{safe_port}"


def parse_panel_url(value: str) -> tuple[str, str, int]:
    normalized = normalize_panel_url(value)
    parsed = urlparse(normalized)
    return parsed.scheme, parsed.hostname or "", parsed.port or 2222


def panel_ssl_mode() -> str:
    """How the panel got the certificate it is serving.

    'letsencrypt' and 'domain' are both real certificates — the first issued for
    the panel's own hostname, the second borrowed from a website hosted here.
    'selfsigned' is the default a server with no domain gets; 'none' means the
    panel is answering in the clear, which should not happen any more.
    """
    mode = (getattr(settings, "panel_ssl_mode", "") or os.environ.get("PANEL_SSL_MODE") or "").strip().lower()
    if mode in {"letsencrypt", "domain", "selfsigned"}:
        return mode if has_panel_certificate() else "none"
    if not has_panel_certificate():
        return "none"
    # Installed before the mode was recorded: the filename says which it is.
    return "selfsigned" if "selfsigned" in (settings.panel_ssl_cert or "") else "letsencrypt"


def domains_with_certificate() -> list[str]:
    """Websites on this server whose certificate the panel could borrow.

    Asked through the helper: /etc/letsencrypt/live is root-only, so the panel
    reading it directly finds nothing and reports, wrongly, that there is
    nothing to borrow.
    """
    result = shell.privileged(
        "panel-ssl-domains",
        check=False,
        timeout=30,
        fallback=["bash", "-lc", "echo ''"],
    )
    if result.returncode != 0:
        return []
    found = []
    for line in (result.stdout or "").splitlines():
        name = line.strip().strip("/")
        if name and name != "README" and DOMAIN_RE.fullmatch(name):
            found.append(name)
    return sorted(set(found))


def use_domain_certificate(domain: str, panel_port: int | None = None) -> dict:
    """Serve the panel with a certificate a website here already has."""
    host = normalize_panel_hostname(domain)
    port = int(panel_port or settings.panel_port or 2222)
    if host not in domains_with_certificate():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{host} chưa có chứng chỉ trên máy này. Cài SSL cho website đó trước.",
        )
    result = shell.privileged(
        "panel-ssl-use-domain",
        helper_args=[host, str(port)],
        check=False,
        timeout=300,
        fallback=["bash", "-lc", "echo dry-run-panel-ssl-use-domain"],
    )
    if result.returncode != 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(result.stderr or result.stdout or "Could not switch the panel certificate").strip()[-500:],
        )
    return {
        "message": (
            f"Panel dùng chứng chỉ của {host} làm mặc định. "
            "Các domain khác có SSL trên máy vẫn mở panel được bằng chứng chỉ riêng."
        ),
        "panel_url": f"https://{host}:{port}",
    }


def regenerate_self_signed(panel_port: int | None = None) -> dict:
    """Go back to a certificate the panel signs for itself."""
    data = _read_raw()
    host = ""
    if data.get("panel_url") or settings.panel_url:
        try:
            _scheme, host, _port = parse_panel_url(data.get("panel_url") or settings.panel_url)
        except ValueError:
            host = ""
    host = host or (os.environ.get("PANEL_DOMAIN") or "").strip() or "127.0.0.1"
    port = int(panel_port or settings.panel_port or 2222)
    result = shell.privileged(
        "panel-ssl-selfsigned",
        helper_args=[host, str(port)],
        check=False,
        timeout=300,
        fallback=["bash", "-lc", "echo dry-run-panel-ssl-selfsigned"],
    )
    if result.returncode != 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(result.stderr or result.stdout or "Could not generate a certificate").strip()[-500:],
        )
    return {"message": "Panel dùng chứng chỉ tự ký.", "panel_url": f"https://{host}:{port}"}


def has_panel_certificate() -> bool:
    cert_pairs = [
        (settings.panel_ssl_cert, settings.panel_ssl_key),
        ("/etc/snpanel/panel-fullchain.pem", "/etc/snpanel/panel-privkey.pem"),
    ]
    return any(bool(cert) and bool(key) and Path(cert).exists() and Path(key).exists() for cert, key in cert_pairs)


def current_settings() -> dict:
    data = _read_raw()
    app_name = (data.get("app_name") or settings.app_name or "SNPanel").strip() or "SNPanel"
    panel_url = data.get("panel_url") or settings.panel_url or ""
    panel_hostname = ""
    panel_port = settings.panel_port or 2222
    if panel_url:
        try:
            _scheme, panel_hostname, panel_port = parse_panel_url(panel_url)
        except ValueError:
            panel_hostname = ""
            panel_port = settings.panel_port or 2222
    ssl_enabled = panel_url.startswith("https://") and has_panel_certificate()
    from app.services import malware_scan

    mw = malware_scan.refresh_status()
    return {
        "app_name": app_name,
        "panel_url": panel_url,
        "panel_hostname": panel_hostname,
        "panel_port": panel_port,
        "logo_url": _asset_url(data.get("logo_filename")),
        "favicon_url": _asset_url(data.get("favicon_filename")) or "/favicon.png",
        "ssl_enabled": ssl_enabled,
        "ssl_mode": panel_ssl_mode(),
        "ipv6": panel_ipv6.status(),
        # Where this server answers. Global addresses only: loopback and
        # link-local reach nobody.
        "server_ipv4": server_network.ipv4_addresses(),
        "malware_scan_enabled": mw["enabled"],
        "malware_scan_installed": mw["installed"],
        "malware_scan_active": mw["active"],
        "malware_scan_detail": mw["detail"],
    }


def update_settings(
    app_name: str | None = None,
    panel_hostname: str | None = None,
    panel_port: int | None = None,
    panel_url: str | None = None,
) -> dict:
    del panel_port  # The panel port is install-time only; settings can change hostname/branding.
    data = _read_raw()
    if app_name is not None:
        value = app_name.strip()
        if not 2 <= len(value) <= 80:
            raise ValueError("Panel name must be 2-80 characters")
        data["app_name"] = value
    if (panel_hostname is not None and panel_hostname.strip()) or (panel_url is not None and panel_url.strip()):
        existing_url = data.get("panel_url") or settings.panel_url or ""
        existing_normalized = normalize_panel_url(existing_url) if existing_url else ""
        existing_scheme, existing_host, existing_port = parse_panel_url(existing_normalized) if existing_normalized else ("http", "", settings.panel_port or 2222)
        if panel_hostname is not None and panel_hostname.strip():
            normalized = panel_url_from_parts(panel_hostname, existing_port, existing_scheme)
        elif panel_url is not None and panel_url.strip():
            requested_scheme, requested_host, _requested_port = parse_panel_url(panel_url)
            normalized = panel_url_from_parts(requested_host, existing_port, requested_scheme)
        else:
            normalized = existing_normalized
        if not normalized:
            raise ValueError("Panel hostname is required")
        scheme, host, port = parse_panel_url(normalized)
        if scheme == "https" and not has_panel_certificate():
            raise ValueError("Use Install SSL before saving an HTTPS panel URL")
        if normalized != existing_normalized:
            result = shell.privileged(
                "panel-url-set",
                helper_args=[scheme, host, str(port)],
                check=False,
                fallback=["bash", "-lc", "true"],
            )
            if result.returncode != 0:
                raise RuntimeError((result.stderr or result.stdout or "Could not update panel URL").strip())
        data["panel_url"] = normalized
    _write_raw(data)
    return current_settings()


def detect_asset_type(content: bytes, filename: str) -> tuple[str, str]:
    suffix = Path(filename or "").suffix.lower().lstrip(".")
    if content.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", "image/png"
    if content.startswith(b"\xff\xd8\xff"):
        return "jpg", "image/jpeg"
    if content.startswith(b"RIFF") and content[8:12] == b"WEBP":
        return "webp", "image/webp"
    if content.startswith(b"\x00\x00\x01\x00"):
        return "ico", "image/x-icon"
    if suffix in ALLOWED_ASSET_TYPES:
        raise ValueError("Uploaded file content does not match its image type")
    raise ValueError("Only PNG, JPG, WEBP, and ICO images are supported")


async def save_asset(kind: str, upload: UploadFile) -> dict:
    if kind not in {"logo", "favicon"}:
        raise ValueError("Invalid asset kind")
    content = await upload.read(MAX_ASSET_SIZE + 1)
    if len(content) > MAX_ASSET_SIZE:
        raise ValueError("Image must be 1 MB or smaller")
    ext, _media_type = detect_asset_type(content, upload.filename or "")
    ASSETS_DIR.mkdir(parents=True, exist_ok=True)
    data = _read_raw()
    previous = data.get(f"{kind}_filename")
    if previous:
        try:
            (ASSETS_DIR / previous).unlink()
        except OSError:
            pass
    filename = f"{kind}.{ext}"
    (ASSETS_DIR / filename).write_bytes(content)
    data[f"{kind}_filename"] = filename
    _write_raw(data)
    return current_settings()


def asset_path(filename: str) -> tuple[Path, str]:
    if not re.fullmatch(r"(?:logo|favicon)\.(?:png|jpg|jpeg|webp|ico)", filename or ""):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    path = ASSETS_DIR / filename
    if not path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    media_type = ALLOWED_ASSET_TYPES.get(path.suffix.lower().lstrip("."), "application/octet-stream")
    return path, media_type


def install_panel_ssl(email: str | None = None, panel_hostname: str | None = None, panel_port: int | None = None, panel_url: str | None = None) -> dict:
    if panel_hostname:
        normalized = panel_url_from_parts(panel_hostname, panel_port, "http")
    elif panel_url:
        normalized = normalize_panel_url(panel_url)
    else:
        raise ValueError("Panel hostname is required")
    _scheme, host, port = parse_panel_url(normalized)
    if not is_domain(host):
        raise ValueError("Panel SSL requires a domain name, not an IP address")
    certbot_email = (email or settings.ssl_email or default_ssl_email(host)).strip()
    helper_args = [host, str(port)]
    if certbot_email:
        helper_args.append(certbot_email)
    result = shell.privileged(
        "panel-ssl-install",
        helper_args=helper_args,
        check=False,
        fallback=["bash", "-lc", "true"],
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "Could not install panel SSL").strip())
    data = _read_raw()
    data["panel_url"] = f"https://{host}:{port}"
    _write_raw(data)
    current = current_settings()
    current["message"] = result.stdout.strip() or f"Panel SSL enabled for {host}"
    return current


# --------------------------------------------------------------------------
# Optional ClamAV malware scanning
# --------------------------------------------------------------------------
import threading

from app.services import malware_scan as _malware_scan

MALWARE_JOBS: dict[str, dict] = {}
MALWARE_JOB_THREADS: dict[str, threading.Thread] = {}
MALWARE_JOBS_LOCK = threading.RLock()
MALWARE_JOBS_DIR = SETTINGS_DIR / "malware-scan-jobs"
MAX_MALWARE_LOG_LINES = 1000


def _persist_malware_enabled(enabled: bool) -> None:
    """Write the malware_scan_enabled flag to the panel settings file so it
    survives restarts. The flag is the source of truth that the API reads via
    ``settings.malware_scan_enabled`` (overridden here from persisted state)."""
    data = _read_raw()
    data["malware_scan_enabled"] = bool(enabled)
    _write_raw(data)


def _persist_malware_realtime(enabled: bool) -> None:
    data = _read_raw()
    data["malware_realtime_enabled"] = bool(enabled)
    _write_raw(data)


def set_malware_realtime(enabled: bool) -> dict:
    """Level 2: turn the LMD inotify monitor on or off.

    Installs LMD first (in the background) if it is not present yet, exactly
    like enabling the scanner does for ClamAV.
    """
    from app.services import maldet

    enabled = bool(enabled)
    if enabled and not maldet.installed():
        _persist_malware_enabled(True)
        _persist_malware_realtime(True)
        threading.Thread(target=_install_realtime_flow, daemon=True).start()
        current = malware_scan_status()
        current["detail"] = "Đang cài LMD; bảo vệ thời gian thực sẽ bật khi cài xong."
        return current
    _persist_malware_realtime(enabled)
    try:
        if enabled:
            maldet.monitor_start()
        else:
            maldet.monitor_stop()
    except RuntimeError as exc:
        raise RuntimeError(str(exc)) from exc
    return malware_scan_status()


def _install_realtime_flow() -> None:
    from app.services import maldet

    try:
        maldet.install()
        maldet.monitor_start()
    except Exception as exc:  # noqa: BLE001 - recorded in the status file
        # Carry the reason, the way _install_and_enable_flow does. The helper
        # names the missing package ("real-time protection needs ed..."); a
        # bare "failed" sent an administrator looking through journals for a
        # sentence the panel already had in hand.
        _malware_scan._write_status(
            {
                **_malware_scan.refresh_status(),
                "detail": f"LMD install/monitor failed: {exc}"[:400],
            }
        )


def malware_scan_status() -> dict:
    return _malware_scan.refresh_status()


def set_malware_scan(enabled: bool) -> dict:
    """Toggle malware scanning on/off.

    Enabling on a server without the engine installs LMD + the ClamAV package
    in a background thread so the API returns immediately. Disabling just turns
    the flag off (LMD/clamav are left on disk).
    """
    from app.services import maldet

    enabled = bool(enabled)
    if enabled and not (maldet.installed() or _malware_scan.clamav_installed()):
        _persist_malware_enabled(True)
        threading.Thread(target=_install_and_enable_flow, daemon=True).start()
        current = current_settings()
        current["message"] = (
            "LMD + ClamAV đang được cài trong nền. Quét sẽ sẵn sàng khi cài xong "
            "(1-3 phút)."
        )
        return current
    _persist_malware_enabled(enabled)
    current = current_settings()
    if enabled:
        current["message"] = "Đã bật trình quét malware"
    else:
        _persist_malware_realtime(False)
        try:
            maldet.monitor_stop()
        except Exception:  # noqa: BLE001
            pass
        _malware_scan.stop_clamd()
        current = current_settings()
        current["message"] = "Đã tắt trình quét malware"
    return current


def _install_and_enable_flow() -> None:
    """Background worker: install the scan engine (LMD + the ClamAV package),
    then leave the persisted flag on.

    The flag was already persisted as True by set_malware_scan(); this just
    performs the heavy install. Failures are captured in the status file.
    """
    from app.services import maldet

    try:
        # maldet-install pulls the clamav package (engine) itself and does NOT
        # enable the resident daemon.
        maldet.install()
    except Exception as exc:  # noqa: BLE001 - record failure, do not crash thread
        try:
            _malware_scan.install_clamav()  # last resort: at least get clamscan
        except Exception:
            pass
        _malware_scan._write_status(
            {**_malware_scan.refresh_status(), "detail": f"LMD install failed: {exc}"}
        )


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _public_malware_job(job: dict) -> dict:
    return dict(job)


def _finalize_stale_malware_job(job: dict) -> dict:
    if job.get("status") not in {"queued", "running"}:
        return job
    with MALWARE_JOBS_LOCK:
        thread = MALWARE_JOB_THREADS.get(job.get("job_id"))
        if thread and thread.is_alive():
            return job
        MALWARE_JOB_THREADS.pop(job.get("job_id"), None)
    job = dict(job)
    job.update(
        status="interrupted",
        message="Scan interrupted. Start a new scan to continue.",
        error="Scan worker is no longer running.",
        finished_at=job.get("finished_at") or _now_iso(),
        updated_at=_now_iso(),
    )
    _write_malware_job(job)
    with MALWARE_JOBS_LOCK:
        MALWARE_JOBS[job["job_id"]] = job
    return job


def _write_malware_job(job: dict) -> None:
    try:
        MALWARE_JOBS_DIR.mkdir(parents=True, exist_ok=True)
        path = MALWARE_JOBS_DIR / f"{job['job_id']}.json"
        path.write_text(json.dumps(_public_malware_job(job), indent=2) + "\n", encoding="utf-8")
    except OSError:
        pass


def _remember_malware_job(job: dict) -> dict:
    with MALWARE_JOBS_LOCK:
        MALWARE_JOBS[job["job_id"]] = job
    _write_malware_job(job)
    return _public_malware_job(job)


def _update_malware_job(job_id: str, **updates) -> None:
    with MALWARE_JOBS_LOCK:
        job = MALWARE_JOBS.get(job_id)
        if not job:
            return
        updates.setdefault("updated_at", _now_iso())
        job.update(updates)
        if len(job.get("log", [])) > MAX_MALWARE_LOG_LINES:
            job["log"] = job["log"][-MAX_MALWARE_LOG_LINES:]
        snapshot = dict(job)
    _write_malware_job(snapshot)


def _append_malware_log(job_id: str, line: str) -> None:
    with MALWARE_JOBS_LOCK:
        job = MALWARE_JOBS.get(job_id)
        if not job:
            return
        job.setdefault("log", []).append(f"{_now_iso()} {line}")
        job["updated_at"] = _now_iso()
        if len(job["log"]) > MAX_MALWARE_LOG_LINES:
            job["log"] = job["log"][-MAX_MALWARE_LOG_LINES:]
        snapshot = dict(job)
    _write_malware_job(snapshot)


def get_malware_scan_job(job_id: str) -> dict:
    with MALWARE_JOBS_LOCK:
        job = MALWARE_JOBS.get(job_id)
        if job:
            return _public_malware_job(_finalize_stale_malware_job(job))
    path = MALWARE_JOBS_DIR / f"{job_id}.json"
    try:
        if path.exists():
            return _public_malware_job(_finalize_stale_malware_job(json.loads(path.read_text(encoding="utf-8"))))
    except (OSError, json.JSONDecodeError):
        pass
    raise ValueError("Scan job not found")


def get_latest_malware_scan_job() -> dict:
    with MALWARE_JOBS_LOCK:
        jobs = list(MALWARE_JOBS.values())
    try:
        if MALWARE_JOBS_DIR.exists():
            for path in MALWARE_JOBS_DIR.glob("*.json"):
                try:
                    jobs.append(json.loads(path.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    continue
    except OSError:
        pass
    unique: dict[str, dict] = {}
    for job in jobs:
        job_id = job.get("job_id")
        if not job_id:
            continue
        current = unique.get(job_id)
        if not current or (job.get("updated_at") or job.get("started_at") or job.get("created_at") or "") >= (
            current.get("updated_at") or current.get("started_at") or current.get("created_at") or ""
        ):
            unique[job_id] = job
    if not unique:
        raise ValueError("Scan job not found")
    running = [job for job in unique.values() if job.get("status") in {"queued", "running"}]
    candidates = running or list(unique.values())
    return _public_malware_job(
        _finalize_stale_malware_job(max(candidates, key=lambda job: job.get("updated_at") or job.get("started_at") or job.get("created_at") or ""))
    )


def list_malware_scan_jobs(limit: int = 50) -> list[dict]:
    jobs = []
    with MALWARE_JOBS_LOCK:
        jobs.extend(MALWARE_JOBS.values())
    try:
        if MALWARE_JOBS_DIR.exists():
            for path in MALWARE_JOBS_DIR.glob("*.json"):
                try:
                    jobs.append(json.loads(path.read_text(encoding="utf-8")))
                except (OSError, json.JSONDecodeError):
                    continue
    except OSError:
        pass
    unique: dict[str, dict] = {}
    for job in jobs:
        job_id = job.get("job_id")
        if not job_id:
            continue
        current = unique.get(job_id)
        stamp = job.get("updated_at") or job.get("started_at") or job.get("created_at") or ""
        current_stamp = current.get("updated_at") or current.get("started_at") or current.get("created_at") or "" if current else ""
        if not current or stamp >= current_stamp:
            unique[job_id] = job
    sorted_jobs = sorted(
        (_finalize_stale_malware_job(job) for job in unique.values()),
        key=lambda job: job.get("updated_at") or job.get("started_at") or job.get("created_at") or "",
        reverse=True,
    )
    return [_public_malware_job(job) for job in sorted_jobs[: max(1, min(limit, 200))]]


def _select_scan_websites(website_id: int | None, db) -> list:
    from app.models.entities import Website

    if website_id is None:
        return db.query(Website).order_by(Website.domain.asc()).all()
    website = db.query(Website).filter(Website.id == website_id).first()
    if not website:
        raise ValueError("Website not found")
    return [website]


# --- whole-server scan ------------------------------------------------------
# A website scan walks a few thousand files from the panel's own account. The
# whole machine is a different job: 150,000 files on a small VPS, most of them
# unreadable to anyone but root. That one runs through the helper, which hands
# clamd an open descriptor per file, and reports its progress through a log the
# panel reads while it works.

SERVER_SCAN_TIMEOUT_SECONDS = 6 * 60 * 60
SERVER_SCAN_POLL_SECONDS = 3


def _server_scan_log(job_id: str) -> Path:
    return MALWARE_JOBS_DIR / f"{job_id}.scan.log"


def _parse_clamdscan_line(line: str) -> tuple[str, str, str]:
    """One line of clamdscan output as (status, path, detail)."""
    stripped = line.strip()
    if not stripped or ":" not in stripped:
        return ("", "", "")
    path, _, rest = stripped.rpartition(":")
    rest = rest.strip()
    if not path:
        return ("", "", "")
    if rest == "OK":
        return ("clean", path, "")
    if rest.endswith(" FOUND"):
        return ("infected", path, rest[: -len(" FOUND")].strip())
    if rest.endswith(" ERROR") or rest.endswith("ERROR"):
        return ("error", path, rest.removesuffix("ERROR").strip())
    return ("", "", "")


class _ServerScanProgress:
    """Reads the scanner's log as it grows and keeps the job in step with it."""

    def __init__(self, job_id: str):
        self.job_id = job_id
        self.offset = 0
        self.total = 0
        self.scanned = 0
        self.errors = 0
        self.threats: list[dict] = []
        self.pending = b""

    def poll(self) -> None:
        path = _server_scan_log(self.job_id)
        try:
            size = path.stat().st_size
        except OSError:
            return
        if size < self.offset:  # the log was replaced under us
            self.offset = 0
        if size == self.offset:
            return
        try:
            with path.open("rb") as handle:
                handle.seek(self.offset)
                chunk = handle.read(size - self.offset)
                self.offset = handle.tell()
        except OSError:
            return
        data = self.pending + chunk
        lines = data.split(b"\n")
        self.pending = lines.pop()
        for raw_line in lines:
            self._consume(raw_line.decode("utf-8", "replace"))
        self._publish()

    def _consume(self, line: str) -> None:
        if line.startswith("total="):
            try:
                self.total = int(line.split("=", 1)[1])
            except ValueError:
                pass
            return
        status, path, detail = _parse_clamdscan_line(line)
        if not status:
            return
        self.scanned += 1
        if status == "infected":
            self.threats.append({"path": path, "signature": detail, "domain": ""})
            _append_malware_log(self.job_id, f"INFECTED {path}: {detail}")
        elif status == "error":
            self.errors += 1
            if self.errors <= 50:  # a log of 150,000 unreadable sockets helps nobody
                _append_malware_log(self.job_id, f"ERROR {path}: {detail}")

    def _publish(self) -> None:
        percent = int((self.scanned / self.total) * 100) if self.total else 0
        _update_malware_job(
            self.job_id,
            total_files=self.total,
            scanned=self.scanned,
            infected=len(self.threats),
            errors=self.errors,
            threats=self.threats,
            progress_percent=min(percent, 99),
            message=(
                f"Scanning {self.scanned}/{self.total} files"
                if self.total
                else "Listing files on the server"
            ),
        )


def start_server_scan_job() -> dict:
    """Scan every file on the machine, not just the websites."""
    from app.services import maldet

    if not (maldet.installed() or _malware_scan.engine_available()):
        raise RuntimeError("Trình quét malware chưa được cài. Bật nó trước.")
    job = _new_malware_job(scope="server", message="Queued")
    if maldet.installed():
        job["engine"] = "lmd"
        return _spawn_malware_job(job, lambda: _run_maldet_job(job["job_id"], "/"))
    return _spawn_malware_job(job, lambda: _run_server_scan_job(job["job_id"]))


def _run_server_scan_job(job_id: str) -> None:
    _update_malware_job(
        job_id,
        status="running",
        started_at=_now_iso(),
        message="Listing files on the server",
    )
    _append_malware_log(job_id, "Whole-server scan started")
    progress = _ServerScanProgress(job_id)
    stop = threading.Event()

    def watch() -> None:
        while not stop.is_set():
            progress.poll()
            stop.wait(SERVER_SCAN_POLL_SECONDS)
        progress.poll()

    watcher = threading.Thread(target=watch, daemon=True)
    watcher.start()
    try:
        result = shell.privileged(
            "malware-scan-server",
            helper_args=[job_id],
            check=False,
            timeout=SERVER_SCAN_TIMEOUT_SECONDS,
            fallback=["bash", "-lc", "echo dry-run-malware-scan-server"],
        )
        stop.set()
        watcher.join(timeout=30)
        # clamdscan exits 1 when it found something and 2 on an error; neither
        # means the scan failed to run.
        if result.returncode not in (0, 1, 2):
            detail = (result.stderr or result.stdout or "").strip()[-400:]
            raise RuntimeError(detail or f"Scanner exited with {result.returncode}")
        status = "infected" if progress.threats else "done"
        _update_malware_job(
            job_id,
            status=status,
            progress_percent=100,
            total_files=progress.total,
            scanned=progress.scanned,
            infected=len(progress.threats),
            errors=progress.errors,
            threats=progress.threats,
            message=(
                f"Scan complete: {progress.scanned} files, "
                f"{len(progress.threats)} threats, {progress.errors} errors"
            ),
            finished_at=_now_iso(),
        )
        _append_malware_log(job_id, "Scan finished")
    except Exception as exc:  # noqa: BLE001 - a failed scan is reported, not raised
        stop.set()
        _update_malware_job(
            job_id,
            status="error",
            message="Scan failed",
            error=str(exc),
            finished_at=_now_iso(),
        )
        _append_malware_log(job_id, f"ERROR scan failed: {exc}")
    finally:
        stop.set()
        with MALWARE_JOBS_LOCK:
            MALWARE_JOB_THREADS.pop(job_id, None)
        try:
            _server_scan_log(job_id).unlink(missing_ok=True)
        except OSError:
            pass


# --- LMD (Linux Malware Detect) scan path ---------------------------------
# When maldet is installed it replaces the per-file clamdscan loop: one
# `maldet -a /home` (or `-r /home <days>` for the incremental) is far faster and
# reports named malware families. The clamd path stays as the fallback.

_DOMAIN_IN_PATH = re.compile(r"^/home/[^/]+/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9-]+)+)/")


def _domain_from_path(path: str) -> str:
    m = _DOMAIN_IN_PATH.match(path or "")
    return m.group(1) if m else ""


def _run_maldet_job(job_id: str, target: str, *, recent_days: int | None = None) -> None:
    from app.services import maldet

    kind = f"tăng dần {recent_days} ngày" if recent_days else "toàn bộ"
    _update_malware_job(
        job_id, status="running", started_at=_now_iso(), engine="lmd",
        message=f"Đang quét ({kind}) bằng LMD: {target}",
    )
    _append_malware_log(job_id, f"maldet scan of {target} started")
    try:
        result = maldet.scan(job_id, [target], recent_days=recent_days)
        total, threats = maldet.read_job_report(job_id)
        for threat in threats:
            threat["domain"] = threat.get("domain") or _domain_from_path(threat["path"])
            _append_malware_log(job_id, f"INFECTED {threat['path']}: {threat['signature']}")
        status = "infected" if threats else "done"
        # maldet exit: 0 ok, 2 malware found, 1 error running.
        if result["exit"] not in (0, 2) and not threats:
            raise RuntimeError((result.get("raw") or "maldet scan failed").strip()[-400:])
        _update_malware_job(
            job_id, status=status, progress_percent=100,
            total_files=total, scanned=total, infected=len(threats),
            threats=threats, scanid=result["scanid"],
            message=f"Quét xong: {total} tệp, {len(threats)} mối đe doạ",
            finished_at=_now_iso(),
        )
        _append_malware_log(job_id, "maldet scan finished")
    except Exception as exc:  # noqa: BLE001 - a failed scan is reported, not raised
        _update_malware_job(
            job_id, status="error", message="Scan failed", error=str(exc), finished_at=_now_iso(),
        )
        _append_malware_log(job_id, f"ERROR scan failed: {exc}")
    finally:
        with MALWARE_JOBS_LOCK:
            MALWARE_JOB_THREADS.pop(job_id, None)


def _new_malware_job(**overrides) -> dict:
    job = {
        "job_id": uuid.uuid4().hex, "status": "queued", "scope": "website",
        "website_id": None, "domains": [], "message": "Queued", "engine": "",
        "progress_percent": 0, "total_files": 0, "scanned": 0, "infected": 0,
        "errors": 0, "skipped": 0, "threats": [], "log": [],
        "created_at": _now_iso(), "started_at": "", "finished_at": "", "updated_at": _now_iso(),
    }
    job.update(overrides)
    return job


def _spawn_malware_job(job: dict, run) -> dict:
    """``run`` is a zero-arg callable that executes the job in a daemon thread."""
    _remember_malware_job(job)
    thread = threading.Thread(target=run, daemon=True)
    with MALWARE_JOBS_LOCK:
        MALWARE_JOB_THREADS[job["job_id"]] = thread
    thread.start()
    return _public_malware_job(job)


def start_incremental_scan_job(days: int = 2) -> dict:
    """Daily 'recent files' LMD scan of every website root."""
    from app.services import maldet

    if not maldet.installed():
        raise RuntimeError("LMD chưa được cài. Bật trình quét malware để cài.")
    days = max(1, min(int(days or 2), 30))
    job = _new_malware_job(scope="incremental", engine="lmd", message=f"Queued (recent {days}d)")
    return _spawn_malware_job(
        job, lambda: _run_maldet_job(job["job_id"], "/home", recent_days=days)
    )


def start_scan_job(website_id: int | None, db) -> dict:
    """Start a background malware scan for one website or all websites."""
    websites = _select_scan_websites(website_id, db)
    if not websites:
        raise ValueError("No websites found")
    targets = []
    for website in websites:
        root_path = website.root_path
        if not root_path or not Path(root_path).is_dir():
            raise ValueError(f"Website root not found: {root_path}")
        targets.append({"id": website.id, "domain": website.domain, "root_path": root_path})

    job = _new_malware_job(
        scope="all" if website_id is None else "website",
        website_id=website_id,
        domains=[target["domain"] for target in targets],
    )

    from app.services import maldet

    if maldet.installed():
        job["engine"] = "lmd"
        # One site -> its root; all sites -> /home (covers every user).
        scan_path = targets[0]["root_path"] if len(targets) == 1 else "/home"
        return _spawn_malware_job(job, lambda: _run_maldet_job(job["job_id"], scan_path))

    return _spawn_malware_job(job, lambda: _run_scan_job(job["job_id"], targets))


def _run_scan_job(job_id: str, targets: list[dict]) -> None:
    _update_malware_job(job_id, status="running", started_at=_now_iso(), message="Preparing scan")
    try:
        if not _malware_scan.clamd_running():
            raise RuntimeError("ClamAV daemon is not running. Enable malware scanning first.")
        target_files: list[tuple[dict, str]] = []
        skipped = 0
        for target in targets:
            files, skipped_lines = _malware_scan.collect_regular_files(target["root_path"])
            skipped += len(skipped_lines)
            _append_malware_log(job_id, f"Prepared {target['domain']}: {len(files)} files")
            for line in skipped_lines:
                _append_malware_log(job_id, line)
            target_files.extend((target, file_path) for file_path in files)
        total = len(target_files)
        _update_malware_job(job_id, total_files=total, skipped=skipped, message=f"Scanning 0/{total} files")

        threats = []
        errors = 0
        scanned = 0
        for target, file_path in target_files:
            result = _malware_scan.scan_file_with_clamdscan(file_path)
            scanned += 1
            status = result["status"]
            if status == "infected":
                threat = {"path": file_path, "signature": result["signature"], "domain": target["domain"]}
                threats.append(threat)
                _append_malware_log(job_id, f"INFECTED {target['domain']} {file_path}: {result['signature']}")
            elif status == "error":
                errors += 1
                _append_malware_log(job_id, f"ERROR {target['domain']} {file_path}: {result['detail']}")
            elif status == "skipped":
                skipped += 1
                _append_malware_log(job_id, f"SKIP {target['domain']} {file_path}: {result['detail']}")

            percent = int((scanned / total) * 100) if total else 100
            _update_malware_job(
                job_id,
                scanned=scanned,
                infected=len(threats),
                errors=errors,
                skipped=skipped,
                threats=threats,
                progress_percent=percent,
                message=f"Scanning {scanned}/{total} files",
            )

        status = "infected" if threats else "done"
        _update_malware_job(
            job_id,
            status=status,
            progress_percent=100,
            scanned=scanned,
            infected=len(threats),
            errors=errors,
            skipped=skipped,
            threats=threats,
            message=f"Scan complete: {scanned} files, {len(threats)} threats, {errors} errors",
            finished_at=_now_iso(),
        )
        _append_malware_log(job_id, "Scan finished")
    except Exception as exc:  # noqa: BLE001 - scan jobs should report errors, not crash the API
        _update_malware_job(
            job_id,
            status="error",
            message="Scan failed",
            error=str(exc),
            finished_at=_now_iso(),
        )
        _append_malware_log(job_id, f"ERROR scan failed: {exc}")
    finally:
        with MALWARE_JOBS_LOCK:
            MALWARE_JOB_THREADS.pop(job_id, None)


def run_scan(website_id: int, db) -> dict:
    """Trigger an on-demand malware scan of a website's root directory."""
    from app.models.entities import Website

    website = db.query(Website).filter(Website.id == website_id).first()
    if not website:
        raise ValueError("Website not found")
    root_path = website.root_path
    if not root_path or not Path(root_path).is_dir():
        raise ValueError(f"Website root not found: {root_path}")
    return _malware_scan.scan_directory(root_path)
