#!/usr/bin/env bash
# Install the standalone DirectAdmin backup importer as SNPanel menu option 13.
#
# Usage on the SNPanel server:
#   bash da_import_install.sh
#   snpanel
#   choose 13

set -euo pipefail

APP_DIR="${APP_DIR:-/opt/snpanel}"
SNPANEL_CLI="${SNPANEL_CLI:-/usr/local/sbin/snpanel}"
SNPANELCTL="${SNPANELCTL:-/usr/local/sbin/snpanelctl}"
IMPORTER="${IMPORTER:-/usr/local/sbin/snpanel-directadmin-import}"

fail() {
  echo "ERROR: $*" >&2
  exit 1
}

if [[ "${EUID}" -ne 0 ]]; then
  fail "Please run as root on the SNPanel server."
fi

[[ -d "${APP_DIR}/backend" ]] || fail "${APP_DIR}/backend not found. Set APP_DIR if SNPanel is installed elsewhere."
[[ -x "${APP_DIR}/backend/.venv/bin/python" ]] || fail "${APP_DIR}/backend/.venv/bin/python not found."
[[ -f "${APP_DIR}/backend/.env" ]] || fail "${APP_DIR}/backend/.env not found."
[[ -f "${SNPANEL_CLI}" ]] || fail "${SNPANEL_CLI} not found."

install -d -m 700 -o root -g root /root/backup

cat >"${IMPORTER}" <<'PYIMPORTER'
#!/usr/bin/env python3
"""Import DirectAdmin user backups into SNPanel.

The root process only reads /root/backup, extracts archives into a temporary
staging directory, then re-executes the worker as the snpanel user. The worker
uses SNPanel's own backend services so users, websites, vhosts, PHP-FPM pools,
MariaDB credentials, and panel DB rows stay consistent.
"""

from __future__ import annotations

import argparse
import bz2
import datetime as _dt
import gzip
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Iterable


APP_DIR = Path(os.environ.get("APP_DIR", "/opt/snpanel"))
BACKUP_DIR = Path(os.environ.get("DIRECTADMIN_BACKUP_DIR", "/root/backup"))
STAGE_BASE = Path(os.environ.get("DIRECTADMIN_STAGE_BASE", "/var/lib/snpanel/directadmin-import"))
DEFAULT_PHP_VERSION = os.environ.get("DIRECTADMIN_IMPORT_PHP", "8.3")
DEFAULT_STORAGE_MB = int(os.environ.get("DIRECTADMIN_IMPORT_STORAGE_MB", "102400"))
DOMAIN_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{2,31}$")
DB_RE = re.compile(r"^[a-z0-9_]{1,64}$")
RESERVED_USERS = {
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "_apt",
    "nobody", "snpanel", "snpanel-sites", "snpanel-sftp", "mysql", "redis", "nginx",
    "admin",
}
ARCHIVE_SUFFIXES = (
    ".tar.zst", ".tzst", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar",
)
SQL_SUFFIXES = (".sql", ".sql.gz", ".sql.bz2", ".sql.zst")
SQL_DATABASE_DIRECTIVE_RE = re.compile(
    r"^\s*(?:/\*![0-9]{5}\s*)?(?:CREATE\s+DATABASE|DROP\s+DATABASE|USE)\b",
    re.IGNORECASE,
)
SQL_DEFINER_RE = re.compile(
    r"DEFINER\s*=\s*(?:`[^`]*`|'[^']*'|\"[^\"]*\"|[^\s*/]+)\s*@\s*(?:`[^`]*`|'[^']*'|\"[^\"]*\"|[^\s*/]+)",
    re.IGNORECASE,
)


class ImportErrorWithContext(RuntimeError):
    pass


def log(message: str) -> None:
    print(message, flush=True)


def utc_stamp() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%d-%H%M%S")


def server_ip_addresses() -> set[str]:
    addresses: set[str] = set()
    configured = os.environ.get("DIRECTADMIN_SERVER_IP", "")
    for value in re.split(r"[\s,]+", configured.strip()):
        if value:
            try:
                addresses.add(str(ipaddress.ip_address(value)))
            except ValueError:
                pass

    try:
        result = subprocess.run(
            ["ip", "-j", "address", "show", "scope", "global"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            for interface in json.loads(result.stdout or "[]"):
                for address in interface.get("addr_info", []):
                    local = address.get("local")
                    if local:
                        addresses.add(str(ipaddress.ip_address(local)))
    except (FileNotFoundError, json.JSONDecodeError, subprocess.TimeoutExpired, ValueError):
        pass
    return addresses


def domain_ip_addresses(domain: str) -> set[str]:
    addresses: set[str] = set()
    for item in socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM):
        value = item[4][0].split("%", 1)[0]
        try:
            addresses.add(str(ipaddress.ip_address(value)))
        except ValueError:
            pass
    return addresses


def enable_ssl_when_dns_matches(db, website, item_summary: dict) -> None:
    from app.services import ssl

    try:
        domain_ips = domain_ip_addresses(website.domain)
    except socket.gaierror as exc:
        warning = f"SSL skipped for {website.domain}: DNS lookup failed ({exc})"
        item_summary["warnings"].append(warning)
        log(f"  warning: {warning}")
        return

    server_ips = server_ip_addresses()
    matching_ips = domain_ips & server_ips
    if not matching_ips:
        domain_text = ", ".join(sorted(domain_ips)) or "none"
        server_text = ", ".join(sorted(server_ips)) or "none"
        warning = (
            f"SSL skipped for {website.domain}: DNS resolves to [{domain_text}], "
            f"server IPs are [{server_text}]"
        )
        item_summary["warnings"].append(warning)
        log(f"  {warning}")
        return

    log(f"  DNS matches this server ({', '.join(sorted(matching_ips))}); installing SSL for {website.domain} ...")
    result = ssl.issue_ssl(website.domain)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "certbot failed").strip().replace("\n", " ")
        warning = f"SSL failed for {website.domain}: {detail[:500]}"
        item_summary["warnings"].append(warning)
        log(f"  warning: {warning}")
        return

    website.ssl_enabled = True
    db.commit()
    db.refresh(website)
    item_summary["ssl_enabled_domains"].append(website.domain)
    log(f"  SSL installed for {website.domain}")


def is_archive(path: Path) -> bool:
    name = path.name.lower()
    return path.is_file() and any(name.endswith(suffix) for suffix in ARCHIVE_SUFFIXES)


def strip_archive_suffix(name: str) -> str:
    lower = name.lower()
    for suffix in ARCHIVE_SUFFIXES:
        if lower.endswith(suffix):
            return name[: -len(suffix)]
    return Path(name).stem


def safe_name(value: str, fallback: str = "backup") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-")
    return (cleaned or fallback)[:80]


def ensure_inside(base: Path, target: Path) -> Path:
    base_resolved = base.resolve()
    target_resolved = target.resolve(strict=False)
    try:
        target_resolved.relative_to(base_resolved)
    except ValueError as exc:
        raise ImportErrorWithContext(f"Unsafe archive path: {target}") from exc
    return target_resolved


def safe_extract_tar(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    proc = None
    if archive.name.lower().endswith((".tar.zst", ".tzst")):
        zstd = shutil.which("zstdcat") or shutil.which("zstd")
        if not zstd:
            raise ImportErrorWithContext("zstd is required to extract .tar.zst backups. Install package: zstd")
        args = [zstd, str(archive)] if Path(zstd).name == "zstdcat" else [zstd, "-dc", str(archive)]
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        tar = tarfile.open(fileobj=proc.stdout, mode="r|")
    else:
        tar = tarfile.open(archive, "r:*")
    with tar:
        for member in tar:
            raw_name = member.name.replace("\\", "/")
            parts = [part for part in raw_name.split("/") if part not in ("", ".")]
            if not parts or raw_name.startswith("/") or ".." in parts:
                raise ImportErrorWithContext(f"Unsafe path in {archive.name}: {member.name}")
            target = ensure_inside(destination, destination.joinpath(*parts))
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                continue
            if not member.isfile():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                continue
            with source, target.open("wb") as out:
                shutil.copyfileobj(source, out, length=1024 * 1024)
            try:
                os.utime(target, (member.mtime, member.mtime))
            except OSError:
                pass
    if proc is not None:
        _, stderr = proc.communicate(timeout=30)
        if proc.returncode != 0:
            raise ImportErrorWithContext(stderr.decode("utf-8", errors="replace").strip() or "zstd extraction failed")


def chown_recursive(path: Path, user: str, group: str) -> None:
    shutil.chown(path, user=user, group=group)
    for root, dirs, files in os.walk(path):
        for name in dirs:
            shutil.chown(Path(root) / name, user=user, group=group)
        for name in files:
            shutil.chown(Path(root) / name, user=user, group=group)


def list_archives(backup_dir: Path) -> list[Path]:
    if not backup_dir.exists():
        raise SystemExit(f"Backup directory not found: {backup_dir}")
    archives = sorted(path for path in backup_dir.iterdir() if is_archive(path))
    if not archives:
        raise SystemExit(f"No DirectAdmin .tar/.tar.gz backups found in {backup_dir}")
    return archives


def prepare_run_stage() -> tuple[Path, str]:
    run_id = utc_stamp()
    STAGE_BASE.mkdir(parents=True, exist_ok=True)
    shutil.chown(STAGE_BASE, user="snpanel", group="snpanel")
    os.chmod(STAGE_BASE, 0o750)
    stage = STAGE_BASE / f"run-{run_id}"
    stage.mkdir(parents=True, exist_ok=True)
    os.chmod(stage, 0o750)
    shutil.chown(stage, user="root", group="snpanel")
    return stage, run_id


def prepare_archive_stage(run_stage: Path, run_id: str, archive: Path, index: int, backup_dir: Path) -> Path:
    digest = hashlib.sha1(str(archive).encode("utf-8")).hexdigest()[:10]
    item_stage = run_stage / f"{index:04d}-{safe_name(strip_archive_suffix(archive.name))}-{digest}"
    target = item_stage / "extracted"
    target.mkdir(parents=True, exist_ok=True)
    metadata = {
        "run_id": run_id,
        "backup_dir": str(backup_dir),
        "archives": [{
            "archive_path": str(archive),
            "archive_name": archive.name,
            "extracted_dir": str(target),
        }],
    }

    log(f"Extracting {archive.name} ...")
    safe_extract_tar(archive, target)
    metadata_path = item_stage / "metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    chown_recursive(item_stage, "snpanel", "snpanel")
    return item_stage


def run_worker(stage: Path, backup_dir: Path, force: bool, keep_stage: bool) -> int:
    python = APP_DIR / "backend" / ".venv" / "bin" / "python"
    cmd = [
        "runuser", "-u", "snpanel", "--",
        "env",
        f"HOME={APP_DIR}",
        "SNPANEL_USE_HELPER=true",
        f"APP_DIR={APP_DIR}",
        str(python),
        str(Path(__file__).resolve()),
        "--worker",
        "--stage-root", str(stage),
        "--backup-dir", str(backup_dir),
    ]
    if force:
        cmd.append("--force")
    if keep_stage:
        cmd.append("--keep-stage")
    return subprocess.call(cmd)


def merge_item_reports(stage: Path, credentials: list[str], summary: list[dict]) -> None:
    credential_file = stage / "credentials.txt"
    if credential_file.exists():
        for line in credential_file.read_text(encoding="utf-8", errors="replace").splitlines():
            if line and not line.startswith("#"):
                credentials.append(line)

    summary_file = stage / "summary.json"
    if summary_file.exists():
        data = json.loads(summary_file.read_text(encoding="utf-8"))
        if isinstance(data, list):
            summary.extend(data)


def write_reports(run_id: str, backup_dir: Path, credentials: list[str], summary: list[dict]) -> None:
    backup_dir.mkdir(parents=True, exist_ok=True)
    reports = {
        "credentials.txt": "\n".join(credentials) + "\n",
        "summary.json": json.dumps(summary, indent=2, ensure_ascii=True) + "\n",
    }
    for name, content in reports.items():
        target = backup_dir / f"snpanel-directadmin-import-{run_id}-{name}"
        target.write_text(content, encoding="utf-8")
        os.chmod(target, 0o600)
        log(f"Report saved: {target}")


def cleanup_archive_stage(stage: Path, keep_stage: bool, rc: int) -> None:
    if keep_stage or rc != 0:
        log(f"Stage kept: {stage}")
        return
    resolved = stage.resolve()
    base = STAGE_BASE.resolve()
    try:
        resolved.relative_to(base)
    except ValueError:
        raise SystemExit(f"Refusing to remove unexpected stage path: {stage}")
    shutil.rmtree(resolved, ignore_errors=True)


def cleanup_run_stage(stage: Path, keep_stage: bool) -> None:
    if keep_stage:
        log(f"Run stage kept: {stage}")
        return
    try:
        stage.rmdir()
    except OSError:
        log(f"Run stage contains failed user data and was kept: {stage}")


def load_worker_context() -> None:
    backend = APP_DIR / "backend"
    os.chdir(backend)
    sys.path.insert(0, str(backend))


def read_key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists() or not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, value = line.split("=", 1)
        elif ":" in line:
            key, value = line.split(":", 1)
        else:
            continue
        values[key.strip().lower()] = value.strip().strip("'\"")
    return values


def find_backup_root(extracted: Path) -> Path:
    if (extracted / "backup").exists() or (extracted / "domains").exists() or (extracted / "mysql").exists():
        return extracted
    candidates = []
    for path in extracted.rglob("backup"):
        if not path.is_dir():
            continue
        parent = path.parent
        score = 1
        if (parent / "domains").exists():
            score += 3
        if (parent / "mysql").exists():
            score += 2
        if (path / "user.conf").exists():
            score += 3
        candidates.append((score, parent))
    if candidates:
        return sorted(candidates, key=lambda item: item[0], reverse=True)[0][1]
    return extracted


def archive_username(name: str) -> str:
    base = strip_archive_suffix(name)
    pieces = [piece for piece in re.split(r"[._-]+", base) if piece]
    if len(pieces) >= 3 and pieces[0] in {"user", "reseller"}:
        return pieces[-1]
    for piece in reversed(pieces):
        if piece.lower() not in {"backup", "user", "admin", "reseller"}:
            return piece
    return base


def normalize_username(raw: str, archive_name: str = "") -> str:
    value = (raw or "").strip().lower()
    value = re.sub(r"[^a-z0-9_-]+", "_", value).strip("_-")
    if not value or not re.match(r"^[a-z_]", value):
        value = f"da_{value}" if value else "da_user"
    value = value[:32]
    if len(value) < 3:
        value = f"{value}_da"[:32]
    if value in RESERVED_USERS or not USER_RE.fullmatch(value):
        digest = hashlib.sha1((raw + archive_name).encode("utf-8")).hexdigest()[:8]
        stem = re.sub(r"[^a-z0-9_]+", "_", value).strip("_") or "user"
        value = f"da_{stem[:18]}_{digest}"[:32]
    return value


def normalize_domain(value: str) -> str | None:
    domain = (value or "").strip().lower().rstrip(".")
    return domain if DOMAIN_RE.fullmatch(domain) else None


def normalize_db_identifier(raw: str, fallback: str, existing: set[str]) -> str:
    value = (raw or fallback).strip().lower()
    value = re.sub(r"[^a-z0-9_]+", "_", value).strip("_")
    if not value:
        value = fallback
    if not re.match(r"^[a-z0-9_]+$", value):
        value = re.sub(r"[^a-z0-9_]+", "_", value)
    value = value[:64]
    if value not in existing and DB_RE.fullmatch(value):
        return value
    digest = hashlib.sha1((raw + fallback).encode("utf-8")).hexdigest()[:6]
    stem = (value[:55].strip("_") or fallback[:55].strip("_") or "db")
    candidate = f"{stem}_{digest}"[:64]
    counter = 2
    while candidate in existing or not DB_RE.fullmatch(candidate):
        suffix = f"_{counter}"
        candidate = f"{stem[:64 - len(suffix)]}{suffix}"
        counter += 1
    return candidate


def discover_username(root: Path, archive_name: str) -> tuple[str, str]:
    user_conf = read_key_values(root / "backup" / "user.conf")
    raw = (
        user_conf.get("username")
        or user_conf.get("user")
        or user_conf.get("account")
        or archive_username(archive_name)
    )
    email = user_conf.get("email") or user_conf.get("emailaddress") or ""
    return normalize_username(raw, archive_name), email


def discover_domains(root: Path) -> list[str]:
    found: list[str] = []
    domains_list = root / "backup" / "domains.list"
    if domains_list.exists():
        for line in domains_list.read_text(encoding="utf-8", errors="ignore").splitlines():
            domain = normalize_domain(line)
            if domain and domain not in found:
                found.append(domain)
    backup_dir = root / "backup"
    if backup_dir.exists():
        for item in backup_dir.iterdir():
            if item.is_file() and item.name.endswith(".conf"):
                domain = normalize_domain(item.name[:-5])
                if domain and domain not in found:
                    found.append(domain)
    domains_dir = root / "domains"
    if domains_dir.exists():
        for item in domains_dir.iterdir():
            if item.is_dir():
                domain = normalize_domain(item.name)
                if domain and domain not in found:
                    found.append(domain)
    return found


def source_for_domain(root: Path, domain: str) -> Path | None:
    candidates = [
        root / "domains" / domain / "public_html",
        root / "domains" / domain / "private_html",
        root / "domains" / domain,
        root / domain / "public_html",
        root / domain,
    ]
    for candidate in candidates:
        if candidate.exists() and candidate.is_dir():
            if candidate.name == domain and (candidate / "public_html").exists():
                return candidate / "public_html"
            return candidate
    for path in root.rglob("public_html"):
        if path.is_dir() and domain in {part.lower() for part in path.parts}:
            return path
    return None


def has_php_files(path: Path) -> bool:
    return any(item.is_file() and item.suffix.lower() in {".php", ".phtml"} for item in path.rglob("*"))


def detect_app_type(source: Path | None) -> str:
    if not source:
        return "php"
    if (source / "wp-config.php").exists() or (source / "wp-config-sample.php").exists():
        return "wordpress"
    return "php" if has_php_files(source) else "static"


def copy_site_files(source: Path | None, public: Path) -> None:
    public.mkdir(parents=True, exist_ok=True)
    if not source or not source.exists():
        return
    for root, dirs, files in os.walk(source):
        root_path = Path(root)
        rel_root = root_path.relative_to(source)
        target_root = public / rel_root
        target_root.mkdir(parents=True, exist_ok=True)
        dirs[:] = [name for name in dirs if not (root_path / name).is_symlink()]
        for name in files:
            src = root_path / name
            if src.is_symlink() or not src.is_file():
                continue
            dst = target_root / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def clear_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink(missing_ok=True)


def sql_base_name(path: Path) -> str:
    name = path.name
    for suffix in SQL_SUFFIXES:
        if name.lower().endswith(suffix):
            return name[: -len(suffix)]
    return path.stem


def discover_sql_files(root: Path) -> dict[str, Path]:
    preferred = [root / "mysql", root / "backup"]
    files: list[Path] = []
    for directory in preferred:
        if directory.exists():
            files.extend(path for path in directory.rglob("*") if path.is_file() and any(path.name.lower().endswith(s) for s in SQL_SUFFIXES))
    if not files:
        for path in root.rglob("*"):
            if path.is_file() and any(path.name.lower().endswith(s) for s in SQL_SUFFIXES):
                if "domains" not in {part.lower() for part in path.parts}:
                    files.append(path)
    result: dict[str, Path] = {}
    for path in files:
        result.setdefault(sql_base_name(path).lower(), path)
    return result


def temporary_sql_file(sql_file: Path) -> Path:
    lower = sql_file.name.lower()
    tmp = Path(tempfile.mkstemp(prefix="snpanel-da-", suffix=".sql")[1])
    if lower.endswith(".sql"):
        opener = open
    elif lower.endswith(".gz"):
        opener = gzip.open
    elif lower.endswith(".bz2"):
        opener = bz2.open
    elif lower.endswith(".zst"):
        zstd = shutil.which("zstdcat") or shutil.which("zstd")
        if not zstd:
            tmp.unlink(missing_ok=True)
            raise ImportErrorWithContext("zstd is required to import .sql.zst files. Install package: zstd")
        args = [zstd, str(sql_file)] if Path(zstd).name == "zstdcat" else [zstd, "-dc", str(sql_file)]
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8", errors="replace")
        try:
            with tmp.open("w", encoding="utf-8") as target:
                assert proc.stdout is not None
                for line in proc.stdout:
                    if SQL_DATABASE_DIRECTIVE_RE.match(line):
                        continue
                    target.write(SQL_DEFINER_RE.sub("", line))
            _, stderr = proc.communicate(timeout=30)
            if proc.returncode != 0:
                tmp.unlink(missing_ok=True)
                raise ImportErrorWithContext(stderr.strip() or "zstd SQL decompression failed")
            return tmp
        finally:
            if proc.poll() is None:
                proc.kill()
    else:
        raise ImportErrorWithContext(f"Unsupported SQL compression: {sql_file}")
    with opener(sql_file, "rt", encoding="utf-8", errors="replace") as source, tmp.open("w", encoding="utf-8") as target:
        for line in source:
            if SQL_DATABASE_DIRECTIVE_RE.match(line):
                continue
            target.write(SQL_DEFINER_RE.sub("", line))
    return tmp


def parse_wp_config(path: Path) -> dict[str, str]:
    config = path / "wp-config.php"
    if not config.exists():
        return {}
    text = config.read_text(encoding="utf-8", errors="ignore")
    found: dict[str, str] = {}
    for key in ("DB_NAME", "DB_USER", "DB_PASSWORD", "DB_HOST"):
        match = re.search(r"define\s*\(\s*['\"]" + key + r"['\"]\s*,\s*['\"]([^'\"]*)['\"]\s*\)", text)
        if match:
            found[key] = match.group(1)
    return found


def parse_dotenv_config(path: Path) -> dict[str, str]:
    env_file = path / ".env"
    if not env_file.exists():
        return {}
    values = read_key_values(env_file)
    result: dict[str, str] = {}
    if values.get("db_database"):
        result["DB_NAME"] = values["db_database"]
    if values.get("db_username"):
        result["DB_USER"] = values["db_username"]
    if values.get("db_password"):
        result["DB_PASSWORD"] = values["db_password"]
    if values.get("db_host"):
        result["DB_HOST"] = values["db_host"]
    return result


def parse_php_variable_config(path: Path) -> dict[str, str]:
    config = path / "configuration.php"
    if not config.exists():
        return {}
    text = config.read_text(encoding="utf-8", errors="ignore")
    mappings = {
        "DB_NAME": ("db", "db_name", "database", "db_database"),
        "DB_USER": ("user", "dbuser", "db_user", "db_username", "username"),
        "DB_PASSWORD": ("password", "dbpass", "db_password"),
        "DB_HOST": ("host", "db_host"),
    }
    result: dict[str, str] = {}
    for key, names in mappings.items():
        for name in names:
            match = re.search(r"(?:public\s+)?\$" + re.escape(name) + r"\s*=\s*['\"]([^'\"]*)['\"]\s*;", text)
            if match:
                result[key] = match.group(1)
                break
    return result


def parse_app_db_config(path: Path) -> dict[str, str]:
    for parser in (parse_wp_config, parse_dotenv_config, parse_php_variable_config):
        values = parser(path)
        if values.get("DB_NAME"):
            return values
    return {}


def replace_define(text: str, key: str, value: str) -> str:
    pattern = re.compile(r"(define\s*\(\s*['\"]" + key + r"['\"]\s*,\s*)['\"][^'\"]*['\"](\s*\)\s*;)")
    if pattern.search(text):
        return pattern.sub(lambda match: f"{match.group(1)}'{value}'{match.group(2)}", text, count=1)
    return text + f"\ndefine('{key}', '{value}');\n"


def update_app_db_config(public: Path, db_name: str, db_user: str, db_password: str) -> None:
    wp = public / "wp-config.php"
    if wp.exists():
        text = wp.read_text(encoding="utf-8", errors="ignore")
        text = replace_define(text, "DB_NAME", db_name)
        text = replace_define(text, "DB_USER", db_user)
        text = replace_define(text, "DB_PASSWORD", db_password)
        text = replace_define(text, "DB_HOST", "localhost")
        wp.write_text(text, encoding="utf-8")

    env_file = public / ".env"
    if env_file.exists():
        lines = env_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        replacements = {
            "DB_DATABASE": db_name,
            "DB_USERNAME": db_user,
            "DB_PASSWORD": db_password,
            "DB_HOST": "127.0.0.1",
        }
        out = []
        seen = set()
        for line in lines:
            key = line.split("=", 1)[0].strip() if "=" in line else ""
            if key in replacements:
                out.append(f"{key}={replacements[key]}")
                seen.add(key)
            else:
                out.append(line)
        if "DB_DATABASE" in seen or "DB_USERNAME" in seen:
            env_file.write_text("\n".join(out) + "\n", encoding="utf-8")

    config_php = public / "configuration.php"
    if config_php.exists():
        text = config_php.read_text(encoding="utf-8", errors="ignore")
        replacements = {
            "db": db_name,
            "db_name": db_name,
            "dbuser": db_user,
            "db_user": db_user,
            "db_username": db_user,
            "password": db_password,
            "dbpass": db_password,
            "db_password": db_password,
            "host": "localhost",
            "db_host": "localhost",
        }
        for key, value in replacements.items():
            text = re.sub(r"(\$" + re.escape(key) + r"\s*=\s*)['\"][^'\"]*['\"](\s*;)", rf"\1'{value}'\2", text)
        config_php.write_text(text, encoding="utf-8")


def existing_identifiers(db, DatabaseAccount) -> tuple[set[str], set[str]]:
    rows = db.query(DatabaseAccount).all()
    return {row.db_name for row in rows}, {row.db_user for row in rows}


def create_panel_database(db, owner, website, old_db: str, old_user: str | None, sql_file: Path | None, credentials: list[str]):
    from app.core.secrets import encrypt
    from app.models.entities import DatabaseAccount
    from app.services import mariadb

    used_names, used_users = existing_identifiers(db, DatabaseAccount)
    fallback = mariadb.safe_db_identifier((website.domain if website else owner.username), "da")
    db_name = normalize_db_identifier(old_db, fallback, used_names)
    db_user = normalize_db_identifier(old_user or db_name, f"u_{db_name}"[:64], used_users)
    db_password = mariadb.random_password()

    mariadb.create_database_credentials(db_name, db_user, db_password)
    temp_sql: Path | None = None
    try:
        if sql_file is not None:
            temp_sql = temporary_sql_file(sql_file)
            mariadb.import_database(db_name, str(temp_sql))
    except Exception:
        mariadb.drop_database(db_name, db_user)
        raise
    finally:
        if temp_sql is not None:
            temp_sql.unlink(missing_ok=True)

    item = DatabaseAccount(
        owner_id=owner.id,
        website_id=website.id if website else None,
        db_name=db_name,
        db_user=db_user,
        db_password=encrypt(db_password),
    )
    db.add(item)
    db.commit()
    target = website.domain if website else owner.username
    credentials.append(f"database target={target} db_name={db_name} db_user={db_user} db_password={db_password}")
    return db_name, db_user, db_password


def unique_email(db, User, username: str, preferred: str, domains: list[str]) -> str:
    domain = domains[0] if domains else "import.local"
    base = preferred if preferred and "@" in preferred else f"{username}@{domain}"
    local, _, host = base.partition("@")
    local = re.sub(r"[^A-Za-z0-9_.+-]+", ".", local).strip(".") or username
    host = host or domain
    candidate = f"{local}@{host}"
    counter = 2
    while db.query(User).filter(User.email == candidate).first():
        candidate = f"{local}+{counter}@{host}"
        counter += 1
    return candidate


def delete_database_record(db, db_item) -> None:
    from app.services import mariadb

    try:
        mariadb.drop_database(db_item.db_name, db_item.db_user)
    finally:
        db.delete(db_item)
        db.flush()


def delete_website_record(db, website) -> None:
    from app.models.entities import DatabaseAccount
    from app.services import nginx, wordpress

    for db_item in db.query(DatabaseAccount).filter(DatabaseAccount.website_id == website.id).all():
        delete_database_record(db, db_item)
    try:
        nginx.delete_wordpress_vhost(website.domain)
    finally:
        try:
            wordpress.delete_wordpress(website.root_path)
        finally:
            db.delete(website)
            db.flush()


def delete_existing_domain(db, domain: str) -> bool:
    from app.models.entities import Website

    website = db.query(Website).filter(Website.domain == domain).first()
    if not website:
        return False
    log(f"  deleting existing domain before import: {domain}")
    delete_website_record(db, website)
    db.commit()
    return True


def delete_existing_user(db, username: str) -> bool:
    from app.models.entities import DatabaseAccount, User, Website
    from app.services import site_users

    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    log(f"  deleting existing user before import: {username}")
    for website in db.query(Website).filter(Website.owner_id == user.id).order_by(Website.id.asc()).all():
        delete_website_record(db, website)
    for db_item in db.query(DatabaseAccount).filter(DatabaseAccount.owner_id == user.id).all():
        delete_database_record(db, db_item)
    site_users.delete_panel_user(username)
    db.delete(user)
    db.commit()
    return True


def ensure_panel_user_record(db, username: str, email: str, domains: list[str], credentials: list[str]):
    from app.core.security import hash_password
    from app.models.entities import User
    from app.services import site_users

    password = secrets.token_urlsafe(18)
    site_users.ensure_panel_user(username, password)
    user = User(
        username=username,
        email=unique_email(db, User, username, email, domains),
        hashed_password=hash_password(password),
        role="end_user",
        website_limit=max(5, len(domains) + 5),
        storage_limit_mb=DEFAULT_STORAGE_MB,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    credentials.append(f"panel_user username={username} password={password}")
    return user, True


def create_or_update_website(db, user, domain: str, source: Path | None, app_type: str, force: bool, credentials: list[str]):
    from app.models.entities import Website
    from app.services import nginx, site_users, waf

    root_path = site_users.site_root_for_panel_user(user.username, domain)
    linux_user = site_users.ensure_site_runtime(domain, root_path, DEFAULT_PHP_VERSION if app_type in {"wordpress", "php"} else None, user.username)
    public = site_users.document_root(root_path)
    clear_directory(public)
    copy_site_files(source, public)

    selected_rules = [rule["id"] for rule in waf.DEFAULT_RULES]
    waf_enabled = True
    waf_result = waf.sync_site_rules(domain, selected_rules, "")
    if waf_result.returncode != 0:
        waf_enabled = False
        log(f"  warning: WAF rules failed for {domain}; vhost will be created with WAF disabled")

    socket = site_users.site_php_fpm_socket(linux_user, root_path, DEFAULT_PHP_VERSION if app_type in {"wordpress", "php"} else None)
    rewrite_mode = "front_controller" if app_type == "wordpress" else "none"
    try:
        nginx.write_vhost(
            domain,
            root_path,
            app_type=app_type,
            php_version=DEFAULT_PHP_VERSION if app_type in {"wordpress", "php"} else None,
            php_fpm_socket_override=socket,
            waf_enabled=waf_enabled,
            rewrite_mode=rewrite_mode,
        )
    except RuntimeError:
        if not waf_enabled:
            raise
        waf_enabled = False
        log(f"  warning: nginx rejected WAF for {domain}; retrying vhost with WAF disabled")
        nginx.write_vhost(
            domain,
            root_path,
            app_type=app_type,
            php_version=DEFAULT_PHP_VERSION if app_type in {"wordpress", "php"} else None,
            php_fpm_socket_override=socket,
            waf_enabled=False,
            rewrite_mode=rewrite_mode,
        )

    website = Website(
        domain=domain,
        owner_id=user.id,
        root_path=root_path,
        linux_user=linux_user,
        php_version=DEFAULT_PHP_VERSION,
        app_type=app_type,
        status="active",
        waf_enabled=waf_enabled,
        nginx_rewrite_mode=rewrite_mode,
    )
    db.add(website)
    db.commit()
    db.refresh(website)
    site_users.fix_site_permissions(root_path, linux_user)
    credentials.append(f"website domain={domain} owner={user.username} root={root_path} app_type={app_type}")
    return website, True


def matched_sql_for_config(app_config: dict[str, str], sql_files: dict[str, Path], single_site: bool) -> tuple[str, Path | None]:
    if app_config.get("DB_NAME"):
        key = app_config["DB_NAME"].lower()
        if key in sql_files:
            return key, sql_files[key]
    if single_site and len(sql_files) == 1:
        return next(iter(sql_files.items()))
    return "", None


def process_archive(entry: dict, force: bool, credentials: list[str], summary: list[dict]) -> None:
    from app.core.database import SessionLocal
    from app.models.entities import DatabaseAccount, Website
    from app.services import site_users

    archive_name = entry["archive_name"]
    extracted = Path(entry["extracted_dir"])
    root = find_backup_root(extracted)
    domains = discover_domains(root)
    username, email = discover_username(root, archive_name)

    item_summary = {
        "archive": archive_name,
        "username": username,
        "domains": domains,
        "imported_domains": [],
        "databases": [],
        "ssl_enabled_domains": [],
        "warnings": [],
    }
    if not domains:
        item_summary["warnings"].append("No domains found")
        summary.append(item_summary)
        log(f"Skipping {archive_name}: no domains found")
        return

    db = SessionLocal()
    try:
        for domain in domains:
            delete_existing_domain(db, domain)
        delete_existing_user(db, username)

        user, created = ensure_panel_user_record(db, username, email, domains, credentials)

        sql_files = discover_sql_files(root)
        imported_sql_keys: set[str] = set()
        websites = []
        for domain in domains:
            source = source_for_domain(root, domain)
            app_type = detect_app_type(source)
            app_config = parse_app_db_config(source) if source else {}
            log(f"Importing domain {domain} for user {username} ...")
            website, changed = create_or_update_website(db, user, domain, source, app_type, force, credentials)
            if not website:
                continue
            websites.append(website)
            item_summary["imported_domains"].append(domain)

            public = site_users.document_root(website.root_path)
            app_config = app_config or parse_app_db_config(public)
            matched_key, matched_sql = matched_sql_for_config(app_config, sql_files, len(domains) == 1)
            if matched_sql:
                db_name, db_user, db_password = create_panel_database(
                    db,
                    user,
                    website,
                    app_config.get("DB_NAME") or matched_key,
                    app_config.get("DB_USER"),
                    matched_sql,
                    credentials,
                )
                imported_sql_keys.add(matched_key)
                update_app_db_config(public, db_name, db_user, db_password)
                site_users.fix_site_permissions(website.root_path, website.linux_user)
                item_summary["databases"].append({"domain": domain, "source": str(matched_sql), "db_name": db_name})

        for key, sql_path in sql_files.items():
            if key in imported_sql_keys:
                continue
            if db.query(DatabaseAccount).filter(DatabaseAccount.db_name == key).first() and not force:
                continue
            log(f"Importing unassigned database {key} for user {username} ...")
            db_name, db_user, _db_password = create_panel_database(db, user, None, key, key, sql_path, credentials)
            item_summary["databases"].append({"domain": None, "source": str(sql_path), "db_name": db_name, "db_user": db_user})

        for website in websites:
            enable_ssl_when_dns_matches(db, website, item_summary)

        summary.append(item_summary)
    finally:
        db.close()


def worker(stage_root: Path, force: bool) -> int:
    load_worker_context()
    from app.core.database import run_migrations

    run_migrations()
    metadata = json.loads((stage_root / "metadata.json").read_text(encoding="utf-8"))
    credentials: list[str] = [
        "# SNPanel DirectAdmin import credentials",
        f"# Run: {metadata.get('run_id')}",
        "# Keep this file private. It contains generated panel and database passwords.",
    ]
    summary: list[dict] = []
    failures = 0
    for entry in metadata["archives"]:
        try:
            log(f"Processing {entry['archive_name']} ...")
            process_archive(entry, force, credentials, summary)
        except Exception as exc:
            failures += 1
            log(f"FAILED {entry['archive_name']}: {exc}")
            summary.append({"archive": entry["archive_name"], "error": str(exc)})

    (stage_root / "credentials.txt").write_text("\n".join(credentials) + "\n", encoding="utf-8")
    (stage_root / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=True), encoding="utf-8")
    return 1 if failures else 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Import DirectAdmin backups into SNPanel.")
    parser.add_argument("--backup-dir", default=str(BACKUP_DIR), help="Directory containing DirectAdmin backup archives.")
    parser.add_argument("--stage-root", default="", help=argparse.SUPPRESS)
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--force", action="store_true", help="Overwrite existing SNPanel website records and public_html.")
    parser.add_argument("--keep-stage", action="store_true", help="Keep extracted staging files after a successful import.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    backup_dir = Path(args.backup_dir)
    if args.worker:
        return worker(Path(args.stage_root), args.force)

    if os.geteuid() != 0:
        raise SystemExit("Run this importer as root, normally from the snpanel menu.")
    if not (APP_DIR / "backend" / ".venv" / "bin" / "python").exists():
        raise SystemExit(f"SNPanel Python virtualenv not found under {APP_DIR}")
    try:
        subprocess.check_call(["id", "snpanel"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        raise SystemExit("Linux user 'snpanel' not found")

    archives = list_archives(backup_dir)
    run_stage, run_id = prepare_run_stage()
    credentials: list[str] = [
        "# SNPanel DirectAdmin import credentials",
        f"# Run: {run_id}",
        "# Keep this file private. It contains generated panel and database passwords.",
    ]
    summary: list[dict] = []
    failures = 0

    for index, archive in enumerate(archives, start=1):
        item_stage: Path | None = None
        rc = 1
        try:
            log(f"[{index}/{len(archives)}] Starting {archive.name}")
            item_stage = prepare_archive_stage(run_stage, run_id, archive, index, backup_dir)
            rc = run_worker(item_stage, backup_dir, args.force, args.keep_stage)
            merge_item_reports(item_stage, credentials, summary)
            if rc == 0:
                log(f"[{index}/{len(archives)}] Completed {archive.name}")
            else:
                failures += 1
                log(f"[{index}/{len(archives)}] FAILED {archive.name}")
        except Exception as exc:
            failures += 1
            log(f"[{index}/{len(archives)}] FAILED {archive.name}: {exc}")
            summary.append({"archive": archive.name, "error": str(exc)})
        finally:
            write_reports(run_id, backup_dir, credentials, summary)
            if item_stage is not None:
                cleanup_archive_stage(item_stage, args.keep_stage, rc)

    cleanup_run_stage(run_stage, args.keep_stage)
    if failures == 0:
        log("DirectAdmin import completed.")
    else:
        log("DirectAdmin import finished with errors. Check the summary report.")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
PYIMPORTER

chmod 0755 "${IMPORTER}"
chown root:root "${IMPORTER}"


patch_cli() {
  local cli="$1"
  [[ -f "$cli" ]] || return 0
  python3 - "$cli" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

text = text.replace('    echo "13) Tu dong Import Backup DirectAdmin (/root/backup)"\n', '')
text = text.replace('      13)\n        /opt/snpanel_da.sh\n        ;;\n', '')

if "directadmin_import_menu()" not in text:
    marker = "\nmenu() {\n"
    fn = '''
directadmin_import_menu() {
  if [[ ! -x /usr/local/sbin/snpanel-directadmin-import ]]; then
    fail "/usr/local/sbin/snpanel-directadmin-import not found. Run da_import_install.sh first."
  fi
  echo "Importing DirectAdmin backups from /root/backup"
  /usr/local/sbin/snpanel-directadmin-import --backup-dir /root/backup
}

'''
    if marker not in text:
        raise SystemExit("Cannot find menu() in snpanel CLI")
    text = text.replace(marker, "\n" + fn + "menu() {\n", 1)

if 'echo "13) Import DirectAdmin backups"' not in text:
    text = text.replace('    echo "12) Sync admin password from root"\n', '    echo "12) Sync admin password from root"\n    echo "13) Import DirectAdmin backups"\n', 1)

if "13) directadmin_import_menu ;;" not in text:
    text = text.replace('      12) sync_admin_root_password ;;\n', '      12) sync_admin_root_password ;;\n      13) directadmin_import_menu ;;\n', 1)

if "directadmin-import|--directadmin-import" not in text:
    text = text.replace('  sync-admin-root-password|--sync-admin-root-password|admin-use-root-password|--admin-use-root-password) sync_admin_root_password ;;\n',
                        '  sync-admin-root-password|--sync-admin-root-password|admin-use-root-password|--admin-use-root-password) sync_admin_root_password ;;\n  directadmin-import|--directadmin-import) directadmin_import_menu ;;\n',
                        1)

if "|directadmin-import|" not in text:
    text = text.replace("|update]", "|directadmin-import|update]")

path.write_text(text, encoding="utf-8")
PY
}

patch_end_user_quick_login() {
  local app_file="${APP_DIR}/frontend/src/App.jsx"
  [[ -f "${app_file}" ]] || {
    echo "WARNING: ${app_file} not found; skipped end-user quick-login compatibility patch." >&2
    return
  }

  python3 - "${app_file}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")

if "const refreshedUser = await loadCurrentUser();" in text:
    raise SystemExit(0)

old_load = """      if (!res.ok) {
        if (res.status === 401) clearSession('Session expired.');
        return;
      }
      const data = await res.json();
      setCurrentUser(data);
      setIsAuthenticated(true);
    } catch {
      setCurrentUser(null);
    }
"""
new_load = """      if (!res.ok) {
        if (res.status === 401) clearSession('Session expired.');
        return null;
      }
      const data = await res.json();
      setCurrentUser(data);
      setIsAuthenticated(true);
      return data;
    } catch {
      setCurrentUser(null);
      return null;
    }
"""
old_refresh = """  async function refreshAll() {
    await loadCurrentUser();
"""
new_refresh = """  async function refreshAll() {
    const refreshedUser = await loadCurrentUser();
"""
old_admin = "    if (isAdmin) await loadPhpVersions();\n"
new_admin = "    if (refreshedUser?.role === 'admin') await loadPhpVersions();\n"

if old_load not in text or old_refresh not in text or old_admin not in text:
    print("WARNING: SNPanel frontend layout differs; skipped end-user quick-login compatibility patch.", file=sys.stderr)
    raise SystemExit(0)

text = text.replace(old_load, new_load, 1)
text = text.replace(old_refresh, new_refresh, 1)
text = text.replace(old_admin, new_admin, 1)
path.write_text(text, encoding="utf-8")
PY

  if grep -q "const refreshedUser = await loadCurrentUser();" "${app_file}"; then
    (cd "${APP_DIR}/frontend" && npm run build)
    echo "Patched end-user quick login: ${app_file}"
  fi
}

patch_cli "${SNPANEL_CLI}"
patch_end_user_quick_login
ln -sfn "${SNPANEL_CLI}" "${SNPANELCTL}"

echo "Installed: ${IMPORTER}"
echo "Patched menu: ${SNPANEL_CLI}"
echo "Backup directory: /root/backup"
echo "Run: snpanel, then choose 13"
