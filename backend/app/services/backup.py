from datetime import datetime
from io import StringIO
import hashlib
import json
import logging
from pathlib import Path
import posixpath
import re
import secrets
import tarfile
import tempfile
from typing import List, Optional

import paramiko
from paramiko.pkey import PKey
from paramiko.ssh_exception import SSHException

from app.core.config import settings
from app.core.secrets import decrypt, encrypt
from app.core.security import hash_password
from app.core.permissions import normalize_role
from app.models.entities import DatabaseAccount, SiteApp, User, Website, WebsiteAlias
from app.services import mariadb, nginx, site_users, waf, wordpress
from app.services.shell import shell


logger = logging.getLogger("snpanel.backup")

MAX_UPLOAD_BYTES = 1024 * 1024 * 1024
BACKUP_MANIFEST = "manifest.json"
PANEL_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")

# Full-user archives SNPanel will restore. SNPanel writes "snpanel_user"; "opanel_user"
# is the same archive layout (manifest.json, sites/<domain>/site, databases/<domain>.sql)
# written by opanel, a sibling panel, so accept it too and move accounts between the
# two. opanel archives carry no "applications" section - only domains, files and
# databases come across.
RESTORABLE_BACKUP_KINDS = ("snpanel_user", "opanel_user")
_PLACEHOLDER_EMAIL_SUFFIXES = (
    "@users.snpanel.test", "@users.snpanel.vn",
    "@users.opanel.test", "@users.opanel.vn",
)


def _hostname_conflicts(db, domain: str, exclude_website_id: int | None = None) -> bool:
    safe = (domain or "").strip().lower()
    if not safe:
        return True
    reserved: set[str] = set()
    for website in db.query(Website).all():
        if exclude_website_id is not None and website.id == exclude_website_id:
            continue
        hostname = (website.domain or "").strip().lower()
        if hostname:
            reserved.add(hostname)
            reserved.add(f"www.{hostname}")
    for alias in db.query(WebsiteAlias).all():
        if exclude_website_id is not None and alias.website_id == exclude_website_id:
            continue
        alias_host = (alias.domain or "").strip().lower()
        if alias_host:
            reserved.add(alias_host)
    return safe in reserved or f"www.{safe}" in reserved


def create_backup(website: Website, db_name: Optional[str] = None) -> str:
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    backup_dir = Path(settings.backup_root) / website.domain
    archive = backup_dir / f"{website.domain}-{stamp}.tar.gz"
    sql_file = backup_dir / f"{website.domain}-{stamp}.sql"
    shell.run(["mkdir", "-p", str(backup_dir)])
    backup_dir.mkdir(parents=True, exist_ok=True)
    if db_name:
        mariadb.export_database(db_name, str(sql_file))
        if settings.command_dry_run and not sql_file.exists():
            sql_file.write_text(f"-- DRY RUN database dump for {db_name}\n", encoding="utf-8")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(website.root_path, arcname="site")
        if sql_file.exists():
            tar.add(sql_file, arcname=f"database/{sql_file.name}")
    return str(archive)


def _user_backup_dir(username: str) -> Path:
    if not PANEL_USERNAME_RE.fullmatch(username or ""):
        raise ValueError("Invalid panel username")
    return Path(settings.backup_root) / "users" / username


def _user_restore_dir() -> Path:
    return Path(settings.backup_root) / "users" / "restore"


def user_restore_dir() -> str:
    return str(_user_restore_dir())


def create_user_backup(user: User, db) -> str:
    stamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    backup_dir = _user_backup_dir(user.username)
    backup_dir.mkdir(parents=True, exist_ok=True)
    archive = backup_dir / f"user-{user.username}-{stamp}.tar.gz"
    websites = db.query(Website).filter(Website.owner_id == user.id).order_by(Website.id.asc()).all()

    with tempfile.TemporaryDirectory(prefix="snpanel-user-backup-", dir=str(backup_dir)) as tmp:
        tmp_dir = Path(tmp)
        manifest = {
            "kind": "snpanel_user",
            "version": 1,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "user": {
                "username": user.username,
                "email": user.email,
                "hashed_password": user.hashed_password,
                "role": user.role,
                "is_active": user.is_active,
                "website_limit": user.website_limit,
                "storage_limit_mb": user.storage_limit_mb,
            },
            "websites": [],
            "applications": [],
        }

        # Applications are not websites and their data is not under a website
        # root, so without this a restore brought back the sites and quietly
        # dropped every container's workflows and database.
        app_payloads: dict[str, Path] = {}
        for app_entry, payload in _collect_applications(user, db, tmp_dir):
            manifest["applications"].append(app_entry)
            if payload:
                app_payloads[app_entry["name"]] = payload

        sql_files: dict[str, Path] = {}
        for website in websites:
            site_entry = {
                "domain": website.domain,
                "php_version": website.php_version,
                "app_type": website.app_type or "wordpress",
                "status": website.status or "active",
                "document_root": getattr(website, "document_root", "public_html") or "public_html",
                "nginx_custom": website.nginx_custom or "",
                "nginx_config_mode": "managed",
                "nginx_rewrite_mode": getattr(website, "nginx_rewrite_mode", "none") or "none",
                "waf_enabled": bool(website.waf_enabled),
                "waf_default_rules": website.waf_default_rules or "",
                "waf_custom_rules": website.waf_custom_rules or "",
                "http_flood_enabled": bool(getattr(website, "http_flood_enabled", False)),
                "http_flood_config": getattr(website, "http_flood_config", "") or "",
                "aliases": [alias.domain for alias in getattr(website, "aliases", []) or [] if getattr(alias, "mode", "alias") == "alias"],
                "database": None,
            }
            db_item = db.query(DatabaseAccount).filter(DatabaseAccount.website_id == website.id).first()
            if db_item:
                sql_name = f"{website.domain}.sql"
                sql_path = tmp_dir / sql_name
                mariadb.export_database(db_item.db_name, str(sql_path))
                if settings.command_dry_run and not sql_path.exists():
                    sql_path.write_text(f"-- DRY RUN database dump for {db_item.db_name}\n", encoding="utf-8")
                sql_files[website.domain] = sql_path
                try:
                    db_password = decrypt(db_item.db_password)
                except RuntimeError:
                    db_password = ""
                site_entry["database"] = {
                    "db_name": db_item.db_name,
                    "db_user": db_item.db_user,
                    "db_password": db_password,
                    "sql_member": f"databases/{sql_name}",
                }
            manifest["websites"].append(site_entry)

        manifest_path = tmp_dir / BACKUP_MANIFEST
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=True, indent=2), encoding="utf-8")
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(manifest_path, arcname=BACKUP_MANIFEST)
            for website in websites:
                root = Path(website.root_path)
                if root.exists():
                    tar.add(root, arcname=f"sites/{website.domain}/site")
                sql_path = sql_files.get(website.domain)
                if sql_path and sql_path.exists():
                    tar.add(sql_path, arcname=f"databases/{website.domain}.sql")
            for name, payload in app_payloads.items():
                if payload.exists():
                    tar.add(payload, arcname=f"applications/{name}.tar")
    return str(archive)


def _collect_applications(user: User, db, tmp_dir: Path) -> list[tuple[dict, Optional[Path]]]:
    """Each of a user's applications: what it is, and a tar of what it holds.

    An application whose data cannot be read is still recorded — coming back with
    the settings and an empty directory beats not coming back at all — and the
    manifest says so, so a restore can tell the customer which ones need their
    data putting back by hand.
    """
    from app.services import addons, site_apps

    if not addons.is_installed(addons.APPLICATION):
        return []
    apps = db.query(SiteApp).filter(SiteApp.owner_id == user.id).order_by(SiteApp.id.asc()).all()
    collected: list[tuple[dict, Optional[Path]]] = []
    for app in apps:
        entry = {
            "name": app.name,
            "kind": app.kind,
            "port": app.port,
            "memory_limit_mb": app.memory_limit_mb,
            "cpu_limit": app.cpu_limit or "1",
            "autostart": bool(app.autostart),
            "env": app.env or "",
            "start_kind": app.start_kind,
            "start_arg": app.start_arg,
            "node_major": app.node_major,
            "image": app.image,
            "container_port": app.container_port,
            "compose_source": app.compose_source or "",
            "web_service": app.web_service,
            "websites": [website.domain for website in app.websites],
            "payload_member": None,
            "payload_error": "",
        }
        payload: Optional[Path] = None
        try:
            target = tmp_dir / f"app-{app.name}.tar"
            site_apps.export_payload(app, str(target))
            if target.exists():
                payload = target
                entry["payload_member"] = f"applications/{app.name}.tar"
        except (RuntimeError, ValueError) as exc:
            entry["payload_error"] = str(exc)[-500:]
            logger.warning("Could not export application %s: %s", app.name, exc)
        collected.append((entry, payload))
    return collected


def list_user_backups(username: str) -> List[str]:
    backup_dir = _user_backup_dir(username)
    if settings.command_dry_run or not backup_dir.exists():
        return []
    return [str(path) for path in sorted(backup_dir.glob("*.tar.gz"), reverse=True)]


def list_uploaded_user_backups(username: Optional[str] = None) -> List[str]:
    backup_dirs = [_user_restore_dir(), Path(settings.backup_root) / "users" / "uploads"]
    if settings.command_dry_run:
        return []
    items = []
    seen = set()
    for backup_dir in backup_dirs:
        if not backup_dir.exists():
            continue
        for path in sorted(backup_dir.glob("*.tar.gz"), reverse=True):
            if path in seen:
                continue
            if username:
                try:
                    manifest = read_backup_manifest(str(path))
                except Exception:
                    continue
                if (manifest.get("user") or {}).get("username") != username:
                    continue
            seen.add(path)
            items.append(str(path))
    return items


def describe_user_backup(backup_file: str) -> dict:
    path = user_backup_path(backup_file)
    item = {
        "backup_file": str(path),
        "filename": path.name,
        "size": path.stat().st_size,
        "username": "",
        "generated_at": "",
        "websites": 0,
        "applications": 0,
        "valid": False,
        "source": "snpanel",
        "error": "",
    }
    try:
        manifest = read_backup_manifest(str(path))
        kind = manifest.get("kind")
        item["valid"] = kind in RESTORABLE_BACKUP_KINDS
        item["source"] = "opanel" if kind == "opanel_user" else "snpanel"
        item["username"] = (manifest.get("user") or {}).get("username") or ""
        item["generated_at"] = manifest.get("generated_at") or ""
        item["websites"] = len(manifest.get("websites") or [])
        item["applications"] = len(manifest.get("applications") or [])
        if not item["valid"]:
            item["error"] = "This is not a snpanel or opanel user backup"
    except Exception as exc:
        item["error"] = str(exc)
    return item


def list_user_restore_backups() -> list[dict]:
    backup_dir = _user_restore_dir()
    if settings.command_dry_run or not backup_dir.exists():
        return []
    return [describe_user_backup(str(path)) for path in sorted(backup_dir.glob("*.tar.gz"), reverse=True)]


def user_backup_path(backup_file: str) -> Path:
    backup_root = Path(settings.backup_root).resolve()
    path = Path(backup_file).resolve()
    if backup_root != path and backup_root not in path.parents:
        raise FileNotFoundError("Backup not found")
    if not path.exists() or not path.is_file() or path.suffixes[-2:] != [".tar", ".gz"]:
        raise FileNotFoundError("Backup not found")
    return path


def delete_user_backup(backup_file: str) -> str:
    path = user_backup_path(backup_file)
    path.unlink()
    return str(path)


def delete_user_restore_backup(backup_file: str) -> str:
    path = user_backup_path(backup_file)
    restore_dir = _user_restore_dir().resolve()
    if restore_dir not in path.parents:
        raise FileNotFoundError("Backup not found")
    path.unlink()
    return str(path)


def prune_user_backups(username: str, keep: int) -> None:
    keep = max(int(keep or 1), 1)
    for old_backup in list_user_backups(username)[keep:]:
        Path(old_backup).unlink(missing_ok=True)


def read_backup_manifest(backup_file: str) -> dict:
    archive = user_backup_path(backup_file)
    with tarfile.open(archive, "r:gz") as tar:
        try:
            member = tar.getmember(BACKUP_MANIFEST)
        except KeyError as exc:
            raise ValueError("Backup manifest not found") from exc
        if member.size > 2 * 1024 * 1024:
            raise ValueError("Backup manifest is too large")
        source = tar.extractfile(member)
        if source is None:
            raise ValueError("Backup manifest cannot be read")
        return json.loads(source.read().decode("utf-8"))


def _safe_extract_prefix(archive: Path, prefix: str, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    prefix = prefix.strip("/")
    with tarfile.open(archive, "r:gz") as tar:
        for original in tar.getmembers():
            if original.name == prefix:
                continue
            if not original.name.startswith(prefix + "/"):
                continue
            if original.islnk():
                continue
            original.name = original.name[len(prefix) + 1:]
            if not original.name:
                continue

            def safe_filter(member: tarfile.TarInfo, dest_path: str):
                if member.islnk():
                    return None
                return tarfile.data_filter(member, dest_path)

            try:
                tar.extract(original, path=str(destination), filter=safe_filter)
            except TypeError:
                member_path = (destination / original.name).resolve()
                if destination != member_path and destination not in member_path.parents:
                    raise ValueError("Backup archive contains unsafe paths")
                if original.issym():
                    link_path = (member_path.parent / original.linkname).resolve()
                    if destination != link_path and destination not in link_path.parents:
                        raise ValueError("Backup archive contains unsafe links")
                tar.extract(original, str(destination))


def _extract_member_to_file(archive: Path, member_name: str, output_dir: Path) -> Optional[Path]:
    with tarfile.open(archive, "r:gz") as tar:
        try:
            member = tar.getmember(member_name)
        except KeyError:
            return None
        if not member.isfile() or member.size > MAX_UPLOAD_BYTES:
            raise ValueError("Invalid SQL backup member")
        source = tar.extractfile(member)
        if source is None:
            return None
        output_dir.mkdir(parents=True, exist_ok=True)
        target = output_dir / Path(member_name).name
        with target.open("wb") as output:
            while chunk := source.read(1024 * 1024):
                output.write(chunk)
        return target


def restore_user_backup(backup_file: str, db) -> dict:
    archive = user_backup_path(backup_file)
    manifest = read_backup_manifest(str(archive))
    if manifest.get("kind") not in RESTORABLE_BACKUP_KINDS:
        raise ValueError("This is not a snpanel or opanel user backup")
    user_info = manifest.get("user") or {}
    username = user_info.get("username") or ""
    if not PANEL_USERNAME_RE.fullmatch(username):
        raise ValueError("Invalid user in backup")

    user = db.query(User).filter(User.username == username).first()
    created_user = False
    if user is None:
        email = user_info.get("email") or f"{username}@users.snpanel.invalid"
        if email.endswith(_PLACEHOLDER_EMAIL_SUFFIXES):
            email = f"{username}@users.snpanel.invalid"
        if db.query(User).filter(User.email == email).first():
            email = f"{username}-{secrets.token_hex(4)}@users.snpanel.invalid"
        backup_role = user_info.get("role") or "end_user"
        try:
            role = normalize_role(backup_role).value
        except Exception:
            role = "end_user"
        user = User(
            username=username,
            email=email,
            hashed_password=user_info.get("hashed_password") or hash_password(secrets.token_urlsafe(18)),
            role=role,
            is_active=bool(user_info.get("is_active", True)),
            website_limit=int(user_info.get("website_limit") or 5),
            storage_limit_mb=int(user_info.get("storage_limit_mb") or 1024),
        )
        db.add(user)
        db.flush()
        created_user = True
    site_users.ensure_panel_user(user.username)

    restored_websites = []
    # Stage under the panel-owned import area: the helper only copies site files
    # into place from there (the site dir belongs to its Linux user, not snpanel).
    site_users.IMPORT_STAGE_BASE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="snpanel-user-restore-", dir=str(site_users.IMPORT_STAGE_BASE)
    ) as tmp:
        tmp_dir = Path(tmp)
        for site_info in manifest.get("websites") or []:
            domain = (site_info.get("domain") or "").strip().lower()
            if not site_users.DOMAIN_RE.fullmatch(domain):
                raise ValueError(f"Invalid domain in backup: {domain}")
            php_version = site_info.get("php_version") or settings.default_php_version
            app_type = site_info.get("app_type") or "wordpress"
            if app_type not in {"wordpress", "php", "static"}:
                app_type = "wordpress"
            nginx_rewrite_mode = site_info.get("nginx_rewrite_mode")
            if nginx_rewrite_mode not in {"none", "front_controller", "laravel", "codeigniter", "seohburl"}:
                nginx_rewrite_mode = "front_controller" if app_type in {"wordpress", "php"} else "none"
            document_root = site_users.validate_document_root(site_info.get("document_root") or "public_html")
            backup_aliases = [
                (alias or "").strip().lower()
                for alias in (site_info.get("aliases") or [])
                if (alias or "").strip()
            ]
            backup_aliases = sorted({alias for alias in backup_aliases if alias != domain})
            linux_user = site_users.linux_user_for_panel_username(user.username)
            root_path = site_users.site_root_for_panel_user(user.username, domain)
            runtime_php_version = php_version if app_type in {"wordpress", "php"} else None
            site_users.ensure_site_runtime(domain, root_path, runtime_php_version, linux_user)
            site_stage = tmp_dir / "site" / domain
            _safe_extract_prefix(archive, f"sites/{domain}/site", site_stage)
            site_users.import_site_files(root_path, linux_user, str(site_stage))
            # Backups from older SNPanel releases may contain public/. Normalize
            # the document root after extraction before rewriting the vhost.
            site_users.ensure_site_runtime(domain, root_path, runtime_php_version, linux_user)
            site_users.ensure_document_root(root_path, document_root, linux_user)

            website = db.query(Website).filter(Website.domain == domain).first()
            created_site = False
            if website is None:
                website = Website(
                    domain=domain,
                    owner_id=user.id,
                    root_path=root_path,
                    document_root=document_root,
                    linux_user=linux_user,
                    php_version=php_version,
                    app_type=app_type,
                    ssl_enabled=False,
                    status=site_info.get("status") or "active",
                    nginx_custom=site_info.get("nginx_custom") or "",
                    nginx_config_mode="managed",
                    nginx_rewrite_mode=nginx_rewrite_mode,
                    waf_enabled=bool(site_info.get("waf_enabled", True)),
                    waf_default_rules=site_info.get("waf_default_rules") or "",
                    waf_custom_rules=site_info.get("waf_custom_rules") or "",
                    http_flood_enabled=bool(site_info.get("http_flood_enabled", False)),
                    http_flood_config=site_info.get("http_flood_config") or "",
                )
                db.add(website)
                db.flush()
                created_site = True
            else:
                website.owner_id = user.id
                website.root_path = root_path
                website.document_root = document_root
                website.linux_user = linux_user
                website.php_version = php_version
                website.app_type = app_type
                website.status = site_info.get("status") or "active"
                website.nginx_custom = site_info.get("nginx_custom") or ""
                website.nginx_config_mode = "managed"
                website.nginx_rewrite_mode = nginx_rewrite_mode
                website.waf_enabled = bool(site_info.get("waf_enabled", True))
                website.waf_default_rules = site_info.get("waf_default_rules") or ""
                website.waf_custom_rules = site_info.get("waf_custom_rules") or ""
                website.http_flood_enabled = bool(site_info.get("http_flood_enabled", False))
                website.http_flood_config = site_info.get("http_flood_config") or ""
                db.flush()

            existing_aliases = {
                alias.domain: alias
                for alias in db.query(WebsiteAlias).filter(WebsiteAlias.website_id == website.id).all()
            }
            for alias_domain in backup_aliases:
                if _hostname_conflicts(db, alias_domain, exclude_website_id=website.id):
                    raise ValueError(f"Alias domain already belongs to another website: {alias_domain}")
                if alias_domain not in existing_aliases:
                    db.add(WebsiteAlias(website_id=website.id, domain=alias_domain, mode="alias"))
            for alias_domain, alias_obj in existing_aliases.items():
                if alias_domain not in backup_aliases:
                    db.delete(alias_obj)

            db_info = site_info.get("database") or None
            if db_info:
                db_name = db_info.get("db_name")
                db_user = db_info.get("db_user")
                db_password = db_info.get("db_password") or mariadb.random_password()
                conflict = db.query(DatabaseAccount).filter(
                    DatabaseAccount.db_name == db_name,
                    DatabaseAccount.website_id != website.id,
                ).first()
                if conflict:
                    raise ValueError(f"Database name already belongs to another website: {db_name}")
                # A restore recreates the account this archive already owned.
                mariadb.create_database_credentials(
                    db_name, db_user, db_password, allow_existing_user=True
                )
                sql_member = db_info.get("sql_member") or f"databases/{domain}.sql"
                sql_path = _extract_member_to_file(archive, sql_member, tmp_dir)
                if sql_path:
                    mariadb.import_database(db_name, str(sql_path))
                db_account = db.query(DatabaseAccount).filter(DatabaseAccount.website_id == website.id).first()
                if db_account is None:
                    db.add(DatabaseAccount(
                        owner_id=website.owner_id,
                        website_id=website.id,
                        db_name=db_name,
                        db_user=db_user,
                        db_password=encrypt(db_password),
                    ))
                else:
                    db_account.owner_id = website.owner_id
                    db_account.db_name = db_name
                    db_account.db_user = db_user
                    db_account.db_password = encrypt(db_password)

            result = waf.sync_website_rules(website)
            if result.returncode != 0:
                raise RuntimeError((result.stderr or result.stdout or "Could not write WAF rules").strip())
            if website.http_flood_enabled:
                result = nginx.sync_http_flood_zones(db.query(Website).all())
                if result.returncode != 0:
                    raise RuntimeError((result.stderr or result.stdout or "Could not write HTTP flood zones").strip())
            nginx.rewrite_vhost(
                domain,
                root_path,
                app_type=app_type,
                php_version=php_version,
                custom_directives=website.nginx_custom or "",
                php_fpm_socket_override=site_users.site_php_fpm_socket(linux_user, root_path, runtime_php_version),
                waf_enabled=website.waf_enabled,
                http_flood_enabled=website.http_flood_enabled,
                http_flood_config=website.http_flood_config or "",
                document_root=document_root,
                rewrite_mode=nginx_rewrite_mode,
                aliases=backup_aliases,
            )
            if not website.http_flood_enabled:
                result = nginx.sync_http_flood_zones(db.query(Website).all())
                if result.returncode != 0:
                    raise RuntimeError((result.stderr or result.stdout or "Could not write HTTP flood zones").strip())
            wordpress.fix_permissions(root_path, linux_user)
            restored_websites.append({"domain": domain, "created": created_site})

        restored_apps = _restore_applications(manifest, user, db, archive, tmp_dir)

    db.commit()
    return {
        "created_user": created_user,
        "username": username,
        "websites": restored_websites,
        "applications": restored_apps,
    }


def _restore_applications(manifest: dict, user: User, db, archive: Path, tmp_dir: Path) -> list[dict]:
    """Bring back a user's applications, stopped.

    Deliberately not started: the images may not be pulled yet, and a customer
    should look at what came back before it starts answering on their domain. The
    panel's Deploy button does the rest.
    """
    entries = manifest.get("applications") or []
    if not entries:
        return []
    from app.services import addons, site_apps

    if not addons.is_installed(addons.APPLICATION):
        # Recorded rather than dropped, so the operator knows what this backup
        # holds and can install the addon and restore again.
        return [{"name": entry.get("name"), "skipped": "Addon Application chưa được cài"} for entry in entries]

    results: list[dict] = []
    for entry in entries:
        name = (entry.get("name") or "").strip()
        try:
            name = site_apps.validate_name(name)
            kind = entry.get("kind") if entry.get("kind") in site_apps.APP_KINDS else "node"
        except ValueError as exc:
            results.append({"name": name, "error": str(exc)})
            continue

        app = db.query(SiteApp).filter(SiteApp.owner_id == user.id, SiteApp.name == name).first()
        created = app is None
        if created:
            try:
                port = site_apps.allocate_port(db, entry.get("port"))
            except ValueError:
                port = site_apps.allocate_port(db, None)
            app = SiteApp(owner_id=user.id, name=name, kind=kind, port=port, status="stopped")
            db.add(app)
        app.kind = kind
        app.start_kind = entry.get("start_kind")
        app.start_arg = entry.get("start_arg")
        app.node_major = entry.get("node_major")
        app.image = entry.get("image")
        app.container_port = int(entry.get("container_port") or 3000)
        app.cpu_limit = entry.get("cpu_limit") or "1"
        app.env = entry.get("env") or ""
        app.compose_source = entry.get("compose_source") or ""
        app.web_service = entry.get("web_service")
        app.memory_limit_mb = int(entry.get("memory_limit_mb") or 512)
        app.autostart = bool(entry.get("autostart", True))
        app.status = "stopped"
        db.flush()

        record = {"name": name, "created": created, "data_restored": False}
        member = entry.get("payload_member")
        if member:
            payload = _extract_member_to_file(archive, member, tmp_dir)
            if payload:
                # The helper only reads from the backup tree, so the extracted
                # payload has to live there rather than in /tmp — and inside the
                # user's own directory, the one level of it the panel may write.
                staging_dir = _user_backup_dir(user.username)
                staged = staging_dir / f".restore-{name}.tar"
                try:
                    staging_dir.mkdir(parents=True, exist_ok=True)
                    staged.write_bytes(payload.read_bytes())
                    site_apps.import_payload(app, str(staged))
                    record["data_restored"] = True
                except (OSError, RuntimeError, ValueError) as exc:
                    record["error"] = str(exc)[-500:]
                    logger.warning("Could not restore application %s: %s", name, exc)
                finally:
                    staged.unlink(missing_ok=True)
        elif entry.get("payload_error"):
            record["error"] = f"Backup này không có dữ liệu: {entry['payload_error']}"
        results.append(record)
    return results


def save_uploaded_backup(domain: str, filename: str, source_file) -> str:
    backup_dir = (Path(settings.backup_root).resolve() / domain).resolve()
    backup_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(filename).name
    if not safe_name.endswith(".tar.gz"):
        raise ValueError("Only .tar.gz backup files are supported")
    target = (backup_dir / safe_name).resolve()
    if backup_dir not in target.parents:
        raise ValueError("Invalid backup filename")
    written = 0
    with target.open("wb") as buffer:
        while chunk := source_file.read(1024 * 1024):
            written += len(chunk)
            if written > MAX_UPLOAD_BYTES:
                target.unlink(missing_ok=True)
                raise ValueError("Backup file is too large")
            buffer.write(chunk)
    return str(target)


def save_uploaded_user_backup(filename: str, source_file) -> str:
    backup_dir = _user_restore_dir().resolve()
    backup_dir.mkdir(parents=True, exist_ok=True)
    safe_name = Path(filename).name
    if not safe_name.endswith(".tar.gz"):
        raise ValueError("Only .tar.gz backup files are supported")
    target = (backup_dir / safe_name).resolve()
    if backup_dir not in target.parents:
        raise ValueError("Invalid backup filename")
    if target.exists():
        stem = safe_name[:-7]
        suffix = datetime.utcnow().strftime("%Y%m%d%H%M%S")
        target = (backup_dir / f"{stem}-{suffix}-{secrets.token_hex(3)}.tar.gz").resolve()
    written = 0
    with target.open("wb") as buffer:
        while chunk := source_file.read(1024 * 1024):
            written += len(chunk)
            if written > MAX_UPLOAD_BYTES:
                target.unlink(missing_ok=True)
                raise ValueError("Backup file is too large")
            buffer.write(chunk)
    return str(target)


def restore_backup(website: Website, backup_file: str) -> str:
    archive = backup_path(website.domain, backup_file)
    destination = Path(website.root_path).resolve()

    # Single-pass extraction with PEP 706 data filter (Python 3.12+).
    # The data filter rejects path traversal, absolute paths, and unsafe
    # symlinks at the tarfile layer itself.
    with tarfile.open(archive, "r:gz") as tar:
        members = list(tar.getmembers())
        has_site_prefix = any(m.name == "site" or m.name.startswith("site/") for m in members)

        def safe_filter(member: tarfile.TarInfo, dest_path: str):
            # Hard-links inside backups are uncommon and risky; refuse outright.
            if member.islnk():
                return None
            if member.name.startswith("database/"):
                return None
            if has_site_prefix:
                if member.name == "site":
                    return None
                if not member.name.startswith("site/"):
                    return None
                member.name = member.name[len("site/"):]
            return tarfile.data_filter(member, dest_path)

        try:
            tar.extractall(path=str(destination), filter=safe_filter)
        except TypeError:
            # Older Python (<3.12) without the filter parameter — fall back to
            # manual extraction with the existing safety check.
            _ensure_safe_tar(archive, destination)
            for member in members:
                if member.name.startswith("database/"):
                    continue
                if has_site_prefix:
                    if member.name == "site":
                        continue
                    if not member.name.startswith("site/"):
                        continue
                    member.name = member.name[len("site/"):]
                tar.extract(member, str(destination))
    return str(destination)


def backup_path(domain: str, backup_file: str) -> Path:
    backup_root = (Path(settings.backup_root).resolve() / domain).resolve()
    path = Path(backup_file).resolve()
    if backup_root not in path.parents or not path.exists() or path.suffixes[-2:] != [".tar", ".gz"] or not path.is_file():
        raise FileNotFoundError("Backup not found")
    return path


def _ensure_safe_tar(archive: Path, destination: Path) -> None:
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar.getmembers():
            member_path = (destination / member.name).resolve()
            if destination != member_path and destination not in member_path.parents:
                raise ValueError("Backup archive contains unsafe paths")
            if member.issym() or member.islnk():
                link_path = (member_path.parent / member.linkname).resolve()
                if destination != link_path and destination not in link_path.parents:
                    raise ValueError("Backup archive contains unsafe links")


def delete_backup(domain: str, backup_file: str) -> str:
    path = backup_path(domain, backup_file)
    path.unlink()
    return str(path)


def list_backups(domain: str) -> List[str]:
    backup_dir = Path(settings.backup_root) / domain
    if settings.command_dry_run:
        return []
    if not backup_dir.exists():
        return []
    return [str(path) for path in sorted(backup_dir.glob("*.tar.gz"), reverse=True)]


def _load_private_key(private_key: str, password: Optional[str] = None):
    key_stream = StringIO(private_key)
    key_classes = (
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.Ed25519Key,
        paramiko.DSSKey,
    )
    last_error = None
    for key_class in key_classes:
        key_stream.seek(0)
        try:
            return key_class.from_private_key(key_stream, password=password or None)
        except Exception as exc:  # pragma: no cover - depends on key type
            last_error = exc
    raise ValueError(f"Cannot load SFTP private key: {last_error}")


def _ensure_remote_dir(sftp, remote_dir: str) -> None:
    remote_dir = posixpath.normpath(remote_dir or ".")
    if remote_dir in {".", "/"}:
        return
    parts = [part for part in remote_dir.split("/") if part]
    current = "/" if remote_dir.startswith("/") else "."
    for part in parts:
        current = posixpath.join(current, part) if current != "/" else f"/{part}"
        try:
            sftp.stat(current)
        except FileNotFoundError:
            sftp.mkdir(current)


class SftpHostKeyMismatch(RuntimeError):
    """Raised when a pinned host key no longer matches the server."""


def _fingerprint(key: PKey) -> str:
    """SHA256:base64 fingerprint, identical to OpenSSH ``ssh-keygen -lf``."""
    digest = hashlib.sha256(key.asbytes()).digest()
    import base64 as _b64

    return "SHA256:" + _b64.b64encode(digest).rstrip(b"=").decode("ascii")


class _PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Paramiko policy that captures the server host key on first connect.

    When ``expected`` is ``None`` (TOFU bootstrap) the policy accepts the key
    and stores it on ``self.captured`` for the caller to persist. When
    ``expected`` is set the policy refuses to fall back here at all because
    the verification has already happened in the caller; this is purely a
    safety net to surface a clear error if logic upstream changes.
    """

    def __init__(self, expected_type: Optional[str], expected_fingerprint: Optional[str]):
        self.expected_type = expected_type
        self.expected_fingerprint = expected_fingerprint
        self.captured_type: Optional[str] = None
        self.captured_fingerprint: Optional[str] = None

    def missing_host_key(self, client, hostname, key):  # type: ignore[override]
        captured = _fingerprint(key)
        if self.expected_fingerprint:
            # Verification path: a key was pinned but Paramiko did not find a
            # matching entry. Refuse the connection.
            raise SftpHostKeyMismatch(
                f"SFTP host key mismatch for {hostname}: "
                f"expected {self.expected_type or '?'} {self.expected_fingerprint}, "
                f"got {key.get_name()} {captured}"
            )
        # TOFU bootstrap.
        self.captured_type = key.get_name()
        self.captured_fingerprint = captured
        logger.warning(
            "SFTP TOFU bootstrap: pinning %s host key %s %s",
            hostname,
            self.captured_type,
            self.captured_fingerprint,
        )


def upload_to_sftp(
    local_file: str,
    *,
    host: str,
    port: int,
    username: str,
    remote_path: str,
    password: Optional[str] = None,
    private_key: Optional[str] = None,
    expected_host_key_type: Optional[str] = None,
    expected_host_key_fingerprint: Optional[str] = None,
) -> dict:
    """Upload ``local_file`` to ``host:port`` via SFTP.

    Host key handling:
      * If a fingerprint is pinned, the server's key is compared against it
        before any auth bytes are sent. A mismatch raises
        :class:`SftpHostKeyMismatch`.
      * If no fingerprint is pinned yet (TOFU bootstrap), the server's key is
        captured and returned. The caller must persist it.

    Returns a dict ``{"remote_file": ..., "host_key_type": ...,
    "host_key_fingerprint": ...}``.
    """
    local_path = Path(local_file).resolve()
    if not local_path.exists() or not local_path.is_file():
        raise FileNotFoundError("Local backup file not found")
    if not password and not private_key:
        raise ValueError("SFTP password or private key is required")

    pkey = _load_private_key(private_key, password=password) if private_key else None
    remote_dir = posixpath.normpath(remote_path.strip() or ".")
    remote_file = posixpath.join(remote_dir, local_path.name)

    captured_type: Optional[str] = expected_host_key_type
    captured_fp: Optional[str] = expected_host_key_fingerprint

    client = paramiko.SSHClient()
    # Note: we deliberately do NOT call load_system_host_keys() because the
        # daemon runs as the snpanel service user with no interactive shell
        # history; trusting its known_hosts blindly would defeat the pinning model.
    if expected_host_key_fingerprint:
        # Strict: the only acceptable key is the one pinned in the DB.
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            host_keys = client.get_host_keys()
            host_key_obj = _decode_pinned_key(
                expected_host_key_type or "", expected_host_key_fingerprint
            )
            if host_key_obj is not None:
                host_keys.add(host, expected_host_key_type or host_key_obj.get_name(), host_key_obj)
        except Exception:  # pragma: no cover - decoding fallback
            pass
        # Even if we could not pre-load the key (e.g. only fingerprint stored),
        # the missing_host_key policy below performs the comparison itself.
        client.set_missing_host_key_policy(
            _PinnedHostKeyPolicy(expected_host_key_type, expected_host_key_fingerprint)
        )
    else:
        # TOFU bootstrap path: capture the server key for the caller.
        client.set_missing_host_key_policy(
            _PinnedHostKeyPolicy(None, None)
        )

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password if not pkey else None,
            pkey=pkey,
            timeout=20,
            banner_timeout=20,
            auth_timeout=20,
            allow_agent=False,
            look_for_keys=False,
        )
        # Verify the server key we actually negotiated against the pin. The
        # policy catches the "missing" case; this catches the case where the
        # key was already in the local known_hosts and the policy was not
        # called at all.
        transport = client.get_transport()
        if transport is None:
            raise SSHException("SFTP transport unavailable")
        server_key = transport.get_remote_server_key()
        server_fp = _fingerprint(server_key)
        server_type = server_key.get_name()
        if expected_host_key_fingerprint:
            if server_fp != expected_host_key_fingerprint:
                raise SftpHostKeyMismatch(
                    f"SFTP host key mismatch for {host}: "
                    f"expected {expected_host_key_type or '?'} {expected_host_key_fingerprint}, "
                    f"got {server_type} {server_fp}"
                )
            captured_type = expected_host_key_type or server_type
            captured_fp = expected_host_key_fingerprint
        else:
            captured_type = server_type
            captured_fp = server_fp
        with client.open_sftp() as sftp:
            _ensure_remote_dir(sftp, remote_dir)
            sftp.put(str(local_path), remote_file)
    finally:
        client.close()
    return {
        "remote_file": remote_file,
        "host_key_type": captured_type,
        "host_key_fingerprint": captured_fp,
    }


def _decode_pinned_key(key_type: str, fingerprint: str) -> Optional[PKey]:
    """We store only the fingerprint, so reconstructing a PKey is not always
    possible. Returns ``None`` to indicate the caller should rely on the
    in-policy fingerprint comparison instead."""
    return None
