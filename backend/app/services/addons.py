"""Optional parts of the panel, installed only where they are wanted.

Everything here is off until an administrator asks for it. A server that hosts
WordPress has no reason to carry a container runtime, its firewall rules or its
upgrades, and a customer has no reason to see a section of the panel their
package does not include.

The state lives beside the panel's other settings rather than in the database,
so the answer to "is this installed" costs nothing and is available to code that
has no session to hand.
"""

import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import HTTPException, status

ADDONS_DIR = Path(os.environ.get("SNPANEL_DATA_DIR", "/var/lib/snpanel"))
ADDONS_FILE = ADDONS_DIR / "addons.json"

APPLICATION = "application"

# What an administrator sees in the Addons page. The version is the addon's own:
# it moves when the addon changes, independently of the panel's version.
CATALOGUE: dict[str, dict] = {
    APPLICATION: {
        "name": "Application",
        "version": "1.0.0",
        "summary": "Chạy ứng dụng Node.js, container và Docker Compose, đưa ra domain qua Nginx.",
        "details": [
            "Cài Docker và các bản Node.js khi cần, không nằm trong bản cài mặc định.",
            "Mỗi ứng dụng có cổng nội bộ riêng, giới hạn RAM/CPU và chạy dưới user của khách.",
            "Website chọn mode Application để Nginx trỏ vào ứng dụng đã cài.",
        ],
        "notes": [
            "Backup hiện chưa bao gồm dữ liệu ứng dụng (thư mục apps và named volume).",
            "Dung lượng image và volume Docker chưa được tính vào quota đĩa của khách.",
        ],
        # Nothing is deleted when this goes away, so turning it off is safe to
        # try; see uninstall() for what actually happens.
        "keeps_data_on_uninstall": True,
    },
}


def _read() -> dict:
    try:
        with ADDONS_FILE.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(data: dict) -> None:
    ADDONS_DIR.mkdir(parents=True, exist_ok=True)
    with NamedTemporaryFile("w", encoding="utf-8", dir=str(ADDONS_DIR), delete=False) as tmp:
        json.dump(data, tmp, ensure_ascii=True, indent=2, sort_keys=True)
        tmp.write("\n")
        tmp_path = Path(tmp.name)
    tmp_path.replace(ADDONS_FILE)


def known(slug: str) -> dict:
    entry = CATALOGUE.get(slug)
    if not entry:
        raise HTTPException(status_code=404, detail=f"No such addon: {slug}")
    return entry


def is_installed(slug: str) -> bool:
    record = _read().get(slug)
    return bool(record and record.get("installed"))


def installed_slugs() -> list[str]:
    return sorted(slug for slug in CATALOGUE if is_installed(slug))


def state() -> list[dict]:
    """The catalogue with each addon's installed state folded in."""
    stored = _read()
    entries = []
    for slug, entry in sorted(CATALOGUE.items()):
        record = stored.get(slug) or {}
        entries.append({
            "slug": slug,
            **entry,
            "installed": bool(record.get("installed")),
            "installed_version": record.get("version") or "",
            "installed_at": record.get("installed_at") or "",
        })
    return entries


def install(slug: str) -> dict:
    entry = known(slug)
    from datetime import datetime, timezone

    data = _read()
    data[slug] = {
        "installed": True,
        "version": entry["version"],
        "installed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    _write(data)
    return data[slug]


def uninstall(slug: str) -> dict:
    """Turn an addon off without touching anything it created.

    Applications keep their files, their containers' volumes and their rows in
    the database; the panel simply stops offering the feature and stops the units
    so nothing keeps running behind a section nobody can see. Installing again
    picks up where it left off.
    """
    known(slug)
    data = _read()
    record = data.get(slug) or {}
    record["installed"] = False
    data[slug] = record
    _write(data)
    return record


def adopt_existing(slug: str, in_use: bool) -> bool:
    """Count a feature already in use as installed, once.

    The addon split arrives as an update, and a server that has been running
    applications for months must not lose them the moment the panel restarts.
    If there is no record either way and the feature is demonstrably in use, it
    was installed before there was anything to record. Only ever runs when the
    file has no entry, so an administrator who later removes the addon does not
    find it back after the next restart.
    """
    if not in_use:
        return False
    data = _read()
    if slug in data:
        return False
    install(slug)
    return True


def require(slug: str) -> None:
    """Refuse an API call that belongs to an addon nobody installed."""
    entry = known(slug)   # a slug that is not in the catalogue is a bug, not a 409
    if not is_installed(slug):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Addon {entry['name']} chưa được cài. Vào Addons để cài trước.",
        )


def require_application() -> None:
    """FastAPI dependency for every route the Application addon owns."""
    require(APPLICATION)
