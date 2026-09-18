"""Which distribution the panel is running on, and what it calls things.

The panel was written for Ubuntu, where the web server runs as ``www-data``,
Redis is ``redis-server`` and packages come from ``apt-get``. On EL each of
those has a different name, and a hard-coded one is not a cosmetic problem: a
cron job written for ``www-data`` on a box whose web server is ``nginx`` runs
as the wrong user, or not at all.

This mirrors ``snpanel_osabi::platform::Platform`` (Rust) and
``installer/platform.sh`` (the installer). The three are kept in step by
``tests/test_platform_matches_installer.py``, which reads the shell table and
compares it with this one, so a value corrected in one place cannot be quietly
left wrong in another.

The PHP *paths* are deliberately absent. On EL the installer presents Debian's
``/etc/php/<version>/fpm`` layout as symlinks into the Remi tree, so the
panel's PHP code needs no branch; see ``setup_php_compat_shim`` in
``installer/install.sh`` for what that shim covers.
"""

from __future__ import annotations

import functools
from pathlib import Path

OS_RELEASE = Path("/etc/os-release")

# Ubuntu's values are the defaults, because an unrecognised system is far more
# likely to be a Debian derivative than an EL one, and because that is what
# every development checkout is.
_DEBIAN = {
    "os_family": "debian",
    "web_user": "www-data",
    "web_group": "www-data",
    "redis_service": "redis-server",
    "cron_service": "cron",
    "ssh_service": "ssh",
    "clamav_service": "clamav-daemon",
    "package_manager": "apt-get",
    "phpmyadmin_root": "/usr/share/phpmyadmin",
}

_RHEL = {
    "os_family": "rhel",
    "web_user": "nginx",
    "web_group": "nginx",
    # EL10 ships no `redis` package at all; Valkey replaced it, wire-compatible
    # on the same port, so REDIS_URL is unchanged and only the unit differs.
    "redis_service": "valkey",
    "cron_service": "crond",
    "ssh_service": "sshd",
    "clamav_service": "clamd@scan",
    "package_manager": "dnf",
    "phpmyadmin_root": "/usr/share/phpMyAdmin",
}


def _parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


@functools.lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    try:
        fields = _parse_os_release(OS_RELEASE.read_text(encoding="utf-8"))
    except OSError:
        return _DEBIAN

    # ID_LIKE catches the rebuilds that do not name themselves: an EL clone
    # that calls itself something new still says `ID_LIKE="rhel centos fedora"`.
    identifiers = {fields.get("ID", "").lower()}
    identifiers.update(fields.get("ID_LIKE", "").lower().split())
    if identifiers & {"rhel", "centos", "fedora", "almalinux", "rocky", "ol"}:
        return _RHEL
    return _DEBIAN


def os_family() -> str:
    """``"debian"`` or ``"rhel"``."""
    return _table()["os_family"]


def web_user() -> str:
    """The account the web server runs as: ``www-data`` or ``nginx``."""
    return _table()["web_user"]


def web_group() -> str:
    return _table()["web_group"]


def redis_service() -> str:
    """The systemd unit for the Redis-compatible server."""
    return _table()["redis_service"]


def cron_service() -> str:
    return _table()["cron_service"]


def ssh_service() -> str:
    return _table()["ssh_service"]


def clamav_service() -> str:
    return _table()["clamav_service"]


def phpmyadmin_root() -> str:
    return _table()["phpmyadmin_root"]


def install_command(*packages: str) -> str:
    """A shell command that installs *packages* non-interactively.

    Used by the on-demand installs the panel offers (ClamAV, a certbot DNS
    plugin). These run through the privileged helper in production; this is the
    fallback for a panel running without it.
    """
    if os_family() == "rhel":
        return "dnf -y install " + " ".join(packages)
    return (
        "export DEBIAN_FRONTEND=noninteractive; apt-get update "
        "&& apt-get install -y " + " ".join(packages)
    )


def upgrade_command() -> str:
    """A shell command that applies pending OS updates."""
    if os_family() == "rhel":
        return "dnf -y upgrade"
    return "apt-get update && apt-get upgrade -y"
