"""Firewall service.

IP blocking runs on iptables + ipset. The snpanel-helper owns the rule file and
the kernel state; this module only validates input and renders what the helper
reports.
"""

import ipaddress
import json
import re
from typing import Optional

from app.core.config import settings
from app.services.shell import CommandResult, shell


PORT_RE = re.compile(r"^[0-9]{1,5}$")
PROTOCOLS = {"tcp", "udp"}
DEFAULT_PROTECTED_PORTS = {22, 80, 443, 465, 587, 2222}
PANEL_ZONE = "PanelZone"
USER_ZONE = "UserZone"


def _validate_protocol(protocol: str) -> str:
    value = (protocol or "tcp").strip().lower()
    if value not in PROTOCOLS:
        raise ValueError("Protocol must be tcp or udp")
    return value


def _validate_port(port: str | int) -> str:
    value = str(port).strip()
    if not PORT_RE.match(value):
        raise ValueError("Port must be a number from 1 to 65535")
    number = int(value)
    if number < 1 or number > 65535:
        raise ValueError("Port must be a number from 1 to 65535")
    return value


def _validate_network(network: str) -> str:
    value = (network or "").strip()
    try:
        parsed = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError("IP must be a valid IPv4/IPv6 address or CIDR network") from exc
    return str(parsed)


def protected_ports() -> set[int]:
    ports = set(DEFAULT_PROTECTED_PORTS)
    try:
        ports.add(int(settings.panel_port or 2222))
    except (TypeError, ValueError):
        pass
    return ports


def status() -> CommandResult:
    return shell.privileged(
        "firewall-status",
        check=False,
        fallback=["bash", "-lc", "echo 'Status: unknown'; echo 'Engine: iptables + ipset'"],
    )


def rules() -> list[dict]:
    """Return the helper's structured rule list.

    Falls back to an empty list when the helper is unavailable (dev mode) or
    emits something unparsable, so the status page never breaks on a bad line.
    """
    result = shell.privileged(
        "firewall-list",
        check=False,
        fallback=["bash", "-lc", 'echo "{\\"rules\\": []}"'],
    )
    if result.returncode != 0:
        return []
    return parse_rules(result.stdout)


def parse_rules(output: str) -> list[dict]:
    try:
        data = json.loads(output or "{}")
    except (ValueError, TypeError):
        return []
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("rules") or []
    else:
        return []
    return [item for item in items if isinstance(item, dict)]


def is_protected_rule(rule: dict) -> bool:
    if rule.get("protected"):
        return True
    if (rule.get("zone") or "") == PANEL_ZONE:
        return True
    if (rule.get("action") or "").upper() != "ALLOW":
        return False
    if rule.get("ip"):
        return False
    try:
        return int(rule.get("port") or 0) in protected_ports()
    except (TypeError, ValueError):
        return False


def enable() -> CommandResult:
    return shell.privileged("firewall-enable", fallback=["true"])


def disable() -> CommandResult:
    return shell.privileged("firewall-disable", fallback=["true"])


def reload() -> CommandResult:
    return shell.privileged("firewall-reload", fallback=["true"])


def allow_port(port: str | int, protocol: str = "tcp") -> CommandResult:
    clean_port = _validate_port(port)
    clean_protocol = _validate_protocol(protocol)
    return shell.privileged(
        "firewall-allow-port",
        helper_args=[clean_port, clean_protocol],
        fallback=["true"],
    )


def allow_ip(network: str, port: Optional[str | int] = None, protocol: str = "tcp") -> CommandResult:
    clean_network = _validate_network(network)
    if not port:
        return shell.privileged(
            "firewall-allow-ip",
            helper_args=[clean_network],
            fallback=["true"],
        )
    clean_port = _validate_port(port)
    clean_protocol = _validate_protocol(protocol)
    return shell.privileged(
        "firewall-allow-ip",
        helper_args=[clean_network, clean_port, clean_protocol],
        fallback=["true"],
    )


def block_ip(network: str, port: Optional[str | int] = None, protocol: str = "tcp") -> CommandResult:
    clean_network = _validate_network(network)
    if not port:
        return shell.privileged(
            "firewall-deny-ip",
            helper_args=[clean_network],
            fallback=["true"],
        )
    clean_port = _validate_port(port)
    clean_protocol = _validate_protocol(protocol)
    return shell.privileged(
        "firewall-deny-ip",
        helper_args=[clean_network, clean_port, clean_protocol],
        fallback=["true"],
    )


def delete_rule(number: int) -> CommandResult:
    if number < 1:
        raise ValueError("Rule number must be greater than 0")
    selected = next((rule for rule in rules() if rule.get("id") == number), None)
    if selected is None:
        raise ValueError(f"Rule #{number} was not found")
    if is_protected_rule(selected):
        raise ValueError("Default panel, mail, web, and SSH firewall rules cannot be deleted")
    return shell.privileged(
        "firewall-delete",
        helper_args=[str(number)],
        fallback=["true"],
    )


def blocklists() -> CommandResult:
    return shell.privileged(
        "firewall-blocklist-status",
        check=False,
        fallback=["bash", "-lc", "echo 'URLs:'; echo '  (none)'; echo; echo 'Engine:'; echo '  iptables + ipset'"],
    )


def add_blocklist_url(url: str) -> CommandResult:
    return shell.privileged(
        "firewall-blocklist-add",
        helper_args=[url],
        check=False,
        fallback=["bash", "-lc", "echo URL added"],
    )


def delete_blocklist_url(url: str) -> CommandResult:
    return shell.privileged(
        "firewall-blocklist-delete",
        helper_args=[url],
        check=False,
        fallback=["bash", "-lc", "echo URL removed"],
    )


def update_blocklists() -> CommandResult:
    return shell.privileged(
        "firewall-blocklist-run",
        check=False,
        fallback=["bash", "-lc", "echo blocklist update skipped"],
    )
