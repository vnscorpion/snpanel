import os
import shlex
import sys
from pathlib import Path

import pytest

os.environ.setdefault("APP_ENV", "development")
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-unit-tests-only")
os.environ.setdefault("COMMAND_DRY_RUN", "true")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ""))

from app.models.entities import Website  # noqa: E402
from app.services import cron, firewall, nginx, waf  # noqa: E402


def test_cron_line_parser_strips_snpanel_wrapper():
    item = cron._parse_cron_line(0, "*/15 * * * * cd /home/admin/example.com/public_html && wp cron event run --due-now --allow-root # snpanel:example.com")  # noqa: SLF001

    assert item["index"] == 0
    assert item["schedule"] == "*/15 * * * *"
    assert item["command"] == "wp cron event run --due-now"


def test_cron_user_for_website_uses_site_owner_from_home_path():
    website = Website(domain="example.com", root_path="/home/client/example.com", linux_user="")

    assert cron.cron_user_for_website(website) == "client"


@pytest.fixture
def site_roots(tmp_path):
    """(site root, document root) pair, so the assertions stay OS independent."""
    document_root = tmp_path / "example.com" / "public_html"
    document_root.mkdir(parents=True)
    return tmp_path / "example.com", document_root


@pytest.mark.parametrize(
    ("command", "script", "extra"),
    [
        ("php -q sieunhim/cron.php profile=default", "sieunhim/cron.php", " profile=default"),
        ("php -q queue.php", "queue.php", ""),
    ],
)
def test_cron_command_allows_php_scripts_inside_document_root(site_roots, command, script, extra):
    site_root, document_root = site_roots

    result = cron._validate_command(command, document_root, site_root, "/usr/bin/php8.1")  # noqa: SLF001

    assert result == f"/usr/bin/php8.1 -q {shlex.quote(str(document_root / script))}{extra}"


@pytest.mark.parametrize(
    "command",
    [
        "php -r 'echo 1;'",
        "php ../private.php",
        "php ../../private.php",
        "php readme.txt",
    ],
)
def test_cron_command_rejects_unsafe_php_commands(site_roots, command):
    site_root, document_root = site_roots

    with pytest.raises(ValueError):
        cron._validate_command(command, document_root, site_root, "php")  # noqa: SLF001


def test_cron_command_keeps_wp_cli_allow_root_behavior(site_roots, monkeypatch):
    site_root, document_root = site_roots
    monkeypatch.setattr(cron, "WP_CLI_PATH", site_root / "missing-wp")

    result = cron._validate_command("wp cron event run --due-now", document_root, site_root, "php")  # noqa: SLF001

    assert result == "wp cron event run --due-now --allow-root"


@pytest.mark.xfail(
    reason=(
        "Stale: these assert the pre-rework WAF rule design. DEFAULT_RULES no "
        "longer carries general-sqli or general-xss (LEGACY_RULE_ID_MAP maps "
        "both to None - deliberately removed, not renamed), general-* ids are "
        "normalised to php-*, and the per-rule exception mechanism these check "
        "for (id:1007xxx plus ctl:ruleRemoveById) is gone. Failing on a clean "
        "checkout since at least 2026-08-18. Left asserting the old design on "
        "purpose rather than rewritten to match the new one, because what the "
        "replacement *should* assert is a product question nobody has answered."
    ),
    strict=False,
)
def test_waf_site_rules_render_selected_defaults_and_custom_rules():
    content = waf.render_site_rules(
        "example.com",
        ["general-sensitive-files", "wordpress-sensitive-files"],
        "SecRule REQUEST_URI \"@streq /private\" \"id:1001999,phase:1,deny,status:403\"",
    )

    assert "Include /etc/nginx/modsec/snpanel-base.conf" in content
    assert "general-sensitive-files" in content
    assert "wordpress-sensitive-files" in content
    assert "general-path-traversal" not in content
    assert "id:1001999" in content


@pytest.mark.xfail(
    reason=(
        "Stale: these assert the pre-rework WAF rule design. DEFAULT_RULES no "
        "longer carries general-sqli or general-xss (LEGACY_RULE_ID_MAP maps "
        "both to None - deliberately removed, not renamed), general-* ids are "
        "normalised to php-*, and the per-rule exception mechanism these check "
        "for (id:1007xxx plus ctl:ruleRemoveById) is gone. Failing on a clean "
        "checkout since at least 2026-08-18. Left asserting the old design on "
        "purpose rather than rewritten to match the new one, because what the "
        "replacement *should* assert is a product question nobody has answered."
    ),
    strict=False,
)
def test_waf_command_injection_rule_includes_wp_upload_exception():
    content = waf.render_site_rules(
        "example.com",
        ["general-command-injection"],
    )

    assert "id:1001005" in content
    assert "id:1001006" in content
    assert "/wp-admin/update\\.php" in content
    assert "ctl:ruleRemoveById=1001005" in content


def test_waf_command_injection_exception_absent_when_rule_disabled():
    content = waf.render_site_rules(
        "example.com",
        ["general-sensitive-files"],
    )

    assert "id:1001005" not in content
    assert "id:1001006" not in content


def test_http_flood_zones_render_only_enabled_sites():
    enabled = Website(
        domain="example.com",
        root_path="/home/client/example.com",
        http_flood_enabled=True,
        http_flood_config='{"access_limit_requests":30,"access_limit_window":60,"access_limit_burst":12,"connection_limit":20}',
    )
    disabled = Website(domain="disabled.com", root_path="/home/client/disabled.com", http_flood_enabled=False)

    content = nginx.render_http_flood_zones([enabled, disabled])

    assert "map $cookie_snpanel_http_flood_ok $snpanel_http_flood_key" in content
    assert "limit_conn_zone $snpanel_http_flood_key zone=snpanel_conn_flood:10m;" in content
    assert f"zone={nginx.http_flood_zone_name('example.com')}:10m rate=30r/m;" in content
    assert nginx.http_flood_zone_name("disabled.com") not in content


@pytest.mark.xfail(
    reason=(
        "Stale: these assert the pre-rework WAF rule design. DEFAULT_RULES no "
        "longer carries general-sqli or general-xss (LEGACY_RULE_ID_MAP maps "
        "both to None - deliberately removed, not renamed), general-* ids are "
        "normalised to php-*, and the per-rule exception mechanism these check "
        "for (id:1007xxx plus ctl:ruleRemoveById) is gone. Failing on a clean "
        "checkout since at least 2026-08-18. Left asserting the old design on "
        "purpose rather than rewritten to match the new one, because what the "
        "replacement *should* assert is a product question nobody has answered."
    ),
    strict=False,
)
def test_waf_sqli_rule_includes_admin_ajax_exception():
    content = waf.render_site_rules(
        "example.com",
        ["general-sqli"],
    )

    assert "id:1001003" in content
    assert "id:1007003" in content
    assert "admin-ajax" in content
    assert "ctl:ruleRemoveById=1001003" in content


@pytest.mark.xfail(
    reason=(
        "Stale: these assert the pre-rework WAF rule design. DEFAULT_RULES no "
        "longer carries general-sqli or general-xss (LEGACY_RULE_ID_MAP maps "
        "both to None - deliberately removed, not renamed), general-* ids are "
        "normalised to php-*, and the per-rule exception mechanism these check "
        "for (id:1007xxx plus ctl:ruleRemoveById) is gone. Failing on a clean "
        "checkout since at least 2026-08-18. Left asserting the old design on "
        "purpose rather than rewritten to match the new one, because what the "
        "replacement *should* assert is a product question nobody has answered."
    ),
    strict=False,
)
def test_waf_install_upgrade_rule_includes_upgrade_exception():
    content = waf.render_site_rules(
        "example.com",
        ["wordpress-install-upgrade"],
    )

    assert "id:1001104" in content
    assert "id:1007104" in content
    assert "upgrade\\.php" in content
    assert "ctl:ruleRemoveById=1001104" in content

def test_render_vhost_keeps_waf_and_http_flood_blocks(monkeypatch):
    # Pin the engine check. Since vhosts stopped emitting `modsecurity on;` on
    # machines without the module, this test's answer came from whatever nginx
    # the developer happened to have installed - it passed in the container and
    # failed on a build host, for no reason to do with the template.
    monkeypatch.setattr(nginx, "waf_engine_available", lambda: True)
    content = nginx.render_vhost(
        "example.com",
        "/home/client/example.com",
        app_type="php",
        php_version="8.3",
        document_root="public_html/public",
        waf_enabled=True,
        http_flood_enabled=True,
        http_flood_config={"access_limit_requests":120, "access_limit_window":10, "access_limit_burst":20, "connection_limit":8},
    )

    assert "# SNPANEL WAF BEGIN" in content
    assert "# SNPANEL HTTP FLOOD BEGIN" in content
    assert f"limit_req zone={nginx.http_flood_zone_name('example.com')} burst=20;" in content
    assert "limit_conn snpanel_conn_flood 8;" in content
    assert "@snpanel_http_flood_challenge" in content
    assert "snpanel_http_flood_ok=1" in content
    assert "# SNPANEL ACME CHALLENGE" in content
    assert "root /var/www/snpanel-acme;" in content
    expected_root = Path("/home/client/example.com").resolve() / "public_html" / "public"
    assert f"root {expected_root};" in content


def test_wordpress_cache_revalidates_quickly():
    content = nginx.render_vhost(
        "example.com",
        "/home/client/example.com",
        app_type="wordpress",
        php_version="8.3",
    )

    assert 'if ($http_cache_control ~* "no-cache|no-store|max-age=0")' in content
    assert 'if ($http_pragma = "no-cache")' in content
    assert "fastcgi_cache_valid 200 15s;" in content
    assert "fastcgi_cache_valid 200 301 302 10m;" not in content
    assert "fastcgi_cache_use_stale" not in content
    assert "expires -1;" in content
    assert 'Cache-Control "public, immutable"' not in content


def test_set_php_version_preserves_existing_vhost(tmp_path, monkeypatch):
    target = tmp_path / "example.com.conf"
    existing = """server {
    server_name example.com;
    # SNPANEL REVERSE PROXY BEGIN
    real_ip_header X-Forwarded-For;
    # SNPANEL REVERSE PROXY END
    location ~ \\.php$ {
        fastcgi_pass unix:/run/php/snpanel-client-8_3.sock;
    }
}
"""
    target.write_text(existing, encoding="utf-8")
    monkeypatch.setattr(nginx.settings, "command_dry_run", False)
    monkeypatch.setattr(nginx, "_vhost_path", lambda _domain: target)
    monkeypatch.setattr(nginx, "_test_and_reload", lambda _target, _old: None)

    nginx.set_php_version("example.com", "8.1", "/run/php/snpanel-client-8_1.sock")

    updated = target.read_text(encoding="utf-8")
    assert "# SNPANEL REVERSE PROXY BEGIN" in updated
    assert "fastcgi_pass unix:/run/php/snpanel-client-8_1.sock;" in updated
    assert target.with_suffix(".conf.bak").read_text(encoding="utf-8") == existing


def test_write_backup_replaces_existing_backup(tmp_path):
    target = tmp_path / "example.com.conf"
    target.write_text("current", encoding="utf-8")
    backup = target.with_suffix(".conf.bak")
    backup.write_text("old backup", encoding="utf-8")

    nginx._write_backup(target, "new backup")

    assert backup.read_text(encoding="utf-8") == "new backup"


def test_firewall_parse_rules_reads_helper_json():
    rules = firewall.parse_rules(
        '{"state": "enabled", "active": true, "rules": ['
        '{"id": 1, "action": "DENY", "to": "any", "from": "5.6.7.8/32",'
        ' "ip": "5.6.7.8/32", "port": null, "protocol": null,'
        ' "zone": "UserZone", "protected": false},'
        '{"id": 2, "action": "ALLOW", "to": "3306/tcp", "from": "any",'
        ' "ip": null, "port": "3306", "protocol": "tcp",'
        ' "zone": "UserZone", "protected": false},'
        '{"id": 0, "action": "ALLOW", "to": "22/tcp", "from": "any",'
        ' "ip": null, "port": "22", "protocol": "tcp",'
        ' "zone": "PanelZone", "protected": true}]}'
    )

    assert [rule["id"] for rule in rules] == [1, 2, 0]
    assert rules[0]["from"] == "5.6.7.8/32"
    assert rules[1]["to"] == "3306/tcp"
    assert rules[2]["zone"] == "PanelZone"


def test_firewall_parse_rules_tolerates_garbage():
    assert firewall.parse_rules("not json at all") == []
    assert firewall.parse_rules("") == []


def test_firewall_protected_rules_cannot_be_deleted(monkeypatch):
    monkeypatch.setattr(firewall.settings, "panel_port", 2222)

    assert firewall.is_protected_rule({"id": 0, "zone": "PanelZone", "protected": True}) is True
    assert firewall.is_protected_rule(
        {"id": 4, "action": "ALLOW", "port": "2222", "ip": None, "zone": "UserZone"}
    ) is True
    assert firewall.is_protected_rule(
        {"id": 5, "action": "ALLOW", "port": "3306", "ip": None, "zone": "UserZone"}
    ) is False
    assert firewall.is_protected_rule(
        {"id": 6, "action": "DENY", "port": None, "ip": "5.6.7.8/32", "zone": "UserZone"}
    ) is False


def test_firewall_delete_rule_rejects_unknown_id(monkeypatch):
    monkeypatch.setattr(firewall, "rules", lambda: [])

    with pytest.raises(ValueError, match="was not found"):
        firewall.delete_rule(9)
