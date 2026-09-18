"""Turning the OWASP rule set on needs an engine to run it in.

Reported from the panel on AlmaLinux 10:

    Error: Unable to find a match: modsecurity-crs
    snpanel-helper: could not install modsecurity-crs

That is a true sentence about dnf and a useless one about the server. EL10
packages neither the nginx ModSecurity module nor the rule set, and without the
module there is nothing to load the rules into even if they were installed.

The condition these tests pin is the module's presence, not the distribution: a
Debian machine whose WAF package failed to install is in the same position, and
`install.sh` treats that failure as a warning and carries on.
"""

from pathlib import Path

import pytest

from app.services import nginx, waf

HELPER_SCRIPT = Path(__file__).resolve().parents[3] / "installer" / "files" / "snpanel-helper.sh"


@pytest.fixture(autouse=True)
def _clear_cache():
    nginx.waf_engine_available.cache_clear()
    yield
    nginx.waf_engine_available.cache_clear()


@pytest.mark.parametrize("mode", ["detect", "block"])
def test_turning_crs_on_without_the_module_is_refused(monkeypatch, mode):
    monkeypatch.setattr(nginx, "waf_engine_available", lambda: False)
    with pytest.raises(ValueError) as caught:
        waf.set_crs_mode(mode, [])
    message = str(caught.value)
    # The message has to name the cause. "Unable to find a match" did not.
    assert "ModSecurity" in message
    assert "not installed" in message


def test_turning_crs_off_always_works(monkeypatch):
    """The way out of a bad state must not be gated on the same check.

    A server that somehow has CRS recorded as on, with no engine, still has to
    be able to turn it off.
    """
    monkeypatch.setattr(nginx, "waf_engine_available", lambda: False)
    monkeypatch.setattr(waf.shell, "privileged", lambda *a, **k: waf.CommandResult(
        command="waf-crs-mode off", returncode=0, stdout="OWASP CRS disabled", stderr="",
    ))
    monkeypatch.setattr(waf, "active_crs_mode", lambda: "off")
    # No ValueError - whatever else happens downstream, the refusal is not here.
    try:
        waf.set_crs_mode("off", [])
    except ValueError as exc:  # pragma: no cover - the assertion is the point
        pytest.fail(f"turning CRS off was refused: {exc}")


def test_the_status_says_whether_an_engine_exists(monkeypatch):
    monkeypatch.setattr(nginx, "waf_engine_available", lambda: False)
    monkeypatch.setattr(waf.shell, "privileged", lambda *a, **k: waf.CommandResult(
        command="waf-crs-status", returncode=0,
        stdout="mode=off\ninstalled=no\nconf=no\nrule_files=0\nsites_including=0",
        stderr="",
    ))
    assert waf.crs_status()["engine_available"] is False

    # No cache_clear here: monkeypatch replaced the cached function outright,
    # so the second setattr is the whole change.
    monkeypatch.setattr(nginx, "waf_engine_available", lambda: True)
    assert waf.crs_status()["engine_available"] is True


def test_the_helper_checks_the_module_before_installing_the_rules():
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    body = helper[helper.index("install_waf_crs() {"):]
    body = body[: body.index("\n}\n")]
    assert "waf_engine_present" in body, (
        "install_waf_crs reaches the package manager without checking for the "
        "module; dnf's 'no match' is what the user ends up reading"
    )


def test_the_helper_refuses_to_switch_crs_on_without_the_module():
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    body = helper[helper.index("set_waf_crs_mode() {"):]
    body = body[: body.index("\n}\n")]
    assert "waf_engine_present" in body
    # ...but only for the on states.
    assert '"$mode" != "off"' in body


def test_the_helper_asks_nginx_rather_than_the_distribution():
    """The check must not be `if EL then refuse`.

    Debian's WAF package can fail to install too - install.sh prints a warning
    and continues - and that machine needs the same answer.
    """
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    body = helper[helper.index("waf_engine_present() {"):]
    body = body[: body.index("\n}\n")]
    assert "nginx -V" in body
    assert "OS_FAMILY" not in body

# --- a module built from source ---------------------------------------------
#
# AlmaLinux 10 packages no ModSecurity module, so the only way to have one is to
# build it and load it with a `load_module` directive. Such a module appears in
# neither of the first two checks: `nginx -V` reports compile-time arguments,
# not what nginx has loaded, and the EL layout has no modules-enabled directory.
#
# `nginx -T` would report it, and was tried - but the panel runs as the snpanel
# user and nginx -T exits before printing anything when it cannot open the
# error log, so that branch returned False exactly where it was needed. The
# configuration files are read directly instead.


def _no_packaged_module(monkeypatch):
    monkeypatch.setattr(nginx, "MODSECURITY_MODULE_CONF", "/nonexistent/modsec.conf")

    class Result:
        stdout = ""
        stderr = "nginx version: nginx/1.26.3\nconfigure arguments: --with-compat"

    monkeypatch.setattr(nginx.subprocess, "run", lambda *a, **k: Result())


def test_a_dynamically_loaded_module_counts_as_an_engine(monkeypatch, tmp_path):
    _no_packaged_module(monkeypatch)
    conf = tmp_path / "50-mod-http-modsecurity.conf"
    conf.write_text(
        'load_module "/usr/lib64/nginx/modules/ngx_http_modsecurity_module.so";\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(nginx, "MODULE_CONFIG_PATTERNS", (str(tmp_path / "*.conf"),))
    nginx.waf_engine_available.cache_clear()
    assert nginx.waf_engine_available() is True


def test_a_commented_out_load_module_does_not_count(monkeypatch, tmp_path):
    _no_packaged_module(monkeypatch)
    conf = tmp_path / "50-mod-http-modsecurity.conf"
    conf.write_text('# load_module "ngx_http_modsecurity_module.so";\n', encoding="utf-8")
    monkeypatch.setattr(nginx, "MODULE_CONFIG_PATTERNS", (str(tmp_path / "*.conf"),))
    nginx.waf_engine_available.cache_clear()
    assert nginx.waf_engine_available() is False


def test_an_unrelated_module_does_not_count(monkeypatch, tmp_path):
    _no_packaged_module(monkeypatch)
    (tmp_path / "10-brotli.conf").write_text(
        'load_module "/usr/lib64/nginx/modules/ngx_http_brotli_filter_module.so";\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(nginx, "MODULE_CONFIG_PATTERNS", (str(tmp_path / "*.conf"),))
    nginx.waf_engine_available.cache_clear()
    assert nginx.waf_engine_available() is False


def test_an_unreadable_file_is_skipped_rather_than_raising(monkeypatch, tmp_path):
    """A directory or a permission error must not take the panel down.

    This runs on every vhost write, so an unreadable file has to be a shrug.
    """
    _no_packaged_module(monkeypatch)
    monkeypatch.setattr(nginx, "MODULE_CONFIG_PATTERNS", (str(tmp_path / "*"),))
    (tmp_path / "adirectory.conf").mkdir()
    nginx.waf_engine_available.cache_clear()
    assert nginx.waf_engine_available() is False


def test_the_helper_reads_the_same_files_the_panel_does():
    """The two implementations must not be able to disagree.

    The helper runs as root and could use `nginx -T`; it deliberately does not,
    because then one of them could say yes while the other said no.
    """
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    body = helper[helper.index("waf_engine_present() {"):]
    body = body[: body.index("\n}\n")]
    # Comments are stripped before asserting what the code does *not* contain.
    # Twice now an assertion of that shape has failed on the comment explaining
    # the very thing it was outlawing, which is worth doing once and not again.
    code = "\n".join(
        line for line in body.splitlines() if not line.strip().startswith("#")
    )
    assert "nginx -T" not in code, "the helper cannot use nginx -T; the panel cannot"
    for path in ("/etc/nginx/nginx.conf", "/usr/share/nginx/modules/*.conf"):
        assert path in code, f"the helper does not look at {path}"
    # *.conf globs, not directories. A recursive search reads files nginx never
    # includes - including the one the module guard renames aside when it
    # disables a module it cannot load, which made a disabled module report as
    # present while the panel, which globs *.conf, correctly said it was gone.
    assert "grep -rq" not in code and "grep -r " not in code, (
        "a recursive search sees files nginx does not include"
    )
    # Still no pipes into grep -q, for the reason the other test gives.
    assert not [line for line in code.splitlines() if "| grep -q" in line]


def test_the_panel_looks_where_load_module_is_legal():
    """Both layouts, because the panel supports both."""
    assert "/etc/nginx/nginx.conf" in nginx.MODULE_CONFIG_PATTERNS
    assert any("modules-enabled" in p for p in nginx.MODULE_CONFIG_PATTERNS)
    assert any("/usr/share/nginx/modules" in p for p in nginx.MODULE_CONFIG_PATTERNS)

def test_a_module_disabled_by_the_guard_is_not_reported_as_present(monkeypatch, tmp_path):
    """The guard renames rather than deletes, so the file is still on disk.

    nginx includes `*.conf` and nothing else, so a renamed file is not loaded -
    and anything that reports it as loaded is telling the panel there is a WAF
    where there is none.
    """
    _no_packaged_module(monkeypatch)
    (tmp_path / "50-mod-http-modsecurity.conf.disabled-by-snpanel").write_text(
        'load_module "/usr/lib64/nginx/modules/ngx_http_modsecurity_module.so";\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(nginx, "MODULE_CONFIG_PATTERNS", (str(tmp_path / "*.conf"),))
    nginx.waf_engine_available.cache_clear()
    assert nginx.waf_engine_available() is False
