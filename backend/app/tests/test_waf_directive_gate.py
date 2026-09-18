"""A vhost must never name a directive nginx does not have.

`modsecurity on;` without the module loaded is not ignored: nginx rejects the
whole configuration with `unknown directive "modsecurity"`. The blast radius is
the machine, not the site - the next reload anywhere fails, so every site goes
with it.

This was found on AlmaLinux 10, which packages no nginx ModSecurity module at
all, but it was never an EL-only bug: install.sh prints "WARNING: WAF engine
installation failed; continuing without ModSecurity" and carries on, so a
Ubuntu box whose WAF step failed had the same loaded gun.
"""

import pytest

from app.services import nginx


@pytest.fixture(autouse=True)
def _clear_cache():
    nginx.waf_engine_available.cache_clear()
    yield
    nginx.waf_engine_available.cache_clear()


def render(monkeypatch, *, engine: bool) -> str:
    monkeypatch.setattr(nginx, "waf_engine_available", lambda: engine)
    return nginx.render_vhost(
        "example.com",
        "/home/site/example.com",
        app_type="php",
        php_version="8.4",
        waf_enabled=True,
    )


def test_no_modsecurity_directives_without_the_module(monkeypatch):
    body = render(monkeypatch, engine=False)
    assert "modsecurity" not in body
    assert "SNPANEL WAF BEGIN" not in body


def test_the_directives_are_written_when_the_module_is_loaded(monkeypatch):
    body = render(monkeypatch, engine=True)
    assert "modsecurity on;" in body
    assert "modsecurity_rules_file" in body


def test_the_site_is_otherwise_identical(monkeypatch):
    # Only the WAF block differs. A missing engine must not quietly change the
    # PHP socket, the document root or anything else the site depends on.
    without = render(monkeypatch, engine=False)
    with_engine = render(monkeypatch, engine=True)
    stripped = "\n".join(
        line for line in with_engine.splitlines()
        if "modsecurity" not in line and "SNPANEL WAF" not in line
    )
    assert stripped.split() == without.split()


def test_the_probe_survives_nginx_being_absent(monkeypatch):
    # A development checkout has no nginx binary. The answer there is "no
    # engine", not a traceback on every vhost write.
    monkeypatch.setattr(nginx.Path, "exists", lambda self: False)

    def no_such_binary(*args, **kwargs):
        raise FileNotFoundError("nginx")

    monkeypatch.setattr(nginx.subprocess, "run", no_such_binary)
    nginx.waf_engine_available.cache_clear()
    assert nginx.waf_engine_available() is False


def test_the_probe_reads_stderr(monkeypatch):
    # `nginx -V` writes its build configuration to stderr, not stdout. Reading
    # only stdout would report every machine as having no engine.
    monkeypatch.setattr(nginx.Path, "exists", lambda self: False)

    class Probe:
        stdout = ""
        stderr = "configure arguments: --add-dynamic-module=/build/ModSecurity-nginx"

    monkeypatch.setattr(nginx.subprocess, "run", lambda *a, **k: Probe())
    nginx.waf_engine_available.cache_clear()
    assert nginx.waf_engine_available() is True
