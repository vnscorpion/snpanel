"""Terminal entitlement and sandboxing — issue #119 (SNPANEL-2026-001/002)."""

import pytest
from fastapi import HTTPException

from app.api import terminal as terminal_api


class _User:
    def __init__(self, role="end_user", terminal_enabled=False, user_id=2):
        self.role = role
        self.terminal_enabled = terminal_enabled
        self.id = user_id


def test_an_end_user_without_the_entitlement_is_refused():
    """UserPackage.terminal_enabled existed but nothing read it.

    Both terminal doors checked website ownership only, so any end user could
    open a shell on their own site regardless of the package they were paying
    for. Hiding the button in the frontend is not access control - curl with a
    valid session cookie reached the same endpoint.
    """
    assert terminal_api.may_use_terminal(_User(terminal_enabled=False)) is False


def test_an_end_user_with_the_entitlement_is_allowed():
    assert terminal_api.may_use_terminal(_User(terminal_enabled=True)) is True


def test_an_admin_always_may():
    # Admins administer the server; the entitlement is a per-package sales
    # boundary, not a security boundary against the operator.
    assert terminal_api.may_use_terminal(_User(role="admin", terminal_enabled=False)) is True


def test_the_rest_endpoint_refuses_before_touching_the_site():
    """The check has to live in get_user_website, which /exec goes through.

    Driven with asyncio.run rather than pytest-asyncio: the suite has no async
    plugin and one coroutine is not worth adding a dependency for.
    """
    import asyncio

    class _Website:
        id = 1
        owner_id = 2
        linux_user = "client"

    class _Query:
        def filter(self, *_a):
            return self

        def first(self):
            return _Website()

    class _DB:
        def query(self, *_a):
            return _Query()

    with pytest.raises(HTTPException) as exc:
        asyncio.run(terminal_api.get_user_website(1, _DB(), _User(terminal_enabled=False)))

    assert exc.value.status_code == 403
    assert "not enabled" in str(exc.value.detail).lower()


def test_assigning_a_package_copies_its_terminal_flag():
    """The flag is copied onto the user, the way website_limit already is, so
    enforcement reads one column and a user without a package still resolves."""
    from app.api.users import _apply_package_limits

    class _Package:
        id = 1
        website_limit = 10
        storage_limit_mb = 2048
        terminal_enabled = True

    class _Target:
        package_id = None
        website_limit = 5
        storage_limit_mb = 1024
        terminal_enabled = False

    user = _Target()
    _apply_package_limits(user, _Package())

    assert user.terminal_enabled is True


def test_php_run_through_the_terminal_is_confined_to_the_tenant():
    """SNPANEL-2026-002: PHP CLI from the terminal had no open_basedir at all.

    The FPM pool for the same site has always had one; the terminal is a
    separate pipeline and was missed. Because it runs as the site user and site
    files are world-readable by design, `php -r "readfile('/home/other/...')"`
    read another customer's files. Confirmed against a running server before
    the fix - it printed /etc/passwd.

    Asserted against the shipped helper rather than a copy, so the guarantee
    cannot drift away from what actually runs.
    """
    from pathlib import Path

    helper = Path(__file__).resolve().parents[3] / "installer" / "files" / "snpanel-helper.sh"
    script = helper.read_text(encoding="utf-8")

    start = script.index("  terminal-exec)")
    end = script.index("  nginx-upgrade-map-ensure)", start)
    block = script[start:end]

    # The value is built once from the tenant's home, not a single site root:
    # a customer with several sites still has to work across their own.
    assert 'terminal_open_basedir="$HOME_ROOT/$user:' in block

    # Every PHP entry point uses it. node/npm/npx/yarn/git are deliberately
    # absent: open_basedir is a PHP mechanism and does nothing for them.
    for line in block.splitlines():
        if '"$php_bin"' in line and line.strip().startswith("exec "):
            assert "open_basedir" in line, f"unconfined PHP invocation: {line.strip()[:90]}"
