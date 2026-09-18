"""Clearing what deleted websites leave on disk.

The risk here runs one way: this deletes customer certificates and config on
every server that updates, without anyone watching. These tests pin down the
cases where it must refuse.
"""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.entities import User, Website, WebsiteAlias
from app.services import orphans
from app.services.shell import CommandResult

from pathlib import Path

HELPER_SCRIPT = Path(__file__).resolve().parents[3] / "installer" / "files" / "snpanel-helper.sh"


def _db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(bind=engine)()
    db.add(User(id=1, username="admin", email="a@b.c", hashed_password="x", role="admin"))
    db.add(Website(id=1, domain="Live-One.test", owner_id=1, root_path="/home/a/live-one.test"))
    db.add(Website(id=2, domain="live-two.test", owner_id=1, root_path="/home/a/live-two.test"))
    db.add(WebsiteAlias(id=1, website_id=1, domain="shop.live-one.test", mode="alias"))
    db.commit()
    return db


def _capture(monkeypatch, stdout=""):
    calls = []

    def fake_privileged(helper_command, helper_args=None, **kwargs):
        calls.append((helper_command, kwargs.get("input", "")))
        return CommandResult(command=helper_command, returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr(orphans.shell, "privileged", fake_privileged)
    return calls


def test_aliases_count_as_live():
    """A certificate covering only an alias is still in use."""
    names = orphans.live_domains(_db())

    assert "shop.live-one.test" in names
    # Domains are compared lowercase; a stored mixed-case domain must still match.
    assert "live-one.test" in names


def test_cleanup_is_never_asked_to_run_with_an_empty_live_list(monkeypatch):
    """A broken query must not become a request to delete everything."""
    calls = _capture(monkeypatch)
    monkeypatch.setattr(orphans, "live_domains", lambda db: [])

    with pytest.raises(ValueError):
        orphans.clean(_db())
    assert calls == []


def test_the_live_list_is_what_reaches_the_helper(monkeypatch):
    calls = _capture(monkeypatch, stdout="summary\tcerts=0\n")
    orphans.clean(_db())

    verb, payload = calls[0]
    assert verb == "orphans-clean"
    sent = payload.split()
    assert "live-one.test" in sent
    assert "shop.live-one.test" in sent


def test_scan_never_calls_the_clean_verb(monkeypatch):
    calls = _capture(monkeypatch, stdout="cert\tgone.test\nsummary\tcerts=1\n")
    orphans.scan(_db())

    assert calls[0][0] == "orphans-scan"


def test_the_report_names_what_was_removed(monkeypatch):
    _capture(monkeypatch, stdout=(
        "cert\tgone.test\n"
        "vhost-backup\tgone.test.conf.bak\n"
        "summary\tcerts=1 waf-rules=0 vhost-backups=1\n"
        "archive\t/root/snpanel-removed/orphans-20260913-120000\n"
    ))
    outcome = orphans.clean(_db())

    assert outcome["total"] == 2
    assert outcome["summary"]["certs"] == 1
    text = orphans.describe(outcome)
    assert "2 orphaned item(s)" in text
    # Say where the copy went, or "removed" reads as unrecoverable.
    assert "/root/snpanel-removed/orphans-20260913-120000" in text


def test_nothing_orphaned_reads_as_success(monkeypatch):
    _capture(monkeypatch, stdout="summary\tcerts=0 waf-rules=0\n")
    assert "Nothing orphaned" in orphans.describe(orphans.clean(_db()))


def test_helper_refuses_an_empty_live_list_on_its_own():
    """Defence in depth: the helper must not trust the caller to have checked."""
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    body = helper.split("cleanup_orphans()")[1].split("\n}\n")[0]

    assert 'deny "refusing to clean orphans: no live domains were supplied"' in body
    # Every category must be archived before removal.
    assert "ORPHAN_ARCHIVE_ROOT" in helper
    assert "orphan_cert_covers_live" in body
    # The panel's own certificate is added to the live list, never deleted.
    assert "PANEL_DOMAIN" in body
    for verb in ("orphans-scan)", "orphans-clean)"):
        assert verb in helper


def test_helper_keeps_a_certificate_that_still_covers_a_live_name():
    """A lineage named for a dead site can carry a live SAN."""
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    body = helper.split("orphan_cert_covers_live()")[1].split("\n}\n")[0]

    assert "subjectAltName" in body
    assert "grep -qxF" in body
