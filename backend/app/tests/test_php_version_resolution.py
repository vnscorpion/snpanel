"""The panel must act on a PHP version this machine actually has.

Reported from the panel on Ubuntu 26.04, from Auto tune:

    snpanel-helper: PHP FPM config directory not found: /etc/php/8.4/fpm/conf.d

26.04 carries PHP 8.5 and nothing else. Four separate places carried "8.4" as a
constant - two query defaults, `settings.default_php_version`, and the
interface's initial state - and the installer, the one thing that knows which
version it just installed, recorded it nowhere.

`SUPPORTED_PHP_VERSIONS` is the set the panel knows how to tune, not the set
the machine has, so validating against it let an absent-but-supported version
straight through to the privileged helper.
"""

from pathlib import Path

import pytest

from app.services import php_tune, system

REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def fake_php_tree(tmp_path, monkeypatch):
    """A machine with the versions named, and no others."""

    def build(*versions: str):
        root = tmp_path / "php"
        for version in versions:
            (root / version / "fpm").mkdir(parents=True)
            (root / version / "fpm" / "php-fpm.conf").write_text("", encoding="utf-8")
        monkeypatch.setattr(system, "PHP_ETC_DIR", root)
        return root

    return build


def test_installed_versions_are_read_from_disk(fake_php_tree):
    fake_php_tree("8.3", "8.5")
    assert system.installed_php_versions() == ["8.3", "8.5"]


def test_a_directory_without_php_fpm_conf_does_not_count(fake_php_tree, tmp_path):
    root = fake_php_tree("8.5")
    (root / "8.4" / "fpm").mkdir(parents=True)  # no php-fpm.conf: not installed
    assert system.installed_php_versions() == ["8.5"]


def test_the_default_is_the_newest_installed_when_the_preference_is_absent(
    fake_php_tree, monkeypatch
):
    fake_php_tree("8.3", "8.5")
    monkeypatch.setattr(system.settings, "default_php_version", "8.4")
    # 8.4 is configured and not installed - which is exactly the Ubuntu 26.04
    # case, where the constant was wrong on every machine.
    assert system.default_php_version() == "8.5"


def test_the_configured_preference_wins_when_it_is_installed(
    fake_php_tree, monkeypatch
):
    fake_php_tree("8.3", "8.4", "8.5")
    monkeypatch.setattr(system.settings, "default_php_version", "8.4")
    # An operator running several versions and naming one means it.
    assert system.default_php_version() == "8.4"


def test_resolve_prefers_what_was_asked_for_when_it_exists(fake_php_tree, monkeypatch):
    fake_php_tree("8.3", "8.5")
    monkeypatch.setattr(system.settings, "default_php_version", "8.5")
    assert php_tune.resolve_version("8.3") == "8.3"


def test_resolve_falls_back_rather_than_handing_over_a_missing_path(
    fake_php_tree, monkeypatch
):
    """This is the bug. 8.4 is supported, and not here."""
    fake_php_tree("8.5")
    monkeypatch.setattr(system.settings, "default_php_version", "8.4")
    assert php_tune.resolve_version("8.4") == "8.5"
    assert php_tune.resolve_version(None) == "8.5"
    assert php_tune.resolve_version("") == "8.5"


def test_the_endpoints_no_longer_carry_the_constant():
    source = (REPO_ROOT / "backend" / "app" / "api" / "maintenance.py").read_text(
        encoding="utf-8"
    )
    offenders = [
        line.strip()
        for line in source.splitlines()
        if 'Query(default="8.4")' in line
    ]
    assert offenders == [], offenders


def test_the_installer_records_the_version_it_installed():
    """The fallback covers old installs; this stops new ones needing it."""
    installer = (REPO_ROOT / "installer" / "install.sh").read_text(encoding="utf-8")
    assert "DEFAULT_PHP_VERSION=${PHP_DEFAULT}" in installer, (
        "the installer knows which PHP it installed and writes it nowhere"
    )

def test_a_nonsense_version_is_still_refused(fake_php_tree, monkeypatch):
    """Falling back must not swallow a mistake.

    A version the panel supports and this machine lacks is the interface's
    stale default arriving, and gets the machine's default. A version that is
    not a PHP version at all is somebody being wrong, and silently tuning
    something else would hide it.
    """
    fake_php_tree("8.5")
    monkeypatch.setattr(system.settings, "default_php_version", "8.5")
    with pytest.raises(ValueError) as caught:
        php_tune.resolve_version("9.9")
    assert "9.9" in str(caught.value)


def test_the_two_cases_are_told_apart(fake_php_tree, monkeypatch):
    fake_php_tree("8.5")
    monkeypatch.setattr(system.settings, "default_php_version", "8.5")
    # supported, absent -> fall back
    assert php_tune.resolve_version("8.3") == "8.5"
    # unsupported -> refuse
    with pytest.raises(ValueError):
        php_tune.resolve_version("not-a-version")
