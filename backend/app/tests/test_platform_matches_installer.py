"""The same table exists three times. This is what stops them drifting.

There is one description of "which distribution is this and what does it call
things" for Rust (``crates/snpanel-osabi``), one for the installer
(``installer/platform.sh``) and one for the running panel
(``app/core/platform.py``). Three copies is one more than anybody wants, but
they are read by three different runtimes, and the alternative - the panel
shelling out to the installer's shell functions - is worse.

What makes three copies tolerable is that a disagreement between them is a test
failure rather than a support ticket. The value that prompted this test is
``redis``: EL10 ships no such package, Valkey replaced it, and the Rust table
said ``redis`` anyway because the unit test asserting it had been written from
the same assumption as the code it checked. A test that only compares a table
with itself will agree with itself forever.
"""

import re
import subprocess
from pathlib import Path

import pytest

from app.core import platform

REPO_ROOT = Path(__file__).resolve().parents[3]
PLATFORM_SH = REPO_ROOT / "installer" / "platform.sh"
RHEL_RS = REPO_ROOT / "crates" / "snpanel-osabi" / "src" / "rhel.rs"
DEBIAN_RS = REPO_ROOT / "crates" / "snpanel-osabi" / "src" / "debian.rs"

QUOTED_LITERAL = r'"([^"]+)"'


def shell_table(family_function: str) -> dict[str, str]:
    """Source installer/platform.sh, pick a family, and read its values back."""
    script = f"""
        fail() {{ echo "FAIL: $1" >&2; exit 1; }}
        source {PLATFORM_SH}
        {family_function}
        echo "web_user=$WEB_USER"
        echo "web_group=$WEB_GROUP"
        echo "redis_service=$REDIS_SERVICE"
        echo "cron_service=$CRON_SERVICE"
        echo "ssh_service=$SSH_SERVICE"
        echo "phpmyadmin_root=$PHPMYADMIN_ROOT"
        echo "clamav_service=${{CLAMAV_SERVICE%.service}}"
    """
    completed = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", script],
        capture_output=True,
        text=True,
        check=True,
    )
    return dict(
        line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line
    )


@pytest.mark.parametrize(
    ("family_function", "python_table"),
    [
        ("platform_debian", platform._DEBIAN),
        ("platform_rhel10", platform._RHEL),
    ],
)
def test_the_installer_and_the_panel_agree(family_function, python_table):
    for key, value in shell_table(family_function).items():
        assert python_table[key] == value, (
            f"{key}: installer says {value!r}, panel says {python_table[key]!r}"
        )


def rust_literal(source: Path, method: str) -> str:
    """The string a zero-argument &'static str method in a Platform impl returns."""
    pattern = (
        r"fn " + re.escape(method) + r"\(&self\) -> &.static str \{\s*\n\s*"
        + QUOTED_LITERAL
    )
    match = re.search(pattern, source.read_text(encoding="utf-8"))
    assert match, f"could not find {method} in {source.name}"
    return match.group(1)


@pytest.mark.parametrize(
    ("source", "python_table"),
    [(RHEL_RS, platform._RHEL), (DEBIAN_RS, platform._DEBIAN)],
)
@pytest.mark.parametrize("method", ["redis_service", "cron_service"])
def test_the_rust_table_and_the_panel_agree(source, python_table, method):
    # These are unit names the panel starts and stops. Naming a unit nothing
    # provides fails quietly - the service simply reports as inactive - which
    # is exactly why they are worth pinning across implementations.
    assert rust_literal(source, method) == python_table[method]


def test_a_rebuild_that_only_declares_id_like_is_still_el():
    # An EL rebuild nobody has heard of still says ID_LIKE="rhel centos fedora".
    # Matching on ID alone would silently hand it www-data and a Redis unit
    # that does not exist on it.
    fields = platform._parse_os_release('ID=someclone\nID_LIKE="rhel centos fedora"')
    identifiers = {fields.get("ID", "").lower()}
    identifiers.update(fields.get("ID_LIKE", "").lower().split())
    assert identifiers & {"rhel", "centos", "fedora", "almalinux", "rocky", "ol"}


def test_an_unrecognised_system_is_treated_as_debian(monkeypatch, tmp_path):
    # A panel that cannot identify its host is far more likely to be on a
    # Debian derivative or a development checkout than on an EL rebuild, and
    # www-data is the safer wrong answer: it exists on the machines where this
    # is most likely to happen.
    missing = tmp_path / "no-such-os-release"
    monkeypatch.setattr(platform, "OS_RELEASE", missing)
    platform._table.cache_clear()
    try:
        assert platform.os_family() == "debian"
        assert platform.web_user() == "www-data"
    finally:
        platform._table.cache_clear()

# --- the gate ---------------------------------------------------------------
#
# A gate that is wrong in the permissive direction is the dangerous one: the
# installer gets halfway through on a platform it does not understand and
# leaves a broken machine. These pin both directions.

GATE_SCRIPT = """
    fail() {{ echo "REFUSED"; exit 1; }}
    source() {{ builtin source "${{1/\\/etc\\/os-release/{fake}}}"; }}
    source {table}
    detect_platform
"""


def gate_verdict(tmp_path, os_id: str, version: str) -> str:
    fake = tmp_path / "os-release"
    fake.write_text(
        f'ID={os_id}\nVERSION_ID="{version}"\nPRETTY_NAME="{os_id} {version}"\n',
        encoding="utf-8",
    )
    completed = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", GATE_SCRIPT.format(fake=fake, table=PLATFORM_SH)],
        capture_output=True, text=True, check=False,
    )
    return completed.stdout.strip().splitlines()[-1] if completed.stdout.strip() else ""


@pytest.mark.parametrize(("os_id", "version"), [
    ("ubuntu", "24.04"),
    ("ubuntu", "26.04"),
    ("debian", "13"),
    ("debian", "12"),
    ("almalinux", "10.2"),   # a point release is not a different platform
    ("almalinux", "10"),
    ("rocky", "10.1"),
])
def test_the_supported_platforms_are_accepted(tmp_path, os_id, version):
    assert gate_verdict(tmp_path, os_id, version).startswith("Platform:")


@pytest.mark.parametrize(("os_id", "version"), [
    ("ubuntu", "22.04"),
    ("ubuntu", "25.10"),     # an interim release is not an LTS
    ("debian", "11"),        # oldoldstable; 12 and 13 are supported now
    ("almalinux", "9.4"),    # EL9 is not EL10; Remi and Valkey both differ
    ("fedora", "41"),
    ("arch", "rolling"),
])
def test_everything_else_is_refused(tmp_path, os_id, version):
    assert gate_verdict(tmp_path, os_id, version) == "REFUSED"

# --- PHP differs by Ubuntu release ------------------------------------------
#
# 24.04 gets 8.3 and 8.4 from Ondrej's PPA. 26.04 cannot: the PPA has no
# `resolute` suite, and the distribution carries 8.5 and nothing else. Asking
# for 8.3 there fails on every package name, so the versions have to come from
# the release rather than from a constant at the top of the installer.


def php_values_for(tmp_path, version: str) -> dict[str, str]:
    fake = tmp_path / "os-release"
    fake.write_text(f'ID=ubuntu\nVERSION_ID="{version}"\n', encoding="utf-8")
    script = f"""
        fail() {{ echo "FAIL: $1" >&2; exit 1; }}
        source() {{ builtin source "${{1/\\/etc\\/os-release/{fake}}}"; }}
        source {PLATFORM_SH}
        detect_platform >/dev/null
        echo "versions=$PLATFORM_PHP_VERSIONS"
        echo "default=$PLATFORM_PHP_DEFAULT"
        echo "ppa=$PHP_FROM_PPA"
    """
    out = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", script], capture_output=True, text=True, check=True
    ).stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def test_2404_takes_php_from_the_ppa(tmp_path):
    values = php_values_for(tmp_path, "24.04")
    assert values["versions"] == "8.3 8.4"
    assert values["default"] == "8.4"
    assert values["ppa"] == "yes"


def test_2604_takes_php_from_the_distribution(tmp_path):
    # The PPA has no resolute suite. Adding it anyway would give an empty
    # repository and then fail on every package name.
    values = php_values_for(tmp_path, "26.04")
    assert values["versions"] == "8.5"
    assert values["default"] == "8.5"
    assert values["ppa"] == "no"


def test_the_installer_only_adds_the_ppa_where_it_exists():
    installer = (REPO_ROOT / "installer" / "install.sh").read_text(encoding="utf-8")
    line = [
        raw for raw in installer.splitlines()
        if "ppa:ondrej/php" in raw and not raw.strip().startswith("#")
    ]
    assert line, "the PPA is never added; 24.04 would lose PHP 8.3 and 8.4"
    body = installer[installer.index("install_php() {"):]
    body = body[: body.index("\n}\n")]
    assert 'PHP_FROM_PPA" == "yes"' in body, (
        "the PPA is added unconditionally; on 26.04 that adds an empty repository"
    )


def test_the_installer_does_not_name_the_modsecurity_library():
    """It was renamed in the 64-bit time_t transition.

    `libmodsecurity3` on 24.04, `libmodsecurity3t64` on 26.04. The nginx module
    depends on whichever the release has, so naming it is both unnecessary and
    a way to fail on one of them.
    """
    installer = (REPO_ROOT / "installer" / "install.sh").read_text(encoding="utf-8")
    code = [
        raw for raw in installer.splitlines() if not raw.strip().startswith("#")
    ]
    offenders = [raw.strip() for raw in code if "libmodsecurity3" in raw]
    assert offenders == [], offenders

# --- sudoers ----------------------------------------------------------------


def test_requiretty_is_not_written_unconditionally():
    """sudo 1.9.17 removed the setting, and one build rejects the whole file.

    Ubuntu 26.04 answers

        /etc/sudoers.d/snpanel:18:19: syntax error: unknown setting: 'requiretty'

    and the install stops. AlmaLinux 10 ships the same sudo version and parses
    it happily, so the difference is between builds, not versions - which is why
    the installer asks visudo instead of branching on the distribution.
    """
    installer = (REPO_ROOT / "installer" / "install.sh").read_text(encoding="utf-8")
    body = installer[installer.index("install_privileged_helper() {"):]
    body = body[: body.index("\n}\n")]
    code = "\n".join(
        line for line in body.splitlines() if not line.strip().startswith("#")
    )
    assert "sudoers_understands_requiretty" in code, (
        "the sudoers file is installed without checking whether sudo still has "
        "the setting; on Ubuntu 26.04 that fails the install"
    )
    assert "visudo -c -f /etc/sudoers.d/snpanel" in code, (
        "the file must still be validated after any edit"
    )


def test_the_probe_asks_visudo_rather_than_the_distribution():
    installer = (REPO_ROOT / "installer" / "install.sh").read_text(encoding="utf-8")
    body = installer[installer.index("sudoers_understands_requiretty() {"):]
    body = body[: body.index("\n}\n")]
    assert "visudo -c" in body, "the probe has to use the parser that will judge our file"
    assert "OS_FAMILY" not in body and "VERSION_ID" not in body, (
        "the same sudo version behaves differently on the two platforms, so the "
        "distribution is not the thing to test"
    )


def test_the_sudoers_file_still_carries_the_hardening():
    """Whatever happens to requiretty, these must survive."""
    sudoers = (REPO_ROOT / "installer" / "files" / "snpanel-sudoers").read_text(encoding="utf-8")
    assert "Defaults:snpanel env_reset" in sudoers
    assert "secure_path=" in sudoers

# --- adding a PPA that does not exist ---------------------------------------
#
# Reported from the panel on Ubuntu 26.04, from "install PHP version":
#
#     E: The repository '.../ondrej/php/ubuntu resolute Release' does not have
#        a Release file.
#
# `add-apt-repository` succeeds for a suite the PPA does not publish. It writes
# the source file, and from then on every `apt-get update` on the machine fails
# - including the ones the installer and the updater run - so the damage
# outlives the action that caused it.


def helper_function(name: str) -> str:
    helper = (REPO_ROOT / "installer" / "files" / "snpanel-helper.sh").read_text(
        encoding="utf-8"
    )
    body = helper[helper.index(f"{name}() {{"):]
    return body[: body.index("\n}\n")]


def test_the_helper_checks_the_ppa_before_adding_it():
    body = helper_function("install_php_version")
    code = "\n".join(l for l in body.splitlines() if not l.strip().startswith("#"))
    assert "ondrej_ppa_publishes_this_release" in code, (
        "the helper adds the PPA without checking whether it publishes this "
        "release; on 26.04 that leaves apt broken for everything afterwards"
    )
    # And the refusal has to come before the repository is touched.
    assert code.index("ondrej_ppa_publishes_this_release") < code.index(
        "add-apt-repository"
    )


def test_the_probe_asks_the_ppa_rather_than_guessing():
    body = helper_function("ondrej_ppa_publishes_this_release")
    assert "VERSION_CODENAME" in body, "the suite is named by codename, not version"
    assert "launchpadcontent.net" in body, "nothing else can answer this question"
    assert "curl" in body


def test_an_already_configured_ppa_is_found_in_either_format():
    """add-apt-repository writes deb822 `.sources` on current Ubuntu.

    A check that reads only `*.list` never sees its own work, so it re-adds the
    repository on every attempt.
    """
    body = helper_function("install_php_version")
    line = [l for l in body.splitlines() if "ondrej/php" in l and "grep" in l]
    assert line, "nothing checks whether the PPA is already configured"
    assert "sources.list.d/" in line[0], line[0]
    assert "*.list" not in line[0], (
        f"only *.list is searched, so deb822 sources are missed: {line[0].strip()}"
    )


def test_the_refusal_names_what_is_installable():
    """A refusal that does not say what *would* work is half an answer."""
    body = helper_function("install_php_version")
    assert "php_versions_installable" in body
    versions = helper_function("php_versions_installable")
    # It has to ask apt rather than carry a list - and ask the right question:
    # `apt-cache show` says yes to names with no installable version, which is
    # how this refusal once told the user PHP 7.4 was available on a release
    # that has no such package.
    assert "apt_installable" in versions
    assert "apt-cache show" not in versions

# --- "is this package installable" is not what apt-cache show answers -------
#
# Measured on Ubuntu 26.04:
#
#     php7.4-fpm   apt-cache show -> rc=0,  apt-cache policy -> Candidate: (none)
#
# Something in the archive still references the name, so `show` finds a record
# while there is no installable version. The installer uses this check to pick
# which PHP extension packages to hand to apt, and a false yes puts an
# uninstallable name into a single `apt-get install` - failing the whole
# transaction instead of skipping one optional module.


def test_platform_pkg_exists_asks_for_a_candidate():
    table = PLATFORM_SH.read_text(encoding="utf-8")
    body = table[table.index("pkg_exists() {"):]
    body = body[: body.index("\n}\n")]
    code = "\n".join(l for l in body.splitlines() if not l.strip().startswith("#"))
    assert "apt-cache policy" in code, "apt-cache show answers a different question"
    assert "(none)" in code, "the candidate has to be checked, not just its presence"
    assert "apt-cache show" not in code


def test_the_helper_asks_the_same_way():
    helper = (REPO_ROOT / "installer" / "files" / "snpanel-helper.sh").read_text(
        encoding="utf-8"
    )
    code = "\n".join(
        l for l in helper.splitlines() if not l.strip().startswith("#")
    )
    assert "apt-cache show" not in code, (
        "the helper still uses apt-cache show somewhere; it says yes to "
        "packages that cannot be installed"
    )
    body = helper[helper.index("apt_installable() {"):]
    body = body[: body.index("\n}\n")]
    assert "apt-cache policy" in body and "(none)" in body


def test_both_implementations_use_the_same_test():
    """A package the installer thinks exists and the panel does not - or the
    reverse - is a difference nobody would look for."""
    table = PLATFORM_SH.read_text(encoding="utf-8")
    helper = (REPO_ROOT / "installer" / "files" / "snpanel-helper.sh").read_text(
        encoding="utf-8"
    )
    needle = "sed -n 's/^  Candidate: //p'"
    assert needle in table, "platform.sh does not read the candidate this way"
    assert needle in helper, "the helper does not read the candidate this way"

# --- Debian is not Ubuntu spelled differently -------------------------------
#
# They share a package manager and a filesystem layout. They do not share the
# PHP source, and `software-properties-common` - the package that provides
# `add-apt-repository` - is not in Debian's archive at all, so asking for it
# fails the first transaction.


def debian_values(tmp_path, version: str) -> dict[str, str]:
    fake = tmp_path / "os-release"
    fake.write_text(
        f'ID=debian\nVERSION_ID="{version}"\nVERSION_CODENAME=trixie\n', encoding="utf-8"
    )
    script = f"""
        fail() {{ echo "FAIL: $1" >&2; exit 1; }}
        source() {{ builtin source "${{1/\\/etc\\/os-release/{fake}}}"; }}
        source {PLATFORM_SH}
        detect_platform >/dev/null
        echo "ppa=$PHP_FROM_PPA"
        echo "sury=$PHP_FROM_SURY"
        echo "nodesource=$NODE_FROM_NODESOURCE"
        echo "versions=$PLATFORM_PHP_VERSIONS"
        echo "packages=${{BASE_PACKAGES[*]}}"
    """
    out = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", script], capture_output=True, text=True, check=True
    ).stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def test_debian_takes_php_from_sury_not_a_ppa(tmp_path):
    values = debian_values(tmp_path, "13")
    assert values["sury"] == "yes"
    assert values["ppa"] == "no", "there is no add-apt-repository on Debian"


def test_debian_does_not_ask_for_software_properties_common(tmp_path):
    """It is not in Debian's archive; asking fails the base transaction."""
    values = debian_values(tmp_path, "13")
    assert "software-properties-common" not in values["packages"]


def test_ubuntu_still_asks_for_it(tmp_path):
    fake = tmp_path / "os-release"
    fake.write_text('ID=ubuntu\nVERSION_ID="24.04"\n', encoding="utf-8")
    script = f"""
        fail() {{ echo "FAIL: $1" >&2; exit 1; }}
        source() {{ builtin source "${{1/\\/etc\\/os-release/{fake}}}"; }}
        source {PLATFORM_SH}
        detect_platform >/dev/null
        echo "packages=${{BASE_PACKAGES[*]}}"
        echo "ppa=$PHP_FROM_PPA"
    """
    out = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", script], capture_output=True, text=True, check=True
    ).stdout
    assert "software-properties-common" in out
    assert "ppa=yes" in out


def test_debian_does_not_pipe_a_vendor_node_script(tmp_path):
    """NodeSource publishes no trixie suite, and Debian carries nodejs 20."""
    assert debian_values(tmp_path, "13")["nodesource"] == "no"


def test_the_sury_repository_is_scoped_to_its_own_key():
    """An unscoped key in trusted.gpg.d would vouch for every repository."""
    installer = (REPO_ROOT / "installer" / "install.sh").read_text(encoding="utf-8")
    body = installer[installer.index("add_sury_repo() {"):]
    body = body[: body.index("\n}\n")]
    assert "signed-by=" in body
    assert "trusted.gpg.d" not in body
    # And it must not leave a broken source behind if the suite is absent.
    assert "rm -f /etc/apt/sources.list.d/sury-php.list" in body
