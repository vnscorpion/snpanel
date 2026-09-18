"""The updater must apply its own changes in the run that brings them in.

bash reads a script as it runs, so update.sh re-execs a copy of itself from
/tmp - a copy of the *previous* release. Without a handover, anything an update
changes about updating itself lands one release late, which is how a server
once kept running the old panel start-up script after the release that replaced
it.
"""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
UPDATE_SCRIPT = PROJECT_ROOT / "installer" / "update.sh"
INSTALL_SCRIPT = PROJECT_ROOT / "installer" / "install.sh"


def _script() -> str:
    return UPDATE_SCRIPT.read_text(encoding="utf-8")


def _handover_block() -> str:
    script = _script()
    start = script.index("# bash reads a script as it runs")
    return script[start : script.index("# --- Sync code into APP_DIR")]


def test_the_updater_hands_over_to_the_one_from_the_new_release():
    block = _handover_block()
    assert 'exec /bin/bash "$stage2_copy"' in block
    assert 'cp "$SOURCE_DIR/installer/update.sh" "$stage2_copy"' in block
    # Only when it actually differs, so an unchanged updater keeps going.
    assert 'cmp -s "$SOURCE_DIR/installer/update.sh"' in block


def test_the_handover_cannot_loop():
    block = _handover_block()
    assert '[[ -z "${SNPANEL_UPDATE_STAGE2:-}"' in block
    assert "SNPANEL_UPDATE_STAGE2=1" in block


def test_the_second_stage_does_not_fetch_the_release_again():
    block = _handover_block()
    assert "SKIP_PULL=true" in block
    assert 'SOURCE_DIR="$SOURCE_DIR"' in block
    # The release name has to survive, or the panel would report the update as
    # coming from a temporary directory.
    assert 'SNPANEL_UPDATE_REF_OVERRIDE="${UPDATE_REF:-}"' in _handover_block()
    assert 'UPDATE_REF="${SNPANEL_UPDATE_REF_OVERRIDE:-local:${SOURCE_DIR}}"' in _script()


def test_the_handover_leaves_nothing_behind():
    script = _script()
    block = _handover_block()
    # exec skips the EXIT trap, so the second stage inherits the cleanup.
    assert 'SNPANEL_UPDATE_PREVIOUS_COPY="${SNPANEL_UPDATE_STABLE_COPY:-}"' in block
    assert 'RELEASE_WORK_DIR="${RELEASE_WORK_DIR:-}"' in block
    assert (
        'rm -f "${SNPANEL_UPDATE_STABLE_COPY:-}" "${SNPANEL_UPDATE_PREVIOUS_COPY:-}"' in script
    )
    # ...and the work dir it was handed must not be wiped out on the way in.
    assert 'RELEASE_WORK_DIR=""' not in script


def test_the_second_stage_does_not_snapshot_the_database_twice():
    script = _script()
    assert '''if [[ -n "${SNPANEL_UPDATE_STAGE2:-}" ]]; then
  log "Continuing with the updater shipped in this release"
else
  log "Backing up SQLite DB before update"
  backup_db''' in script


def test_a_stuck_apt_dependency_does_not_leave_ipset_missing_forever():
    # A stuck package pin (seen in the field: libsystemd-shared) can leave
    # ipset "not going to be installed" - apt itself suggests --fix-broken.
    # An update that only warns and moves on means every server that hit this
    # once stays without an enforced firewall on every future update too.
    script = _script()
    start = script.index("# --- Firewall: move IP blocking")
    block = script[start : script.index("if id -u snpanel", start)]
    assert "apt-get --fix-broken install -y" in block
    # The repair is a retry, not the only attempt - it must not run unless the
    # plain install actually failed.
    assert "if ! DEBIAN_FRONTEND=noninteractive apt-get install -y iptables ipset" in block


def test_a_fresh_install_repairs_the_same_stuck_apt_dependency():
    # install_base_packages hits the same class of stuck-pin failure a fresh
    # VPS image can ship with; without a repair+retry the whole install dies
    # on this one line instead of a targeted, recoverable failure.
    script = INSTALL_SCRIPT.read_text(encoding="utf-8")
    start = script.index("install_base_packages() {")
    block = script[start : script.index("\n}", start)]
    # The install itself now goes through pkg_install, which dispatches on the
    # platform - but the repair is apt's own suggestion for an apt-specific
    # failure, so it stays spelled out, and it stays a *retry*: it must not run
    # unless the plain install actually failed.
    assert 'if ! pkg_install "${pkgs[@]}"; then' in block
    assert "apt_get_locked --fix-broken install -y" in block
    assert 'apt_get_locked install -y "${pkgs[@]}"' in block
    # `apt_get_locked`, not `apt-get`: every Debian call goes through a wrapper
    # that waits out the dpkg lock a freshly-booted image holds.
    assert "apt-get --fix-broken" not in block
    # EL has no equivalent repair, so it must fail rather than fall through the
    # Debian branch and report success it did not achieve.
    assert "fail \"Base package installation failed" in block


def test_every_apt_call_waits_for_the_dpkg_lock():
    # A fresh Ubuntu runs unattended-upgrades on boot. Any apt call that races
    # it dies on "Could not get lock /var/lib/dpkg/lock-frontend" and leaves a
    # half-configured box, so no call site may reach apt-get directly.
    script = INSTALL_SCRIPT.read_text(encoding="utf-8")
    assert "fuser /var/lib/dpkg/lock-frontend" in script
    direct = [
        line.strip()
        for line in script.splitlines()
        # The wrapper body is the one place the real binary is invoked.
        if "apt-get " in line and not line.strip().startswith("#")
        and 'DEBIAN_FRONTEND=noninteractive apt-get "$@"' not in line
    ]
    assert direct == []
