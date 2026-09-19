"""Keep the suite out of the machine's real directories.

CI found this, and only CI could have. The backend job runs as an ordinary
user, so when `test_turning_crs_off_always_works` reached
`panel_settings._write_raw` it got

    PermissionError: [Errno 13] Permission denied: '/var/lib/snpanel'

The same test passed locally - because the suite was being run as root, which
does not get a permission error. It gets a directory. `/var/lib/snpanel` had
been created on the development box by a test run, and the GeoIP test had
written a real `dbip-country-lite-2026-09.csv.gz` into it. Nobody noticed,
because succeeding quietly looks exactly like not doing it at all.

Nine modules resolve a path under `/var/lib/snpanel`, most of them at import
time from an environment variable, so the redirection has to happen before any
of them is imported - which is what a conftest at the rootdir is for.

Two things are deliberately not done here:

  * No fixture in this file requests `monkeypatch`. Requesting it creates the
    monkeypatch instance earlier than the test does, which moves its *undo*
    later than the teardown of module-level fixtures - and
    `_clear_cache` in two WAF test files then calls `.cache_clear()` on a
    function that is still monkeypatched to a plain lambda. Seven tests
    errored that way on the first attempt at this file.
  * Nothing in the product grows a test-only environment variable. The paths
    that are spelled out as constants are redirected here instead.
"""

from __future__ import annotations

import os
import pathlib
import tempfile

# A directory per pytest process, created at import time - before any app
# module is imported - so every module that resolves its path from the
# environment picks this up rather than the real one.
_DATA = pathlib.Path(tempfile.mkdtemp(prefix="snpanel-test-data-"))
(_DATA / "assets").mkdir(parents=True, exist_ok=True)

os.environ["SNPANEL_DATA_DIR"] = str(_DATA)
os.environ["SNPANEL_IMPORT_STAGE_BASE"] = str(_DATA / "import-stage")
os.environ["DA_IMPORT_STAGE_BASE"] = str(_DATA / "da-import")
os.environ["SNPANEL_UPDATE_STATE_FILE"] = str(_DATA / "update-state.json")
# pydantic-settings maps the field name to this, with no prefix. Without it a
# test downloads a real GeoIP database into /var/lib/snpanel/geoip.
os.environ["GEOIP_DBIP_CACHE_DIR"] = str(_DATA / "geoip")

# Whether the real directory existed before any test ran. On a server it does;
# on a build machine it should not, and if it appears during the run something
# has escaped the redirection above.
_REAL = pathlib.Path("/var/lib/snpanel")
_REAL_EXISTED = _REAL.exists()

# `maldet.JOBS_DIR` is a constant rather than an environment lookup, because
# the helper and the panel have to agree on one path. Redirected at import
# time rather than in a fixture, for the monkeypatch reason above.
try:  # pragma: no cover - only if the suite does not use this module
    from app.services import maldet as _maldet

    _maldet.JOBS_DIR = _DATA / "malware-scan-jobs"
except Exception:  # noqa: BLE001
    pass

# `sso_tokens.TOKEN_DIR` is a fixed /tmp path shared by everything on the box,
# so whoever runs the suite first owns it and the next user cannot write to
# it. That is not hypothetical: minting a token as root once left the
# directory root-owned and locked the panel out of its own SSO. The product
# keeps the path - phpMyAdmin's signon script has to find it - and the tests
# get their own.
try:  # pragma: no cover
    from app.services import sso_tokens as _sso_tokens

    _sso_tokens.TOKEN_DIR = _DATA / "phpmyadmin-sso"
except Exception:  # noqa: BLE001
    pass


def pytest_sessionfinish(session, exitstatus):  # noqa: ARG001
    """Say so if a test wrote to the real data directory after all.

    Reported rather than raised: the run is over by now and failing here would
    obscure whatever the tests actually found. On CI this cannot happen - the
    job has no permission to create it - so this is for the root shell where
    it silently can.
    """
    if _REAL_EXISTED or not _REAL.exists():
        return
    leaked = sorted(str(p.relative_to(_REAL)) for p in _REAL.rglob("*"))[:10]
    session.config.stash  # noqa: B018 - keep the attribute access explicit
    print(
        f"\n!! a test created {_REAL} despite the redirection in "
        f"backend/conftest.py: {leaked or '(empty)'}\n"
        "   Find the path it used and add it above, rather than deleting the "
        "directory and forgetting."
    )
