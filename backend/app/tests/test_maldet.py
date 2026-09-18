"""Linux Malware Detect (maldet) integration."""

from pathlib import Path

from app.services import maldet

HELPER_SCRIPT = Path(__file__).resolve().parents[3] / "installer" / "files" / "snpanel-helper.sh"

_REPORT = """\
Linux Malware Detect v1.6.5
            (C) 2002-2023, R-fx Networks <proj@rfxn.com>

malware detect scan report for host: bp
SCAN ID: 260902-1811.123456
TIME: Sep 2 2026 18:11:07 +0700
PATH: /home
TOTAL FILES: 16676
TOTAL HITS: 2
TOTAL CLEANED: 0

FILE HIT LIST:
{HEX}php.base64.v23eb9 : /home/nhs/nganhaso.net/public_html/shell.php
perl.mailer.x : /home/other/x.pl
===============================================
"""


def test_report_parsing_pulls_family_names_and_total():
    total, threats = maldet.parse_report_text(_REPORT)
    assert total == 16676
    assert threats == [
        {"path": "/home/nhs/nganhaso.net/public_html/shell.php", "signature": "{HEX}php.base64.v23eb9", "domain": ""},
        {"path": "/home/other/x.pl", "signature": "perl.mailer.x", "domain": ""},
    ]


def test_report_parsing_of_a_clean_scan():
    clean = "SCAN ID: 260902-1.2\nTOTAL FILES: 12\nTOTAL HITS: 0\n"
    total, threats = maldet.parse_report_text(clean)
    assert total == 12
    assert threats == []


def test_scan_builds_recent_vs_all_args(monkeypatch):
    calls = {}

    def fake_privileged(cmd, helper_args=None, **kw):
        calls["cmd"] = cmd
        calls["args"] = helper_args

        class R:
            stdout = "scanid=260902-1.2\nexit=0\n"
            returncode = 0
        return R()

    monkeypatch.setattr(maldet.shell, "privileged", fake_privileged)

    maldet.scan("abc123", ["/home"], recent_days=7)
    assert calls["cmd"] == "maldet-scan"
    assert calls["args"] == ["abc123", "recent", "7", "/home"]

    out = maldet.scan("abc123", ["/home/u/site"])
    assert calls["args"] == ["abc123", "all", "0", "/home/u/site"]
    assert out == {"scanid": "260902-1.2", "exit": 0, "raw": "scanid=260902-1.2\nexit=0\n"}


class TestHelper:
    def test_maldet_verbs_and_confinement(self):
        helper = HELPER_SCRIPT.read_text(encoding="utf-8")
        for verb in ("maldet-install)", "maldet-scan)", "maldet-monitor)", "maldet-update-sigs)", "maldet-report)"):
            assert verb in helper
        # scan paths are confined to / or /home
        assert "scan path must be / or under /home" in helper
        # scanid is anchored
        assert "^[0-9]{6}-[0-9]{4}\\.[0-9]+$" in helper
        # ClamAV engine on, resident daemon deliberately not enabled
        assert 'scan_clamscan=1' in helper
        assert "quarantine_hits=0" in helper
        # scans run at the lowest priority
        body = helper.split("run_maldet_scan() {", 1)[1].split("\n}", 1)[0]
        assert "nice -n 19" in body and "ionice -c3" in body
        # inotify limits raised before the monitor starts
        assert "fs.inotify.max_user_watches" in helper
