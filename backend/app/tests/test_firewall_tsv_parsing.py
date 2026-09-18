"""`IFS=$'\t' read` cannot parse a TSV with empty fields, and the firewall did.

Tab is IFS *whitespace* in bash: runs of tabs collapse into one delimiter, so a
row whose middle field is empty shifts every field after it one place left.

The rules file has empty fields by design. "Open port 8080 to every source" is
stored with no IP, which `firewall_add_rule` accepts explicitly, and that row
was read as ip=8080, port=tcp. Two things followed, neither of them loud:

  * the ipset entry came out as "8080,:tcp", ipset rejected it, and the helper's
    `deny` aborted the whole sync - `firewall-enable` failed and applied nothing;
  * the branch that opens a port for everyone tests `-z "$ip"`, which was then
    false, so the port stayed closed while the panel listed the rule as active.

These tests run the helper's own reader, so they check the mechanism rather
than asserting on the source text.
"""

import subprocess
from pathlib import Path

import pytest

HELPER_SCRIPT = Path(__file__).resolve().parents[3] / "installer" / "files" / "snpanel-helper.sh"


def helper_reader() -> str:
    """The firewall_read_tsv definition, lifted out of the helper.

    The helper refuses to run unless invoked through sudo as the panel user, so
    the function is extracted and exercised on its own.
    """
    text = HELPER_SCRIPT.read_text(encoding="utf-8")
    start = text.index("firewall_read_tsv() {")
    end = text.index("\n}\n", start) + len("\n}\n")
    return text[start:end]


def read_row(row: str, fields: int = 5) -> list[str]:
    script = f"""
        {helper_reader()}
        printf '%s' "$1" | firewall_read_tsv {fields} | while IFS='|' read -r a b c d e; do
            printf '[%s][%s][%s][%s][%s]\\n' "$a" "$b" "$c" "$d" "$e"
        done
    """
    out = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", script, "bash", row],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    return out[1:-1].split("][") if out else []


def test_an_empty_ip_column_does_not_shift_the_row():
    # This is the rule shape for "open this port to every source".
    assert read_row("3\tallow\t\t8080\ttcp") == ["3", "allow", "", "8080", "tcp"]


def test_a_rule_with_no_port_still_parses():
    # And this is "allow this address on every port" - trailing empties.
    assert read_row("1\tallow\t203.0.113.44\t\t") == ["1", "allow", "203.0.113.44", "", ""]


def test_a_short_row_is_padded_rather_than_running_off_the_end():
    assert read_row("7\tdeny\t198.51.100.0/24") == ["7", "deny", "198.51.100.0/24", "", ""]


def test_the_plain_bash_idiom_really_is_broken():
    """The bug, demonstrated, so nobody reintroduces the shorter spelling.

    If this ever fails, bash has changed how IFS whitespace works and the
    workaround can go.
    """
    script = (
        "IFS=$'\\t' read -r a b c d e <<< \"$1\"; "
        "printf '[%s][%s][%s][%s][%s]\\n' \"$a\" \"$b\" \"$c\" \"$d\" \"$e\""
    )
    out = subprocess.run(  # noqa: S603
        ["/bin/bash", "-c", script, "bash", "3\tallow\t\t8080\ttcp"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert out == "[3][allow][8080][tcp][]", out


@pytest.mark.parametrize("consumer", [
    "firewall_sync_sets",
    "firewall_apply_family",
    "firewall_import_ufw_rules",
])
def test_no_consumer_of_the_rules_file_splits_on_tab(consumer):
    text = HELPER_SCRIPT.read_text(encoding="utf-8")
    start = text.index(f"{consumer}() {{")
    body = text[start:text.index("\n}\n", start)]
    assert "IFS=$'\\t' read" not in body, (
        f"{consumer} splits on tab again; empty fields will shift the row"
    )
