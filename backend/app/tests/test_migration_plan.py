"""The plan has to stay true, or it stops being read.

Two failures this guards against, both already observed in this repository:

  * **A citation that resolves to nothing.** `Cargo.toml` and about a dozen
    source comments cite "the plan" by section - §4.1, §6.1, §6.3, §8,
    Appendix B - and the file they cite was not in the repository at all. A
    reader following the reference found nothing and had no way to know
    whether the plan had moved or never existed.

  * **A number that has drifted.** `RUST_MIGRATION_STATUS.md` said "thirteen
    of the sixteen routers are answered natively, six of them whole" while the
    route table said four of seventeen, and per-endpoint coverage was a
    quarter rather than the three-quarters that sentence suggests. Nobody was
    being careless; the code moved and the prose did not.

The second test will fail whenever an endpoint is ported. That is deliberate:
updating one line of the plan is the cost of keeping it worth reading, and it
is a great deal cheaper than discovering at the end that the plan described a
project nobody was working on.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
PLAN = REPO_ROOT / "RUST_MIGRATION_PLAN.md"
PY_API = REPO_ROOT / "backend" / "app" / "api"
RS_ROUTES = REPO_ROOT / "crates" / "snpanel-api" / "src" / "routes"

PY_EP = re.compile(r"@router\.(get|post|put|patch|delete)\b")
VERB = re.compile(r"\b(get|post|put|patch|delete)\s*\(")
# "Plan §6.1", "plan §8", "Plan Appendix B" - the forms actually used.
CITATION = re.compile(r"[Pp]lan (?:§\s*(\d+)(?:\.\d+)?|(Appendix [A-Z]))")


def _router_body(text: str) -> str:
    """The body of `pub fn router()`, brace-matched.

    Regex alone gets this wrong: a non-greedy match to the first `)` stops
    inside `post(login)` and undercounts a ten-route file as five.
    """
    m = re.search(r"pub fn router\(\)[^{]*\{", text)
    if not m:
        return ""
    start = m.end() - 1
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return text[start:]


def _rs_endpoints(path: Path) -> int:
    if not path.is_file():
        return 0
    text = path.read_text(encoding="utf-8", errors="replace")
    cut = text.find("#[cfg(test)]")
    if cut != -1:
        text = text[:cut]
    # `fallback(...)` is the strangler hand-off, not an endpoint of its own.
    body = re.sub(r"fallback\([^)]*\)", "", _router_body(text))
    return len(VERB.findall(body))


def _coverage() -> tuple[int, int]:
    """(endpoints answered by Rust, endpoints in Python)."""
    total = native = 0
    for f in sorted(PY_API.glob("*.py")):
        if f.stem == "__init__":
            continue
        n = len(PY_EP.findall(f.read_text(encoding="utf-8", errors="replace")))
        total += n
        native += min(_rs_endpoints(RS_ROUTES / f"{f.stem}.rs"), n)
    return native, total


@pytest.mark.skipif(not PLAN.is_file(), reason="no plan document in this tree")
def test_every_plan_citation_in_the_code_resolves_to_a_section():
    """A reference to a section that does not exist is worse than no reference."""
    plan = PLAN.read_text(encoding="utf-8")
    sections = set(re.findall(r"^##\s+(\d+)\.", plan, re.M))
    appendices = set(re.findall(r"^##\s+(Appendix [A-Z])", plan, re.M))

    sources: list[Path] = []
    sources += [p for p in (REPO_ROOT / "crates").rglob("*.rs")]
    sources += [REPO_ROOT / "Cargo.toml"]

    missing: set[str] = set()
    for path in sources:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for number, appendix in CITATION.findall(text):
            if number and number not in sections:
                missing.add(f"§{number}")
            if appendix and appendix not in appendices:
                missing.add(appendix)

    assert not missing, (
        "the code cites plan sections that RUST_MIGRATION_PLAN.md does not "
        f"have: {sorted(missing)}. Either add the section or fix the citation "
        "- a reference that leads nowhere sends a reader looking for a "
        "document that is not there."
    )


@pytest.mark.skipif(not PLAN.is_file(), reason="no plan document in this tree")
def test_the_plan_states_the_coverage_the_code_actually_has():
    """The headline figure has to match the route table.

    If this fails after porting an endpoint, that is the test working: update
    the table in §1 of the plan to the numbers in the assertion message.
    """
    native, total = _coverage()
    plan = PLAN.read_text(encoding="utf-8")

    stated = re.search(r"\*\*(\d+)\s+of\s+(\d+)\*\*", plan)
    assert stated, "the plan no longer states coverage as '**N of M**' in §1"
    said_native, said_total = int(stated.group(1)), int(stated.group(2))

    assert (said_native, said_total) == (native, total), (
        f"the plan says {said_native} of {said_total} endpoints are answered "
        f"by Rust; the route table says {native} of {total} "
        f"({native * 100 // total}%). Update §1 of RUST_MIGRATION_PLAN.md."
    )
