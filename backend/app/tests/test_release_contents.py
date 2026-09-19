"""What a clone gets has to be what the build needs.

This exists because of one missing character. `.gitignore` carried a rule
`style.css`, written for a landing page at the repository root. A gitignore
pattern with no slash in it matches at every depth, so it also matched
`frontend/src/style.css` - the panel's main stylesheet, 989 lines, imported by
`App.jsx` on line 18.

Nothing complained. `git add -A` is silent about files it skips, the push
succeeded, the release tarball looked complete, and the failure surfaced two
jobs later as a Vite resolve error in CI. Anyone cloning the repository got a
frontend that could not build and no hint why.

The two tests below are deliberately about the *shape* of the mistake rather
than the one file: an unanchored rule that happens to share a name with a
source file, and an import that resolves to nothing.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
GITIGNORE = REPO_ROOT / ".gitignore"
FRONTEND = REPO_ROOT / "frontend"

# Directories whose contents are build output or vendored code; a clone is
# meant to be without them.
SKIP_DIRS = {"node_modules", "dist", ".vite"}


def _frontend_sources() -> list[Path]:
    return [
        p
        for p in FRONTEND.rglob("*")
        if p.is_file() and not any(part in SKIP_DIRS for part in p.parts)
    ]


def _ignore_patterns() -> list[str]:
    lines = GITIGNORE.read_text(encoding="utf-8").splitlines()
    return [
        line.strip()
        for line in lines
        if line.strip() and not line.strip().startswith("#")
    ]


@pytest.mark.skipif(not FRONTEND.is_dir(), reason="no frontend tree here")
def test_no_unanchored_ignore_rule_matches_a_frontend_source_file():
    """A bare filename in .gitignore applies at every depth, not just the root.

    `style.css` was meant to exclude one file beside `landing.html`. It
    excluded the app's stylesheet as well, because git treats a pattern with
    no slash as "anywhere". Anchoring it (`/style.css`) says what was meant.
    """
    names = {p.name for p in _frontend_sources()}
    offenders = []
    for pattern in _ignore_patterns():
        # Anchored, or scoped to a directory - those say where they apply.
        if "/" in pattern or pattern.startswith("!"):
            continue
        # A glob is a deliberate breadth; a bare name usually is not.
        if any(ch in pattern for ch in "*?["):
            continue
        if pattern in names:
            offenders.append(pattern)

    assert offenders == [], (
        "these .gitignore rules are unanchored and match a frontend source "
        f"file by name, so a clone would not get it: {offenders}. "
        "Add a leading slash to scope the rule to the repository root."
    )


@pytest.mark.skipif(
    not (FRONTEND / "src" / "App.jsx").is_file(), reason="no App.jsx here"
)
def test_every_local_import_in_the_app_resolves_to_a_file():
    """The other half: an import that points at nothing fails the build.

    Catches a file that was moved or renamed as well as one that a gitignore
    rule swallowed, and it does so in the Python suite - which runs long
    before anyone installs npm.
    """
    app = FRONTEND / "src" / "App.jsx"
    text = app.read_text(encoding="utf-8")
    # Only relative imports: bare specifiers are npm packages.
    imports = re.findall(r"""^\s*import\s+['"](\.[^'"]+)['"]""", text, re.M)
    assert imports, "no relative imports found; the regex has stopped matching"

    missing = []
    for spec in imports:
        target = (app.parent / spec).resolve()
        if target.is_file():
            continue
        # An extensionless import may resolve through several suffixes.
        if any(
            target.with_suffix(suffix).is_file()
            for suffix in (".js", ".jsx", ".ts", ".tsx", ".css", ".json")
        ):
            continue
        missing.append(spec)

    assert missing == [], f"App.jsx imports files that are not there: {missing}"
