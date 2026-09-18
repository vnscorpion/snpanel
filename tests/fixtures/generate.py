#!/usr/bin/env python3
"""Generate the cross-language compatibility fixtures.

Everything the Rust port has to stay bug-for-bug compatible with is produced
here, by the *actual* Python libraries the panel runs today, and committed to
the repository. The Rust test suite then consumes these files. That direction
matters: if a Rust test only checked Rust's own output it would prove nothing.

Run against the panel's own dependency set:

    python3 -m venv .venv && .venv/bin/pip install \\
        cryptography bcrypt passlib python-jose pyotp jinja2
    .venv/bin/python tests/fixtures/generate.py

Covers plan contracts C1 (bcrypt), C3 (Fernet), C4 (JWT), C6 (TOTP) and C19
(nginx templates rendered by Jinja2).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent
GOLDEN = REPO / "tests" / "golden"

# A fixed secret so the fixtures are reproducible. This is a test value and is
# deliberately not a real key; the panel refuses anything under 32 chars in
# production, and this is 38.
SECRET = "test-secret-key-at-least-32-chars-long"


def w(path: pathlib.Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    print(f"  wrote {path.relative_to(REPO)}")


# ---------------------------------------------------------------------------
# C3 - Fernet
# ---------------------------------------------------------------------------
def gen_fernet() -> None:
    from cryptography.fernet import Fernet

    print("C3 Fernet:")
    key = base64.urlsafe_b64encode(hashlib.sha256(SECRET.encode("utf-8")).digest())
    f = Fernet(key)

    cases = {
        "simple": "correct horse battery",
        "empty": "",
        "unicode": "mật khẩu cơ sở dữ liệu ✓",
        "block_aligned": "0123456789abcdef",  # exactly one AES block
        "long": "x" * 500,
        "mysql_password": "Str0ng!DbP@ss-2026#xyz",
    }
    out = {
        "secret_key": SECRET,
        "derived_key": key.decode("ascii"),
        "cases": {
            name: {
                "plaintext": plain,
                # Stored exactly as secrets.encrypt() writes it, prefix and all.
                "stored": "fernet:" + f.encrypt(plain.encode("utf-8")).decode("ascii"),
            }
            for name, plain in cases.items()
        },
    }
    w(HERE / "fernet.json", json.dumps(out, indent=2, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# C1 - bcrypt via passlib
# ---------------------------------------------------------------------------
def gen_bcrypt() -> None:
    from passlib.context import CryptContext

    print("C1 bcrypt:")
    ctx = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__truncate_error=True)

    passwords = {
        "admin": "admin-password-123",
        "unicode": "mật-khẩu-2026",
        "long_71": "y" * 71,  # just under the 72-byte bcrypt limit
        "symbols": "p@$$w0rd!#%^&*()_+{}|:<>?",
    }
    cases = {name: {"password": pw, "hash": ctx.hash(pw)} for name, pw in passwords.items()}

    # A hash generated at a non-default cost, to prove the Rust verifier reads
    # the cost from the hash rather than assuming one.
    cases["cost_10"] = {
        "password": "cost-ten-password",
        "hash": CryptContext(schemes=["bcrypt"], bcrypt__rounds=10).hash("cost-ten-password"),
    }

    out = {
        "cases": cases,
        # verify_password() also accepts /etc/shadow hashes (yescrypt, sha512crypt)
        # because the admin account is synced to a Linux user. Rust must not
        # treat these as bcrypt.
        "shadow_prefixes": ["$y$", "$gy$", "$7$", "$6$", "$5$"],
        "bcrypt_prefixes": ["$2a$", "$2b$", "$2y$"],
    }
    w(HERE / "bcrypt.json", json.dumps(out, indent=2, ensure_ascii=False) + "\n")


# ---------------------------------------------------------------------------
# C4 - JWT
# ---------------------------------------------------------------------------
def gen_jwt() -> None:
    """Tokens in the exact shape `api/auth.py` issues them.

    The claim names are the contract, and they are not the obvious ones:

    - ``sub`` is the **username**, not the user id
      (``create_access_token(user.username, ...)``).
    - the token version is ``tv``, not ``token_version``
      (``{"role": user.role, "tv": user.token_version or 0}``).

    Getting either wrong breaks the strangler in the worst way: a token issued
    by one implementation authenticates as nobody in the other, so every open
    session drops the moment a route moves over. An earlier version of this
    file invented the names and the Rust side matched the invention, which is
    how a passing test proved nothing.
    """
    from jose import jwt

    print("C4 JWT:")
    iat = 1_700_000_000
    exp = 4_102_444_800  # 2100-01-01
    payload = {
        "sub": "admin",                 # username, per create_access_token
        "iat": iat,
        "exp": exp,
        "jti": "fixed-jti-for-the-fixture",
        "role": "admin",
        "tv": 3,                        # token_version, per token_extra
    }
    expired = dict(payload, exp=iat + 60, jti="expired-jti")
    impersonation = dict(payload, imp=True, jti="impersonation-jti")

    out = {
        "secret_key": SECRET,
        "algorithm": "HS256",
        "claim_names": {
            "subject": "sub  (the username)",
            "token_version": "tv",
            "role": "role",
            "impersonation": "imp",
        },
        "valid": {"claims": payload, "token": jwt.encode(payload, SECRET, algorithm="HS256")},
        "expired": {"claims": expired, "token": jwt.encode(expired, SECRET, algorithm="HS256")},
        "impersonation": {
            "claims": impersonation,
            "token": jwt.encode(impersonation, SECRET, algorithm="HS256"),
        },
        "wrong_key": {
            "token": jwt.encode(payload, "a-completely-different-secret-key-value", algorithm="HS256")
        },
    }
    w(HERE / "jwt.json", json.dumps(out, indent=2) + "\n")


# ---------------------------------------------------------------------------
# C6 - TOTP
# ---------------------------------------------------------------------------
def gen_totp() -> None:
    import pyotp

    print("C6 TOTP:")
    secret = "JBSWY3DPEHPK3PXP"  # the canonical RFC test secret, base32
    totp = pyotp.TOTP(secret)
    # Codes at fixed timestamps, so Rust can be checked without freezing a clock.
    timestamps = [0, 1_700_000_000, 1_700_000_029, 1_700_000_030, 2_000_000_000]
    out = {
        "secret": secret,
        "digits": 6,
        "period": 30,
        "algorithm": "SHA1",
        "issuer": "SNPanel",
        "codes": {str(ts): totp.at(ts) for ts in timestamps},
        "provisioning_uri": pyotp.TOTP(secret, issuer="SNPanel").provisioning_uri(
            name="admin", issuer_name="SNPanel"
        ),
    }
    w(HERE / "totp.json", json.dumps(out, indent=2) + "\n")


# ---------------------------------------------------------------------------
# C19 - nginx templates
# ---------------------------------------------------------------------------
def gen_nginx_golden() -> None:
    """Render vhosts through the real `render_vhost` and save the bytes.

    Deliberately *not* a bare Jinja2 render. `render_vhost` also rewrites the
    bot block, applies manual SSL config and appends redirect vhosts, and the
    minijinja port has to reproduce the finished file, not the template output.
    Rendering only the template would leave those three steps untested.

    Needs the site roots to exist on disk, because render_vhost resolves and
    checks them - so they are created under a temporary /home for the run.
    """
    import tempfile

    print("C19 nginx templates:")
    sys.path.insert(0, str(REPO / "backend"))
    os.environ.setdefault("SECRET_KEY", SECRET)
    os.environ.setdefault("COMMAND_DRY_RUN", "true")

    try:
        from app.services import nginx, site_users
    except Exception as exc:  # noqa: BLE001
        print(f"  SKIP: cannot import the backend ({type(exc).__name__}: {exc})", file=sys.stderr)
        return

    # Capture what `render_vhost` actually passes to each template. This is
    # the input the minijinja port must accept, and guessing it from reading
    # the templates would leave out anything computed in Python (the flood
    # zone name, the challenge block, the resolved socket path).
    captured = []
    import jinja2

    original_render = jinja2.Template.render

    def recording_render(self, *args, **kwargs):
        ctx = dict(*args, **kwargs) if (args or kwargs) else {}
        result = original_render(self, *args, **kwargs)
        captured.append({"template": pathlib.Path(self.filename or "").name,
                         "context": ctx, "output": result})
        return result

    jinja2.Template.render = recording_render

    manifest = []
    with tempfile.TemporaryDirectory() as tmp:
        home = pathlib.Path(tmp) / "home"
        home.mkdir()
        # render_vhost insists the root is the managed root for the domain, so
        # point HOME_ROOT at the sandbox rather than weakening the check.
        original_home = site_users.HOME_ROOT
        site_users.HOME_ROOT = home
        try:
            for case in _nginx_cases():
                domain = case["kwargs"]["domain"]
                user = site_users.linux_user_for_domain(domain)
                root = home / user / domain
                (root / "public_html").mkdir(parents=True, exist_ok=True)

                kwargs = dict(case["kwargs"])
                kwargs["domain"] = domain
                kwargs["root_path"] = str(root)
                try:
                    rendered = nginx.render_vhost(**kwargs)
                except Exception as exc:  # noqa: BLE001
                    print(
                        f"  SKIP {case['name']}: {type(exc).__name__}: {exc}",
                        file=sys.stderr,
                    )
                    continue

                # The sandbox path must not leak into the committed fixture.
                rendered = rendered.replace(str(home), "/home")
                out_path = GOLDEN / "nginx" / f"{case['name']}.expected"
                w(out_path, rendered)
                manifest.append(
                    {
                        "name": case["name"],
                        "kwargs": {
                            k: v for k, v in kwargs.items() if k != "root_path"
                        },
                        "expected": str(out_path.relative_to(REPO)),
                    }
                )
        finally:
            site_users.HOME_ROOT = original_home
            jinja2.Template.render = original_render

    w(GOLDEN / "nginx" / "manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(f"  {len(manifest)} vhosts captured")

    # The template-level spike (plan Phase 0, C19): same template, same
    # context, rendered by Jinja2. minijinja must reproduce these bytes.
    for i, entry in enumerate(captured):
        entry["context"] = _jsonable(entry["context"])
        entry["output"] = entry["output"].replace(str(home), "/home")
        entry["context"] = _jsonable(
            json.loads(json.dumps(entry["context"]).replace(str(home), "/home"))
        )
    w(
        GOLDEN / "nginx" / "template_renders.json",
        json.dumps(captured, indent=2, ensure_ascii=False) + "\n",
    )
    print(f"  {len(captured)} template-level renders captured")


def _jsonable(value):
    """Drop anything that will not survive a JSON round trip."""
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _nginx_cases() -> list[dict]:
    """Input vectors chosen to exercise each branch in the templates.

    Every app type, both WAF states, each rewrite mode, aliases present and
    absent, http-flood on and off, and a custom directive block.
    """
    cases = []

    def add(name, **kwargs):
        kwargs.setdefault("domain", f"{name.replace('_', '-')}.example.com")
        cases.append({"name": name, "kwargs": kwargs})

    # One per app type, the default configuration.
    for app_type in ("wordpress", "php", "static", "application"):
        extra = {"app_port": 3000} if app_type == "application" else {}
        add(f"{app_type}_default", app_type=app_type, **extra)

    # WAF off, which flips a block in every template.
    add("wordpress_waf_off", app_type="wordpress", waf_enabled=False)

    # http-flood, which pulls in the zone and the challenge block.
    add("wordpress_flood", app_type="wordpress", http_flood_enabled=True)

    # Aliases change server_names, which is a join() in the template.
    add(
        "wordpress_aliases",
        app_type="wordpress",
        aliases=["alias1.example.com", "alias2.example.com"],
    )

    # Every rewrite mode, on the php template that implements them.
    for mode in ("front_controller", "laravel", "codeigniter", "seohburl"):
        add(f"php_{mode}", app_type="php", rewrite_mode=mode)

    # A non-default PHP version and document root.
    add("wordpress_php83", app_type="wordpress", php_version="8.3")
    add("php_subdir_root", app_type="php", document_root="public_html/public")

    # A custom directive block, which is inserted verbatim after validation.
    add(
        "wordpress_custom",
        app_type="wordpress",
        custom_directives="client_max_body_size 128M;",
    )

    # Blocked bots, which are post-processed rather than templated.
    add("wordpress_bots", app_type="wordpress", blocked_bots=["AhrefsBot", "SemrushBot"])

    # A non-default upstream port on the proxy template.
    add("application_port8080", app_type="application", app_port=8080)

    return cases


# ---------------------------------------------------------------------------
# C13 - IP/CIDR normalisation as the firewall stores it
# ---------------------------------------------------------------------------
def gen_ipnorm() -> None:
    """What `require_ip_or_cidr_normalized` produces, from the real ipaddress.

    The bash helper shells out to `ipaddress.ip_network(value, strict=False)`
    for every address that goes into rules.tsv, so the Rust side has to agree
    exactly or a rule written by one implementation will not match the
    duplicate check in the other.
    """
    import ipaddress

    print("C13 IP normalisation:")
    values = [
        "203.0.113.44",
        "203.0.113.44/32",
        "10.0.0.0/8",
        "10.0.0.5/8",          # host bits set: must be masked off
        "192.168.1.130/25",
        "172.16.255.255/12",
        "0.0.0.0/0",
        "255.255.255.255",
        "2001:db8::1",
        "2001:db8::1/128",
        "2001:db8::/32",
        "2001:db8:abcd:1234::1/48",   # host bits set
        "::/0",
        "fe80::1%0" if False else "fe80::1",
    ]
    out = {
        v: str(ipaddress.ip_network(v, strict=False))
        for v in values
    }
    w(HERE / "ipnorm.json", json.dumps(out, indent=2) + "\n")


def main() -> int:
    print(f"Generating fixtures into {HERE.relative_to(REPO)} and {GOLDEN.relative_to(REPO)}\n")
    gen_fernet()
    gen_bcrypt()
    gen_jwt()
    gen_totp()
    gen_ipnorm()
    gen_nginx_golden()
    print("\nDone.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
