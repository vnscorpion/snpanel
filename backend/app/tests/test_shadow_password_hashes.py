"""An account whose stored hash came from /etc/shadow must still log in.

Python 3.13 removed the `crypt` module (PEP 594) and Ubuntu 26.04 ships 3.14.
The panel catches the ImportError, so nothing crashes; what happens instead is
that `verify_shadow_password` returns False for every input and every account
imported from another panel is locked out with "incorrect password". No
traceback, no log line - which is why this is tested by behaviour rather than
by checking that an import succeeds.

passlib, already a dependency, could stand in for `$6$` but not for `$y$`
yescrypt, which is what Debian 12 and Ubuntu 24.04+ actually write. So the
yescrypt case is the one that matters.
"""

import pytest

from app.core import security


def crypt_impl():
    """Whatever this interpreter has: the stdlib module or the ctypes binding."""
    return security.unix_crypt


# A yescrypt salt has to be in yescrypt's own encoding. libcrypt signals a
# rejected salt by *returning* '*0' rather than raising, so a made-up salt
# produces a test that fails while the code is fine - which is what happened
# the first time this was written.
YESCRYPT_SALT = "$y$j9T$MJEXaVYnZUVDVSBNJcRR6/$"
SHA512_SALT = "$6$rounds=5000$snpaneltest$"


def make_hash(salt: str) -> str:
    impl = crypt_impl()
    if impl is None:
        pytest.skip("no crypt implementation on this interpreter")
    hashed = impl.crypt("correct horse", salt)
    if not hashed or hashed.startswith("*"):
        pytest.skip(f"this platform's libcrypt rejected the salt: {hashed!r}")
    return hashed


def test_there_is_a_crypt_implementation_at_all():
    """On 3.12 it is the stdlib module; on 3.14 it must be legacycrypt.

    None of the other tests in this file can fail meaningfully if this one
    does - they skip - so this is the one that would catch the dependency
    being dropped from requirements.txt.
    """
    assert crypt_impl() is not None, (
        "neither crypt nor legacycrypt is importable; every shadow-hash "
        "account would be locked out with 'incorrect password'"
    )


@pytest.mark.parametrize(("label", "salt"), [
    ("sha512-crypt", SHA512_SALT),
    ("yescrypt", YESCRYPT_SALT),
])
def test_a_shadow_hash_verifies(label, salt):
    hashed = make_hash(salt)
    assert security.is_shadow_password_hash(hashed), label
    assert security.verify_password("correct horse", hashed) is True, label


@pytest.mark.parametrize(("label", "salt"), [
    ("sha512-crypt", SHA512_SALT),
    ("yescrypt", YESCRYPT_SALT),
])
def test_the_wrong_password_is_still_refused(label, salt):
    hashed = make_hash(salt)
    assert security.verify_password("wrong horse", hashed) is False, label


def test_a_libcrypt_failure_token_is_not_treated_as_a_hash():
    """'*0' is how libcrypt says no. It must never verify against anything."""
    assert security.verify_shadow_password("correct horse", "*0") is False
    assert security.verify_shadow_password("", "*1") is False


def test_bcrypt_still_goes_through_passlib():
    """The shadow path must not swallow the panel's own hashes.

    Bcrypt prefixes are in SHADOW_HASH_PREFIXES too, so the ordering in
    verify_password is what keeps an ordinary admin login working.
    """
    hashed = security.hash_password("correct horse")
    assert hashed.startswith(security.BCRYPT_HASH_PREFIXES)
    assert security.verify_password("correct horse", hashed) is True
    assert security.verify_password("wrong horse", hashed) is False


def test_requirements_pin_the_fallback():
    """It is only a dependency on 3.13+, but it has to be declared somewhere."""
    from pathlib import Path

    requirements = (
        Path(__file__).resolve().parents[2] / "requirements.txt"
    ).read_text(encoding="utf-8")
    assert "legacycrypt" in requirements
