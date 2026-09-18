import base64
import logging
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime
from io import BytesIO
from threading import Lock
from typing import Deque, Dict, Optional

import pyotp
import qrcode
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_current_user_optional
from app.core.config import settings
from app.core.database import get_db
from app.core.permissions import Role, ensure_role
from app.core.security import create_access_token, hash_password, needs_rehash, verify_password
from app.core.secrets import decrypt, encrypt
from app.core.step_up import require_sensitive_action_step_up, verify_totp
from app.models.entities import RevokedToken, User
from app.schemas.schemas import (
    LoginResponse,
    TwoFactorDisableRequest,
    TwoFactorEnableRequest,
    TwoFactorSetup,
    TwoFactorSetupRequest,
    TwoFactorStatus,
)
from app.services import storage_quota
from app.services.audit import log_action
from app.services.sso_tokens import consume_panel_login_token

# Hard caps for credentials submitted to /auth/login. bcrypt accepts at most
# 72 bytes anyway and we never want to spend CPU comparing absurd payloads.
_MAX_USERNAME_LEN = 64
_MAX_PASSWORD_LEN = 72

router = APIRouter(prefix="/auth", tags=["auth"])


# Cookie names. The session cookie is HttpOnly so JavaScript cannot read it,
# which mitigates token theft via XSS. The CSRF cookie is readable by JS so
# the SPA can echo it in the X-CSRF-Token header for mutating requests
# (double-submit cookie pattern).
SESSION_COOKIE = "snpanel_session"
CSRF_COOKIE = "snpanel_csrf"
CSRF_HEADER = "X-CSRF-Token"


# Login rate limiter for /auth/login. Production uses Redis so counters are
# shared across uvicorn workers; development can opt into the in-process backend.
_LOGIN_WINDOW_SECONDS = 60
_LOGIN_MAX_ATTEMPTS = 8
_LOGIN_LOCKOUT_SECONDS = 15 * 60
_LOGIN_LOCKOUT_THRESHOLD = 20
_login_attempts: Dict[str, Deque[float]] = defaultdict(deque)
_login_failures: Dict[str, Deque[float]] = defaultdict(deque)
_login_lockouts: Dict[str, float] = {}
_login_lock = Lock()
_redis_client = None

# Pre-computed dummy bcrypt hash for constant-time fail path.
_DUMMY_HASH = hash_password("not-a-real-password-snpanel-dummy")


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _username_key(username: str) -> str:
    name = (username or "").strip().lower()
    return f"user:{name}" if name else "user:_unknown"


def _is_secure_request(request: Request) -> bool:
    """Decide whether to set the Secure cookie flag.

    True when the inbound request was HTTPS. The panel can also be served
    directly over http://IP:2222 during first install, so production mode alone
    must not force Secure cookies.
    """
    forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip().lower()
    if forwarded_proto == "https":
        return True
    if request.url.scheme == "https":
        return True
    return False


def _set_session_cookies(
    response: Response,
    request: Request,
    token: str,
    max_age_seconds: Optional[int] = None,
    csrf_token: Optional[str] = None,
) -> str:
    # A slide-renewed session keeps its CSRF value so a POST already in flight
    # with the old header still matches; a fresh login mints a new one.
    csrf_token = csrf_token or secrets.token_urlsafe(32)
    secure = _is_secure_request(request)
    max_age = (
        max_age_seconds
        if max_age_seconds is not None
        else settings.access_token_expire_minutes * 60
    )
    # HttpOnly session cookie: never visible to JS.
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="lax",
        path="/",
    )
    # CSRF cookie: readable by JS so the SPA can mirror it in a header.
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="lax",
        path="/",
    )
    return csrf_token


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


def _rate_limit_backend() -> str:
    return (settings.rate_limit_backend or "memory").lower()


def _redis() -> Redis:
    global _redis_client
    if _redis_client is None:
        _redis_client = Redis.from_url(settings.redis_url, decode_responses=True)
    return _redis_client


def _rate_limit_key(kind: str, key: str) -> str:
    return f"snpanel:login:{kind}:{key}"


def _rate_limit_unavailable(exc: Exception) -> HTTPException:
    # Kept for backward compatibility but no longer raised during login.
    # If Redis is down the rate limiter falls back to the in-memory backend
    # so that a Redis outage never blocks authentication.
    return HTTPException(status_code=503, detail="Login rate limiter is unavailable")


def _log_redis_fallback(exc: Exception) -> None:
    """Log a warning when Redis is unavailable and we fall back to memory."""
    logging.getLogger("snpanel.auth").warning(
        "Redis unavailable (%s), falling back to in-memory rate limiter", exc,
    )


def _raise_locked(retry_after: int) -> None:
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Too many login attempts. Try again later.",
        headers={"Retry-After": str(max(1, retry_after))},
    )


def _redis_enforce_rate_limit(key: str) -> None:
    now = time.time()
    attempts_key = _rate_limit_key("attempts", key)
    lockout_key = _rate_limit_key("lockout", key)
    try:
        client = _redis()
        retry_after = client.ttl(lockout_key)
        if retry_after and retry_after > 0:
            _raise_locked(int(retry_after))
        pipe = client.pipeline()
        pipe.zremrangebyscore(attempts_key, 0, now - _LOGIN_WINDOW_SECONDS)
        pipe.zcard(attempts_key)
        _, attempts_count = pipe.execute()
    except RedisError as exc:
        raise _rate_limit_unavailable(exc) from exc
    if attempts_count >= _LOGIN_MAX_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many login attempts. Slow down.",
            headers={"Retry-After": str(_LOGIN_WINDOW_SECONDS)},
        )


def _memory_enforce_rate_limit(key: str) -> None:
    now = time.monotonic()
    with _login_lock:
        locked_until = _login_lockouts.get(key)
        if locked_until and locked_until > now:
            retry_after = int(locked_until - now)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Try again later.",
                headers={"Retry-After": str(retry_after)},
            )
        if locked_until and locked_until <= now:
            _login_lockouts.pop(key, None)
        attempts = _login_attempts[key]
        cutoff = now - _LOGIN_WINDOW_SECONDS
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
        if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Slow down.",
                headers={"Retry-After": str(_LOGIN_WINDOW_SECONDS)},
            )


def _enforce_rate_limit(key: str) -> None:
    if _rate_limit_backend() == "redis":
        try:
            _redis_enforce_rate_limit(key)
            return
        except HTTPException as exc:
            if exc.status_code == 503:
                _log_redis_fallback(exc.detail)
            else:
                raise
    _memory_enforce_rate_limit(key)


def _redis_record_failure(key: str, *, apply_lockout: bool) -> None:
    """Record a login failure for ``key``.

    The short-window rate limit (``attempts_key``) always applies, so a single
    source cannot blast through more than ``_LOGIN_MAX_ATTEMPTS`` per minute.
    The long-window hard lockout (``lockout_key``) only applies when
    ``apply_lockout=True`` — used for IP keys, NOT for username keys, so
    attackers cannot lock out a specific account by submitting wrong
    passwords from many IPs (account-DoS).
    """
    now = time.time()
    member = f"{now}:{secrets.token_hex(8)}"
    attempts_key = _rate_limit_key("attempts", key)
    failures_key = _rate_limit_key("failures", key)
    lockout_key = _rate_limit_key("lockout", key)
    try:
        client = _redis()
        pipe = client.pipeline()
        pipe.zadd(attempts_key, {member: now})
        pipe.expire(attempts_key, _LOGIN_WINDOW_SECONDS)
        if apply_lockout:
            pipe.zremrangebyscore(failures_key, 0, now - _LOGIN_LOCKOUT_SECONDS)
            pipe.zadd(failures_key, {member: now})
            pipe.expire(failures_key, _LOGIN_LOCKOUT_SECONDS)
            pipe.zcard(failures_key)
            *_, failure_count = pipe.execute()
            if failure_count >= _LOGIN_LOCKOUT_THRESHOLD:
                client.set(lockout_key, "1", ex=_LOGIN_LOCKOUT_SECONDS)
        else:
            pipe.execute()
    except RedisError as exc:
        raise _rate_limit_unavailable(exc) from exc


def _memory_record_failure(key: str, *, apply_lockout: bool) -> None:
    now = time.monotonic()
    with _login_lock:
        attempts = _login_attempts[key]
        attempts.append(now)
        # Always clean up old attempts — do this before the apply_lockout guard
        # so the list doesn't grow unbounded when lockout is not applied.
        cutoff = now - _LOGIN_WINDOW_SECONDS
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
        if not apply_lockout:
            return
        failures = _login_failures[key]
        failures.append(now)
        failure_cutoff = now - _LOGIN_LOCKOUT_SECONDS
        while failures and failures[0] < failure_cutoff:
            failures.popleft()
        if len(failures) >= _LOGIN_LOCKOUT_THRESHOLD:
            _login_lockouts[key] = now + _LOGIN_LOCKOUT_SECONDS


def _record_failure(key: str, *, apply_lockout: bool = True) -> None:
    if _rate_limit_backend() == "redis":
        try:
            _redis_record_failure(key, apply_lockout=apply_lockout)
            return
        except HTTPException as exc:
            if exc.status_code == 503:
                _log_redis_fallback(exc.detail)
            else:
                raise
    _memory_record_failure(key, apply_lockout=apply_lockout)


def _redis_record_success(key: str) -> None:
    try:
        _redis().delete(
            _rate_limit_key("attempts", key),
            _rate_limit_key("failures", key),
            _rate_limit_key("lockout", key),
        )
    except RedisError as exc:
        raise _rate_limit_unavailable(exc) from exc


def _record_success(key: str) -> None:
    if _rate_limit_backend() == "redis":
        try:
            _redis_record_success(key)
            return
        except HTTPException as exc:
            if exc.status_code == 503:
                _log_redis_fallback(exc.detail)
            else:
                raise
    with _login_lock:
        _login_attempts.pop(key, None)
        _login_failures.pop(key, None)
        _login_lockouts.pop(key, None)


def _issue_login_session(
    response: Response,
    request: Request,
    user: User,
    extra_claims: Optional[dict] = None,
    lifetime_minutes: Optional[int] = None,
) -> str:
    token_extra = {"role": user.role, "tv": user.token_version or 0}
    if extra_claims:
        token_extra.update(extra_claims)
    token = create_access_token(user.username, token_extra, expires_minutes=lifetime_minutes)
    max_age = (lifetime_minutes or settings.access_token_expire_minutes) * 60
    _set_session_cookies(response, request, token, max_age_seconds=max_age)
    return token


# Re-issue a cookie session once it is more than halfway through its life, so an
# admin who keeps the panel open is never bounced to the login screen and the
# fixed lifetime becomes an *idle* timeout instead. token_version still revokes
# every session at once; a stolen token still dies at its original expiry unless
# the thief keeps it warm - the usual sliding-session trade-off.
_SESSION_RENEW_RATIO = 0.5


def maybe_renew_session_cookie(request: Request, response: Response) -> None:
    payload = getattr(request.state, "jwt_payload", None)
    token = getattr(request.state, "jwt_token", None)
    if not payload or not token:
        return
    # Slide browser (cookie) sessions only, never a bearer token.
    if request.cookies.get(SESSION_COOKIE) != token:
        return
    # Impersonation ("Login as") sessions keep their hard expiry - an admin
    # acting as another user must re-initiate rather than stay in it forever.
    if payload.get("imp"):
        return
    # Leave alone any response that already set its own session cookie
    # (login, logout, 2FA toggle, impersonate).
    for raw_name, raw_value in response.raw_headers:
        if raw_name.lower() == b"set-cookie" and raw_value.startswith(SESSION_COOKIE.encode() + b"="):
            return
    try:
        iat = float(payload["iat"])
        exp = float(payload["exp"])
    except (KeyError, TypeError, ValueError):
        return
    lifetime = exp - iat
    now = time.time()
    if lifetime <= 0 or exp <= now:
        return
    if (exp - now) > lifetime * _SESSION_RENEW_RATIO:
        return
    extra = {"role": payload.get("role"), "tv": payload.get("tv", 0)}
    # round(), not truncate, so the lifetime does not creep downward a little
    # with every renewal; clamp to at least a minute so a short token cannot be
    # re-issued already expired.
    new_token = create_access_token(
        payload["sub"], extra, expires_minutes=max(1, round(lifetime / 60))
    )
    _set_session_cookies(
        response,
        request,
        new_token,
        max_age_seconds=int(lifetime),
        csrf_token=request.cookies.get(CSRF_COOKIE),
    )


def _jwt_expiry_from_payload(payload: dict) -> datetime:
    raw_exp = payload.get("exp")
    if isinstance(raw_exp, (int, float)):
        return datetime.utcfromtimestamp(raw_exp)
    return datetime.utcnow()


def _revoke_request_token(db: Session, request: Request, user: User) -> None:
    payload = getattr(request.state, "jwt_payload", {}) or {}
    jti = payload.get("jti")
    if not jti:
        return
    now = datetime.utcnow()
    db.query(RevokedToken).filter(RevokedToken.expires_at <= now).delete()
    if db.query(RevokedToken.id).filter(RevokedToken.jti == jti).first():
        return
    db.add(RevokedToken(jti=jti, user_id=user.id, expires_at=_jwt_expiry_from_payload(payload), revoked_at=now))


def _get_totp_secret(user: User) -> str:
    return decrypt(user.totp_secret or "")


def _verify_totp(user: User, code: str) -> bool:
    return verify_totp(user, code)


def _qr_data_url(uri: str) -> str:
    image = qrcode.make(uri)
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


@router.post("/login", response_model=LoginResponse)
def login(
    request: Request,
    response: Response,
    form: OAuth2PasswordRequestForm = Depends(),
    otp: str = Form(default=""),
    remember: str = Form(default=""),
    db: Session = Depends(get_db),
):
    # Reject oversize credentials early — protects bcrypt and avoids using a
    # huge string as a rate-limit/lockout key.
    if len(form.username) > _MAX_USERNAME_LEN or len(form.password) > _MAX_PASSWORD_LEN:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    ip_key = _client_key(request)
    user_key = _username_key(form.username)
    # IP key gets full lockout (slow attacker from one source).
    _enforce_rate_limit(ip_key)
    # Username key only enforces the short-window rate limit; the lockout
    # check is intentionally skipped so an attacker cannot DoS a known
    # account by spraying wrong passwords from many IPs.
    _enforce_rate_limit(user_key)

    user = db.query(User).filter(User.username == form.username).first()
    if user:
        password_ok = verify_password(form.password, user.hashed_password)
    else:
        verify_password(form.password, _DUMMY_HASH)
        password_ok = False

    if not user or not password_ok:
        _record_failure(ip_key, apply_lockout=True)
        _record_failure(user_key, apply_lockout=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User is suspended",
        )

    if user.totp_enabled:
        if not otp:
            return LoginResponse(requires_2fa=True)
        if not _verify_totp(user, otp):
            _record_failure(ip_key, apply_lockout=True)
            _record_failure(user_key, apply_lockout=False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication code",
            )

    _record_success(ip_key)
    _record_success(user_key)
    if needs_rehash(user.hashed_password):
        try:
            user.hashed_password = hash_password(form.password)
            db.commit()
        except Exception:  # pragma: no cover
            db.rollback()
    remember_me = remember.strip().lower() in {"1", "true", "on", "yes"}
    lifetime = settings.remember_me_expire_minutes if remember_me else None
    token = _issue_login_session(response, request, user, lifetime_minutes=lifetime)

    # Bearer token still returned for backward compatibility with CLI tools or
    # mobile clients that cannot set cookies. Browser clients should ignore it
    # and rely on the HttpOnly cookie set above.
    return LoginResponse(access_token=token)


@router.get("/sso/{token}")
def sso_login(token: str, request: Request, db: Session = Depends(get_db)):
    data = consume_panel_login_token(token)
    if not data:
        raise HTTPException(status_code=404, detail="Invalid or expired token")

    username = (data.get("username") or "").strip()
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=404, detail="Invalid or expired token")
    if not user.is_active:
        return RedirectResponse(url="/?error=account_suspended", status_code=302)

    response = RedirectResponse(url="/", status_code=302)
    _issue_login_session(response, request, user)
    log_action(db, None, "auth.sso", user.username, detail="provisioning", request=request)
    return response


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Invalidate the session by clearing cookies AND bumping token_version.

    The current JWT's jti is stored server-side, and bumping token_version
    forces all other devices/tabs holding a JWT for this user to re-authenticate.
    """
    _revoke_request_token(db, request, current_user)
    current_user.token_version = (current_user.token_version or 0) + 1
    db.commit()
    _clear_session_cookies(response)
    return {"ok": True}


@router.get("/session")
def session_status(
    response: Response,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
):
    if current_user is None:
        _clear_session_cookies(response)
        return {"authenticated": False, "user": None}
    user_data = {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "is_active": current_user.is_active,
        "package_name": current_user.package.name if current_user.package else None,
        "website_limit": current_user.website_limit,
        "storage_limit_mb": current_user.storage_limit_mb,
        "totp_enabled": current_user.totp_enabled,
    }
    user_data.update(storage_quota.storage_usage_summary(db, current_user))
    return {"authenticated": True, "user": user_data}


@router.post("/impersonate/{user_id}", response_model=LoginResponse)
def impersonate_user(
    user_id: int,
    request: Request,
    response: Response,
    otp: str = Form(default=""),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Issue a session cookie for ``user_id`` while the caller stays admin.

    Impersonation is a high-trust operation: it bypasses normal auth for the
    target account. We therefore (1) require the admin to re-prove possession
    of their TOTP if 2FA is enabled, and (2) audit-log every successful
    impersonation with the actor and target identities.
    """
    ensure_role(current_user.role, Role.admin)

    # Rate-limit impersonation attempts to prevent enumeration of user IDs.
    _enforce_rate_limit(_client_key(request))
    _enforce_rate_limit(_username_key(current_user.username))

    target_user = db.query(User).filter(User.id == user_id).first()
    if target_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Re-prompt TOTP for admins that have 2FA. Refusing without a code keeps
    # the feature usable from the SPA (which can pop a modal on 401) while
    # blocking session-stealing attackers who don't have the admin's phone.
    if current_user.totp_enabled:
        if not otp:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Two-factor authentication code required",
            )
        if not _verify_totp(current_user, otp):
            _record_failure(_client_key(request), apply_lockout=True)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication code",
            )

    # Audit log must be written before the session is issued so a DB failure
    # doesn't leave an impersonation succeeded with no audit trail.
    log_action(
        db,
        current_user.id,
        "auth.impersonate",
        target_user.username,
        detail=f"target_user_id={target_user.id} target_role={target_user.role}",
        request=request,
    )
    token = _issue_login_session(response, request, target_user, extra_claims={"imp": True})
    return LoginResponse(access_token=token)


@router.get("/csrf")
def get_csrf(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
):
    """Return (and refresh) the CSRF cookie for the current session.

    The SPA calls this on bootstrap when the cookie is missing, e.g. after a
    page reload that pre-dates this code change.
    """
    secure = _is_secure_request(request)
    csrf_token = request.cookies.get(CSRF_COOKIE) or secrets.token_urlsafe(32)
    response.set_cookie(
        CSRF_COOKIE,
        csrf_token,
        max_age=settings.access_token_expire_minutes * 60,
        httponly=False,
        secure=secure,
        samesite="lax",
        path="/",
    )
    return {"csrf_token": csrf_token}


@router.get("/2fa/status", response_model=TwoFactorStatus)
def two_factor_status(current_user: User = Depends(get_current_user)):
    return TwoFactorStatus(enabled=bool(current_user.totp_enabled))


@router.post("/2fa/setup", response_model=TwoFactorSetup)
def setup_two_factor(
    payload: TwoFactorSetupRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_sensitive_action_step_up(current_user, payload.current_password, payload.code)
    if current_user.totp_enabled:
        raise HTTPException(status_code=400, detail="Two-factor authentication is already enabled")
    secret = pyotp.random_base32()
    current_user.totp_secret = encrypt(secret)
    db.commit()
    account_name = current_user.email or current_user.username
    uri = pyotp.TOTP(secret).provisioning_uri(name=account_name, issuer_name=settings.totp_issuer)
    return TwoFactorSetup(secret=secret, provisioning_uri=uri, qr_data_url=_qr_data_url(uri))


@router.post("/2fa/enable", response_model=TwoFactorStatus)
def enable_two_factor(
    payload: TwoFactorEnableRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="Set up two-factor authentication first")
    if not _verify_totp(current_user, payload.code):
        raise HTTPException(status_code=400, detail="Invalid authentication code")
    if not current_user.totp_enabled:
        current_user.totp_enabled = True
        current_user.token_version = (current_user.token_version or 0) + 1
        db.commit()
        db.refresh(current_user)
    _issue_login_session(response, request, current_user)
    return TwoFactorStatus(enabled=True)


@router.post("/2fa/disable", response_model=TwoFactorStatus)
def disable_two_factor(
    payload: TwoFactorDisableRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    require_sensitive_action_step_up(current_user, payload.current_password, payload.code)
    current_user.totp_enabled = False
    current_user.totp_secret = None
    current_user.token_version = (current_user.token_version or 0) + 1
    db.commit()
    db.refresh(current_user)
    _issue_login_session(response, request, current_user)
    return TwoFactorStatus(enabled=False)
