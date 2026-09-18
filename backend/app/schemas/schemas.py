import re
from datetime import datetime
import json
from typing import Literal, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


DOMAIN_RE = re.compile(r"^(?!-)([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$")
SUPPORTED_PHP_VERSIONS = {"5.6", "7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"}
SUPPORTED_APP_TYPES = {"wordpress", "php", "static", "application"}
SUPPORTED_NGINX_REWRITE_MODES = {"none", "front_controller", "laravel", "codeigniter", "seohburl"}
SUPPORTED_ROLES = {"admin", "end_user"}
SIZE_RE = re.compile(r"^\d{1,6}[KMG]?$")  # e.g. "512M", "1024M"
PANEL_HOST_RE = re.compile(r"^(?:localhost|(?:\d{1,3}\.){3}\d{1,3}|(?:(?!-)[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,})$")
RESERVED_LINUX_USERNAMES = {
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "nginx", "backup", "list", "irc", "_apt",
    "nobody", "snpanel", "snpanel-sites", "snpanel-sftp", "mysql", "redis", "nginx",
}


def _validate_linux_login_password(value: str) -> str:
    if any(char in value for char in (":", "\r", "\n", "\x00")):
        raise ValueError("password cannot contain ':', newlines, or NUL characters because it is synced to the Linux/SFTP account")
    return value


def _validate_php_version(value: Optional[str]) -> Optional[str]:
    if value is None:
        return value
    if value not in SUPPORTED_PHP_VERSIONS:
        raise ValueError(f"Unsupported PHP version. Allowed: {sorted(SUPPORTED_PHP_VERSIONS)}")
    return value


def _validate_app_type(value: Optional[str]) -> Optional[str]:
    if value is None:
        return value
    if value not in SUPPORTED_APP_TYPES:
        raise ValueError(f"Unsupported app type. Allowed: {sorted(SUPPORTED_APP_TYPES)}")
    return value


def _validate_nginx_rewrite_mode(value: Optional[str]) -> Optional[str]:
    if value is None:
        return value
    normalized = value.strip().lower()
    if normalized not in SUPPORTED_NGINX_REWRITE_MODES:
        raise ValueError(f"Unsupported nginx rewrite mode. Allowed: {sorted(SUPPORTED_NGINX_REWRITE_MODES)}")
    return normalized


def _validate_document_root(value: Optional[str]) -> Optional[str]:
    if value is None:
        return value
    cleaned = value.strip().replace("\\", "/")
    if cleaned.startswith("/") or re.match(r"^[A-Za-z]:/", cleaned):
        raise ValueError("document_root must be relative to the website root")
    cleaned = cleaned.strip("/")
    if not cleaned or len(cleaned) > 255:
        raise ValueError("document_root must be a relative path up to 255 characters")
    parts = cleaned.split("/")
    if any(part in {"", ".", ".."} or not re.fullmatch(r"[A-Za-z0-9._-]+", part) for part in parts):
        raise ValueError("document_root must be a safe relative path such as public_html/public")
    return "/".join(parts)


def _validate_panel_url(value: Optional[str]) -> Optional[str]:
    if value is None:
        return value
    value = value.strip()
    if not value:
        return value
    test_value = value if "://" in value else f"http://{value}"
    parsed = urlparse(test_value)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("panel_url must start with http:// or https://")
    host = parsed.hostname or ""
    if not PANEL_HOST_RE.fullmatch(host):
        raise ValueError("panel_url host must be a domain name or IPv4 address")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("panel_url port is invalid") from exc
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("panel_url port is out of range")
    return value


def _validate_panel_hostname(value: Optional[str]) -> Optional[str]:
    if value is None:
        return value
    value = value.strip().lower().rstrip(".")
    if not value:
        return value
    if "://" in value or "/" in value or ":" in value:
        raise ValueError("panel_hostname must be a hostname or IPv4 address only")
    if not PANEL_HOST_RE.fullmatch(value):
        raise ValueError("panel_hostname must be a domain name or IPv4 address")
    return value


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginResponse(BaseModel):
    access_token: Optional[str] = None
    token_type: str = "bearer"
    requires_2fa: bool = False


class TwoFactorStatus(BaseModel):
    enabled: bool


class TwoFactorSetup(BaseModel):
    secret: str
    provisioning_uri: str
    qr_data_url: str


class TwoFactorCode(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class TwoFactorSetupRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=72)
    code: Optional[str] = Field(default=None, min_length=6, max_length=12)


class TwoFactorEnableRequest(BaseModel):
    code: str = Field(min_length=6, max_length=12)


class TwoFactorDisableRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=72)
    code: Optional[str] = Field(default=None, min_length=6, max_length=12)


class UserPackageCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    slug: Optional[str] = Field(default=None, max_length=100)
    website_limit: int = Field(default=5, ge=0, le=1000)
    storage_limit_mb: int = Field(default=1024, ge=0, le=1024 * 1024)
    database_limit: int = Field(default=5, ge=0, le=10000)
    alias_limit: int = Field(default=0, ge=0, le=1000)
    backup_retention_days: int = Field(default=7, ge=0, le=365)
    terminal_enabled: bool = False
    waf_enabled: bool = True
    wordpress_enabled: bool = True
    node_apps_limit: int = Field(default=0, ge=0, le=100)
    node_app_memory_mb: int = Field(default=512, ge=64, le=16384)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        value = re.sub(r"\s+", " ", value.strip())
        if not value:
            raise ValueError("name is required")
        return value


class UserPackageUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    slug: Optional[str] = Field(default=None, max_length=100)
    website_limit: Optional[int] = Field(default=None, ge=0, le=1000)
    storage_limit_mb: Optional[int] = Field(default=None, ge=0, le=1024 * 1024)
    database_limit: Optional[int] = Field(default=None, ge=0, le=10000)
    alias_limit: Optional[int] = Field(default=None, ge=0, le=1000)
    backup_retention_days: Optional[int] = Field(default=None, ge=0, le=365)
    terminal_enabled: Optional[bool] = None
    waf_enabled: Optional[bool] = None
    wordpress_enabled: Optional[bool] = None
    node_apps_limit: Optional[int] = Field(default=None, ge=0, le=100)
    node_app_memory_mb: Optional[int] = Field(default=None, ge=64, le=16384)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = re.sub(r"\s+", " ", value.strip())
        if not value:
            raise ValueError("name is required")
        return value


class UserPackageOut(BaseModel):
    id: int
    name: str
    slug: Optional[str] = None
    website_limit: int
    storage_limit_mb: int
    database_limit: int = 5
    alias_limit: int = 0
    backup_retention_days: int = 7
    terminal_enabled: bool = False
    waf_enabled: bool = True
    wordpress_enabled: bool = True
    node_apps_limit: int = 0
    node_app_memory_mb: int = 512
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-z_][a-z0-9_-]{2,31}$")
    email: EmailStr
    password: str = Field(min_length=12, max_length=72)  # bcrypt 72-byte limit
    role: Literal["admin", "end_user"] = "end_user"
    package_id: Optional[int] = Field(default=None, ge=1)
    website_limit: int = Field(default=5, ge=0, le=1000)
    storage_limit_mb: int = Field(default=1024, ge=0, le=1024 * 1024)

    @field_validator("username")
    @classmethod
    def validate_linux_safe_username(cls, value: str) -> str:
        if value in RESERVED_LINUX_USERNAMES:
            raise ValueError("username is reserved by the system")
        return value

    @field_validator("password")
    @classmethod
    def validate_sftp_password(cls, value: str) -> str:
        return _validate_linux_login_password(value)


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    role: Optional[Literal["admin", "end_user"]] = None
    is_active: Optional[bool] = None
    package_id: Optional[int] = Field(default=None, ge=1)
    website_limit: Optional[int] = Field(default=None, ge=0, le=1000)
    storage_limit_mb: Optional[int] = Field(default=None, ge=0, le=1024 * 1024)


class UserPasswordUpdate(BaseModel):
    password: str = Field(min_length=12, max_length=72)
    current_password: Optional[str] = Field(default=None, min_length=1, max_length=72)
    code: Optional[str] = Field(default=None, min_length=6, max_length=12)

    @field_validator("password")
    @classmethod
    def validate_sftp_password(cls, value: str) -> str:
        return _validate_linux_login_password(value)


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    package_id: Optional[int] = None
    package_name: Optional[str] = None
    website_limit: int
    storage_limit_mb: int
    storage_used_bytes: int = 0
    storage_limit_bytes: Optional[int] = None
    storage_percent: float = 0.0
    totp_enabled: bool = False

    class Config:
        from_attributes = True


class AuditLogOut(BaseModel):
    id: int
    user_id: Optional[int] = None
    action: str
    target: str
    detail: str = ""
    created_at: Optional[str] = None

    class Config:
        from_attributes = True

    @classmethod
    def from_row(cls, row) -> "AuditLogOut":
        return cls(
            id=row.id,
            user_id=row.user_id,
            action=row.action,
            target=row.target,
            detail=row.detail or "",
            created_at=row.created_at.isoformat() if row.created_at else None,
        )


class WebsiteCreate(BaseModel):
    domain: str
    owner_id: Optional[int] = None
    php_version: str = "8.4"
    app_type: str = "wordpress"
    # Required when app_type is "application": which installed app to serve.
    app_id: Optional[int] = None
    install_wordpress: bool = True
    title: str = "My WordPress Site"
    admin_user: str = "admin"
    admin_email: Optional[EmailStr] = None
    admin_password: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def ignore_wordpress_fields_for_plain_sites(cls, values):
        if not isinstance(values, dict):
            return values
        app_type = values.get("app_type") or "wordpress"
        install_wordpress = bool(values.get("install_wordpress", True))
        if app_type != "wordpress" or not install_wordpress:
            values = dict(values)
            values["admin_email"] = None
            values["admin_password"] = None
        return values

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        value = value.strip().lower()
        if not DOMAIN_RE.match(value):
            raise ValueError("Invalid domain")
        return value

    @field_validator("php_version")
    @classmethod
    def validate_php(cls, value: str) -> str:
        return _validate_php_version(value)

    @field_validator("app_type")
    @classmethod
    def validate_app(cls, value: str) -> str:
        return _validate_app_type(value)

    @field_validator("admin_password")
    @classmethod
    def validate_admin_password(cls, value: Optional[str]) -> Optional[str]:
        if value is None or value == "":
            return value
        if len(value) < 10:
            raise ValueError("admin_password must be at least 10 characters")
        return value


class WebsiteWordPressInstall(BaseModel):
    title: str = Field(default="", max_length=120)
    admin_user: str = Field(default="admin", min_length=1, max_length=60)
    admin_email: EmailStr
    admin_password: str = Field(min_length=10, max_length=72)


class WebsiteUpdate(BaseModel):
    php_version: Optional[str] = None
    app_type: Optional[str] = None
    app_id: Optional[int] = None
    document_root: Optional[str] = None
    status: Optional[str] = None
    owner_id: Optional[int] = None
    nginx_custom: Optional[str] = None
    nginx_rewrite_mode: Optional[str] = None
    waf_enabled: Optional[bool] = None
    http_flood_enabled: Optional[bool] = None

    @field_validator("php_version")
    @classmethod
    def validate_php(cls, value: Optional[str]) -> Optional[str]:
        return _validate_php_version(value)

    @field_validator("app_type")
    @classmethod
    def validate_app(cls, value: Optional[str]) -> Optional[str]:
        return _validate_app_type(value)

    @field_validator("nginx_rewrite_mode")
    @classmethod
    def validate_nginx_rewrite_mode(cls, value: Optional[str]) -> Optional[str]:
        return _validate_nginx_rewrite_mode(value)

    @field_validator("document_root")
    @classmethod
    def validate_document_root(cls, value: Optional[str]) -> Optional[str]:
        return _validate_document_root(value)

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        allowed = {"active", "suspended", "pending"}
        if value not in allowed:
            raise ValueError(f"status must be one of {sorted(allowed)}")
        return value


class WebsiteNginxCustom(BaseModel):
    nginx_custom: str = ""


class WebsiteNginxConfig(BaseModel):
    nginx_config: str = Field(default="", max_length=128 * 1024)

    @field_validator("nginx_config")
    @classmethod
    def validate_nginx_config(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("nginx_config contains a NUL byte")
        return value.replace("\r\n", "\n").strip() + "\n"


class WebsiteWafUpdate(BaseModel):
    waf_enabled: bool


class WebsiteBotBlockUpdate(BaseModel):
    """One website's bot list. Free text: the service layer splits and cleans it,
    so the operator can paste a list in whatever shape they copied it."""

    blocked_bots: str = ""


class WafGlobalBotsUpdate(BaseModel):
    """The server-wide bad-bot list. Free text, cleaned by the service layer."""

    blocked_bots: str = ""


class WafBotBlockApply(BaseModel):
    """Apply one list to several websites at once.

    `replace` overwrites each site's list; `add` merges into what is already
    there. Merging is the safer default for importing a public blocklist on top
    of entries an operator added by hand, but replace is what you want when the
    imported list is the source of truth, so both are offered explicitly.
    """

    blocked_bots: str = ""
    website_ids: list[int] = Field(default_factory=list)
    mode: Literal["replace", "add"] = "add"


class WebsiteHttpFloodUpdate(BaseModel):
    http_flood_enabled: bool
    access_limit_requests: int = Field(default=100, ge=1, le=100000)
    access_limit_window: int = Field(default=10, ge=1, le=3600)
    access_limit_burst: int = Field(default=100, ge=0, le=100000)
    connection_limit: int = Field(default=60, ge=1, le=10000)


class WebsiteAliasCreate(BaseModel):
    domain: str
    mode: Literal["alias", "redirect"] = "alias"

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: str) -> str:
        value = value.strip().lower()
        if not DOMAIN_RE.match(value):
            raise ValueError("Invalid domain")
        return value


class WebsiteAliasOut(BaseModel):
    id: int
    website_id: int
    domain: str
    mode: Literal["alias", "redirect"] = "alias"
    ssl_enabled: bool = False
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class WildcardSslRequest(BaseModel):
    # Optional: omit to reuse the token already saved for the detected zone.
    cloudflare_api_token: Optional[str] = None

    @field_validator("cloudflare_api_token")
    @classmethod
    def _clean_token(cls, value: Optional[str]) -> Optional[str]:
        value = (value or "").strip()
        return value or None


class SharedSslRequest(BaseModel):
    source_domain: str

    @field_validator("source_domain")
    @classmethod
    def _validate_source(cls, value: str) -> str:
        value = value.strip().lower()
        if not DOMAIN_RE.match(value):
            raise ValueError("Invalid source domain")
        return value


class SslSourceOut(BaseModel):
    domain: str
    ssl_mode: str
    wildcard: bool = False
    not_after: str = ""


class CloudflareZoneOut(BaseModel):
    zone: Optional[str] = None
    has_token: bool = False


class WebsiteLogOut(BaseModel):
    domain: str
    kind: Literal["access", "error"]
    path: str
    lines: int
    content: str = ""
    exists: bool = False


class WebsiteAccessLogOut(BaseModel):
    id: str
    domain: str
    verdict: Literal["allow", "block", "error"]
    timestamp: str = ""
    duration_ms: int = 0
    ip: str = ""
    country: str = ""
    country_code: str = ""
    method: str = ""
    path: str = ""
    protocol: str = ""
    status: int = 0
    reason: str = ""
    user_agent: str = ""
    referer: str = ""
    raw: str = ""


class WebsiteAccessLogsOut(BaseModel):
    items: list[WebsiteAccessLogOut] = []
    total: int = 0
    scanned: int = 0
    limit: int = 50
    lines: int = 5000
    verdict: Literal["all", "allow", "block", "error"] = "all"
    query: str = ""
    missing: list[str] = []
    generated_at: str = ""


class SystemAutoUpdateConfig(BaseModel):
    enabled: bool = True
    mode: Literal["security", "all"] = "security"
    auto_reboot: bool = False


class DatabasePasswordUpdate(BaseModel):
    password: str = Field(min_length=12)


class DatabaseCreate(BaseModel):
    db_name: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")
    db_user: Optional[str] = Field(default=None, min_length=1, max_length=64, pattern=r"^[a-z0-9_]+$")
    db_password: Optional[str] = Field(default=None, min_length=12, max_length=128)

    @field_validator("db_name", mode="before")
    @classmethod
    def validate_db_name(cls, value) -> str:
        if value is None or value == "":
            raise ValueError("db_name is required")
        return str(value).strip().lower()

    @field_validator("db_user", mode="before")
    @classmethod
    def validate_db_user(cls, value) -> Optional[str]:
        if value is None or value == "":
            return None
        return str(value).strip().lower()

    @field_validator("db_password", mode="before")
    @classmethod
    def validate_db_password(cls, value) -> Optional[str]:
        if value is None or value == "":
            return None
        return value


class CronDelete(BaseModel):
    website_id: int
    index: int


class ComposeValidateRequest(BaseModel):
    compose_source: str
    web_service: Optional[str] = None
    # Which of the web service's ports the domain reaches, when it declares more
    # than one.
    web_port: Optional[int] = Field(default=None, ge=1, le=65535)
    # The .env box, so a file written against one validates as it will run.
    env: str = ""


class SiteAppCreate(BaseModel):
    name: str = "app"
    kind: Literal["node", "docker", "compose"] = "node"
    # Compose runtimes: the file the customer pasted and which service serves
    # the domain.
    compose_source: Optional[str] = None
    web_service: Optional[str] = None
    # Admins may create an app on behalf of another panel user.
    owner_id: Optional[int] = None
    # Omit to let the panel pick a free port from its own range.
    port: Optional[int] = None
    start_kind: Optional[Literal["node", "npm", "npx", "yarn"]] = None
    start_arg: Optional[str] = None
    node_major: Optional[str] = None
    image: Optional[str] = None
    container_port: Optional[int] = None
    cpu_limit: Optional[str] = None
    env: Optional[str] = None
    memory_limit_mb: Optional[int] = None
    autostart: bool = True


class SiteAppUpdate(BaseModel):
    name: Optional[str] = None
    port: Optional[int] = None
    compose_source: Optional[str] = None
    web_service: Optional[str] = None
    start_kind: Optional[Literal["node", "npm", "npx", "yarn"]] = None
    start_arg: Optional[str] = None
    node_major: Optional[str] = None
    image: Optional[str] = None
    container_port: Optional[int] = None
    cpu_limit: Optional[str] = None
    env: Optional[str] = None
    memory_limit_mb: Optional[int] = None
    autostart: Optional[bool] = None


class SiteAppControl(BaseModel):
    action: Literal["start", "stop", "restart"]


class NodeInstallRequest(BaseModel):
    major: str


class SiteAppOut(BaseModel):
    id: int
    owner_id: int
    name: str
    kind: str
    port: int
    start_kind: Optional[str] = None
    start_arg: Optional[str] = None
    node_major: Optional[str] = None
    image: Optional[str] = None
    container_port: int = 3000
    cpu_limit: str = "1"
    env: str = ""
    compose_source: str = ""
    web_service: Optional[str] = None
    memory_limit_mb: int = 512
    autostart: bool = True
    status: str = "stopped"
    last_error: str = ""
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class WebsiteOut(BaseModel):
    id: int
    domain: str
    owner_id: int
    root_path: str
    document_root: str = "public_html"
    linux_user: Optional[str] = None
    panel_username: Optional[str] = None
    panel_password: Optional[str] = None
    php_version: str
    app_type: str
    ssl_enabled: bool
    ssl_mode: str = "none"
    ssl_source_domain: Optional[str] = None
    ssl_updated_at: Optional[datetime] = None
    ssl_has_ca: bool = False
    ssl_cert_path: Optional[str] = Field(default=None, exclude=True)
    ssl_key_path: Optional[str] = Field(default=None, exclude=True)
    ssl_ca_path: Optional[str] = Field(default=None, exclude=True)
    status: str
    nginx_custom: str = ""
    nginx_config_mode: str = "managed"
    nginx_rewrite_mode: str = "none"
    waf_enabled: bool = True
    waf_default_rules: str = ""
    waf_custom_rules: str = ""
    http_flood_enabled: bool = False
    http_flood_config: str = ""
    blocked_bots: str = ""
    wordpress_installed: bool = False
    app_id: Optional[int] = None
    aliases: list[WebsiteAliasOut] = Field(default_factory=list)

    class Config:
        from_attributes = True

    @model_validator(mode="after")
    def derive_ssl_fields(self):
        if not self.ssl_mode:
            self.ssl_mode = "letsencrypt" if self.ssl_enabled else "none"
        self.ssl_has_ca = bool(self.ssl_ca_path)
        return self


class DatabaseOut(BaseModel):
    id: int
    owner_id: int
    website_id: Optional[int] = None
    db_name: str
    db_user: str

    class Config:
        from_attributes = True


class DatabaseCreatedOut(DatabaseOut):
    db_password: str


class ServiceAction(BaseModel):
    name: str
    action: str


class PanelSettingsOut(BaseModel):
    app_name: str = "SNPanel"
    panel_url: str = ""
    panel_hostname: str = ""
    panel_port: int = 2222
    logo_url: str = ""
    favicon_url: str = "/favicon.png"
    ssl_enabled: bool = False
    # none | selfsigned | letsencrypt | domain — where the certificate came from,
    # so the panel can say whether the browser warning is expected.
    ssl_mode: str = "none"
    # available: this machine has a global IPv6 address at all.
    # enabled: the websites and the panel are listening on it.
    ipv6: dict = {}
    # The server's own public IPv4 addresses, for the settings page to show.
    server_ipv4: list[str] = []
    message: Optional[str] = None
    # Optional ClamAV malware scanning status (always present, defaults off).
    malware_scan_enabled: bool = False
    malware_scan_installed: bool = False
    malware_scan_active: bool = False
    malware_scan_detail: Optional[str] = None


class MalwareScanToggle(BaseModel):
    enabled: bool = False


class MalwareScheduleEntry(BaseModel):
    enabled: bool = False
    weekday: int = 6          # Monday is 0
    weekday_label: str = ""
    hour: int = 3
    next_run_at: str = ""
    last_run_at: str = ""
    last_status: str = ""
    last_message: str = ""
    last_job_id: str = ""


class MalwareSchedulesOut(BaseModel):
    websites: MalwareScheduleEntry = MalwareScheduleEntry()
    server: MalwareScheduleEntry = MalwareScheduleEntry()


class MalwareScheduleEntryUpdate(BaseModel):
    enabled: Optional[bool] = None
    weekday: Optional[int] = None
    hour: Optional[int] = None


class MalwareSchedulesUpdate(BaseModel):
    websites: Optional[MalwareScheduleEntryUpdate] = None
    server: Optional[MalwareScheduleEntryUpdate] = None


class MalwareRealtimeToggle(BaseModel):
    enabled: bool = False


class MalwareScanRun(BaseModel):
    website_id: Optional[int] = None
    all: bool = False
    # Scan every file on the machine, not just website roots.
    server: bool = False
    # "incremental" -> maldet -r /home <days>
    mode: str = ""
    days: int = 2


class MalwareScanThreat(BaseModel):
    path: str
    signature: str
    domain: Optional[str] = None


class MalwareScanResult(BaseModel):
    scanned: int = 0
    infected: int = 0
    threats: list[MalwareScanThreat] = []
    exit_code: int = 0
    errors: int = 0
    skipped: int = 0
    log: list[str] = []


class MalwareScanJob(BaseModel):
    job_id: str
    status: str = "queued"
    scope: str = "website"
    engine: str = ""
    scanid: str = ""
    website_id: Optional[int] = None
    domains: list[str] = []
    message: str = ""
    progress_percent: int = 0
    total_files: int = 0
    scanned: int = 0
    infected: int = 0
    errors: int = 0
    skipped: int = 0
    threats: list[MalwareScanThreat] = []
    log: list[str] = []
    error: str = ""
    created_at: str = ""
    started_at: str = ""
    finished_at: str = ""
    updated_at: str = ""


class MalwareScanJobsOut(BaseModel):
    jobs: list[MalwareScanJob] = []


class MalwareScanStatus(BaseModel):
    installed: bool = False
    clamd_running: bool = False
    enabled: bool = False
    active: bool = False
    engine: str = "none"           # "lmd+clamav" | "clamav" | "none"
    lmd_installed: bool = False
    lmd_sig_version: str = ""
    lmd_updated_at: str = ""
    realtime_enabled: bool = False
    monitor_running: bool = False
    socket: str = "/run/clamav/clamd.sock"
    detail: Optional[str] = None
    memory_total_mb: int = 0
    memory_available_mb: int = 0
    # Set when the machine is too small to scan comfortably; explains in plain
    # words what running out of memory does, since "OOM" means nothing to most
    # people who will read it.
    memory_warning: str = ""


class PanelSettingsUpdate(BaseModel):
    app_name: Optional[str] = Field(default=None, min_length=2, max_length=80)
    panel_hostname: Optional[str] = Field(default=None, max_length=255)
    panel_port: Optional[int] = Field(default=None, ge=1, le=65535)
    # Legacy API clients may still send these fields. The panel port is locked
    # after install; updates preserve the existing port and only change host/scheme.
    panel_url: Optional[str] = Field(default=None, max_length=255)

    @field_validator("app_name")
    @classmethod
    def validate_app_name(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("app_name is required")
        return value

    @field_validator("panel_url")
    @classmethod
    def validate_panel_url(cls, value: Optional[str]) -> Optional[str]:
        return _validate_panel_url(value)

    @field_validator("panel_hostname")
    @classmethod
    def validate_panel_hostname(cls, value: Optional[str]) -> Optional[str]:
        return _validate_panel_hostname(value)


class AdminAccountUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(default=None, min_length=12, max_length=72)
    current_password: Optional[str] = Field(default=None, min_length=1, max_length=72)
    code: Optional[str] = Field(default=None, min_length=6, max_length=12)

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        return _validate_linux_login_password(value)

class PanelIpv6Toggle(BaseModel):
    enabled: bool


class PanelSslUseDomain(BaseModel):
    domain: str = Field(min_length=3, max_length=253)
    panel_port: Optional[int] = Field(default=None, ge=1, le=65535)


class PanelSslInstall(BaseModel):
    panel_hostname: Optional[str] = Field(default=None, min_length=3, max_length=255)
    panel_port: int = Field(default=2222, ge=1, le=65535)
    panel_url: Optional[str] = Field(default=None, min_length=3, max_length=255)
    email: Optional[EmailStr] = None

    @field_validator("panel_url")
    @classmethod
    def validate_panel_url(cls, value: Optional[str]) -> Optional[str]:
        validated = _validate_panel_url(value)
        return validated

    @field_validator("panel_hostname")
    @classmethod
    def validate_panel_hostname(cls, value: Optional[str]) -> Optional[str]:
        return _validate_panel_hostname(value)


class FirewallPortRule(BaseModel):
    port: str = Field(min_length=1, max_length=5)
    protocol: str = "tcp"


class FirewallIpRule(BaseModel):
    ip: str = Field(min_length=3, max_length=64)
    port: Optional[str] = Field(default=None, max_length=5)
    protocol: str = "tcp"


class FirewallBlocklistUrl(BaseModel):
    url: str = Field(min_length=8, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("URL must start with http:// or https://")
        if any(ch.isspace() for ch in value):
            raise ValueError("URL must not contain spaces")
        return value


class BackupCreate(BaseModel):
    website_id: int


def _validate_backup_schedule(value: str) -> str:
    fields = (value or "").split()
    field_re = re.compile(r"^(?:\*|\d{1,2})(?:[-/,](?:\*|\d{1,2}))*$")
    if len(fields) != 5 or not all(field_re.fullmatch(field) for field in fields):
        raise ValueError("Invalid cron schedule")
    return " ".join(fields)


class UserBackupCreate(BaseModel):
    user_id: int
    target_id: Optional[int] = None


class UserRestoreBackup(BaseModel):
    backup_file: str


class BackupScheduleCreate(BaseModel):
    user_id: Optional[int] = None
    user_ids: list[int] = Field(default_factory=list)
    all_users: bool = False
    schedule: str = "0 2 * * *"
    target_id: Optional[int] = None
    retention: int = Field(default=7, ge=1, le=365)
    is_active: bool = True

    @field_validator("schedule")
    @classmethod
    def validate_schedule(cls, value: str) -> str:
        return _validate_backup_schedule(value)

    @field_validator("user_ids", mode="before")
    @classmethod
    def validate_user_ids(cls, value) -> list[int]:
        if value in (None, ""):
            return []
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = [item for item in value.split(",") if item]
        if isinstance(value, int):
            value = [value]
        return sorted({int(item) for item in value if int(item) > 0})


class BackupScheduleOut(BaseModel):
    id: int
    user_id: Optional[int] = None
    user_ids: list[int] = Field(default_factory=list)
    all_users: bool = False
    target_id: Optional[int] = None
    schedule: str
    retention: int
    is_active: bool
    last_run_at: Optional[datetime] = None
    last_status: str
    last_message: str = ""

    @field_validator("user_ids", mode="before")
    @classmethod
    def decode_user_ids(cls, value) -> list[int]:
        if value in (None, ""):
            return []
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                value = [item for item in value.split(",") if item]
        if isinstance(value, int):
            value = [value]
        return [int(item) for item in value]

    class Config:
        from_attributes = True


class SftpBackupTargetCreate(BaseModel):
    name: str = Field(min_length=2, max_length=100, pattern=r"^[A-Za-z0-9._ -]+$")
    host: str = Field(min_length=2, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(min_length=1, max_length=128)
    password: Optional[str] = Field(default=None, max_length=4096)
    private_key: Optional[str] = Field(default=None, max_length=20000)
    remote_path: str = Field(default="/backups/snpanel", min_length=1, max_length=500)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        value = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9._:-]+", value):
            raise ValueError("Invalid SFTP host")
        return value

    @field_validator("remote_path")
    @classmethod
    def validate_remote_path(cls, value: str) -> str:
        value = value.strip()
        if "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError("Invalid remote path")
        return value.rstrip("/") or "/"


class SftpBackupTargetOut(BaseModel):
    id: int
    name: str
    host: str
    port: int
    username: str
    remote_path: str
    is_active: bool
    host_key_type: Optional[str] = None
    host_key_fingerprint: Optional[str] = None

    class Config:
        from_attributes = True


class SftpBackupRun(BaseModel):
    website_id: int
    target_id: int


class RestoreBackup(BaseModel):
    website_id: int
    backup_file: str


class PhpConfigUpdate(BaseModel):
    php_version: str = "8.4"
    display_errors: Literal["On", "Off"] = "Off"
    memory_limit: str = "1024M"
    upload_max_filesize: str = "1024M"
    post_max_size: str = "1024M"
    max_execution_time: int = Field(default=300, ge=1, le=3600)
    max_input_time: int = Field(default=600, ge=1, le=3600)
    max_input_vars: int = Field(default=10000, ge=100, le=1_000_000)

    @field_validator("php_version")
    @classmethod
    def validate_php_version(cls, value: str) -> str:
        return _validate_php_version(value) or "8.4"

    @field_validator("memory_limit", "upload_max_filesize", "post_max_size")
    @classmethod
    def validate_size(cls, value: str) -> str:
        value = (value or "").strip()
        if not SIZE_RE.fullmatch(value):
            raise ValueError("must match digits optionally followed by K, M, or G")
        return value


class CronCreate(BaseModel):
    website_id: int
    schedule: str
    command: str


class PhpOpcacheToggle(BaseModel):
    php_version: str = "8.4"
    enabled: bool = True


class PhpConfigRestore(BaseModel):
    php_version: str = "8.4"

    @field_validator("php_version")
    @classmethod
    def validate_php_version(cls, value: str) -> str:
        return _validate_php_version(value) or "8.4"


class WpAction(BaseModel):
    website_id: int
    action: str


class DaImportRequest(BaseModel):
    archive_path: str
    force: bool = False


class DaBulkImportRequest(BaseModel):
    archive_paths: list[str]
    force: bool = False

class ProvisioningAccountCreate(BaseModel):
    external_id: str = Field(min_length=1, max_length=255)
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-z_][a-z0-9_-]{2,31}$")
    email: Optional[EmailStr] = None
    password: str = Field(min_length=12, max_length=72)
    package_id: int = Field(ge=1)
    domain: Optional[str] = None
    php_version: str = "8.4"
    app_type: Literal["wordpress", "php", "static"] = "php"
    install_wordpress: bool = False
    enable_ssl: bool = False

    @field_validator("username")
    @classmethod
    def validate_username(cls, value: str) -> str:
        if value in RESERVED_LINUX_USERNAMES:
            raise ValueError("username is reserved by the system")
        return value

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip().lower()
        if value == "":
            return None
        if not DOMAIN_RE.fullmatch(value):
            raise ValueError("Invalid domain")
        return value

    @field_validator("php_version")
    @classmethod
    def validate_php(cls, value: str) -> str:
        return _validate_php_version(value) or "8.4"

    @model_validator(mode="after")
    def validate_site_options(self):
        if self.domain is None and (self.install_wordpress or self.enable_ssl):
            raise ValueError("domain is required for WordPress install or Auto SSL")
        return self

class ProvisioningAccountOut(BaseModel):
    external_id: str
    # Empty once the account is terminated: the billing record outlives the
    # panel user it pointed at.
    username: str = ""
    email: str = ""
    domain: Optional[str] = None
    package_id: Optional[int] = None
    package_name: Optional[str] = None
    service_label: Optional[str] = None
    status: str
    panel_url: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class ProvisioningSuspendRequest(BaseModel):
    reason: str = ""

class ProvisioningPasswordChange(BaseModel):
    password: str = Field(min_length=12, max_length=72)

class ProvisioningPackageChange(BaseModel):
    package_id: int = Field(ge=1)

class ApiTokenCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    scopes: str = "provisioning:read,provisioning:write"
    allowed_ips: str = ""

class ApiTokenOut(BaseModel):
    id: int
    name: str
    scopes: str
    allowed_ips: str
    is_active: bool
    last_used_at: Optional[datetime] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class ApiTokenCreatedResponse(BaseModel):
    token: str
    info: ApiTokenOut

class ProvisioningUsageOut(BaseModel):
    external_id: str
    storage_used_bytes: int
    storage_limit_bytes: Optional[int] = None
    storage_percent: float
    website_count: int
    database_count: int
