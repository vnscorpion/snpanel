from datetime import datetime
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class UserPackage(Base):
    __tablename__ = "user_packages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    slug: Mapped[Optional[str]] = mapped_column(String(100), unique=True, nullable=True, index=True)
    website_limit: Mapped[int] = mapped_column(Integer, default=5)
    storage_limit_mb: Mapped[int] = mapped_column(Integer, default=1024)
    database_limit: Mapped[int] = mapped_column(Integer, default=5)
    alias_limit: Mapped[int] = mapped_column(Integer, default=0)
    backup_retention_days: Mapped[int] = mapped_column(Integer, default=7)
    terminal_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    waf_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    wordpress_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # 0 keeps app hosting off for every existing package until an admin raises
    # it, the same way terminal_enabled gates the terminal.
    node_apps_limit: Mapped[int] = mapped_column(Integer, default=0)
    node_app_memory_mb: Mapped[int] = mapped_column(Integer, default=512)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    users: Mapped[List["User"]] = relationship(back_populates="package")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # Not unique: several panel users may share a contact email (resellers).
    email: Mapped[str] = mapped_column(String(255), index=True)
    hashed_password: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(32), default="end_user")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    package_id: Mapped[Optional[int]] = mapped_column(ForeignKey("user_packages.id", ondelete="SET NULL"), nullable=True, index=True)
    website_limit: Mapped[int] = mapped_column(Integer, default=5)
    storage_limit_mb: Mapped[int] = mapped_column(Integer, default=1024)
    # Copied from the package when one is assigned, exactly like website_limit
    # and storage_limit_mb above, so that enforcement reads one column and a
    # user without a package still resolves to something. UserPackage has
    # carried terminal_enabled since packages were added but nothing ever read
    # it - the terminal checked website ownership only, so the setting did
    # nothing. New accounts default to off: a shell on the server is not
    # something to hand out implicitly.
    terminal_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # Bumped to invalidate previously-issued JWTs (logout-everywhere, role
    # change, password reset by admin, account disable, etc).
    token_version: Mapped[int] = mapped_column(Integer, default=0)
    totp_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    websites: Mapped[List["Website"]] = relationship(back_populates="owner")
    package: Mapped[Optional[UserPackage]] = relationship(back_populates="users")
    apps: Mapped[List["SiteApp"]] = relationship(back_populates="owner")


class Website(Base):
    __tablename__ = "websites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    root_path: Mapped[str] = mapped_column(String(500))
    document_root: Mapped[str] = mapped_column(String(255), default="public_html")
    linux_user: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    php_version: Mapped[str] = mapped_column(String(16), default="8.4")
    app_type: Mapped[str] = mapped_column(String(32), default="wordpress")
    ssl_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    ssl_mode: Mapped[str] = mapped_column(String(16), default="none")
    ssl_cert_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    ssl_key_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    ssl_ca_path: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    ssl_updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # For ssl_mode "cloudflare" this is the Cloudflare zone whose wildcard cert
    # this vhost points at; for "shared" it is the source website's domain.
    ssl_source_domain: Mapped[Optional[str]] = mapped_column(String(253), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    nginx_custom: Mapped[str] = mapped_column(Text, default="")
    nginx_config_mode: Mapped[str] = mapped_column(String(16), default="managed")
    nginx_rewrite_mode: Mapped[str] = mapped_column(String(32), default="none")
    waf_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    waf_default_rules: Mapped[str] = mapped_column(Text, default="")
    waf_custom_rules: Mapped[str] = mapped_column(Text, default="")
    # OWASP CRS is per site and off by default: unlike the other WAF toggles it
    # costs real memory, roughly 325 MB of nginx RSS per site that loads it.
    crs_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    http_flood_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    http_flood_config: Mapped[str] = mapped_column(Text, default="")
    # User-agent substrings to answer with 403, one per line. Text rather than a
    # side table because it is edited and applied as one list, and the lists
    # people import run to a few hundred names.
    blocked_bots: Mapped[str] = mapped_column(Text, default="")
    # Set when app_type is "application": the installed app this domain serves.
    app_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("site_apps.id", ondelete="SET NULL"), nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    owner: Mapped[User] = relationship(back_populates="websites")
    app: Mapped[Optional["SiteApp"]] = relationship(back_populates="websites")
    database: Mapped[Optional["DatabaseAccount"]] = relationship(back_populates="website", uselist=False)
    aliases: Mapped[List["WebsiteAlias"]] = relationship(
        back_populates="website",
        cascade="all, delete-orphan",
        order_by="WebsiteAlias.domain",
    )


class SiteApp(Base):
    """An application the panel installs, runs and keeps alive.

    An app belongs to a panel user and is independent of any website: it lives
    in its own directory, gets its own loopback port, and runs under its own
    systemd unit. A website in "application" mode then points at one, and nginx
    proxies the domain to that app's port.
    """

    __tablename__ = "site_apps"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(64), default="app")
    kind: Mapped[str] = mapped_column(String(16), default="node")
    start_kind: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)
    start_arg: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    node_major: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)
    # Container runtimes: image reference, the port the process listens on inside
    # the container, and a CPU share. The published side is always loopback.
    image: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    container_port: Mapped[int] = mapped_column(Integer, default=3000)
    cpu_limit: Mapped[str] = mapped_column(String(8), default="1")
    env: Mapped[str] = mapped_column(Text, default="")
    # Compose runtimes: what the customer pasted, and which service the domain
    # reaches. The file that actually runs is regenerated from these, never
    # stored as the source of truth.
    compose_source: Mapped[str] = mapped_column(Text, default="")
    web_service: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    port: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    memory_limit_mb: Mapped[int] = mapped_column(Integer, default=512)
    autostart: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(16), default="stopped")
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    owner: Mapped[User] = relationship(back_populates="apps")
    websites: Mapped[List[Website]] = relationship(back_populates="app")

    __table_args__ = (UniqueConstraint("owner_id", "name", name="uq_site_apps_owner_name"),)


class WebsiteAlias(Base):
    __tablename__ = "website_aliases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    website_id: Mapped[int] = mapped_column(ForeignKey("websites.id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    mode: Mapped[str] = mapped_column(String(16), default="alias")
    ssl_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    website: Mapped[Website] = relationship(back_populates="aliases")


class DatabaseAccount(Base):
    __tablename__ = "database_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    website_id: Mapped[Optional[int]] = mapped_column(ForeignKey("websites.id"), nullable=True)
    db_name: Mapped[str] = mapped_column(String(64), unique=True)
    db_user: Mapped[str] = mapped_column(String(64), unique=True)
    db_password: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    owner: Mapped["User"] = relationship()
    website: Mapped[Optional[Website]] = relationship(back_populates="database")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(128))
    target: Mapped[str] = mapped_column(String(255))
    detail: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    jti: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    revoked_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SftpBackupTarget(Base):
    __tablename__ = "sftp_backup_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(128))
    password: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    private_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remote_path: Mapped[str] = mapped_column(String(500), default="/backups/snpanel")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    # TOFU host key pinning so the second SSH connection on cannot be silently
    # MITM'd. Populated on first successful connect (or by an explicit rotate
    # action) and verified on every connect afterwards.
    host_key_type: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    host_key_fingerprint: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class BackupSchedule(Base):
    __tablename__ = "backup_schedules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True)
    user_ids: Mapped[str] = mapped_column(Text, default="")
    all_users: Mapped[bool] = mapped_column(Boolean, default=False)
    target_id: Mapped[Optional[int]] = mapped_column(ForeignKey("sftp_backup_targets.id"), nullable=True)
    schedule: Mapped[str] = mapped_column(String(100), default="0 2 * * *")
    retention: Mapped[int] = mapped_column(Integer, default=7)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_status: Mapped[str] = mapped_column(String(32), default="pending")
    last_message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ApiToken(Base):
    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(100), index=True)
    token_hash: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    scopes: Mapped[str] = mapped_column(Text, default="provisioning:read,provisioning:write")
    allowed_ips: Mapped[str] = mapped_column(Text, default="")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class CloudflareCredential(Base):
    """A Cloudflare API token (Zone.DNS Edit), one per zone, stored encrypted.

    Used for DNS-01 wildcard issuance and kept so certbot can auto-renew the
    wildcard cert unattended. The plaintext token only ever leaves here to be
    handed to the privileged helper on stdin.
    """

    __tablename__ = "cloudflare_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    zone: Mapped[str] = mapped_column(String(253), unique=True, index=True)
    api_token: Mapped[str] = mapped_column(Text)  # Fernet ciphertext
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ProvisioningAccount(Base):
    __tablename__ = "provisioning_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    external_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    primary_website_id: Mapped[Optional[int]] = mapped_column(ForeignKey("websites.id"), nullable=True)
    package_id: Mapped[Optional[int]] = mapped_column(ForeignKey("user_packages.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="pending")
    last_action: Mapped[str] = mapped_column(String(64), default="")
    last_message: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user: Mapped[Optional[User]] = relationship()
    primary_website: Mapped[Optional[Website]] = relationship(foreign_keys=[primary_website_id])
    package: Mapped[Optional[UserPackage]] = relationship()
