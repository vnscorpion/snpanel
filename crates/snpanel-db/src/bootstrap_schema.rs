//! The schema a fresh install starts with.
//!
//! **Generated — do not edit by hand.** `gen-schema-corpus.py` migrates an
//! empty database to head with Alembic itself and dumps `sqlite_master`;
//! `render-schema-rs.py` writes it out here. Transcribing 31 revisions by
//! reading them is the one place in this port where a mistake is silent — a
//! column typed wrongly does not fail a test, it corrupts a row months
//! later. So nothing here was read: this is a copy of what Python produces.
//!
//! The statements are one-line escaped literals rather than a `.sql` file
//! because SQLAlchemy's DDL carries trailing whitespace that
//! `sqlite_master` records, and an editor that strips it on save would
//! change the schema's text without anything looking wrong.
//!
//! Captured at Alembic revision `0031_website_crs_enabled`.

/// Every statement, in an order that can be replayed: tables first, then
/// everything that refers to one.
pub const BOOTSTRAP_DDL: &[&str] = &[
    // table alembic_version
    "CREATE TABLE alembic_version (\n\tversion_num VARCHAR(32) NOT NULL, \n\tCONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)\n)",
    // table api_tokens
    "CREATE TABLE api_tokens (\n\tid INTEGER NOT NULL, \n\tname VARCHAR(100) NOT NULL, \n\ttoken_hash VARCHAR(128) NOT NULL, \n\tscopes TEXT DEFAULT 'provisioning:read,provisioning:write' NOT NULL, \n\tallowed_ips TEXT DEFAULT '' NOT NULL, \n\tis_active BOOLEAN DEFAULT 1 NOT NULL, \n\tlast_used_at DATETIME, \n\trevoked_at DATETIME, \n\tcreated_at DATETIME, \n\tPRIMARY KEY (id)\n)",
    // table audit_logs
    "CREATE TABLE audit_logs (\n\tid INTEGER NOT NULL, \n\tuser_id INTEGER, \n\taction VARCHAR(128) NOT NULL, \n\ttarget VARCHAR(255) NOT NULL, \n\tdetail TEXT DEFAULT '' NOT NULL, \n\tcreated_at DATETIME, \n\tPRIMARY KEY (id)\n)",
    // table backup_schedules
    "CREATE TABLE \"backup_schedules\" (\n\tid INTEGER NOT NULL, \n\tuser_id INTEGER, \n\ttarget_id INTEGER, \n\tschedule VARCHAR(100) DEFAULT '0 2 * * *' NOT NULL, \n\tretention INTEGER DEFAULT '7' NOT NULL, \n\tis_active BOOLEAN DEFAULT 1 NOT NULL, \n\tlast_run_at DATETIME, \n\tlast_status VARCHAR(32) DEFAULT 'pending' NOT NULL, \n\tlast_message TEXT DEFAULT ('') NOT NULL, \n\tcreated_at DATETIME, \n\tuser_ids TEXT DEFAULT '' NOT NULL, \n\tall_users BOOLEAN DEFAULT 0 NOT NULL, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(target_id) REFERENCES sftp_backup_targets (id), \n\tFOREIGN KEY(user_id) REFERENCES users (id)\n)",
    // table cloudflare_credentials
    "CREATE TABLE cloudflare_credentials (\n\tid INTEGER NOT NULL, \n\tzone VARCHAR(253) NOT NULL, \n\tapi_token TEXT NOT NULL, \n\tcreated_at DATETIME, \n\tupdated_at DATETIME, \n\tPRIMARY KEY (id)\n)",
    // table database_accounts
    "CREATE TABLE \"database_accounts\" (\n\tid INTEGER NOT NULL, \n\twebsite_id INTEGER, \n\tdb_name VARCHAR(64) NOT NULL, \n\tdb_user VARCHAR(64) NOT NULL, \n\tdb_password VARCHAR(255) NOT NULL, \n\tcreated_at DATETIME, \n\towner_id INTEGER NOT NULL, \n\tPRIMARY KEY (id), \n\tUNIQUE (db_user), \n\tFOREIGN KEY(website_id) REFERENCES websites (id), \n\tUNIQUE (db_name)\n)",
    // table provisioning_accounts
    "CREATE TABLE provisioning_accounts (\n\tid INTEGER NOT NULL, \n\texternal_id VARCHAR(255) NOT NULL, \n\tuser_id INTEGER, \n\tprimary_website_id INTEGER, \n\tpackage_id INTEGER, \n\tstatus VARCHAR(32) DEFAULT 'pending' NOT NULL, \n\tlast_action VARCHAR(64) DEFAULT '' NOT NULL, \n\tlast_message TEXT DEFAULT '' NOT NULL, \n\tcreated_at DATETIME, \n\tupdated_at DATETIME, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(user_id) REFERENCES users (id) ON DELETE SET NULL, \n\tFOREIGN KEY(primary_website_id) REFERENCES websites (id) ON DELETE SET NULL, \n\tFOREIGN KEY(package_id) REFERENCES user_packages (id) ON DELETE SET NULL\n)",
    // table revoked_tokens
    "CREATE TABLE revoked_tokens (\n\tid INTEGER NOT NULL, \n\tjti VARCHAR(128) NOT NULL, \n\tuser_id INTEGER, \n\texpires_at DATETIME NOT NULL, \n\trevoked_at DATETIME, \n\tPRIMARY KEY (id)\n)",
    // table sftp_backup_targets
    "CREATE TABLE sftp_backup_targets (\n\tid INTEGER NOT NULL, \n\tname VARCHAR(100) NOT NULL, \n\thost VARCHAR(255) NOT NULL, \n\tport INTEGER DEFAULT '22' NOT NULL, \n\tusername VARCHAR(128) NOT NULL, \n\tpassword TEXT, \n\tprivate_key TEXT, \n\tremote_path VARCHAR(500) DEFAULT '/backups/snpanel' NOT NULL, \n\tis_active BOOLEAN DEFAULT 1 NOT NULL, \n\tcreated_at DATETIME, host_key_type VARCHAR(32), host_key_fingerprint VARCHAR(128), \n\tPRIMARY KEY (id)\n)",
    // table site_apps
    "CREATE TABLE \"site_apps\" (\n\tid INTEGER NOT NULL, \n\tname VARCHAR(64) DEFAULT 'app' NOT NULL, \n\tkind VARCHAR(16) DEFAULT 'proxy' NOT NULL, \n\tstart_kind VARCHAR(16), \n\tstart_arg VARCHAR(255), \n\tnode_major VARCHAR(8), \n\tport INTEGER NOT NULL, \n\tmemory_limit_mb INTEGER DEFAULT '512' NOT NULL, \n\tautostart BOOLEAN DEFAULT 1 NOT NULL, \n\tstatus VARCHAR(16) DEFAULT 'stopped' NOT NULL, \n\tlast_error TEXT DEFAULT ('') NOT NULL, \n\tcreated_at DATETIME, \n\timage VARCHAR(200), \n\tcontainer_port INTEGER DEFAULT '3000' NOT NULL, \n\tcpu_limit VARCHAR(8) DEFAULT '1' NOT NULL, \n\tenv TEXT DEFAULT ('') NOT NULL, \n\towner_id INTEGER NOT NULL, compose_source TEXT DEFAULT '' NOT NULL, web_service VARCHAR(64), \n\tPRIMARY KEY (id), \n\tCONSTRAINT uq_site_apps_owner_name UNIQUE (owner_id, name), \n\tCONSTRAINT fk_site_apps_owner_id_users FOREIGN KEY(owner_id) REFERENCES users (id) ON DELETE CASCADE\n)",
    // table user_packages
    "CREATE TABLE \"user_packages\" (\n\tid INTEGER NOT NULL, \n\tname VARCHAR(100) NOT NULL, \n\twebsite_limit INTEGER DEFAULT '5' NOT NULL, \n\tstorage_limit_mb INTEGER DEFAULT '1024' NOT NULL, \n\tcreated_at DATETIME, \n\tslug VARCHAR(100), \n\tdatabase_limit INTEGER DEFAULT '5' NOT NULL, \n\talias_limit INTEGER DEFAULT '0' NOT NULL, \n\tbackup_retention_days INTEGER DEFAULT '7' NOT NULL, \n\tterminal_enabled BOOLEAN DEFAULT 0 NOT NULL, \n\twaf_enabled BOOLEAN DEFAULT 1 NOT NULL, \n\twordpress_enabled BOOLEAN DEFAULT 1 NOT NULL, node_apps_limit INTEGER DEFAULT '0' NOT NULL, node_app_memory_mb INTEGER DEFAULT '512' NOT NULL, \n\tPRIMARY KEY (id)\n)",
    // table users
    "CREATE TABLE \"users\" (\n\tid INTEGER NOT NULL, \n\tusername VARCHAR(64) NOT NULL, \n\temail VARCHAR(255) NOT NULL, \n\thashed_password VARCHAR(255) NOT NULL, \n\trole VARCHAR(32) DEFAULT 'user' NOT NULL, \n\tis_active BOOLEAN DEFAULT 1 NOT NULL, \n\twebsite_limit INTEGER DEFAULT '5' NOT NULL, \n\tstorage_limit_mb INTEGER DEFAULT '1024' NOT NULL, \n\ttoken_version INTEGER DEFAULT '0' NOT NULL, \n\tcreated_at DATETIME, \n\ttotp_secret VARCHAR(255), \n\ttotp_enabled BOOLEAN DEFAULT 0 NOT NULL, \n\tpackage_id INTEGER, terminal_enabled BOOLEAN DEFAULT '0' NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT fk_users_package_id_user_packages FOREIGN KEY(package_id) REFERENCES user_packages (id) ON DELETE SET NULL\n)",
    // table website_aliases
    "CREATE TABLE website_aliases (\n\tid INTEGER NOT NULL, \n\twebsite_id INTEGER NOT NULL, \n\tdomain VARCHAR(255) NOT NULL, \n\tmode VARCHAR(16) DEFAULT 'alias' NOT NULL, \n\tssl_enabled BOOLEAN DEFAULT 0 NOT NULL, \n\tcreated_at DATETIME, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(website_id) REFERENCES websites (id) ON DELETE CASCADE\n)",
    // table websites
    "CREATE TABLE \"websites\" (\n\tid INTEGER NOT NULL, \n\tdomain VARCHAR(255) NOT NULL, \n\towner_id INTEGER NOT NULL, \n\troot_path VARCHAR(500) NOT NULL, \n\tphp_version VARCHAR(16) DEFAULT '8.3' NOT NULL, \n\tapp_type VARCHAR(32) DEFAULT 'wordpress' NOT NULL, \n\tssl_enabled BOOLEAN DEFAULT 0 NOT NULL, \n\tstatus VARCHAR(32) DEFAULT 'pending' NOT NULL, \n\tnginx_custom TEXT DEFAULT ('') NOT NULL, \n\tcreated_at DATETIME, \n\tlinux_user VARCHAR(32), \n\twaf_enabled BOOLEAN DEFAULT 0 NOT NULL, \n\twaf_default_rules TEXT DEFAULT ('') NOT NULL, \n\twaf_custom_rules TEXT DEFAULT ('') NOT NULL, \n\thttp_flood_enabled BOOLEAN DEFAULT 0 NOT NULL, \n\thttp_flood_config TEXT DEFAULT ('') NOT NULL, \n\tdocument_root VARCHAR(255) DEFAULT 'public_html' NOT NULL, \n\tnginx_config_mode VARCHAR(16) DEFAULT 'managed' NOT NULL, \n\tnginx_rewrite_mode VARCHAR(32) DEFAULT 'none' NOT NULL, \n\tssl_mode VARCHAR(16) DEFAULT 'none' NOT NULL, \n\tssl_cert_path VARCHAR(500), \n\tssl_key_path VARCHAR(500), \n\tssl_ca_path VARCHAR(500), \n\tssl_updated_at DATETIME, \n\tapp_id INTEGER, ssl_source_domain VARCHAR(253), blocked_bots TEXT DEFAULT '' NOT NULL, crs_enabled BOOLEAN DEFAULT '0' NOT NULL, \n\tPRIMARY KEY (id), \n\tCONSTRAINT fk_websites_app_id_site_apps FOREIGN KEY(app_id) REFERENCES site_apps (id) ON DELETE SET NULL, \n\tFOREIGN KEY(owner_id) REFERENCES users (id)\n)",
    // index ix_api_tokens_id
    "CREATE INDEX ix_api_tokens_id ON api_tokens (id)",
    // index ix_api_tokens_name
    "CREATE INDEX ix_api_tokens_name ON api_tokens (name)",
    // index ix_api_tokens_token_hash
    "CREATE UNIQUE INDEX ix_api_tokens_token_hash ON api_tokens (token_hash)",
    // index ix_audit_logs_id
    "CREATE INDEX ix_audit_logs_id ON audit_logs (id)",
    // index ix_backup_schedules_id
    "CREATE INDEX ix_backup_schedules_id ON backup_schedules (id)",
    // index ix_cloudflare_credentials_id
    "CREATE INDEX ix_cloudflare_credentials_id ON cloudflare_credentials (id)",
    // index ix_cloudflare_credentials_zone
    "CREATE UNIQUE INDEX ix_cloudflare_credentials_zone ON cloudflare_credentials (zone)",
    // index ix_database_accounts_id
    "CREATE INDEX ix_database_accounts_id ON database_accounts (id)",
    // index ix_provisioning_accounts_external_id
    "CREATE UNIQUE INDEX ix_provisioning_accounts_external_id ON provisioning_accounts (external_id)",
    // index ix_provisioning_accounts_id
    "CREATE INDEX ix_provisioning_accounts_id ON provisioning_accounts (id)",
    // index ix_provisioning_accounts_user_id
    "CREATE INDEX ix_provisioning_accounts_user_id ON provisioning_accounts (user_id)",
    // index ix_revoked_tokens_id
    "CREATE INDEX ix_revoked_tokens_id ON revoked_tokens (id)",
    // index ix_revoked_tokens_jti
    "CREATE UNIQUE INDEX ix_revoked_tokens_jti ON revoked_tokens (jti)",
    // index ix_sftp_backup_targets_id
    "CREATE INDEX ix_sftp_backup_targets_id ON sftp_backup_targets (id)",
    // index ix_sftp_backup_targets_name
    "CREATE UNIQUE INDEX ix_sftp_backup_targets_name ON sftp_backup_targets (name)",
    // index ix_site_apps_id
    "CREATE INDEX ix_site_apps_id ON site_apps (id)",
    // index ix_site_apps_owner_id
    "CREATE INDEX ix_site_apps_owner_id ON site_apps (owner_id)",
    // index ix_site_apps_port
    "CREATE UNIQUE INDEX ix_site_apps_port ON site_apps (port)",
    // index ix_user_packages_id
    "CREATE INDEX ix_user_packages_id ON user_packages (id)",
    // index ix_user_packages_name
    "CREATE UNIQUE INDEX ix_user_packages_name ON user_packages (name)",
    // index ix_user_packages_slug
    "CREATE UNIQUE INDEX ix_user_packages_slug ON user_packages (slug)",
    // index ix_users_email
    "CREATE INDEX ix_users_email ON users (email)",
    // index ix_users_id
    "CREATE INDEX ix_users_id ON users (id)",
    // index ix_users_package_id
    "CREATE INDEX ix_users_package_id ON users (package_id)",
    // index ix_users_username
    "CREATE UNIQUE INDEX ix_users_username ON users (username)",
    // index ix_website_aliases_domain
    "CREATE UNIQUE INDEX ix_website_aliases_domain ON website_aliases (domain)",
    // index ix_website_aliases_id
    "CREATE INDEX ix_website_aliases_id ON website_aliases (id)",
    // index ix_website_aliases_website_id
    "CREATE INDEX ix_website_aliases_website_id ON website_aliases (website_id)",
    // index ix_websites_app_id
    "CREATE INDEX ix_websites_app_id ON websites (app_id)",
    // index ix_websites_domain
    "CREATE UNIQUE INDEX ix_websites_domain ON websites (domain)",
    // index ix_websites_id
    "CREATE INDEX ix_websites_id ON websites (id)",
];
