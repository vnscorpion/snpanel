import hashlib
from pathlib import Path

import pytest

from app.api import websites
from app.services import site_users

PROJECT_ROOT = Path(__file__).resolve().parents[3]
HELPER_SCRIPT = PROJECT_ROOT / "installer" / "files" / "snpanel-helper.sh"
INSTALL_SCRIPT = PROJECT_ROOT / "installer" / "install.sh"
UPDATE_SCRIPT = PROJECT_ROOT / "installer" / "update.sh"


def test_site_php_fpm_socket_is_scoped_to_site_root(tmp_path):
    first_root = tmp_path / "first.test"
    second_root = tmp_path / "second.test"

    first_socket = site_users.site_php_fpm_socket("siteuser", first_root, "8.3")
    second_socket = site_users.site_php_fpm_socket("siteuser", second_root, "8.3")

    first_hash = hashlib.sha256(str(first_root.resolve()).encode("utf-8")).hexdigest()[:12]
    assert first_socket == f"/run/php/snpanel-siteuser-{first_hash}-8_3.sock"
    assert second_socket != first_socket


def test_site_php_fpm_socket_returns_none_without_php_version(tmp_path):
    assert site_users.site_php_fpm_socket("siteuser", tmp_path, None) is None


def test_php_fpm_socket_rejects_invalid_php_version(tmp_path):
    with pytest.raises(ValueError, match="Invalid PHP version"):
        site_users.site_php_fpm_socket("siteuser", tmp_path, "../8.3")


def test_legacy_user_php_fpm_socket_is_kept_for_callers_without_site_root():
    assert site_users.php_fpm_socket("siteuser", "8.3") == "/run/php/snpanel-siteuser-8_3.sock"


def test_placeholder_page_for_linux_user_uses_site_file_write(tmp_path, monkeypatch):
    root = tmp_path / "site"
    public = root / "public_html"
    public.mkdir(parents=True)
    calls = []

    def fake_privileged(helper_command, helper_args=None, **kwargs):
        calls.append((helper_command, helper_args, kwargs))
        return type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(websites.file_manager.shell, "privileged", fake_privileged)
    monkeypatch.setattr(websites.file_manager, "_clear_fastcgi_cache", lambda: None)

    websites._write_placeholder_page("example.test", str(root), "siteuser", "8.3")

    assert calls[0][0] == "site-file-write"
    assert calls[0][1] == ["siteuser", str(root.resolve()), "public_html/index.html"]
    assert "example.test" in calls[0][2]["input"]


def test_panel_linux_users_are_sftp_chroot_only():
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    for script_path in (INSTALL_SCRIPT, UPDATE_SCRIPT):
        script = script_path.read_text(encoding="utf-8")
        assert "Match Group snpanel-sftp" in script
        assert "ChrootDirectory /home/%u" in script
        assert "ForceCommand internal-sftp -d /" in script
        assert "PermitTTY no" in script
        assert "AllowTcpForwarding no" in script
    assert "--shell /usr/sbin/nologin" in helper
    assert "--shell /bin/bash" not in helper
    assert 'chmod 0711 "$HOME_ROOT"' in helper
    assert 'chown "root:$user" "$home_dir"' in helper
    assert 'chmod 0751 "$home_dir"' in helper
    # The web server account joins the site's group so it can read the site's
    # files. It is `www-data` on Debian and `nginx` on EL, and the helper reads
    # the name from nginx.conf rather than carrying a table, so the assertion
    # is on the membership, not on the spelling of the account.
    assert 'usermod -aG "$user" "$WEB_USER"' in helper
    assert 'WEB_USER="$(awk' in helper


def test_panel_tools_ssl_vhosts_enable_http2_for_nginx_1_24():
    expected = "listen 443 ssl http2 default_server;"
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    assert expected in helper
    for script_path in (INSTALL_SCRIPT, UPDATE_SCRIPT):
        script = script_path.read_text(encoding="utf-8")
        assert expected in script


def test_site_trees_use_the_standard_644_755_modes():
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    update = UPDATE_SCRIPT.read_text(encoding="utf-8")
    assert 'SITE_FILE_MODE="0644"' in helper
    assert 'SITE_DIR_MODE="0755"' in helper
    assert 'find "$target" -type d -exec chmod 755 {} +' in helper
    assert 'find "$target" -type f -exec chmod 644 {} +' in helper
    assert 'install -o "$user" -g "$SNPANEL_SITES_GROUP" -m 0644' in helper
    assert 'chown -R "$user:$SNPANEL_SITES_GROUP" "$target"' in helper
    assert 'harden_site_file "$target" "$user"' in helper
    # The terminal writes with the same default as the file manager.
    assert "umask 022" in helper
    assert "umask 027" not in helper
    # Nothing may put the old restrictive defaults back on a site tree.
    assert 'find "$target" -type d -exec chmod 2750 {} +' not in helper
    assert 'find "$target" -type f -exec chmod 640 {} +' not in helper
    # Existing installs are migrated by the updater.
    assert 'find "$site_dir" -type d -exec chmod 755 {} +' in update
    assert 'find "$site_dir" -type f -exec chmod 644 {} +' in update


def test_files_holding_database_credentials_stay_group_only():
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    update = UPDATE_SCRIPT.read_text(encoding="utf-8")
    assert "SITE_SECRET_FILES=(wp-config.php .env .my.cnf)" in helper
    assert "protect_site_secret_tree()" in helper
    assert 'protect_site_secret_file "$target"' in helper
    assert 'find "$target" -type f -name "$secret" -exec chmod 0640 {} +' in helper
    assert 'find "$site_dir" -type f -name "$secret" -exec chmod 640 {} +' in update
    # A site tree is never re-permissioned without the follow-up pass.
    for block in helper.split('find "$target" -type f -exec chmod 644 {} +')[1:]:
        assert block.lstrip().startswith('protect_site_secret_tree "$target"')


def test_php_upload_tmp_dir_keeps_nginx_readable_group():
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    update = UPDATE_SCRIPT.read_text(encoding="utf-8")
    assert "ensure_php_runtime_dirs()" in helper
    assert 'install -d -o "$user" -g "$SNPANEL_SITES_GROUP" -m 2700 "$upload_dir"' in helper
    assert 'chmod g+s "$upload_dir"' in helper
    assert 'install -d -o "$user" -g "$user" -m 0700 "$sess_dir"' in helper
    assert 'ensure_php_runtime_dirs "$pool_user"' in helper
    assert 'chmod 2700 "/var/lib/php/uploads/$user"' in update


def test_php_fpm_pools_are_auto_tuned_for_vps_size():
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    assert "calculate_php_fpm_pool_tuning()" in helper
    assert "php_fpm_total_memory_mb()" in helper
    assert "php_fpm_cpu_count()" in helper
    assert "php_fpm_pool_count()" in helper
    assert "active_pool_divisor * active_pool_divisor < pool_count" in helper
    assert "pm.max_children = ${PHP_FPM_MAX_CHILDREN}" in helper
    assert "pm.process_idle_timeout = ${PHP_FPM_PROCESS_IDLE_TIMEOUT}s" in helper
    assert "pm.max_requests = ${PHP_FPM_MAX_REQUESTS}" in helper
    assert "request_terminate_timeout = ${PHP_FPM_REQUEST_TERMINATE_TIMEOUT}s" in helper
    assert "SNPANEL_PHP_FPM_WORKER_MB" in helper
    assert "SNPANEL_PHP_FPM_MAX_CHILDREN" in helper
    assert "php-fpm-retune)" in helper
    assert "pm.max_children = 8" not in helper


def test_mariadb_is_auto_tuned_for_vps_size():
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    install = INSTALL_SCRIPT.read_text(encoding="utf-8")
    update = UPDATE_SCRIPT.read_text(encoding="utf-8")
    assert "calculate_mariadb_tuning()" in helper
    assert "write_mariadb_tuning()" in helper
    assert "mariadb-retune)" in helper
    assert "innodb_buffer_pool_size = ${MARIADB_INNODB_BUFFER_POOL_SIZE}" in helper
    assert "max_connections = ${MARIADB_MAX_CONNECTIONS}" in helper
    assert "table_open_cache = ${MARIADB_TABLE_OPEN_CACHE}" in helper
    assert "ensure_mariadb_slow_log" in helper
    assert "SNPANEL_MARIADB_BUFFER_POOL_SIZE" in helper
    for script in (install, update):
        assert "snpanel-autotune.service" in script
        assert "ExecStart=/usr/local/sbin/snpanel-helper php-fpm-retune" in script
        assert "ExecStart=/usr/local/sbin/snpanel-helper mariadb-retune" in script


def test_manual_ssl_helper_installs_private_key_outside_web_root():
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    assert "install_manual_ssl()" in helper
    assert "remove_manual_ssl()" in helper
    assert 'base="/etc/nginx/snpanel/ssl/sites/${domain}"' in helper
    assert 'install -m 0640 -o root -g snpanel "$tmpdir/privkey.key" "$base/privkey.key"' in helper
    assert "manual-ssl-install)" in helper
    assert "manual-ssl-remove)" in helper


def test_terminal_helper_rejects_paths_outside_user_home():
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    assert "require_terminal_path_args()" in helper
    assert "require_terminal_download_args()" in helper
    assert 'deny "terminal path argument is outside panel user home: $arg"' in helper
    assert 'deny "terminal path argument escapes user home: $arg"' in helper
    assert 'deny "terminal URL argument uses local file scheme: $arg"' in helper
    assert 'require_terminal_path_args "$user" "$target" "$@"' in helper
    assert 'require_terminal_download_args "$user" "$target" "$@"' in helper


def test_rm_site_helper_binds_delete_to_user_root_and_deletes_no_follow():
    helper = HELPER_SCRIPT.read_text(encoding="utf-8")
    assert "require_bound_managed_path()" in helper
    assert "delete_no_follow()" in helper
    assert 'target=$(require_bound_managed_path "$user" "$root" "$path")' in helper
    assert "os.path.normpath(sys.argv[1])" in helper
    assert 'root_relative="${normalized_root#${HOME_ROOT}/${user}/}"' in helper
    assert '[[ "$root_relative" == */* ]] && deny "site root must be a direct domain path: $normalized_root"' in helper
    assert '[[ "$target" == "$normalized_root" || "$target_relative" == */* ]] || deny "refusing to operate on a panel user home"' in helper
    assert 'delete_no_follow "$user" "$root" "$target"' in helper
    assert "os.O_NOFOLLOW" in helper
    assert "os.unlink(name, dir_fd=dir_fd)" in helper
    assert 'usage: rm-site <site-user> <site-root> <path>' in helper
