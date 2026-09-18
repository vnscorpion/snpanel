import shlex

import pytest

from app.models.entities import Website
from app.services import cron


def _website(root, php_version="8.1", linux_user="siteuser"):
    return Website(
        domain="example.test",
        owner_id=1,
        root_path=str(root),
        linux_user=linux_user,
        php_version=php_version,
        app_type="php",
    )


@pytest.fixture
def site(tmp_path):
    public = tmp_path / "site" / "public_html"
    public.mkdir(parents=True)
    (public / "queue.php").write_text("<?php\n", encoding="utf-8")
    return tmp_path / "site"


@pytest.fixture
def captured_crontab(monkeypatch):
    """Capture what add_cron feeds to the privileged crontab writer."""
    calls = []

    def fake_privileged(helper_command, helper_args=None, **kwargs):
        calls.append((helper_command, helper_args, kwargs.get("input")))
        stdout = "" if helper_command == "cron-list" else ""
        return type("Result", (), {"returncode": 0, "stdout": stdout, "stderr": ""})()

    monkeypatch.setattr(cron.shell, "privileged", fake_privileged)
    monkeypatch.setattr(cron.site_users, "ensure_site_runtime", lambda *args, **kwargs: None)
    return calls


def test_php_binary_falls_back_when_version_is_unknown(site):
    assert cron.php_binary(_website(site, php_version="")) == "php"
    assert cron.php_binary(_website(site, php_version="not-a-version")) == "php"


def test_php_binary_uses_installed_site_version(site, monkeypatch, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "php8.1").write_text("", encoding="utf-8")
    monkeypatch.setattr(cron, "PHP_BIN_DIR", bin_dir)
    assert cron.php_binary(_website(site, php_version="8.1")) == str(bin_dir / "php8.1")
    assert cron.php_binary(_website(site, php_version="8.3")) == "php"


def test_add_cron_pins_the_website_php_binary(site, monkeypatch, captured_crontab, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "php8.1").write_text("", encoding="utf-8")
    monkeypatch.setattr(cron, "PHP_BIN_DIR", bin_dir)

    line = cron.add_cron(_website(site), "*/5 * * * *", "php -q queue.php")

    assert f"&& {shlex.quote(str(bin_dir / 'php8.1'))} -q " in line
    assert shlex.quote(str(site / "public_html" / "queue.php")) in line
    assert line.endswith("# snpanel:example.test")


def test_add_cron_keeps_redirections_as_shell_syntax(site, monkeypatch, captured_crontab, tmp_path):
    monkeypatch.setattr(cron, "PHP_BIN_DIR", tmp_path / "missing")

    line = cron.add_cron(_website(site), "*/5 * * * *", "php queue.php >/dev/null 2>&1")

    assert line.endswith(">/dev/null 2>&1 # snpanel:example.test")
    assert "'>/dev/null'" not in line


def test_add_cron_accepts_a_detached_redirect_operator(site, monkeypatch, captured_crontab, tmp_path):
    monkeypatch.setattr(cron, "PHP_BIN_DIR", tmp_path / "missing")

    line = cron.add_cron(_website(site), "*/5 * * * *", "php queue.php > /dev/null 2>&1")

    assert ">/dev/null 2>&1 # snpanel:example.test" in line


def test_add_cron_allows_a_log_file_inside_the_website(site, monkeypatch, captured_crontab, tmp_path):
    monkeypatch.setattr(cron, "PHP_BIN_DIR", tmp_path / "missing")

    line = cron.add_cron(_website(site), "*/5 * * * *", "php queue.php >> ../logs/cron.log 2>&1")

    assert f">>{shlex.quote(str(site / 'logs' / 'cron.log'))} 2>&1" in line


def test_add_cron_rejects_a_log_file_outside_the_website(site, monkeypatch, captured_crontab, tmp_path):
    monkeypatch.setattr(cron, "PHP_BIN_DIR", tmp_path / "missing")

    with pytest.raises(ValueError, match="inside this website"):
        cron.add_cron(_website(site), "*/5 * * * *", "php queue.php > ../../../cron.log")


def test_add_cron_rejects_bash_only_redirections(site, monkeypatch, captured_crontab, tmp_path):
    monkeypatch.setattr(cron, "PHP_BIN_DIR", tmp_path / "missing")

    with pytest.raises(ValueError, match="redirections are supported"):
        cron.add_cron(_website(site), "*/5 * * * *", "php queue.php &>/dev/null")


def test_add_cron_escapes_percent_so_cron_does_not_split_the_command(site, monkeypatch, captured_crontab, tmp_path):
    monkeypatch.setattr(cron, "PHP_BIN_DIR", tmp_path / "missing")

    line = cron.add_cron(_website(site), "0 2 * * *", "php queue.php >> ../logs/cron.log 2>&1")
    assert "%" not in line

    line = cron.add_cron(_website(site), "0 2 * * *", "php -q queue.php run=100%")
    assert "run=100\\%" in line


def test_parse_cron_line_reverses_percent_escaping():
    entry = cron._parse_cron_line(0, "0 2 * * * cd '/home/x/public_html' && /usr/bin/php8.1 a.php run=100\\% # snpanel:x.test")
    assert entry["command"] == "/usr/bin/php8.1 a.php run=100%"
    assert entry["schedule"] == "0 2 * * *"


def test_wp_cli_commands_run_on_the_site_php_binary(site, monkeypatch, captured_crontab, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "php8.1").write_text("", encoding="utf-8")
    wp = tmp_path / "wp"
    wp.write_text("", encoding="utf-8")
    monkeypatch.setattr(cron, "PHP_BIN_DIR", bin_dir)
    monkeypatch.setattr(cron, "WP_CLI_PATH", wp)

    line = cron.add_cron(_website(site), "*/5 * * * *", "wp cron event run --due-now")

    php_bin, wp_bin = shlex.quote(str(bin_dir / 'php8.1')), shlex.quote(str(wp))
    assert f"&& {php_bin} {wp_bin} wp cron event run --due-now --allow-root" not in line
    assert f"&& {php_bin} {wp_bin} cron event run --due-now --allow-root" in line


def test_listed_wp_entry_can_be_resubmitted(site, monkeypatch, captured_crontab, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "php8.1").write_text("", encoding="utf-8")
    wp = tmp_path / "wp"
    wp.write_text("", encoding="utf-8")
    monkeypatch.setattr(cron, "PHP_BIN_DIR", bin_dir)
    monkeypatch.setattr(cron, "WP_CLI_PATH", wp)

    line = cron.add_cron(
        _website(site),
        "*/5 * * * *",
        f"{shlex.quote(str(bin_dir / 'php8.1'))} {shlex.quote(str(wp))} cron event run --due-now",
    )

    php_bin, wp_bin = shlex.quote(str(bin_dir / 'php8.1')), shlex.quote(str(wp))
    assert f"{php_bin} {wp_bin} cron event run --due-now --allow-root" in line


def test_add_cron_still_rejects_arbitrary_commands(site, monkeypatch, captured_crontab, tmp_path):
    monkeypatch.setattr(cron, "PHP_BIN_DIR", tmp_path / "missing")

    with pytest.raises(ValueError):
        cron.add_cron(_website(site), "*/5 * * * *", "curl https://example.test")
    with pytest.raises(ValueError, match="public_html"):
        cron.add_cron(_website(site), "*/5 * * * *", "php ../../../elsewhere.php")


def test_retarget_php_binary_rewrites_existing_lines(site, monkeypatch, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "php8.3").write_text("", encoding="utf-8")
    monkeypatch.setattr(cron, "PHP_BIN_DIR", bin_dir)

    existing = (
        "*/5 * * * * cd '/home/siteuser/public_html' && /usr/bin/php8.1 -q '/home/siteuser/public_html/a.php' "
        "# snpanel:example.test\n"
        "0 3 * * * cd '/home/other/public_html' && /usr/bin/php8.1 '/home/other/public_html/b.php' # snpanel:other.test\n"
    )
    written = []

    def fake_privileged(helper_command, helper_args=None, **kwargs):
        if helper_command == "cron-write":
            written.append(kwargs.get("input"))
        return type("Result", (), {"returncode": 0, "stdout": existing, "stderr": ""})()

    monkeypatch.setattr(cron.shell, "privileged", fake_privileged)

    assert cron.retarget_php_binary(_website(site, php_version="8.3")) == 1
    assert f"&& {bin_dir / 'php8.3'} -q " in written[0]
    # The unrelated website keeps its own interpreter and its .php argument is untouched.
    assert "/usr/bin/php8.1 '/home/other/public_html/b.php'" in written[0]
    assert "/home/siteuser/public_html/a.php" in written[0]
