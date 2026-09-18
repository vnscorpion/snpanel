import re
import shlex
from pathlib import Path

from app.core import platform
from app.models.entities import Website
from app.services import site_users
from app.services.shell import shell

CRON_FIELD_RE = r"(?:\*|\d{1,2})(?:[-/,](?:\*|\d{1,2}))*"
DOMAIN_GREP_RE = re.compile(r"^[a-z0-9.\-]{3,253}$")
PHP_VERSION_RE = re.compile(r"^\d\.\d$")
PHP_INTERPRETER_RE = re.compile(r"^php(?:\d\.\d)?$")
PHP_BIN_DIR = Path("/usr/bin")
WP_CLI_PATH = Path("/usr/local/bin/wp")
# Matches the interpreter token of an already installed cron line so it can be
# repointed when the website switches PHP version.
CRON_PHP_TOKEN_RE = re.compile(r"(&&\s+)((?:/usr/bin/)?php(?:\d\.\d)?)(\s)")
# `>file`, `>>file` and `2>file` open a target; `2>&1` / `1>&2` only duplicate a
# descriptor. Cron executes commands with /bin/sh, so bash-only forms such as
# `&>` are rejected instead of silently doing nothing.
REDIRECT_OPEN_RE = re.compile(r"^(\d?>>?)(.*)$")
REDIRECT_DUP_RE = re.compile(r"^\d?>&\d$")
# Anything else that opens with a shell operator (`&>`, `&&`, `|`, `;`, `<`)
# would otherwise be quoted into a literal argument and silently do nothing.
SHELL_OPERATOR_RE = re.compile(r"^[;&|<>]")
ALLOWED_COMMAND_PREFIXES = (
    ("wp", "cron", "event", "run", "--due-now"),
    ("wp", "core", "update"),
    ("wp", "plugin", "update", "--all"),
    ("wp", "theme", "update", "--all"),
)
ALLOWED_PHP_OPTIONS = {"-q"}


def _validate_schedule(schedule: str) -> str:
    fields = schedule.split()
    if len(fields) != 5 or not all(re.fullmatch(CRON_FIELD_RE, field) for field in fields):
        raise ValueError("Invalid cron schedule")
    return " ".join(fields)


def _validate_domain(domain: str) -> str:
    value = (domain or "").lower()
    if not DOMAIN_GREP_RE.fullmatch(value):
        raise ValueError("Invalid domain")
    return value


def php_binary(website: Website) -> str:
    """Return the PHP CLI binary a cron job for this website must use.

    A bare `php` resolves through /etc/alternatives to the newest installed
    version, so a site pinned to 8.1 would silently run its scripts on 8.4 and
    die on the first version-specific extension (ionCube, for example). Cron
    then looks "dead" even though the schedule fired correctly.
    """
    version = (website.php_version or "").strip()
    if not PHP_VERSION_RE.fullmatch(version):
        return "php"
    candidate = PHP_BIN_DIR / f"php{version}"
    return str(candidate) if candidate.exists() else "php"


def _is_php_interpreter(arg: str) -> bool:
    """True for `php`, `php8.1` or `/usr/bin/php8.1`.

    Listed cron entries show the resolved binary, so editing and re-submitting
    one has to keep validating as a PHP command.
    """
    return bool(PHP_INTERPRETER_RE.fullmatch(Path(arg).name))


def _escape_percent(command: str) -> str:
    """crontab turns an unescaped % into a newline fed to the job's stdin."""
    return re.sub(r"(?<!\\)%", r"\\%", command)


def _unescape_percent(command: str) -> str:
    return command.replace("\\%", "%")


def _split_redirection(args: list[str]) -> tuple[list[str], list[str]]:
    for index, arg in enumerate(args):
        if REDIRECT_DUP_RE.fullmatch(arg) or REDIRECT_OPEN_RE.match(arg):
            return args[:index], args[index:]
    return args, []


def _validate_redirect_target(target: str, document_root: str | Path, site_root: str | Path) -> str:
    if not target or any(char in target for char in "\r\n\x00"):
        raise ValueError("Invalid redirection target")
    if target == "/dev/null":
        return target
    script = Path(target)
    base = Path(document_root).resolve(strict=False)
    safe_root = Path(site_root).resolve(strict=False)
    candidate = (script if script.is_absolute() else base / script).resolve(strict=False)
    try:
        candidate.relative_to(safe_root)
    except ValueError as exc:
        raise ValueError(
            "Cron output can only be redirected to /dev/null or a file inside this website's folder"
        ) from exc
    return str(candidate)


def _validate_redirection(tokens: list[str], document_root: str | Path, site_root: str | Path) -> str:
    """Rebuild the trailing redirection so /bin/sh still sees it as syntax.

    Quoting these tokens the way command arguments are quoted turns
    `>/dev/null 2>&1` into two literal arguments: the redirect is lost and every
    run mails its output into a void.
    """
    parts: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if REDIRECT_DUP_RE.fullmatch(token):
            parts.append(token)
            index += 1
            continue
        match = REDIRECT_OPEN_RE.match(token)
        if not match:
            raise ValueError("Only the >, >>, 2> and 2>&1 redirections are supported")
        operator, target = match.group(1), match.group(2)
        if not target:
            index += 1
            if index >= len(tokens):
                raise ValueError("Redirection is missing a target file")
            target = tokens[index]
        parts.append(operator + shlex.quote(_validate_redirect_target(target, document_root, site_root)))
        index += 1
    return " ".join(parts)


def _validate_php_command(args: list[str], document_root: str | Path, php_bin: str) -> str:
    option_count = 1 if len(args) > 1 and args[1] in ALLOWED_PHP_OPTIONS else 0
    script_index = 1 + option_count
    if len(args) <= script_index or args[script_index].startswith("-"):
        raise ValueError("PHP cron commands must run a .php file; only the -q option is allowed")

    script = Path(args[script_index])
    if script.suffix.lower() != ".php":
        raise ValueError("PHP cron commands must run a .php file")

    safe_root = Path(document_root).resolve(strict=False)
    candidate = (script if script.is_absolute() else safe_root / script).resolve(strict=False)
    try:
        candidate.relative_to(safe_root)
    except ValueError as exc:
        raise ValueError("PHP cron scripts must be inside this website's public_html directory") from exc

    resolved = [php_bin, *args[1:script_index], str(candidate), *args[script_index + 1:]]
    return " ".join(shlex.quote(arg) for arg in resolved)


def _validate_wp_command(args: list[str], php_bin: str) -> str:
    normalized = [arg for arg in args if arg != "--allow-root"]
    if not any(tuple(normalized[:len(prefix)]) == prefix for prefix in ALLOWED_COMMAND_PREFIXES):
        raise ValueError("Only safe WP-CLI maintenance commands or PHP scripts inside this website are allowed")
    resolved = [*normalized, "--allow-root"]
    if php_bin != "php" and WP_CLI_PATH.exists():
        # The wp shebang is `#!/usr/bin/env php`, which would pick the system
        # default PHP instead of the version this website runs on.
        resolved = [php_bin, str(WP_CLI_PATH), *resolved[1:]]
    return " ".join(shlex.quote(arg) for arg in resolved)


def _validate_command(command: str, document_root: str | Path, site_root: str | Path, php_bin: str) -> str:
    args = shlex.split(command)
    if not args:
        raise ValueError("Cron command is required")
    args, redirection = _split_redirection(args)
    if not args:
        raise ValueError("Cron command is required")
    for arg in args:
        if SHELL_OPERATOR_RE.match(arg):
            raise ValueError("Only the >, >>, 2> and 2>&1 redirections are supported")
    if _is_php_interpreter(args[0]):
        # Listed WP-CLI entries read back as `<php binary> /usr/local/bin/wp ...`,
        # so drop the interpreter prefix before validating them again.
        if len(args) > 1 and Path(args[1]).name == "wp":
            body = _validate_wp_command(["wp", *args[2:]], php_bin)
        else:
            body = _validate_php_command(args, document_root, php_bin)
    else:
        body = _validate_wp_command(args, php_bin)
    suffix = _validate_redirection(redirection, document_root, site_root)
    return f"{body} {suffix}".strip()


# The account a website's cron jobs run as when the site has no user of its
# own. `www-data` on Ubuntu, `nginx` on EL - a job installed under the wrong
# name does not run at all.
WEB_USER = platform.web_user()


def cron_user_for_website(website: Website) -> str:
    if website.linux_user:
        return site_users.validate_linux_user(website.linux_user)
    try:
        parts = Path(website.root_path).resolve().relative_to(site_users.HOME_ROOT.resolve()).parts
    except ValueError:
        return WEB_USER
    if parts:
        try:
            return site_users.validate_linux_user(parts[0])
        except ValueError:
            return WEB_USER
    return WEB_USER


def _parse_cron_line(index: int, line: str) -> dict:
    parts = line.split(maxsplit=5)
    schedule = " ".join(parts[:5]) if len(parts) >= 5 else ""
    command = parts[5] if len(parts) >= 6 else ""
    command = re.sub(r"\s+#\s*snpanel:[^\s]+\s*$", "", command).strip()
    if command.startswith("cd ") and " && " in command:
        command = command.split(" && ", 1)[1].strip()
    command = _unescape_percent(command).replace(" --allow-root", "").strip()
    return {"index": index, "schedule": schedule, "command": command, "line": line}


def add_cron(website: Website, schedule: str, command: str) -> str:
    safe_schedule = _validate_schedule(schedule)
    document_root = site_users.document_root(website.root_path)
    safe_command = _validate_command(command, document_root, website.root_path, php_binary(website))
    safe_domain = _validate_domain(website.domain)
    marker = f"# snpanel:{safe_domain}"
    line = f"{safe_schedule} cd {shlex.quote(str(document_root))} && {_escape_percent(safe_command)} {marker}"
    cron_user = cron_user_for_website(website)
    if cron_user != WEB_USER:
        runtime_php_version = website.php_version if (website.app_type or "wordpress") in {"wordpress", "php"} else None
        site_users.ensure_site_runtime(website.domain, website.root_path, runtime_php_version, cron_user)
    existing = list_cron_all(cron_user)
    new_content = existing.rstrip() + ("\n" if existing.strip() else "") + line + "\n"
    shell.privileged(
        "cron-write",
        helper_args=[cron_user],
        input=new_content,
        fallback=["bash", "-lc", "crontab -"],
    )
    return line


def list_cron_all(cron_user: str = WEB_USER) -> str:
    if cron_user != WEB_USER:
        site_users.validate_linux_user(cron_user)
    result = shell.privileged(
        "cron-list",
        helper_args=[cron_user],
        check=False,
        fallback=["bash", "-lc", "crontab -l 2>/dev/null || true"],
    )
    return result.stdout or ""


def list_cron(domain: str, cron_user: str = WEB_USER) -> str:
    safe_domain = _validate_domain(domain)
    marker = f"snpanel:{safe_domain}"
    return "\n".join(line for line in list_cron_all(cron_user).splitlines() if marker in line)


def list_cron_entries(domain: str, cron_user: str = WEB_USER) -> list[dict]:
    return [_parse_cron_line(index, line) for index, line in enumerate(list_cron(domain, cron_user).splitlines())]


def delete_cron(domain: str, index: int, cron_user: str = WEB_USER) -> str:
    safe_domain = _validate_domain(domain)
    matching = list_cron(safe_domain, cron_user).splitlines()
    if index < 0 or index >= len(matching):
        raise ValueError("Cron not found")
    target = matching[index]
    full = list_cron_all(cron_user).splitlines()
    new_lines = [line for line in full if line.strip() != target.strip()]
    new_content = "\n".join(new_lines) + ("\n" if new_lines else "")
    shell.privileged(
        "cron-write",
        helper_args=[cron_user],
        input=new_content,
        fallback=["bash", "-lc", "crontab -"],
    )
    return target


def retarget_php_binary(website: Website) -> int:
    """Repoint this website's cron lines at its current PHP CLI.

    Called after a PHP version switch so existing jobs do not keep executing on
    the version the site no longer runs.
    """
    safe_domain = _validate_domain(website.domain)
    php_bin = php_binary(website)
    cron_user = cron_user_for_website(website)
    marker = f"snpanel:{safe_domain}"
    lines = list_cron_all(cron_user).splitlines()
    updated: list[str] = []
    changed = 0
    for line in lines:
        if marker in line:
            new_line = CRON_PHP_TOKEN_RE.sub(lambda match: f"{match.group(1)}{php_bin}{match.group(3)}", line, count=1)
            if new_line != line:
                changed += 1
                line = new_line
        updated.append(line)
    if not changed:
        return 0
    new_content = "\n".join(updated) + ("\n" if updated else "")
    shell.privileged(
        "cron-write",
        helper_args=[cron_user],
        input=new_content,
        fallback=["bash", "-lc", "crontab -"],
    )
    return changed
