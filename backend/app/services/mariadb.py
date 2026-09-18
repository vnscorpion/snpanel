from datetime import datetime
from pathlib import Path
import re
import secrets
import string
import subprocess
from typing import Dict

from app.core.config import settings
from app.services.shell import shell


IDENTIFIER_CHARS = set(string.ascii_lowercase + string.digits + "_")


def random_password(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#%^*_+-"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def safe_db_identifier(domain: str, prefix: str) -> str:
    clean = "".join(ch if ch.isalnum() else "_" for ch in domain.lower())[:38]
    return f"{prefix}_{clean}"[:63]


def _validate_identifier(value: str) -> str:
    if not value or len(value) > 64 or any(ch not in IDENTIFIER_CHARS for ch in value):
        raise ValueError("Invalid database identifier")
    return value


# MariaDB's own accounts, plus the one the panel authenticates as. Creating a
# database must never touch any of them, on any code path - not even a restore.
RESERVED_DB_USERS = frozenset({
    "root",
    "mysql",
    "mariadb.sys",
    "debian-sys-maint",
    "snpanel",
})


def _reject_reserved_user(db_user: str) -> None:
    if db_user.strip().lower() in RESERVED_DB_USERS:
        raise ValueError(f"'{db_user}' is a reserved MariaDB account and cannot be used for a website database")


def user_exists(db_user: str) -> bool:
    """Whether this MariaDB account already exists.

    Asked of MariaDB rather than of SNPanel's own table: the whole point is to
    notice accounts SNPanel does not know about, which is exactly what the
    table cannot tell us.
    """
    safe = _validate_identifier(db_user)
    result = _run_sql(
        f"SELECT 1 FROM mysql.user WHERE user = {_quote_sql_string(safe)} LIMIT 1;\n",
        check=False,
    )
    return "1" in (result.stdout or "")


def _quote_sql_string(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def _quote_identifier(value: str) -> str:
    return f"`{_validate_identifier(value)}`"


_NATIVE_PASSWORD_HASH_RE = re.compile(r"^\*[0-9A-Fa-f]{40}$")


def _auth_clause(db_password: str, password_hash: str | None) -> str:
    """The IDENTIFIED ... clause for CREATE/ALTER USER.

    When a mysql_native_password hash is given (DirectAdmin keeps the original
    in its <db>.conf), the user is recreated with that exact hash so the
    imported site's existing config keeps working untouched. The hash is a
    fixed shape (``*`` + 40 hex) and is validated before it reaches any SQL.
    """
    if password_hash:
        if not _NATIVE_PASSWORD_HASH_RE.match(password_hash):
            raise ValueError("Invalid mysql_native_password hash")
        return f"IDENTIFIED VIA mysql_native_password USING '{password_hash}'"
    return f"IDENTIFIED BY {_quote_sql_string(db_password)}"


def _mysql_args(extra: list = None) -> list:
    args = ["mysql"]
    home_cnf = Path.home() / ".my.cnf"
    if home_cnf.exists():
        args.append(f"--defaults-file={home_cnf}")
    if extra:
        args.extend(extra)
    return args


def _run_sql(sql: str, *, check: bool = True):
    """Pipe SQL through stdin so secrets never appear in argv/ps output."""
    return shell.run(_mysql_args(), check=check, input=sql, sensitive=True)


def create_database(seed: str, prefix: str = "wp", db_name: str | None = None, if_not_exists: bool = True) -> Dict[str, str]:
    db_name = _validate_identifier(db_name or safe_db_identifier(seed, prefix))
    db_user = _validate_identifier(safe_db_identifier(db_name, "u"))
    _reject_reserved_user(db_user)
    db_password = random_password()
    create_clause = "CREATE DATABASE IF NOT EXISTS" if if_not_exists else "CREATE DATABASE"
    sql = (
        f"{create_clause} {_quote_identifier(db_name)} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;\n"
        f"CREATE USER IF NOT EXISTS {_quote_sql_string(db_user)}@'localhost' IDENTIFIED BY {_quote_sql_string(db_password)};\n"
        f"ALTER USER {_quote_sql_string(db_user)}@'localhost' IDENTIFIED BY {_quote_sql_string(db_password)};\n"
        f"GRANT ALL PRIVILEGES ON {_quote_identifier(db_name)}.* TO {_quote_sql_string(db_user)}@'localhost';\n"
        "FLUSH PRIVILEGES;\n"
    )
    _run_sql(sql)
    return {"db_name": db_name, "db_user": db_user, "db_password": db_password}


def create_database_credentials(
    db_name: str, db_user: str, db_password: str, *, password_hash: str | None = None,
    allow_existing_user: bool = False,
) -> Dict[str, str]:
    """Create a database and the account that owns it.

    `CREATE USER IF NOT EXISTS` followed by an unconditional `ALTER USER` used
    to mean "create it, or take it over". Since the panel authenticates to
    MariaDB with ALL PRIVILEGES ON *.*, any panel user who asked for
    db_user=root got root's password reset to a value of their choosing - and
    the API handed it back in the response. On a stock Ubuntu box root is
    `IDENTIFIED VIA mysql_native_password USING 'invalid' OR unix_socket`, so
    the ALTER also drops the socket clause and locks the system's own root out
    of MariaDB.

    Creating now refuses an account that already exists. `allow_existing_user`
    is for the restore paths - a backup or a DirectAdmin import legitimately
    recreates the account that archive already owned - and even those cannot
    touch a reserved account.
    """
    db_name = _validate_identifier(db_name)
    db_user = _validate_identifier(db_user)
    _reject_reserved_user(db_user)

    if not allow_existing_user and user_exists(db_user):
        raise ValueError(
            f"MariaDB account '{db_user}' already exists. Choose another database user name."
        )

    auth = _auth_clause(db_password, password_hash)
    statements = [
        f"CREATE DATABASE IF NOT EXISTS {_quote_identifier(db_name)} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;",
        f"CREATE USER IF NOT EXISTS {_quote_sql_string(db_user)}@'localhost' {auth};",
    ]
    if allow_existing_user:
        # Only a restore sets the password of an account that was already there.
        statements.append(f"ALTER USER {_quote_sql_string(db_user)}@'localhost' {auth};")
    statements += [
        f"GRANT ALL PRIVILEGES ON {_quote_identifier(db_name)}.* TO {_quote_sql_string(db_user)}@'localhost';",
        "FLUSH PRIVILEGES;",
    ]
    _run_sql("\n".join(statements) + "\n")
    return {"db_name": db_name, "db_user": db_user, "db_password": db_password}


def drop_database(db_name: str, db_user: str):
    _reject_reserved_user(_validate_identifier(db_user))
    sql = (
        f"DROP DATABASE IF EXISTS {_quote_identifier(db_name)};\n"
        f"DROP USER IF EXISTS {_quote_sql_string(_validate_identifier(db_user))}@'localhost';\n"
        "FLUSH PRIVILEGES;\n"
    )
    return _run_sql(sql)


def change_database_password(db_user: str, db_password: str):
    _reject_reserved_user(_validate_identifier(db_user))
    sql = (
        f"ALTER USER {_quote_sql_string(_validate_identifier(db_user))}@'localhost' "
        f"IDENTIFIED BY {_quote_sql_string(db_password)};\n"
        "FLUSH PRIVILEGES;\n"
    )
    return _run_sql(sql)


def export_database(db_name: str, output_file: str):
    args = ["mysqldump"]
    home_cnf = Path.home() / ".my.cnf"
    if home_cnf.exists():
        args.append(f"--defaults-file={home_cnf}")
    args.extend([_validate_identifier(db_name), "--result-file", output_file])
    return shell.run(args, sensitive=True)


def import_database(db_name: str, input_file: str):
    safe_name = _validate_identifier(db_name)
    sql_path = Path(input_file).resolve()
    if not sql_path.exists() or not sql_path.is_file():
        raise FileNotFoundError("SQL file not found")
    if settings.command_dry_run:
        return shell.run(["mysql", safe_name], sensitive=True)
    args = _mysql_args([safe_name])
    with sql_path.open("rb") as source:
        completed = subprocess.run(args, stdin=source, capture_output=True, check=False)
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"Database import failed: {stderr.strip()}")
    return completed


def dump_database_file(db_name: str, output_dir: Path) -> Path:
    safe_name = _validate_identifier(db_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    target = output_dir / f"{safe_name}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.sql"
    export_database(safe_name, str(target))
    if settings.command_dry_run and not target.exists():
        target.write_text(f"-- DRY RUN database dump for {safe_name}\n", encoding="utf-8")
    return target
