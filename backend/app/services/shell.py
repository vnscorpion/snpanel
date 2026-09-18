"""
Shell execution layer.

Two trust levels:
- shell.run([...]):  runs as the API user (non-root after install).
- shell.privileged([...]): runs the snpanel-helper trampoline through sudo,
  so only whitelisted operations (defined in /usr/local/sbin/snpanel-helper)
  can ever execute as root.

Setting SNPANEL_USE_HELPER=false in dev/test makes privileged() fall back to
direct execution, so local development without the helper still works.
"""

import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import List, Optional

from app.core.config import settings


HELPER_PATH = "/usr/local/sbin/snpanel-helper"


def _use_helper() -> bool:
    flag = os.environ.get("SNPANEL_USE_HELPER")
    if flag is not None:
        return flag.lower() in {"1", "true", "yes", "on"}
    # Default: use helper when running as a non-root system user in production.
    geteuid = getattr(os, "geteuid", None)
    return bool(geteuid and geteuid() != 0 and os.path.exists(HELPER_PATH))


@dataclass
class CommandResult:
    command: str
    returncode: int
    stdout: str
    stderr: str


def _redact_output(value: str) -> str:
    if not value:
        return ""
    blocked = ("password", "identified by", "user_pass", "db_password")
    return "\n".join(line for line in value.splitlines() if not any(token in line.lower() for token in blocked))


def _decode_stream(value) -> str:
    """TimeoutExpired carries whatever was captured before the kill."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


class ShellRunner:
    def run(
        self,
        args: List[str],
        check: bool = True,
        input: Optional[str] = None,
        sensitive: bool = False,
        timeout: Optional[float] = None,
    ) -> CommandResult:
        """Run a subprocess as the current API user (non-root in production)."""
        return self._exec(list(args), check=check, input=input, sensitive=sensitive, timeout=timeout)

    def privileged(
        self,
        helper_command: str,
        helper_args: Optional[List[str]] = None,
        check: bool = True,
        input: Optional[str] = None,
        sensitive: bool = False,
        fallback: Optional[List[str]] = None,
        timeout: Optional[float] = None,
    ) -> CommandResult:
        """Run a privileged operation through the snpanel-helper sudo trampoline.

        helper_command: subcommand defined in /usr/local/sbin/snpanel-helper
        helper_args:    optional arguments passed to that subcommand
        fallback:       alternate command to run when the helper is not
                        installed (development convenience). Only used if
                        SNPANEL_USE_HELPER is false / unset and helper missing.
        timeout:        wall-clock seconds before the child is killed. Callers
                        that also pass a timeout to the helper should set this
                        slightly higher so the helper's own kill wins first and
                        the real command output is preserved.
        """
        helper_args = list(helper_args or [])
        if _use_helper():
            argv = ["sudo", "-n", HELPER_PATH, helper_command, *helper_args]
        elif fallback is not None:
            argv = list(fallback)
        else:
            raise RuntimeError(
                f"snpanel-helper is not available and no fallback was provided "
                f"for privileged operation '{helper_command}'"
            )
        return self._exec(argv, check=check, input=input, sensitive=sensitive, timeout=timeout)

    def _exec(
        self,
        argv: List[str],
        *,
        check: bool,
        input: Optional[str],
        sensitive: bool,
        timeout: Optional[float] = None,
    ) -> CommandResult:
        quoted = " ".join(shlex.quote(arg) for arg in argv)
        log_command = "[redacted]" if sensitive else quoted
        if settings.command_dry_run:
            return CommandResult(command=log_command, returncode=0, stdout=f"DRY RUN: {log_command}", stderr="")
        try:
            completed = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                check=False,
                input=input,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = _decode_stream(exc.stdout)
            stderr = _decode_stream(exc.stderr)
            message = f"Command timed out after {timeout:g}s"
            result = CommandResult(
                log_command,
                124,
                _redact_output(stdout) if sensitive else stdout,
                (_redact_output(stderr) if sensitive else stderr) + f"\n{message}",
            )
            if check:
                raise RuntimeError(f"{message}: {log_command}") from exc
            return result
        stdout = _redact_output(completed.stdout) if sensitive else completed.stdout
        stderr = _redact_output(completed.stderr) if sensitive else completed.stderr
        result = CommandResult(log_command, completed.returncode, stdout, stderr)
        if check and completed.returncode != 0:
            raise RuntimeError(f"Command failed: {log_command}\n{stderr}")
        return result


shell = ShellRunner()
