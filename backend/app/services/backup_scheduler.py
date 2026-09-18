from datetime import datetime
import json

from app.core.database import SessionLocal
from app.core.secrets import decrypt
from app.models.entities import BackupSchedule, SftpBackupTarget, User
from app.services import backup


def _field_matches(field: str, value: int) -> bool:
    for part in field.split(","):
        part = part.strip()
        if not part:
            continue
        step = 1
        if "/" in part:
            part, step_text = part.split("/", 1)
            step = max(int(step_text or "1"), 1)
        if part == "*":
            start, end = 0, 59
        elif "-" in part:
            start_text, end_text = part.split("-", 1)
            start, end = int(start_text), int(end_text)
        else:
            start = end = int(part)
        if start <= value <= end and (value - start) % step == 0:
            return True
    return False


def _cron_due(schedule: str, now: datetime) -> bool:
    minute, hour, day, month, weekday = schedule.split()
    cron_weekday = (now.weekday() + 1) % 7
    return (
        _field_matches(minute, now.minute)
        and _field_matches(hour, now.hour)
        and _field_matches(day, now.day)
        and _field_matches(month, now.month)
        and (_field_matches(weekday, cron_weekday) or (cron_weekday == 0 and _field_matches(weekday, 7)))
    )


def _upload_if_configured(db, schedule: BackupSchedule, archive: str) -> str:
    if not schedule.target_id:
        return archive
    target = db.query(SftpBackupTarget).filter(SftpBackupTarget.id == schedule.target_id, SftpBackupTarget.is_active == True).first()  # noqa: E712
    if not target:
        raise ValueError("SFTP target not found")
    try:
        password = decrypt(target.password) if target.password else None
    except RuntimeError:
        raise RuntimeError(
            "Failed to decrypt SFTP target password; please re-save the target in panel settings"
        )
    try:
        private_key = decrypt(target.private_key) if target.private_key else None
    except RuntimeError:
        raise RuntimeError(
            "Failed to decrypt SFTP target private key; please re-save the target in panel settings"
        )
    result = backup.upload_to_sftp(
        archive,
        host=target.host,
        port=target.port,
        username=target.username,
        password=password,
        private_key=private_key,
        remote_path=target.remote_path,
        expected_host_key_type=target.host_key_type,
        expected_host_key_fingerprint=target.host_key_fingerprint,
    )
    if not target.host_key_fingerprint and result.get("host_key_fingerprint"):
        target.host_key_type = result["host_key_type"]
        target.host_key_fingerprint = result["host_key_fingerprint"]
        db.commit()
    return f"{target.name}:{result['remote_file']}"


def _decode_user_ids(raw: str | None) -> list[int]:
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        value = [item for item in raw.split(",") if item]
    if isinstance(value, int):
        value = [value]
    return [int(item) for item in value if int(item) > 0]


def _schedule_users(db, schedule: BackupSchedule) -> list[User]:
    if schedule.all_users:
        return db.query(User).filter(User.is_active == True).order_by(User.id.asc()).all()  # noqa: E712
    user_ids = _decode_user_ids(schedule.user_ids)
    if not user_ids and schedule.user_id:
        user_ids = [schedule.user_id]
    if not user_ids:
        return []
    users = db.query(User).filter(User.id.in_(user_ids)).all()
    by_id = {user.id: user for user in users}
    return [by_id[user_id] for user_id in user_ids if user_id in by_id]


def _short_message(parts: list[str]) -> str:
    message = "; ".join(parts)
    return message[:4000]


def run_due_schedules(now: datetime | None = None) -> int:
    now = (now or datetime.now()).replace(second=0, microsecond=0)
    db = SessionLocal()
    ran = 0
    try:
        schedules = db.query(BackupSchedule).filter(BackupSchedule.is_active == True).all()  # noqa: E712
        for schedule in schedules:
            if not _cron_due(schedule.schedule, now):
                continue
            if schedule.last_run_at and schedule.last_run_at.replace(second=0, microsecond=0) == now:
                continue
            users = _schedule_users(db, schedule)
            if not users:
                schedule.last_run_at = now
                schedule.last_status = "error"
                schedule.last_message = "No users selected"
                db.commit()
                continue
            messages = []
            errors = []
            for user in users:
                try:
                    archive = backup.create_user_backup(user, db)
                    target = _upload_if_configured(db, schedule, archive)
                    backup.prune_user_backups(user.username, schedule.retention)
                    messages.append(f"{user.username}: {target}")
                except Exception as exc:  # pragma: no cover - operational path
                    errors.append(f"{user.username}: {exc}")
            if errors:
                schedule.last_status = "error"
                schedule.last_message = _short_message([f"ok {len(messages)} user(s)"] + errors)
            else:
                schedule.last_status = "ok"
                schedule.last_message = _short_message([f"ok {len(messages)} user(s)"] + messages)
                ran += 1
            schedule.last_run_at = now
            db.commit()
    finally:
        db.close()
    return ran


if __name__ == "__main__":
    count = run_due_schedules()
    print(f"SNPanel backup scheduler ran {count} job(s).")
