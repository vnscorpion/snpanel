import os
import secrets
import string

from app.core.database import SessionLocal, run_migrations
from app.core.security import hash_password
from app.models.entities import User
from app.services import site_users


def _admin_password() -> str:
    if password := os.getenv("SNPANEL_ADMIN_PASSWORD"):
        if len(password) < 12:
            raise ValueError("SNPANEL_ADMIN_PASSWORD must be at least 12 characters")
        if any(char in password for char in (":", "\r", "\n", "\x00")):
            raise ValueError("SNPANEL_ADMIN_PASSWORD cannot contain ':', newlines, or NUL characters")
        return password
    alphabet = string.ascii_letters + string.digits + "!@#%^*_+-"
    return "".join(secrets.choice(alphabet) for _ in range(24))


def seed_admin():
    run_migrations()
    db = SessionLocal()
    try:
        password = None
        created = False
        if not db.query(User).filter(User.username == "admin").first():
            password = _admin_password()
            db.add(User(
                username="admin",
                email="admin@example.com",
                hashed_password=hash_password(password),
                role="admin",
                website_limit=999,
                storage_limit_mb=102400,
            ))
            db.commit()
            created = True
            print(f"Created admin user: admin / {password}")
        else:
            print("Admin user already exists")
        site_users.ensure_panel_user("admin", password if created else None)
    finally:
        db.close()


if __name__ == "__main__":
    seed_admin()
