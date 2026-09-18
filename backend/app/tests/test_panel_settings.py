from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api import panel_settings as panel_settings_api
from app.core.database import Base
from app.core.security import hash_password
from app.models.entities import User
from app.schemas.schemas import AdminAccountUpdate, PanelSslInstall


def _db_session():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    return sessionmaker(bind=engine)()


def _admin(email="admin@example.com", password="old-password"):
    return User(
        id=1,
        username="admin",
        email=email,
        hashed_password=hash_password(password),
        role="admin",
        is_active=True,
    )


def test_update_admin_account_updates_email_and_password(monkeypatch):
    db = _db_session()
    user = _admin()
    original_hash = user.hashed_password
    db.add(user)
    db.commit()
    captured = {}

    monkeypatch.setattr(panel_settings_api.site_users, "set_panel_user_password", lambda username, password: captured.update(username=username, password=password))
    monkeypatch.setattr(panel_settings_api, "log_action", lambda *args, **kwargs: None)

    result = panel_settings_api.update_admin_account(
        AdminAccountUpdate(
            email="new-admin@example.com",
            password="new-password-123",
            current_password="old-password",
        ),
        request=None,
        db=db,
        current_user=user,
    )

    db.refresh(user)
    assert result == {"message": "Admin account updated", "password_changed": True}
    assert captured == {"username": "admin", "password": "new-password-123"}
    assert user.email == "new-admin@example.com"
    assert user.token_version == 1
    assert user.hashed_password != original_hash


def test_install_panel_ssl_uses_current_admin_email(monkeypatch):
    db = _db_session()
    user = _admin(email="owner@example.com")
    db.add(user)
    db.commit()
    captured = {}

    def fake_install_panel_ssl(email, panel_hostname=None, panel_port=None, panel_url=None):
        captured["email"] = email
        captured["panel_hostname"] = panel_hostname
        captured["panel_port"] = panel_port
        captured["panel_url"] = panel_url
        return {"message": "ok"}

    monkeypatch.setattr(panel_settings_api.panel_settings, "install_panel_ssl", fake_install_panel_ssl)
    monkeypatch.setattr(panel_settings_api, "log_action", lambda *args, **kwargs: None)

    panel_settings_api.install_panel_ssl(
        PanelSslInstall(
            panel_hostname="panel.example.test",
            panel_port=2222,
            email="ignored@example.com",
        ),
        request=None,
        db=db,
        current_user=user,
    )

    assert captured == {
        "email": "owner@example.com",
        "panel_hostname": "panel.example.test",
        "panel_port": 2222,
        "panel_url": None,
    }
