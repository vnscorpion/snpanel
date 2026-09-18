"""Install and remove the panel's optional features.

Only an administrator sees this: an addon changes the server, not one account.
Every other user is told what exists so they know what to ask for, without being
able to turn it on.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_current_user
from app.core.database import get_db
from app.core.permissions import Role, ensure_role, is_admin_role
from app.models.entities import SiteApp, User
from app.services import addons, site_apps
from app.services.audit import log_action

router = APIRouter(prefix="/addons", tags=["addons"])


@router.get("")
def list_addons(current_user: User = Depends(get_current_user)):
    """What the panel can do, and what it is currently doing.

    Readable by every role: the sections a customer cannot see are the ones an
    addon has not been installed for, and a blank panel with no explanation is
    worse than one that says which feature is missing.
    """
    ensure_role(current_user.role, Role.end_user)
    entries = addons.state()
    if not is_admin_role(current_user.role):
        # A customer has no business knowing how the server is put together.
        for entry in entries:
            entry.pop("notes", None)
    return {"items": entries, "can_manage": is_admin_role(current_user.role)}


@router.post("/{slug}/install")
def install_addon(slug: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    ensure_role(current_user.role, Role.admin)
    entry = addons.known(slug)
    record = addons.install(slug)
    log_action(db, current_user.id, "install_addon", slug, record.get("version", ""))
    return {
        "slug": slug,
        "name": entry["name"],
        "installed": True,
        "version": record.get("version", ""),
        # The runtimes an application needs are installed from the Application
        # page itself, which can report progress; saying so here saves someone
        # wondering why Docker did not appear.
        "next_step": "Vào mục Application để cài Docker hoặc bản Node.js cần dùng."
        if slug == addons.APPLICATION else "",
    }


@router.post("/{slug}/uninstall")
def uninstall_addon(slug: str, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Turn an addon off. Nothing it created is deleted.

    The units are stopped, because a panel that no longer shows a feature should
    not keep running it where nobody can see or manage it. Everything else — the
    files, the volumes, the rows — stays exactly where it is, so installing the
    addon again brings it all back.
    """
    ensure_role(current_user.role, Role.admin)
    entry = addons.known(slug)
    stopped: list[str] = []
    failed: list[str] = []
    if slug == addons.APPLICATION:
        for app in db.query(SiteApp).all():
            try:
                site_apps.control(app, "stop")
                stopped.append(app.name)
            except (RuntimeError, ValueError):
                # Already gone, or never deployed. Not a reason to refuse.
                failed.append(app.name)
    addons.uninstall(slug)
    log_action(db, current_user.id, "uninstall_addon", slug, f"stopped {len(stopped)}")
    return {
        "slug": slug,
        "name": entry["name"],
        "installed": False,
        "stopped": stopped,
        "could_not_stop": failed,
        "kept": "Thư mục ứng dụng, volume và dữ liệu trong panel được giữ nguyên.",
    }
