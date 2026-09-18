from fastapi import APIRouter, Depends, Query

from app.api.deps import get_current_user
from app.core.permissions import Role, ensure_role
from app.models.entities import User
from app.schemas.schemas import SystemAutoUpdateConfig
from app.services import updates

router = APIRouter(prefix="/updates", tags=["updates"])


@router.get("/status")
def get_update_status(refresh: bool = Query(default=False), current_user: User = Depends(get_current_user)):
    ensure_role(current_user.role, Role.admin)
    return updates.status(force_refresh=refresh)


@router.post("/os/run")
def run_os_update(current_user: User = Depends(get_current_user)):
    ensure_role(current_user.role, Role.admin)
    return updates.run_os_update().__dict__


@router.post("/os/auto")
def configure_os_auto_update(payload: SystemAutoUpdateConfig, current_user: User = Depends(get_current_user)):
    ensure_role(current_user.role, Role.admin)
    return updates.configure_os_auto_update(payload.enabled, payload.mode, payload.auto_reboot).__dict__


@router.post("/panel/run")
def run_panel_update(current_user: User = Depends(get_current_user)):
    ensure_role(current_user.role, Role.admin)
    return updates.run_panel_update().__dict__
