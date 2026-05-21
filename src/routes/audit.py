from typing import Any, List

from fastapi import APIRouter, Depends, Query
from xcore.kernel.api import AuthPayload, get_current_user
from xcore.sdk import require_permission

from ..services.audit import AuditService
from ..schemas.audit import AuditLogPage, AuditLogResponse


def audit_router(db: Any) -> APIRouter:
    router = APIRouter(prefix="/audit", tags=["audit"])

    @router.get("/me", response_model=AuditLogPage)
    async def list_my_audit(
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        current_user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        """Retourne l'historique d'activité de l'utilisateur connecté."""
        async with db.session() as session:
            svc = AuditService(session)
            return await svc.list_for_user_paged(
                current_user["sub"], limit=limit, offset=offset
            )

    @router.get("/tenants/{tenant_id}", response_model=List[AuditLogResponse])
    async def list_tenant_audit(
        tenant_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        _: AuthPayload = Depends(require_permission("audit:read")),
    ) -> Any:
        async with db.session() as session:
            svc = AuditService(session)
            return await svc.list_for_tenant(tenant_id, limit=limit, offset=offset)

    @router.get("/users/{user_id}", response_model=List[AuditLogResponse])
    async def list_user_audit(
        user_id: str,
        limit: int = Query(default=100, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        _: AuthPayload = Depends(require_permission("audit:read")),
    ) -> Any:
        async with db.session() as session:
            svc = AuditService(session)
            return await svc.list_for_user(user_id, limit=limit, offset=offset)

    return router
