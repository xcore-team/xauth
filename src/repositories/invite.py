from __future__ import annotations

from typing import Optional

from sqlalchemy import select

from ..models.invite import Invite
from .base import BaseRepository


class InviteRepository(BaseRepository[Invite]):
    model = Invite

    async def get_by_token(self, token: str) -> Optional[Invite]:
        result = await self.session.execute(
            select(Invite).where(Invite.token == token)
        )
        return result.scalar_one_or_none()

    async def list_for_tenant(self, tenant_id: str) -> list[Invite]:
        result = await self.session.execute(
            select(Invite).where(Invite.tenant_id == tenant_id)
        )
        return list(result.scalars().all())
