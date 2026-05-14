from __future__ import annotations

import json
import secrets
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..repositories.user import UserRepository


class MFAService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _generate_backup_codes(self, count: int = 8) -> list[str]:
        return [secrets.token_hex(5).upper() for _ in range(count)]

    async def setup_totp(self, user_id: str) -> dict:
        """
        Generate a TOTP secret and provisioning URI.
        Returns the secret and URI — caller must confirm via verify_totp before enabling.
        """
        try:
            import pyotp
        except ImportError:
            raise RuntimeError("pyotp is required for MFA. Install with: uv add pyotp")

        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user is None:
            raise ValueError("User not found")

        secret = pyotp.random_base32()
        user.mfa_secret = secret
        await self._session.flush()

        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=user.email, issuer_name="xauth")
        backup_codes = self._generate_backup_codes()

        return {
            "secret": secret,
            "provisioning_uri": uri,
            "backup_codes": backup_codes,
        }

    async def verify_totp(self, user_id: str, code: str) -> bool:
        """Verify a TOTP code against the user's stored secret."""
        try:
            import pyotp
        except ImportError:
            raise RuntimeError("pyotp is required for MFA.")

        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user is None or user.mfa_secret is None:
            return False

        totp = pyotp.TOTP(user.mfa_secret)
        return totp.verify(code, valid_window=1)

    async def enable_mfa(self, user_id: str, code: str) -> bool:
        """Enable MFA after confirming the code."""
        valid = await self.verify_totp(user_id, code)
        if not valid:
            return False

        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user:
            user.mfa_enabled = True
            await self._session.flush()
        return True

    async def disable_mfa(self, user_id: str) -> None:
        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user:
            user.mfa_enabled = False
            user.mfa_secret = None
            await self._session.flush()
