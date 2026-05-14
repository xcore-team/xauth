from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.kernel.api import AuthBackend

from ..models.session import Session
from ..models.user import TenantMember, User
from ..repositories.session import SessionRepository
from ..repositories.tenant import TenantRepository
from ..repositories.user import TenantMemberRepository, UserRepository
from .events import XAuthEvents
from .token import TokenService


def _get_password_context():
    try:
        from passlib.context import CryptContext

        return CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")
    except ImportError:
        pass
    try:
        from passlib.context import CryptContext

        return CryptContext(schemes=["bcrypt"], deprecated="auto")
    except ImportError:
        raise RuntimeError("passlib is required. Install with: uv add passlib[argon2]")


_pwd_context = None


def get_pwd_context():
    global _pwd_context
    if _pwd_context is None:
        _pwd_context = _get_password_context()
    return _pwd_context


def _check_password_policy(
    password: str,
    min_length: int = 8,
    require_uppercase: bool = True,
    require_digit: bool = True,
) -> None:
    if len(password) < min_length:
        raise ValueError(f"Password must be at least {min_length} characters long")
    if require_uppercase and not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")
    if require_digit and not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit")


class AuthService(AuthBackend):
    def __init__(
        self,
        session: AsyncSession,
        token_service: TokenService,
        events: XAuthEvents | None = None,
    ) -> None:
        self._session = session
        self._token = token_service
        self._events = events

    async def register(
        self,
        email: str,
        password: str,
        tenant_slug: Optional[str] = None,
        min_length: int = 8,
        require_uppercase: bool = True,
        require_digit: bool = True,
    ) -> User:
        _check_password_policy(
            password,
            min_length=min_length,
            require_uppercase=require_uppercase,
            require_digit=require_digit,
        )

        user_repo = UserRepository(self._session)
        existing = await user_repo.get_by_email(email)
        if existing is not None:
            raise ValueError("Email already registered")

        hashed = get_pwd_context().hash(password)
        user = User(email=email, hashed_password=hashed)
        await user_repo.save(user)

        # Assigne le membership dans le tenant demandé (ou le tenant par défaut)
        from ..repositories.rbac import RoleRepository

        tenant_repo = TenantRepository(self._session)
        if tenant_slug:
            tenant = await tenant_repo.get_by_slug(tenant_slug)
        else:
            tenant = await tenant_repo.get_by_slug("default")

        if tenant:
            role_repo = RoleRepository(self._session)
            global_roles = await role_repo.list_for_tenant(None)
            user_role = next((r for r in global_roles if r.name == "user"), None)

            member_repo = TenantMemberRepository(self._session)
            membership = TenantMember(
                user_id=user.id,
                tenant_id=tenant.id,
                role_id=user_role.id if user_role else None,
            )
            await member_repo.save(membership)

        if self._events:
            await self._events.user_registered(
                user_id=user.id,
                email=user.email,
                tenant_id=tenant_slug,
            )

        return user

    async def refresh(
        self, refresh_token: str, ip_address: Optional[str] = None
    ) -> dict[str, Any]:
        hashed = self._token.hash_token(refresh_token)
        session_repo = SessionRepository(self._session)
        session = await session_repo.get_by_refresh_token(hashed)

        if session is None:
            raise ValueError("Invalid or expired refresh token")

        now = datetime.now(tz=timezone.utc)
        expires = session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            session.is_revoked = True
            await self._session.flush()
            raise ValueError("Refresh token expired")

        # Rotate: revoke old, create new
        session.is_revoked = True
        await self._session.flush()

        new_refresh_plain = self._token.create_refresh_token()
        new_refresh_hashed = self._token.hash_token(new_refresh_plain)

        new_session = Session(
            user_id=session.user_id,
            tenant_id=session.tenant_id,
            refresh_token=new_refresh_hashed,
            device_fingerprint=session.device_fingerprint,
            ip_address=ip_address or session.ip_address,
            expires_at=datetime.now(tz=timezone.utc)
            + timedelta(days=self._token._refresh_expire),
        )
        await session_repo.save(new_session)

        access_token = self._token.create_access_token(
            user_id=session.user_id, tenant_id=session.tenant_id
        )

        if self._events:
            await self._events.session_refreshed(
                user_id=session.user_id, tenant_id=session.tenant_id
            )

        return {
            "access_token": access_token,
            "refresh_token": new_refresh_plain,
            "token_type": "bearer",
        }

    async def logout(self, refresh_token: str) -> None:
        hashed = self._token.hash_token(refresh_token)
        session_repo = SessionRepository(self._session)
        session = await session_repo.get_by_refresh_token(hashed)
        if session:
            session.is_revoked = True
            await self._session.flush()
            if self._events:
                await self._events.user_logout(user_id=session.user_id)

    async def verify_token(self, token: str) -> dict[str, Any]:
        """Verify an access token and return its claims."""
        return self._token.verify_access_token(token)

    async def login(
        self,
        email: str,
        password: str,
        tenant_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        device_fingerprint: Optional[str] = None,
    ) -> dict[str, Any]:
        user_repo = UserRepository(self._session)
        user = await user_repo.get_by_email(email)
        if user is None or not get_pwd_context().verify(password, user.hashed_password):
            if self._events:
                await self._events.user_login_failed(email=email, ip=ip_address, reason="invalid_credentials")
            raise ValueError("Invalid credentials")
        if not user.is_active:
            if self._events:
                await self._events.user_login_failed(email=email, ip=ip_address, reason="account_inactive")
            raise ValueError("Account is inactive")

        # ── Résolution du tenant ──────────────────────────────────────────────────
        member_repo = TenantMemberRepository(self._session)

        if not tenant_id:
            memberships = await member_repo.get_memberships_for_user(user.id)

            if not memberships:
                raise ValueError("No tenant membership found for this user")

            if len(memberships) == 1:
                # Un seul tenant → on scope directement, flow normal
                tenant_id = memberships[0].tenant_id
            else:
                # Plusieurs tenants → on retourne la liste sans émettre d'access token
                # On crée quand même la session pour le refresh token
                refresh_token_plain = self._token.create_refresh_token()
                refresh_token_hashed = self._token.hash_token(refresh_token_plain)
                session_repo = SessionRepository(self._session)
                session = Session(
                    user_id=user.id,
                    tenant_id=None,
                    refresh_token=refresh_token_hashed,
                    device_fingerprint=device_fingerprint,
                    ip_address=ip_address,
                    expires_at=datetime.now(tz=timezone.utc)
                    + timedelta(days=self._token._refresh_expire),
                )
                await session_repo.save(session)

                # Charger les infos tenant pour l'affichage
                from ..repositories.tenant import TenantRepository
                tenant_repo = TenantRepository(self._session)
                tenants = []
                for m in memberships:
                    t = await tenant_repo.get(m.tenant_id)
                    tenants.append({
                        "id": m.tenant_id,
                        "name": t.name if t else None,
                        "slug": t.slug if t else None,
                        "role_id": m.role_id,
                        "is_owner": m.is_owner,
                    })

                return {
                    "access_token": "",
                    "refresh_token": refresh_token_plain,
                    "token_type": "bearer",
                    "user_id": user.id,
                    "tenant_id": None,
                    "mfa_required": user.mfa_enabled,
                    "tenants": tenants,
                }
        else:
            # tenant_id fourni → vérifier que le user en est bien membre
            membership = await member_repo.get_membership(user.id, tenant_id)
            if membership is None:
                raise ValueError("User is not a member of this tenant")

        # ── Flow normal : émission des tokens ─────────────────────────────────────
        access_token = self._token.create_access_token(user_id=user.id, tenant_id=tenant_id)
        refresh_token_plain = self._token.create_refresh_token()
        refresh_token_hashed = self._token.hash_token(refresh_token_plain)

        session_repo = SessionRepository(self._session)
        session = Session(
            user_id=user.id,
            tenant_id=tenant_id,
            refresh_token=refresh_token_hashed,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            expires_at=datetime.now(tz=timezone.utc)
            + timedelta(days=self._token._refresh_expire),
        )
        await session_repo.save(session)

        if self._events:
            await self._events.user_login(
                user_id=user.id, email=user.email, ip=ip_address, tenant_id=tenant_id
            )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_plain,
            "token_type": "bearer",
            "user_id": user.id,
            "tenant_id": tenant_id,
            "mfa_required": user.mfa_enabled,
            "tenants": None,
        }


    async def select_tenant(
        self,
        refresh_token: str,
        tenant_id: str,
        ip_address: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Émet un access token scopé après sélection du tenant par l'utilisateur.
        Le refresh token doit être valide et non encore scopé (tenant_id = None).
        """
        hashed = self._token.hash_token(refresh_token)
        session_repo = SessionRepository(self._session)
        session = await session_repo.get_by_refresh_token(hashed)

        if session is None:
            raise ValueError("Invalid or expired refresh token")

        now = datetime.now(tz=timezone.utc)
        expires = session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires < now:
            session.is_revoked = True
            await self._session.flush()
            raise ValueError("Refresh token expired")

        # Vérifier que le user appartient bien au tenant demandé
        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(session.user_id, tenant_id)
        if membership is None:
            raise ValueError("User is not a member of this tenant")

        # Mise à jour de la session avec le tenant choisi
        session.tenant_id = tenant_id
        await self._session.flush()

        access_token = self._token.create_access_token(
            user_id=session.user_id, tenant_id=tenant_id
        )

        if self._events:
            await self._events.user_login(
                user_id=session.user_id,
                email="",
                ip=ip_address,
                tenant_id=tenant_id,
            )

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,  # pas de rotation ici
            "token_type": "bearer",
            "user_id": session.user_id,
            "tenant_id": tenant_id,
            "mfa_required": False,
            "tenants": None,
        }
