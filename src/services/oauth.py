from __future__ import annotations

import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

logger = logging.getLogger("xauth.oauth")

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.oauth import OAuthAccount
from ..models.session import Session
from ..models.user import TenantMember, User
from ..providers.base import OAuthProvider, OAuthUserInfo
from ..repositories.oauth import OAuthAccountRepository
from ..repositories.rbac import RoleRepository
from ..repositories.session import SessionRepository
from ..repositories.user import TenantMemberRepository, UserRepository
from ..repositories.tenant import TenantRepository
from .token import TokenService

# TTL du state CSRF en secondes
_STATE_TTL = 1800
_STATE_KEY_PREFIX = "xauth:oauth:state:"


class OAuthService:
    """
    Gère le flow OAuth2 complet : génération d'URL, callback, find-or-create user.
    Le state CSRF est stocké en cache Redis (TTL 10min).
    """

    def __init__(
        self,
        session: AsyncSession,
        token_service: TokenService,
        cache: Any,
        providers: dict[str, OAuthProvider],
    ) -> None:
        self._session = session
        self._token = token_service
        self._cache = cache
        self._providers = providers

    # ── Providers registry ────────────────────────────────────────────────────

    def get_provider(self, name: str) -> OAuthProvider:
        provider = self._providers.get(name)
        if provider is None:
            available = ", ".join(self._providers.keys()) or "aucun"
            raise ValueError(f"Provider '{name}' inconnu. Disponibles : {available}")
        return provider

    def list_providers(self) -> list[str]:
        return list(self._providers.keys())

    # ── Step 1 : générer l'URL d'autorisation ────────────────────────────────

    async def get_auth_url(
        self,
        provider_name: str,
        tenant_id: Optional[str] = None,
        post_login_redirect: Optional[str] = None,
    ) -> str:
        provider = self.get_provider(provider_name)

        state = secrets.token_urlsafe(32)
        state_data = {
            "provider": provider_name,
            "tenant_id": tenant_id,
            "redirect": post_login_redirect,
        }
        await self._cache.set(
            f"{_STATE_KEY_PREFIX}{state}",
            json.dumps(state_data),
            ttl=_STATE_TTL,
        )
        return provider.get_auth_url(state)

    # ── Step 2 : callback — échange le code, trouve ou crée le user ──────────

    async def handle_callback(
        self,
        provider_name: str,
        code: str,
        state: str,
        ip_address: Optional[str] = None,
    ) -> dict[str, Any]:
        # Vérifier et consommer le state CSRF
        state_key = f"{_STATE_KEY_PREFIX}{state}"
        raw = await self._cache.get(state_key)
        if raw is None:
            raise ValueError("State OAuth invalide ou expiré.")
        await self._cache.delete(state_key)

        state_data = raw if isinstance(raw, dict) else json.loads(raw)
        if state_data.get("provider") != provider_name:
            raise ValueError("State OAuth : provider mismatch.")

        provider = self.get_provider(provider_name)

        # Échanger le code contre un access token
        token_data = await provider.exchange_code(code)
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError(f"Le provider n'a pas retourné d'access_token : {token_data}")

        # Récupérer le profil utilisateur
        user_info = await provider.get_user_info(access_token)

        # Find-or-create (stores provider_token on the OAuthAccount)
        user, is_new_user = await self._find_or_create_user(user_info, provider_token=access_token)

        # Créer la session xauth (refresh token rotatif)
        refresh_plain = self._token.create_refresh_token()
        refresh_hashed = self._token.hash_token(refresh_plain)
        tenant_id = state_data.get("tenant_id")

        session_repo = SessionRepository(self._session)
        xauth_session = Session(
            user_id=user.id,
            tenant_id=tenant_id,
            refresh_token=refresh_hashed,
            ip_address=ip_address,
            expires_at=datetime.now(tz=timezone.utc)
            + timedelta(days=self._token._refresh_expire),
        )
        await session_repo.save(xauth_session)

        access_jwt = self._token.create_access_token(
            user_id=user.id, tenant_id=tenant_id
        )

        return {
            "access_token": access_jwt,
            "refresh_token": refresh_plain,
            "token_type": "bearer",
            "user_id": user.id,
            "email": user.email,
            "tenant_id": tenant_id,
            "provider": provider_name,
            "provider_token": token_data.get("access_token"),
            "is_new_user": is_new_user,
            "post_login_redirect": state_data.get("redirect"),
        }

    # ── Lier un provider à un user déjà authentifié ──────────────────────────

    async def link_provider(
        self,
        user_id: str,
        provider_name: str,
        code: str,
        state: str,
    ) -> OAuthAccount:
        # Vérifier le state
        state_key = f"{_STATE_KEY_PREFIX}{state}"
        raw = await self._cache.get(state_key)
        if raw is None:
            raise ValueError("State OAuth invalide ou expiré.")
        await self._cache.delete(state_key)

        provider = self.get_provider(provider_name)
        token_data = await provider.exchange_code(code)
        access_token = token_data.get("access_token")
        if not access_token:
            raise ValueError("Échange de code échoué.")

        user_info = await provider.get_user_info(access_token)

        oauth_repo = OAuthAccountRepository(self._session)

        # Vérifier que ce compte provider n'est pas déjà lié à un autre user
        existing = await oauth_repo.get_by_provider(provider_name, user_info.provider_user_id)
        if existing and existing.user_id != user_id:
            raise ValueError(
                f"Ce compte {provider_name} est déjà lié à un autre utilisateur."
            )

        if existing:
            existing.provider_token = access_token
            return existing

        account = OAuthAccount(
            user_id=user_id,
            provider=provider_name,
            provider_user_id=user_info.provider_user_id,
            provider_email=user_info.email,
            provider_name=user_info.name,
            provider_avatar=user_info.avatar_url,
            provider_token=access_token,
        )
        return await oauth_repo.save(account)

    # ── Délier un provider ────────────────────────────────────────────────────

    async def unlink_provider(self, user_id: str, provider_name: str) -> None:
        oauth_repo = OAuthAccountRepository(self._session)
        account = await oauth_repo.get_by_user_and_provider(user_id, provider_name)
        if account is None:
            raise ValueError(f"Aucun compte {provider_name} lié à cet utilisateur.")

        # Empêcher de délier si c'est le seul moyen de connexion (pas de password)
        user_repo = UserRepository(self._session)
        user = await user_repo.get(user_id)
        if user and not user.hashed_password:
            all_accounts = await oauth_repo.list_for_user(user_id)
            if len(all_accounts) <= 1:
                raise ValueError(
                    "Impossible de délier : ce compte n'a pas de mot de passe. "
                    "Définissez un mot de passe avant de délier ce provider."
                )

        await self._session.delete(account)
        await self._session.flush()

    # ── Internal ──────────────────────────────────────────────────────────────

    async def _find_or_create_user(
        self, info: OAuthUserInfo, provider_token: Optional[str] = None
    ) -> tuple[User, bool]:
        """Retourne (user, is_new) — is_new=True si le compte vient d'être créé."""
        oauth_repo = OAuthAccountRepository(self._session)
        user_repo = UserRepository(self._session)

        # 1. Chercher par (provider, provider_user_id)
        account = await oauth_repo.get_by_provider(info.provider, info.provider_user_id)
        if account:
            # Rafraîchir le token à chaque connexion
            if provider_token:
                account.provider_token = provider_token
            user = await user_repo.get(account.user_id)
            if user:
                await self._assign_default_role(user.id)
                return user, False

        # 2. Chercher un user existant par email
        user = await user_repo.get_by_email(info.email)
        if user:
            new_account = OAuthAccount(
                user_id=user.id,
                provider=info.provider,
                provider_user_id=info.provider_user_id,
                provider_email=info.email,
                provider_name=info.name,
                provider_avatar=info.avatar_url,
                provider_token=provider_token,
            )
            await oauth_repo.save(new_account)
            # S'assurer que ce user a bien un rôle (peut manquer si créé via autre flow)
            await self._assign_default_role(user.id)
            return user, False

        # 3. Créer un nouveau user
        user = User(email=info.email, hashed_password=None, is_active=True)
        await user_repo.save(user)

        new_account = OAuthAccount(
            user_id=user.id,
            provider=info.provider,
            provider_user_id=info.provider_user_id,
            provider_email=info.email,
            provider_name=info.name,
            provider_avatar=info.avatar_url,
            provider_token=provider_token,
        )
        await oauth_repo.save(new_account)

        # Assigner le rôle "user" dans le tenant par défaut
        await self._assign_default_role(user.id)

        return user, True

    async def _assign_default_role(self, user_id: str) -> None:
        """Crée un TenantMember avec le rôle 'user' global dans le tenant par défaut."""
        try:
            tenant_repo = TenantRepository(self._session)
            tenant = await tenant_repo.get_by_slug("default")
            if tenant is None:
                return

            role_repo = RoleRepository(self._session)
            roles = await role_repo.list_for_tenant(None)
            user_role = next((r for r in roles if r.name == "user"), None)

            member_repo = TenantMemberRepository(self._session)
            existing = await member_repo.get_membership(user_id, tenant.id)
            if existing is not None:
                return

            membership = TenantMember(
                user_id=user_id,
                tenant_id=tenant.id,
                role_id=user_role.id if user_role else None,
            )
            await member_repo.save(membership)
        except Exception:
            logger.debug("Impossible d'assigner le rôle par défaut à %s", user_id, exc_info=True)
