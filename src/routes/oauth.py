from __future__ import annotations

import base64
import json
import logging
from typing import Any
from urllib.parse import urlencode, urlparse

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from xcore.kernel.api import AuthPayload, get_current_user

from ..providers.base import OAuthProvider
from ..services.oauth import OAuthService
from ..services.token import TokenService

_logger = logging.getLogger(__name__)


class OAuthLinkRequest(BaseModel):
    code: str
    state: str


def oauth_router(
    db: Any,
    cache: Any,
    token_service: TokenService,
    providers: dict[str, OAuthProvider],
    web_app_url: str = "http://localhost:8000",
    redirect_origins: list[str] | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/oauth", tags=["oauth"])
    default_redirect = f"{web_app_url.rstrip('/')}/auth"
    allowed_origins = set(redirect_origins or [web_app_url.rstrip("/")])

    def _svc(session) -> OAuthService:
        return OAuthService(session, token_service, cache, providers)

    def _extract_ip(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _safe_redirect(candidate: str | None) -> str:
        """
        Valide `candidate` (le `?redirect=` envoyé par le frontend, voir
        api/index.ts::auth.oauthUrl) contre l'allowlist WEB_REDIRECT_ORIGINS
        avant de l'utiliser comme cible d'un RedirectResponse — sans ça,
        n'importe quel appelant pourrait forger une URL /authorize avec
        ?redirect=https://evil.example/steal et se faire renvoyer les
        tokens fraîchement émis (access_token/refresh_token en query
        string) par le navigateur de la victime en fin de flow OAuth.
        Retombe sur default_redirect (WEB_APP_URL + /auth) si absent ou
        hors allowlist, jamais sur une erreur bloquante : un `redirect`
        invalide ne doit pas casser la connexion, juste renvoyer vers la
        page d'accueil du flow plutôt que là où l'appelant l'espérait.
        """
        if not candidate:
            return default_redirect
        origin = urlparse(candidate)
        if f"{origin.scheme}://{origin.netloc}" not in allowed_origins:
            return default_redirect
        return candidate

    @router.get("/providers")
    async def list_providers() -> Any:
        """Liste les providers OAuth configurés et actifs."""
        return {"providers": list(providers.keys())}

    @router.get("/{provider}/authorize")
    async def authorize(
        provider: str,
        tenant_id: str | None = None,
        redirect: str | None = None,
        direct: bool = False,
    ) -> Any:
        """
        Sans `direct` : retourne l'URL d'autorisation en JSON (utilisé par
        le flow de liaison de compte depuis un dashboard déjà chargé — voir
        api/index.ts::oauth.startLink — qui fait le `window.location.href =`
        lui-même en JS après un fetch).
        Avec `direct=true` : redirige (302) directement vers le provider —
        c'est ce que fait le bouton de connexion initial (api/index.ts::
        auth.oauthUrl, `window.location.href = ...` sans fetch intermédiaire
        : un simple JSON ici afficherait le texte brut dans l'onglet au lieu
        d'atteindre GitHub).
        """
        # `redirect` est validé ici (pas seulement au callback) : c'est la
        # valeur persistée dans le state Redis et relue telle quelle par
        # handle_callback, donc le seul moment où on peut refuser une
        # origine hors allowlist plutôt que de la faire transiter en confiance.
        safe_redirect = _safe_redirect(redirect) if redirect else None
        async with db.session() as session:
            svc = _svc(session)
            try:
                url = await svc.get_auth_url(
                    provider, tenant_id=tenant_id, post_login_redirect=safe_redirect
                )
                if direct:
                    return RedirectResponse(url, status_code=status.HTTP_302_FOUND)
                return {"auth_url": url, "provider": provider}
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.get("/{provider}/callback")
    async def callback(
        provider: str,
        request: Request,
        code: str,
        state: str,
    ) -> Any:
        """
        Point d'entrée retour provider — atteint par une navigation top-level
        du navigateur (redirect_uri passé à GitHub/Google/…), PAS par un
        fetch JS : renvoyer du JSON ici (comme avant ce fix) laisse le
        navigateur affiché sur cette réponse brute côté API, le SPA ne
        reprend jamais la main. Ce handler DOIT donc terminer par un
        RedirectResponse vers le frontend (AuthPage.tsx lit exactement ce
        contrat de query params — voir son useEffect de gestion du callback
        OAuth), jamais par un retour JSON ou une HTTPException.
        """
        ip = _extract_ip(request)
        async with db.session() as session:
            svc = _svc(session)
            try:
                result = await svc.handle_callback(provider, code, state, ip_address=ip)
                await session.commit()
            except ValueError as exc:
                # Attendu (state expiré, provider sans email vérifié, …) —
                # pas de traceback, mais tracé quand même : le navigateur ne
                # voit qu'un toast générique (voir AuthPage.tsx), c'est ici
                # qu'il faut regarder pour savoir POURQUOI un callback échoue.
                _logger.warning("[oauth] callback %s rejeté : %s", provider, exc)
                return RedirectResponse(
                    f"{default_redirect}?{urlencode({'error': str(exc)})}",
                    status_code=status.HTTP_302_FOUND,
                )
            except Exception:
                _logger.exception("[oauth] callback %s : erreur provider inattendue", provider)
                return RedirectResponse(
                    f"{default_redirect}?{urlencode({'error': 'Erreur provider'})}",
                    status_code=status.HTTP_302_FOUND,
                )

        target = _safe_redirect(result.get("post_login_redirect"))
        params: dict[str, str] = {}
        if result.get("access_token"):
            params["access_token"] = result["access_token"]
            if result.get("refresh_token"):
                params["refresh_token"] = result["refresh_token"]
        elif result.get("refresh_token"):
            # Pas d'access_token émis — pas encore de tenant résolu (voir
            # services/oauth.py::handle_callback). refresh_token seul,
            # AuthPage.tsx s'en sert pour finir l'onboarding (setup_join /
            # création d'équipe) ou le choix de tenant côté client.
            params["refresh_token"] = result["refresh_token"]
            if result.get("tenants"):
                params["tenants"] = base64.b64encode(
                    json.dumps(result["tenants"]).encode()
                ).decode()
            elif result.get("needs_tenant_setup"):
                params["onboarding"] = "true"

        return RedirectResponse(
            f"{target}?{urlencode(params)}", status_code=status.HTTP_302_FOUND
        )

    @router.post("/{provider}/link")
    async def link_provider(
        provider: str,
        body: OAuthLinkRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        """
        Lie un provider OAuth à un compte authentifié existant.
        Nécessite de compléter d'abord le flow authorize → callback du provider
        pour obtenir code + state.
        """
        async with db.session() as session:
            svc = _svc(session)
            try:
                account = await svc.link_provider(
                    user_id=user["sub"],
                    provider_name=provider,
                    code=body.code,
                    state=body.state,
                )
                await session.commit()
                return {
                    "success": True,
                    "provider": account.provider,
                    "provider_email": account.provider_email,
                }
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.delete("/{provider}/unlink", status_code=status.HTTP_204_NO_CONTENT)
    async def unlink_provider(
        provider: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> None:
        """Délie un provider OAuth du compte authentifié."""
        async with db.session() as session:
            svc = _svc(session)
            try:
                await svc.unlink_provider(user_id=user["sub"], provider_name=provider)
                await session.commit()
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.get("/me/accounts")
    async def list_linked_accounts(
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        """Liste les comptes OAuth liés à l'utilisateur authentifié."""
        async with db.session() as session:
            from ..repositories.oauth import OAuthAccountRepository

            repo = OAuthAccountRepository(session)
            accounts = await repo.list_for_user(user["sub"])
            return [
                {
                    "provider": a.provider,
                    "provider_email": a.provider_email,
                    "provider_name": a.provider_name,
                    "provider_avatar": a.provider_avatar,
                    "linked_at": a.created_at.isoformat(),
                }
                for a in accounts
            ]

    return router
