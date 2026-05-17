from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlencode


@dataclass
class OAuthUserInfo:
    """Profil utilisateur normalisé retourné par tous les providers."""
    provider: str
    provider_user_id: str
    email: str
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    raw: dict = None  # payload brut du provider

    def __post_init__(self):
        if self.raw is None:
            self.raw = {}


class OAuthProvider:
    """
    Classe de base pour tous les providers OAuth2.
    Utilise httpx pour tous les échanges HTTP.
    """

    name: str  # "google", "github", ...
    auth_url: str
    token_url: str
    scopes: list[str]

    def __init__(self, client_id: str, client_secret: str, redirect_uri: str) -> None:
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri

    def get_auth_url(self, state: str, extra_params: dict[str, str] | None = None) -> str:
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(self.scopes),
            "state": state,
        }
        if extra_params:
            params.update(extra_params)
        return f"{self.auth_url}?{urlencode(params)}"

    async def exchange_code(self, code: str) -> dict[str, Any]:
        """Échange le code d'autorisation contre un access token."""
        import httpx

        async with httpx.AsyncClient() as client:
            resp = await client.post(
                self.token_url,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "grant_type": "authorization_code",
                },
                headers={"Accept": "application/json"},
                timeout=10,
            )
            resp.raise_for_status()
            try:
                payload = resp.json()
            except Exception:
                raise ValueError(
                    f"Réponse non-JSON du provider (HTTP {resp.status_code}): {resp.text[:200]}"
                )
            # GitHub returns 200 with {"error": "..."} on failure
            if "error" in payload:
                desc = payload.get("error_description") or payload["error"]
                raise ValueError(f"Échange de code refusé par le provider : {desc}")
            return payload

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        raise NotImplementedError
