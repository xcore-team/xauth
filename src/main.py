from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from xcore.kernel.api import (
    AuthPayload,
    get_current_user,
    register_auth_backend,
    unregister_auth_backend,
)
from xcore.sdk import AutoDispatchMixin, TrustedBase

from .backend import XAuthBackend
from .ipc import IPCCommands
from .models import Base
from .providers import (
    DiscordProvider,
    GitHubProvider,
    GoogleProvider,
    MicrosoftProvider,
)
from .providers.base import OAuthProvider
from .routes import (
    audit_router,
    invites_router,
    mfa_router,
    oauth_router,
    password_router,
    rbac_router,
    tenants_router,
)
from .schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    UserRootSchemas
)
from .services.auth import AuthService
from .services.email import AuthEmailService
from .services.events import XAuthEvents
from .services.token import TokenService
from .services.seed import run_seed

class Plugin(IPCCommands, AutoDispatchMixin, TrustedBase):
    """
    XAuth Plugin — enterprise auth multi-tenant avec RBAC, audit log, invitations.
    Enregistre un AuthBackend global au boot : tous les autres plugins peuvent utiliser
    require_permission() / get_current_user() de xcore.sdk sans dépendre de xauth.
    """

    async def _initialize_tables(self, db) -> None:
        from xcore.services.database.migrations import MigrationRunner
        import logging as _log
        _logger = _log.getLogger("hub.xauth")
        async with db.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        _logger.info("[xauth] Tables créées / vérifiées")
        _migrations_dir = Path(__file__).parent.parent / "migrations"
        runner = MigrationRunner(db_url=str(db.engine.url), migrations_dir=_migrations_dir)
        try:
            await runner.init(autogenerate=False, message="first_initialisation")
            await runner.upgrade()
        except Exception as exc:
            _logger.warning("[xauth] Migration upgrade ignorée : %s", exc)

    async def on_load(self) -> None:
        self.app = APIRouter()

        env = self.ctx.env
        db = self.get_service("db")
        cache = self.get_service("cache")

        await self._initialize_tables(db)

        self._db = db
        self._cache = cache

        # TokenService — python-jose + fichiers PEM configurés dans .env
        self._token_service = TokenService(
            private_key_path=env["JWT_PRIVATE_KEY_PATH"],
            public_key_path=env["JWT_PUBLIC_KEY_PATH"],
            access_expire_minutes=int(env.get("JWT_ACCESS_EXPIRE_MINUTES", "15")),
            refresh_expire_days=int(env.get("JWT_REFRESH_EXPIRE_DAYS", "7")),
        )

        # Service email — extension Xcore (ext.email)
        # Les templates sont définis dans l'extension (extensions/mail/)
        email_ext = self.get_service("ext.email")
        self._email_service = AuthEmailService(
            app_name=env.get("APP_NAME", "XAuth"),
            email_ext=email_ext,
            app_base_url=env.get("APP_BASE_URL", "http://localhost:8000"),
        )

        # Enregistre le backend global Xcore — dès ce moment, tous les plugins
        # peuvent utiliser Depends(require_permission(...)) / Depends(get_current_user)
        register_auth_backend(
            XAuthBackend(
                token_service=self._token_service,
                db=db,
                cache=cache,
            )
        )

        # EventBus Xcore — émetteur typé partagé entre tous les services
        self._events = XAuthEvents(self.ctx.events)

        # Providers OAuth — construits depuis self.ctx.env
        oauth_providers = _build_oauth_providers(env)

        self.app.include_router(
            _auth_router_with_db(
                db, self._token_service, self._email_service, self._events
            )
        )
        self.app.include_router(tenants_router(db))
        self.app.include_router(rbac_router(db, cache=cache))
        self.app.include_router(mfa_router(db))
        self.app.include_router(invites_router(db, self._email_service, self._events))
        self.app.include_router(audit_router(db))
        self.app.include_router(
            oauth_router(db, cache, self._token_service, oauth_providers, self._email_service)
        )
        self.app.include_router(
            password_router(db, cache, self._email_service, self._events)
        )

        from .services.seed import run_seed
        await run_seed(db, UserRootSchemas(
            ADMIN_EMAIL=self.ctx.env['ADMIN_EMAIL'],
            ADMIN_PASSWORD=self.ctx.env['ADMIN_PASSWORD'],
            ADMIN_TENANT_SLUG=self.ctx.env['ADMIN_TENANT_SLUG'],
            ADMIN_TENANT_NAME=self.ctx.env['ADMIN_TENANT_NAME'],
            ADMIN_ROLE_NAME=self.ctx.env['ADMIN_ROLE_NAME'],
            USER_ROLE_NAME=self.ctx.env['USER_ROLE_NAME'],
        ))

    async def on_unload(self) -> None:
        unregister_auth_backend()

    def get_router(self) -> APIRouter | None:
        return self.app


def _auth_router_with_db(
    db,
    token_service: TokenService,
    email_service: AuthEmailService,
    events: XAuthEvents | None = None,
) -> APIRouter:
    router = APIRouter(tags=["auth"])

    def _extract_ip(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    @router.post(
        "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
    )
    async def register(body: RegisterRequest):
        async with db.session() as session:
            svc = AuthService(session, token_service, events)
            try:
                user = await svc.register(
                    email=body.email,
                    password=body.password,
                    tenant_slug=body.tenant_slug,
                )
                await session.commit()
                await session.refresh(user)
                email_service.auth.welcome(
                    to=user.email,
                    username=user.email.split("@")[0],
                )
                return user
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.post("/login", response_model=TokenResponse)
    async def login(body: LoginRequest, request: Request):
        ip = _extract_ip(request)
        async with db.session() as session:
            svc = AuthService(session, token_service, events)
            try:
                result = await svc.login(
                    email=body.email,
                    password=body.password,
                    tenant_id=body.tenant_id,
                    ip_address=ip,
                )
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=401, detail=str(exc))

    @router.post("/refresh", response_model=TokenResponse)
    async def refresh(body: RefreshRequest, request: Request):
        ip = _extract_ip(request)
        async with db.session() as session:
            svc = AuthService(session, token_service, events)
            try:
                result = await svc.refresh(
                    refresh_token=body.refresh_token, ip_address=ip
                )
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=401, detail=str(exc))

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(body: LogoutRequest):
        async with db.session() as session:
            svc = AuthService(session, token_service, events)
            await svc.logout(body.refresh_token)
            await session.commit()

    @router.get("/me", response_model=UserResponse)
    async def me(current_user: AuthPayload = Depends(get_current_user)):
        from .repositories.user import UserRepository  # évite l'import circulaire

        async with db.session() as session:
            repo = UserRepository(session)
            user = await repo.get(current_user["sub"])
            if user is None:
                raise HTTPException(status_code=404, detail="User not found")
            return user

    return router


def _build_oauth_providers(env: dict) -> dict[str, OAuthProvider]:
    """
    Construit le dict provider_name → instance à partir des vars d'env.
    Un provider est activé seulement si BOTH client_id et client_secret sont présents.
    """
    base_url = env.get("APP_BASE_URL", "http://localhost:8000").rstrip("/")
    providers: dict[str, OAuthProvider] = {}

    _registry = [
        (
            "google",
            GoogleProvider,
            "OAUTH_GOOGLE_CLIENT_ID",
            "OAUTH_GOOGLE_CLIENT_SECRET",
        ),
        (
            "github",
            GitHubProvider,
            "OAUTH_GITHUB_CLIENT_ID",
            "OAUTH_GITHUB_CLIENT_SECRET",
        ),
        (
            "discord",
            DiscordProvider,
            "OAUTH_DISCORD_CLIENT_ID",
            "OAUTH_DISCORD_CLIENT_SECRET",
        ),
        (
            "microsoft",
            MicrosoftProvider,
            "OAUTH_MICROSOFT_CLIENT_ID",
            "OAUTH_MICROSOFT_CLIENT_SECRET",
        ),
    ]

    for name, cls, id_key, secret_key in _registry:
        client_id = env.get(id_key, "")
        client_secret = env.get(secret_key, "")
        if client_id and client_secret:
            redirect_uri = f"{base_url}/app/auth/oauth/{name}/callback"
            providers[name] = cls(client_id, client_secret, redirect_uri)

    return providers
