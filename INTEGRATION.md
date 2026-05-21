# XAuth — Guide d'intégration

XAuth est un plugin d'authentification enterprise pour la plateforme **Xcore**. Il fournit : authentification par email/mot de passe, OAuth (Google, GitHub, Discord, Microsoft), MFA TOTP, RBAC multi-tenant, invitations, audit log, et gestion des mots de passe. Il s'enregistre comme **AuthBackend global** au démarrage — tout autre plugin peut utiliser `get_current_user` et `require_permission` de `xcore.sdk` sans dépendance directe sur xauth.

---

## Sommaire

1. [Installation et configuration](#1-installation-et-configuration)
2. [Génération des clés JWT](#2-génération-des-clés-jwt)
3. [Variables d'environnement](#3-variables-denvironnement)
4. [Endpoints HTTP](#4-endpoints-http)
5. [Utilisation depuis un autre plugin Xcore](#5-utilisation-depuis-un-autre-plugin-xcore)
6. [IPC inter-plugins](#6-ipc-inter-plugins)
7. [Événements EventBus](#7-événements-eventbus)
8. [OAuth — configuration par provider](#8-oauth--configuration-par-provider)
9. [MFA TOTP — flux complet](#9-mfa-totp--flux-complet)
10. [Invitations](#10-invitations)
11. [RBAC — rôles et permissions](#11-rbac--rôles-et-permissions)
12. [Audit log](#12-audit-log)

---

## 1. Installation et configuration

Déclarez le plugin dans votre hub Xcore :

```yaml
# hub/plugins.yaml (ou équivalent)
plugins:
  - path: app/xauth
```

XAuth nécessite les services Xcore suivants disponibles avant son chargement :

| Service       | Description                          |
|---------------|--------------------------------------|
| `db`          | Service base de données (SQLAlchemy) |
| `cache`       | Cache Redis / mémoire                |
| `ext.email`   | Extension email Xcore                |

---

## 2. Génération des clés JWT

XAuth utilise **RS256** (paires de clés asymétriques). Générez les fichiers PEM avant le premier démarrage :

```bash
# Créer le dossier
mkdir -p conf

# Clé privée (2048 bits)
openssl genrsa -out conf/private.pem 2048

# Clé publique dérivée
openssl rsa -in conf/private.pem -pubout -out conf/public.pem
```

> Ne commitez jamais `conf/private.pem`. Ajoutez `conf/` à votre `.gitignore`.

---

## 3. Variables d'environnement

Copiez `example.env` en `.env` à la racine du plugin :

```bash
cp app/xauth/example.env app/xauth/.env
```

### Variables obligatoires

| Variable                         | Description                                 |
|----------------------------------|---------------------------------------------|
| `ADMIN_EMAIL`                    | Email du compte admin créé au boot          |
| `ADMIN_PASSWORD`                 | Mot de passe admin initial                  |
| `ADMIN_TENANT_SLUG`              | Slug du tenant par défaut (ex. `default`)   |
| `ADMIN_TENANT_NAME`              | Nom affiché du tenant par défaut            |
| `ADMIN_ROLE_NAME`                | Nom du rôle admin (ex. `admin`)             |
| `USER_ROLE_NAME`                 | Nom du rôle utilisateur (ex. `user`)        |
| `XAUTH_JWT_PRIVATE_KEY_PATH`     | Chemin vers `private.pem`                   |
| `XAUTH_JWT_PUBLIC_KEY_PATH`      | Chemin vers `public.pem`                    |
| `XAUTH_APP_BASE_URL`             | URL de base de l'API (callbacks OAuth, liens mail) |

### Variables optionnelles

| Variable                              | Défaut   | Description                          |
|---------------------------------------|----------|--------------------------------------|
| `XAUTH_APP_NAME`                      | `XAuth`  | Nom affiché dans les emails          |
| `XAUTH_JWT_ACCESS_EXPIRE_MINUTES`     | `15`     | Durée de vie de l'access token       |
| `XAUTH_JWT_REFRESH_EXPIRE_DAYS`       | `7`      | Durée de vie du refresh token        |
| `XAUTH_SMTP_HOST`                     | `localhost` | Hôte SMTP                         |
| `XAUTH_SMTP_PORT`                     | `587`    | Port SMTP                            |
| `XAUTH_SMTP_USER`                     | —        | Identifiant SMTP                     |
| `XAUTH_SMTP_PASSWORD`                 | —        | Mot de passe SMTP                    |
| `XAUTH_SMTP_FROM`                     | —        | Adresse expéditeur                   |
| `XAUTH_SMTP_USE_TLS`                  | `true`   | TLS SMTP                             |

### OAuth (laisser vide pour désactiver)

| Provider   | Client ID                           | Client Secret                          |
|------------|-------------------------------------|----------------------------------------|
| Google     | `XAUTH_OAUTH_GOOGLE_CLIENT_ID`      | `XAUTH_OAUTH_GOOGLE_CLIENT_SECRET`     |
| GitHub     | `XAUTH_OAUTH_GITHUB_CLIENT_ID`      | `XAUTH_OAUTH_GITHUB_CLIENT_SECRET`     |
| Discord    | `XAUTH_OAUTH_DISCORD_CLIENT_ID`     | `XAUTH_OAUTH_DISCORD_CLIENT_SECRET`    |
| Microsoft  | `XAUTH_OAUTH_MICROSOFT_CLIENT_ID`   | `XAUTH_OAUTH_MICROSOFT_CLIENT_SECRET`  |

---

## 4. Endpoints HTTP

Le plugin est monté sous le préfixe défini par le hub (ex. `/app/auth`). Les exemples ci-dessous utilisent ce préfixe.

### Authentification

| Méthode | Chemin             | Auth requise | Description                                      |
|---------|--------------------|--------------|--------------------------------------------------|
| POST    | `/register`        | Non          | Créer un compte                                  |
| POST    | `/login`           | Non          | Se connecter, obtenir access + refresh tokens    |
| POST    | `/refresh`         | Non          | Renouveler les tokens via refresh token          |
| POST    | `/logout`          | Non          | Invalider le refresh token                       |
| GET     | `/me`              | Oui          | Profil de l'utilisateur connecté                 |

#### POST `/register`
```json
{
  "email": "alice@example.com",
  "password": "S3cur3P@ss!",
  "tenant_slug": "default"
}
```
Réponse `201` :
```json
{
  "id": "uuid",
  "email": "alice@example.com",
  "is_active": true,
  "mfa_enabled": false
}
```

#### POST `/login`
```json
{
  "email": "alice@example.com",
  "password": "S3cur3P@ss!",
  "tenant_id": null
}
```
Réponse `200` :
```json
{
  "access_token": "eyJ...",
  "refresh_token": "...",
  "token_type": "bearer",
  "user_id": "uuid",
  "tenant_id": "uuid",
  "mfa_required": false
}
```
Si MFA activé, `mfa_required: true` et `mfa_token` est retourné à la place des tokens finaux. Passer au flux MFA.

#### POST `/refresh`
```json
{ "refresh_token": "..." }
```

#### POST `/logout`
```json
{ "refresh_token": "..." }
```

---

### Gestion des mots de passe

| Méthode | Chemin               | Auth requise | Description                                        |
|---------|----------------------|--------------|----------------------------------------------------|
| POST    | `/password/forgot`   | Non          | Demander un lien de réinitialisation par email     |
| POST    | `/password/reset`    | Non          | Réinitialiser avec le token reçu par email         |
| POST    | `/password/change`   | Oui          | Changer le mot de passe (ancien requis)            |
| POST    | `/password/set`      | Oui          | Définir un mot de passe (comptes OAuth sans password) |

#### POST `/password/forgot`
```json
{ "email": "alice@example.com" }
```
Retourne toujours `202` pour éviter l'énumération des emails.

#### POST `/password/reset`
```json
{
  "token": "<token_reçu_par_email>",
  "new_password": "N3wS3cur3P@ss!"
}
```

#### POST `/password/change`
```json
{
  "current_password": "ancienMdp",
  "new_password": "nouveauMdp"
}
```

---

### MFA TOTP

| Méthode | Chemin              | Auth requise | Description                                    |
|---------|---------------------|--------------|------------------------------------------------|
| POST    | `/mfa/setup`        | Oui          | Générer le secret TOTP et le QR code           |
| POST    | `/mfa/enable`       | Oui          | Confirmer et activer le MFA                    |
| POST    | `/mfa/verify`       | Oui          | Vérifier un code TOTP (session active)         |
| POST    | `/mfa/verify-login` | Non          | Compléter la connexion MFA (échange mfa_token) |
| DELETE  | `/mfa/`             | Oui          | Désactiver le MFA                              |

---

### OAuth

| Méthode | Chemin                        | Auth requise | Description                             |
|---------|-------------------------------|--------------|-----------------------------------------|
| GET     | `/oauth/providers`            | Non          | Lister les providers actifs             |
| GET     | `/oauth/{provider}/authorize` | Non          | Obtenir l'URL d'autorisation            |
| GET     | `/oauth/{provider}/callback`  | Non          | Callback provider (géré automatiquement) |
| POST    | `/oauth/{provider}/link`      | Oui          | Lier un provider à un compte existant   |
| DELETE  | `/oauth/{provider}/unlink`    | Oui          | Délier un provider                      |
| GET     | `/oauth/me/accounts`          | Oui          | Lister les providers liés               |
| GET     | `/oauth/me/token/{provider}`  | Oui          | Récupérer le token OAuth stocké         |

Providers disponibles : `google`, `github`, `discord`, `microsoft`

#### Flux OAuth standard (frontend)
```
1. GET /oauth/{provider}/authorize?redirect=https://monapp.com/callback
   → { "auth_url": "https://accounts.google.com/..." }

2. Rediriger l'utilisateur vers auth_url

3. Le provider rappelle GET /oauth/{provider}/callback?code=...&state=...
   → Retourne les tokens xauth OU redirige vers redirect_url avec tokens en query params
```

---

### Tenants

| Méthode | Chemin                        | Permission requise | Description              |
|---------|-------------------------------|-------------------|--------------------------|
| POST    | `/tenants/`                   | `tenant:write`    | Créer un tenant          |
| GET     | `/tenants/`                   | `tenant:read`     | Lister les tenants       |
| GET     | `/tenants/{id}`               | Authentifié        | Détails d'un tenant      |
| PATCH   | `/tenants/{id}`               | `tenant:write`    | Modifier un tenant       |
| DELETE  | `/tenants/{id}`               | `tenant:delete`   | Supprimer un tenant      |
| GET     | `/tenants/{id}/members`       | `tenant:read`     | Lister les membres       |

---

### RBAC

| Méthode | Chemin                                          | Permission requise    |
|---------|-------------------------------------------------|-----------------------|
| POST    | `/rbac/roles`                                   | `role:create`         |
| GET     | `/rbac/roles`                                   | `role:list`           |
| GET     | `/rbac/roles/{id}`                              | `role:list`           |
| POST    | `/rbac/roles/{id}/permissions`                  | `permission:assign`   |
| DELETE  | `/rbac/roles/{id}/permissions/{perm_id}`        | `role:delete`         |
| POST    | `/rbac/tenants/{tid}/members/{uid}/role`         | `role:update`         |
| POST    | `/rbac/permissions`                             | `role:update`         |
| GET     | `/rbac/permissions`                             | `permission:list`     |
| GET     | `/rbac/users/{uid}/tenants/{tid}/permissions`   | `permission:list`     |

---

### Invitations

| Méthode | Chemin                  | Auth requise         | Description                          |
|---------|-------------------------|----------------------|--------------------------------------|
| POST    | `/invites/`             | `invites:write`      | Créer et envoyer une invitation      |
| GET     | `/invites/{tenant_id}`  | `invites:read`       | Lister les invitations d'un tenant   |
| GET     | `/invites/token/{token}`| Non                  | Consulter une invitation par token   |
| POST    | `/invites/accept`       | Authentifié          | Accepter une invitation              |

#### POST `/invites/`
```json
{
  "tenant_id": "uuid",
  "email": "bob@example.com",
  "role_id": "uuid-ou-null",
  "expires_hours": 72
}
```

#### POST `/invites/accept`
```json
{ "token": "<token_invitation>" }
```

---

### Audit log

| Méthode | Chemin                       | Permission requise | Description                          |
|---------|------------------------------|--------------------|--------------------------------------|
| GET     | `/audit/me`                  | Authentifié        | Historique de l'utilisateur connecté |
| GET     | `/audit/tenants/{tenant_id}` | `audit:read`       | Logs d'un tenant                     |
| GET     | `/audit/users/{user_id}`     | `audit:read`       | Logs d'un utilisateur                |

Paramètres de pagination : `?limit=20&offset=0`

---

## 5. Utilisation depuis un autre plugin Xcore

XAuth enregistre un `AuthBackend` global au boot. Tous les plugins peuvent l'utiliser via `xcore.sdk` sans importer xauth directement.

### Protéger une route

```python
from xcore.sdk import require_permission
from xcore.kernel.api import get_current_user, AuthPayload
from fastapi import APIRouter, Depends

router = APIRouter()

# Requiert une permission spécifique
@router.get("/ressources")
async def list_ressources(
    user: AuthPayload = Depends(require_permission("ressource:read"))
):
    user_id = user["sub"]
    tenant_id = user["user"]["tenant_id"]
    permissions = user["permissions"]
    roles = user["roles"]
    ...

# Requiert uniquement d'être authentifié
@router.get("/mon-profil")
async def get_profil(
    user: AuthPayload = Depends(get_current_user)
):
    ...
```

### Structure de l'AuthPayload

```python
{
  "sub": "uuid-utilisateur",
  "roles": ["admin", "user"],
  "permissions": ["ressource:read", "role:list", ...],
  "user": {
    "email": "alice@example.com",
    "tenant_id": "uuid-tenant"
  }
}
```

### Extraction du token

Le backend extrait le token dans cet ordre :
1. Header `Authorization: Bearer <token>`
2. Cookie `access_token=<token>`
3. Query param `?access_token=<token>` (WebSocket, liens signés)

---

## 6. IPC inter-plugins

Xauth expose des **actions IPC** utilisables par n'importe quel plugin via le bus interne Xcore.

### `xauth.verify_token`

Vérifie un access token et retourne les claims + permissions.

```python
result = await self.ctx.ipc.call("xauth.verify_token", {
    "token": "eyJ..."
})

if result["ok"]:
    user_id    = result["user_id"]
    tenant_id  = result["tenant_id"]
    perms      = result["permissions"]
    jti        = result["jti"]
else:
    print(result["error"])   # "invalid_token" ou "error"
```

### `xauth.has_permission`

Vérifie si un utilisateur possède une permission dans un tenant.

```python
result = await self.ctx.ipc.call("xauth.has_permission", {
    "user_id": "uuid",
    "tenant_id": "uuid",
    "permission": "ressource:delete"
})
# result["has_permission"] → True / False
```

### `xauth.get_user`

Récupère les informations d'un utilisateur.

```python
result = await self.ctx.ipc.call("xauth.get_user", {
    "user_id": "uuid"
})
# result["user"] → { id, email, is_active, mfa_enabled }
```

### `xauth.get_tenant`

Récupère les informations d'un tenant.

```python
result = await self.ctx.ipc.call("xauth.get_tenant", {
    "tenant_id": "uuid"
})
# result["tenant"] → { id, name, slug }
```

### `xauth.create_invite`

Crée une invitation programmatiquement (sans passer par l'API HTTP).

```python
result = await self.ctx.ipc.call("xauth.create_invite", {
    "tenant_id": "uuid",
    "invited_by": "uuid-admin",
    "email": "bob@example.com",
    "role_id": "uuid-ou-null",      # optionnel
    "expires_hours": 72              # optionnel, défaut 72h
})
# result["invite"] → { id, token, email, tenant_id, expires_at }
```

### `xauth.log_event`

Enregistre un événement d'audit depuis un autre plugin.

```python
result = await self.ctx.ipc.call("xauth.log_event", {
    "action": "payment.created",
    "tenant_id": "uuid",             # optionnel
    "user_id": "uuid",               # optionnel
    "resource": "payment",           # optionnel
    "resource_id": "uuid-paiement",  # optionnel
    "ip_address": "1.2.3.4",         # optionnel
    "user_agent": "Mozilla/...",     # optionnel
    "metadata": {"montant": 42.0}    # optionnel
})
# result["audit_log_id"] → id de l'entrée créée
```

---

## 7. Événements EventBus

XAuth émet des événements sur le bus Xcore. Les autres plugins peuvent s'y abonner.

### S'abonner depuis un plugin

```python
async def on_load(self) -> None:
    self.ctx.events.on("xauth.auth.login", self._on_user_login)
    self.ctx.events.on("xauth.invite.accepted", self._on_invite_accepted)

async def _on_user_login(self, event) -> None:
    data = event.data
    user_id   = data["user_id"]
    email     = data["email"]
    ip        = data["ip"]
    tenant_id = data["tenant_id"]
    # ... logique métier
```

### Liste des événements

| Événement                         | Données                                                  |
|-----------------------------------|----------------------------------------------------------|
| `xauth.auth.registered`           | `user_id`, `email`, `tenant_id`                         |
| `xauth.auth.login`                | `user_id`, `email`, `ip`, `tenant_id`                   |
| `xauth.auth.login_failed`         | `email`, `ip`, `reason`                                 |
| `xauth.auth.logout`               | `user_id`                                               |
| `xauth.auth.session_refreshed`    | `user_id`, `tenant_id`                                  |
| `xauth.password.reset_requested`  | `email`                                                 |
| `xauth.password.reset_completed`  | `email`                                                 |
| `xauth.password.changed`          | `user_id`                                               |
| `xauth.password.set`              | `user_id`                                               |
| `xauth.oauth.login`               | `user_id`, `provider`, `is_new_user`                    |
| `xauth.oauth.linked`              | `user_id`, `provider`                                   |
| `xauth.oauth.unlinked`            | `user_id`, `provider`                                   |
| `xauth.invite.created`            | `invite_id`, `email`, `tenant_id`, `invited_by`         |
| `xauth.invite.accepted`           | `invite_id`, `user_id`, `tenant_id`                     |
| `xauth.mfa.enabled`               | `user_id`                                               |
| `xauth.mfa.disabled`              | `user_id`                                               |

---

## 8. OAuth — configuration par provider

### Google

1. Créer un projet sur [console.cloud.google.com](https://console.cloud.google.com/apis/credentials)
2. Activer l'API Google+ ou People
3. Créer un client OAuth 2.0 → type "Application Web"
4. Ajouter comme URI de redirection autorisée : `{APP_BASE_URL}/app/auth/oauth/google/callback`
5. Renseigner `XAUTH_OAUTH_GOOGLE_CLIENT_ID` et `XAUTH_OAUTH_GOOGLE_CLIENT_SECRET`

### GitHub

1. Aller dans [github.com/settings/apps](https://github.com/settings/apps) → "New OAuth App"
2. Homepage URL : `{APP_BASE_URL}`
3. Authorization callback URL : `{APP_BASE_URL}/app/auth/oauth/github/callback`
4. Renseigner `XAUTH_OAUTH_GITHUB_CLIENT_ID` et `XAUTH_OAUTH_GITHUB_CLIENT_SECRET`

### Discord

1. Créer une application sur [discord.com/developers/applications](https://discord.com/developers/applications)
2. Section OAuth2 → Redirects → ajouter `{APP_BASE_URL}/app/auth/oauth/discord/callback`
3. Renseigner `XAUTH_OAUTH_DISCORD_CLIENT_ID` et `XAUTH_OAUTH_DISCORD_CLIENT_SECRET`

### Microsoft / Azure AD

1. Enregistrer une application sur [portal.azure.com](https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps)
2. Authentication → Redirect URI (Web) : `{APP_BASE_URL}/app/auth/oauth/microsoft/callback`
3. Renseigner `XAUTH_OAUTH_MICROSOFT_CLIENT_ID` et `XAUTH_OAUTH_MICROSOFT_CLIENT_SECRET`

---

## 9. MFA TOTP — flux complet

### Activer le MFA (utilisateur connecté)

```
1. POST /mfa/setup
   → { "secret": "BASE32SECRET", "qr_code": "data:image/png;base64,..." }

2. L'utilisateur scanne le QR code avec son app TOTP (Authy, Google Authenticator, etc.)

3. POST /mfa/enable
   { "code": "123456" }
   → { "mfa_enabled": true }
```

### Connexion avec MFA

```
1. POST /login  (email + password normaux)
   → { "mfa_required": true, "mfa_token": "eyJ..." }

2. POST /mfa/verify-login
   { "mfa_token": "eyJ...", "code": "123456" }
   → { "access_token": "...", "refresh_token": "...", ... }
```

---

## 10. Invitations

### Flux d'invitation

```
1. Admin → POST /invites/   (requiert permission invites:write)
   { "tenant_id": "...", "email": "bob@example.com", "expires_hours": 72 }
   → email envoyé à bob@example.com avec lien contenant le token

2. Bob consulte son invitation (optionnel) :
   GET /invites/token/{token}  (public)

3. Bob s'inscrit ou se connecte, puis :
   POST /invites/accept
   { "token": "..." }
   → Bob rejoint le tenant avec le rôle défini dans l'invitation
```

---

## 11. RBAC — rôles et permissions

### Initialisation par défaut

Au démarrage, xauth crée automatiquement deux rôles dans le tenant par défaut :
- `ADMIN_ROLE_NAME` (ex. `admin`)
- `USER_ROLE_NAME` (ex. `user`)

### Permissions internes à xauth

| Permission          | Usage                                        |
|---------------------|----------------------------------------------|
| `role:create`       | Créer un rôle                                |
| `role:list`         | Lister / consulter les rôles                 |
| `role:update`       | Modifier l'assignation des rôles             |
| `role:delete`       | Supprimer une permission d'un rôle           |
| `permission:assign` | Assigner une permission à un rôle            |
| `permission:list`   | Lister les permissions                       |
| `tenant:read`       | Lire les tenants et leurs membres            |
| `tenant:write`      | Créer / modifier des tenants                 |
| `tenant:delete`     | Supprimer un tenant                          |
| `invites:read`      | Voir les invitations                         |
| `invites:write`     | Créer des invitations                        |
| `audit:read`        | Consulter les logs d'audit                   |

### Exemple — créer un rôle et assigner une permission

```bash
# 1. Créer un rôle "moderator" dans un tenant
POST /rbac/roles
Authorization: Bearer <admin_token>
{
  "name": "moderator",
  "tenant_id": "uuid-tenant",
  "description": "Modérateur du contenu"
}

# 2. Créer une permission "content:moderate"
POST /rbac/permissions
{ "name": "content:moderate", "description": "Modérer le contenu" }

# 3. Assigner la permission au rôle
POST /rbac/roles/{role_id}/permissions
{ "permission_id": "uuid-permission" }

# 4. Assigner le rôle à un utilisateur
POST /rbac/tenants/{tenant_id}/members/{user_id}/role
{ "role_id": "uuid-role" }
```

---

## 12. Audit log

Chaque action sensible est automatiquement enregistrée par xauth (login, logout, changement de mot de passe, etc.). D'autres plugins peuvent également enregistrer leurs propres événements via l'IPC `xauth.log_event`.

### Consulter les logs

```bash
# Mes propres logs
GET /audit/me?limit=20&offset=0
Authorization: Bearer <token>

# Logs d'un tenant (requiert audit:read)
GET /audit/tenants/{tenant_id}?limit=100&offset=0

# Logs d'un utilisateur (requiert audit:read)
GET /audit/users/{user_id}?limit=100&offset=0
```

### Structure d'une entrée

```json
{
  "id": "uuid",
  "action": "login",
  "user_id": "uuid",
  "tenant_id": "uuid",
  "resource": null,
  "resource_id": null,
  "ip_address": "1.2.3.4",
  "user_agent": "Mozilla/...",
  "metadata": {},
  "created_at": "2026-05-21T10:00:00Z"
}
```
