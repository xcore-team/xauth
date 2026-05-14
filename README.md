# XAuth Plugin Documentation

XAuth is a high-performance, multi-tenant authentication and authorization plugin for the **xcore** ecosystem. It provides enterprise-grade security features including RBAC, MFA, Audit Logging, and Invitation management.

---

## 🏗 Architecture Overview

The plugin follows a clean, service-oriented architecture:

- **Entry Point (`src/main.py`)**: Manages the plugin lifecycle and registers the global `AuthBackend`.
- **API Layer (`src/routes/`)**: FastAPI-based REST endpoints.
- **IPC Layer (`src/ipc.py`)**: Inter-Process Communication actions for cross-plugin integration.
- **Service Layer (`src/services/`)**: Orchestrates business logic and coordinates between repositories.
- **Data Access Layer (`src/repositories/`)**: Encapsulates database queries using SQLAlchemy.
- **Domain Models (`src/models/`)**: Defines the persistence schema.
- **Validation Schemas (`src/schemas/`)**: Pydantic models for request/response validation.

---

## 🔒 Security Features

### 1. Multi-Tenancy
XAuth is designed from the ground up for multi-tenancy. Most resources (Users, Roles, Invitations, Audit Logs) are scoped to a `tenant_id`. Users can be members of multiple tenants with different roles in each.

### 2. Role-Based Access Control (RBAC)
- **Permissions**: Granular strings like `users:read`, `rbac:write`.
- **Roles**: Collections of permissions.
- **Assignments**: Users are assigned roles within specific tenants.

### 3. Multi-Factor Authentication (MFA)
Supports **TOTP** (Time-based One-Time Password) via apps like Google Authenticator or Authy.
- **Setup**: Generates a secret and a QR code URI.
- **Verification**: Mandatory check during login if enabled for the user.

### 4. Audit Logging
Every security-sensitive action is recorded in the audit log, including:
- Action type (e.g., `login.success`, `user.created`).
- Tenant and User context.
- IP Address and User Agent.
- Custom metadata.

---

## 🚀 API Endpoints

### Authentication (`/xauth/auth`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| POST | `/register` | Create a new user account. |
| POST | `/login` | Authenticate and receive access/refresh tokens. |
| POST | `/refresh` | Rotate tokens using a refresh token. |
| POST | `/logout` | Revoke the current session. |
| GET  | `/me` | Get current authenticated user details. |

### RBAC (`/xauth/rbac`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| POST | `/roles` | Create a new role. |
| GET  | `/roles` | List available roles. |
| POST | `/roles/{id}/permissions` | Assign a permission to a role. |
| POST | `/tenants/{t_id}/members/{u_id}/role` | Assign a role to a tenant member. |

### Tenants & Members (`/xauth/tenants`)
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| POST | `/` | Create a new tenant. |
| GET  | `/` | List all tenants (Admin only). |
| GET  | `/{id}/members` | List all members of a tenant. |

---

## 📡 IPC Actions (Cross-Plugin)

Other plugins can interact with XAuth using the following actions:

- **`xauth.verify_token`**: Validates an access token and returns user/tenant context.
- **`xauth.has_permission`**: Checks if a user has a specific permission in a tenant.
- **`xauth.get_user`**: Retrieves user profile information.
- **`xauth.create_invite`**: Generates a tenant invitation.
- **`xauth.log_event`**: Manually records an entry in the audit log.

---

## 💾 Database Schema (Summary)

- **Users**: Identity, credentials (hashed), MFA status.
- **Tenants**: Organizations with unique slugs and settings.
- **TenantMembers**: Junction table linking Users to Tenants.
- **Roles**: Groups of permissions within a tenant.
- **Permissions**: Individual access rights.
- **Sessions**: Refresh token tracking and device metadata.
- **AuditLogs**: Immutable record of system events.
- **Invitations**: Pending tenant access requests.

---

## 🛠 Integration Guide

### Requiring Authentication in your Plugin
If your plugin is part of the xcore ecosystem, you can use the built-in dependencies:

```python
from xcore.sdk import require_permission, get_current_user
from fastapi import Depends

@router.get("/my-data")
async def secure_route(user = Depends(get_current_user)):
    return {"message": f"Hello {user['email']}"}

@router.post("/config")
async def admin_route(_ = Depends(require_permission("plugin:admin"))):
    return {"status": "authorized"}
```

### Initial Setup
1. Ensure the `db` and `cache` services are available.
2. The plugin will automatically create required tables on its first load via `_initialize_tables`.
3. Default permissions and global roles should be seeded via a bootstrap script (refer to `tasks.md`).
