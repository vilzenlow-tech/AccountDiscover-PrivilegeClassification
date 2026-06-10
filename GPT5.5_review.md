# GPT-5.5 Defensive Security & Architecture Review

Review date: 2026-06-10  
Scope reviewed: FastAPI backend, React frontend auth flow, connector-agent APIs, Docker/nginx configuration, dependency manifests.  
Mode: defensive SSDLC review only. No application files were modified.

## Executive Summary

ADPCT already has useful security foundations: FastAPI/Pydantic typed routes, SQLAlchemy ORM query construction, bcrypt password hashing, role-based dependencies, startup checks for weak production JWT secrets, connector token hashing, and layered security headers. The most important hardening work is around session lifecycle, rate limiting, connector trust boundaries, unbounded ingestion paths, and deployment hygiene.

Priority remediation:

1. Enforce login rate limiting and server-side forced password-change restrictions.
2. Add JWT `iss`/`aud`/`jti`, refresh-token rotation, and revocation/reuse detection.
3. Stop persisting refresh tokens in browser `localStorage`; move them to secure HttpOnly cookies.
4. Bound and schema-validate connector result/log uploads before decompression, JSON parsing, or persistence.
5. Replace hardcoded database/demo secrets and dev bind-mount patterns in production compose profiles.

## Findings

### F-01 High: Login rate-limit setting is declared but not enforced

Evidence: `APP_RATE_LIMIT_LOGIN_PER_MIN` exists in `backend/app/config.py`, but `backend/app/api/v1/auth.py:46-66` only increments a per-user failed-login counter after a matching email is found. Nonexistent-user attempts are audited but not throttled. This leaves the login endpoint reliant on eventual account lockout rather than request-rate control.

Defensive remediation:

```python
# backend/app/security_rate_limit.py
from __future__ import annotations

import hashlib
from fastapi import HTTPException, Request, status
from redis import Redis


def _key(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.lower().encode("utf-8")).hexdigest()
    return f"rl:{prefix}:{digest}"


def enforce_login_rate_limit(
    redis: Redis,
    request: Request,
    email: str,
    limit_per_minute: int,
) -> None:
    client_ip = request.client.host if request.client else "unknown"
    keys = [_key("login-email", email), _key("login-ip", client_ip)]
    for key in keys:
        count = redis.incr(key)
        if count == 1:
            redis.expire(key, 60)
        if count > limit_per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Please retry later.",
            )
```

Apply it before password verification, and keep the current account-lockout logic as a second control.

### F-02 High: JWTs are stateless, lack audience/issuer/JTI, and expose internal decode detail

Evidence: `backend/app/security.py:39-60` issues tokens with `sub`, `roles`, `type`, `exp`, and `iat`, then decodes without `audience`, `issuer`, or `jti` validation. The error response includes the JOSE exception text. `backend/app/api/v1/auth.py:97-110` rotates refresh-token strings but does not revoke the presented refresh token or detect reuse.

Defensive remediation:

```python
# backend/app/security.py
import secrets
from jose import JWTError, jwt
from fastapi import HTTPException, status


def create_token(sub: str, token_type: str, roles: list[str] | None = None) -> tuple[str, str]:
    jti = secrets.token_urlsafe(24)
    payload = {
        "sub": sub,
        "type": token_type,
        "roles": roles or [],
        "jti": jti,
        "iss": _settings.jwt_issuer,
        "aud": _settings.jwt_audience,
        "iat": _now(),
        "exp": _now() + _ttl_for(token_type),
    }
    return jwt.encode(payload, _settings.secret_key, algorithm="HS256"), jti


def decode_token(token: str, expected_type: str) -> dict:
    try:
        data = jwt.decode(
            token,
            _settings.secret_key,
            algorithms=["HS256"],
            issuer=_settings.jwt_issuer,
            audience=_settings.jwt_audience,
        )
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        ) from exc
    if data.get("type") != expected_type:
        raise HTTPException(status_code=401, detail="Invalid token type")
    return data
```

Back this with a Redis denylist keyed by `jti` and a persistent session table for refresh-token families. On refresh, mark the presented `jti` as used before returning the new token; if an already-used refresh `jti` appears, revoke the whole session family.

### F-03 High: `must_change_password` is advisory in the UI, not enforced by the API

Evidence: successful login always receives normal access and refresh tokens in `backend/app/api/v1/auth.py:74-93`; the response only includes `must_change_password`. The frontend displays a toast in `frontend/src/pages/Login.tsx`, but protected API dependencies do not block normal privileged operations while the flag remains set.

Defensive remediation:

```python
# backend/app/security.py
def get_current_principal(...):
    ...
    user = db.query(User).filter(User.id == data["sub"]).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User inactive")
    if user.must_change_password and data.get("type") != "password_change":
        raise HTTPException(status_code=403, detail="Password change required")
    return Principal(id=str(user.id), email=user.email, roles=[r.name for r in user.roles])
```

A cleaner design is to issue a short-lived `password_change` token on login when the flag is set, allow only `/auth/change-password`, and withhold refresh tokens until the change succeeds.

### F-04 High: Browser stores access and refresh tokens in persisted local storage

Evidence: `frontend/src/lib/auth.ts:21-31` persists `accessToken` and `refreshToken` via zustand local storage. `frontend/src/api/client.ts:14-36` reads the access token into an Authorization header and sends the refresh token in JSON to `/auth/refresh`.

Defensive remediation:

```python
# backend/app/api/v1/auth.py
from fastapi import Response

@router.post("/login")
def login(body: LoginRequest, response: Response, request: Request, db: Session = Depends(get_db)):
    ...
    access, _ = create_token(str(user.id), "access", roles)
    refresh, refresh_jti = create_token(str(user.id), "refresh")
    persist_refresh_session(db, user.id, refresh_jti, request)
    response.set_cookie(
        "adpct_refresh",
        refresh,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=get_settings().refresh_token_ttl_min * 60,
        path="/api/v1/auth/refresh",
    )
    return {"access_token": access, "token_type": "bearer", "expires_in": ttl}
```

Keep access tokens in memory only. Refresh on page load through the cookie-backed endpoint, and clear the cookie on logout.

### F-05 High: Connector result ingestion accepts very large chunks and unbounded decompression/JSON structure

Evidence: `backend/app/schemas/connector_agent.py:260-269` allows up to 72 MB per base64 chunk and up to 10,000 chunks. `backend/app/api/v1/connector_agents.py:81-110` concatenates all chunks, optionally `gzip.decompress()`es them, then parses arbitrary JSON and stores the payload. Checksum validation provides integrity, not size or schema safety.

Defensive remediation:

```python
# backend/app/services/safe_json.py
import gzip
import io
import json
from pydantic import BaseModel, Field

MAX_COMPRESSED_BYTES = 50 * 1024 * 1024
MAX_DECOMPRESSED_BYTES = 100 * 1024 * 1024


class TargetResult(BaseModel):
    status: str = Field(max_length=32)
    accounts_discovered: int = Field(default=0, ge=0, le=1_000_000)


class ConnectorResultPayload(BaseModel):
    accounts_discovered: int = Field(default=0, ge=0, le=1_000_000)
    assets_scanned: int = Field(default=0, ge=0, le=100_000)
    target_results: list[TargetResult] = Field(default_factory=list, max_length=100_000)


def decode_connector_payload(compressed: bytes, encoding: str) -> ConnectorResultPayload:
    if len(compressed) > MAX_COMPRESSED_BYTES:
        raise ValueError("Compressed result exceeds configured limit")
    if encoding == "gzip":
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as gz:
            raw = gz.read(MAX_DECOMPRESSED_BYTES + 1)
    else:
        raw = compressed
    if len(raw) > MAX_DECOMPRESSED_BYTES:
        raise ValueError("Decompressed result exceeds configured limit")
    return ConnectorResultPayload.model_validate(json.loads(raw.decode("utf-8")))
```

Also enforce that `chunk_count`, `chunk_index`, and total received bytes match the job’s configured limits, not only the request schema defaults.

### F-06 Medium: Connector enrollment constraints are stored but not enforced

Evidence: enrollment-token creation stores `expected_hostname`, `expected_site`, and `expected_environment` in `backend/app/api/v1/connector_agents.py:224-232`. During enrollment, `backend/app/api/v1/connector_agents.py:688-699` accepts the agent’s supplied hostname and falls back to expected site/environment, but does not reject mismatches.

Defensive remediation:

```python
def _validate_enrollment_constraints(token, body: EnrollRequest) -> None:
    checks = {
        "hostname": (token.expected_hostname, body.hostname),
        "site": (token.expected_site, body.site),
        "environment": (token.expected_environment, body.environment),
    }
    for field, (expected, actual) in checks.items():
        if expected and actual and expected.lower() != actual.lower():
            raise HTTPException(status_code=403, detail=f"Enrollment {field} mismatch")
```

Call this before marking the token as used. Record source IP and user agent in the audit log for enrollment events, and consider source-CIDR restrictions for high-trust deployments.

### F-07 Medium: CSV import and list endpoints need bounded validation

Evidence: asset listing uses unconstrained `limit`/`offset` in `backend/app/api/v1/assets.py:68-105`. CSV import reads the full upload into memory at `backend/app/api/v1/assets.py:196`, decodes it, and processes all rows without a size or row cap.

Defensive remediation:

```python
from typing import Annotated
from fastapi import Query, UploadFile

PageLimit = Annotated[int, Query(default=50, ge=1, le=500)]
PageOffset = Annotated[int, Query(default=0, ge=0, le=1_000_000)]

MAX_CSV_BYTES = 5 * 1024 * 1024
MAX_CSV_ROWS = 10_000


async def read_bounded_upload(file: UploadFile) -> str:
    content = await file.read(MAX_CSV_BYTES + 1)
    if len(content) > MAX_CSV_BYTES:
        raise HTTPException(status_code=413, detail="CSV file is too large")
    return content.decode("utf-8-sig")
```

Validate hostname, IP address, port ranges, environment values, and criticality through Pydantic models before writing rows.

### F-08 Medium: CORS and CSP are permissive for a credentialed internal application

Evidence: `backend/app/main.py:91-97` enables credentials with all methods and all headers. `backend/app/main.py:105-113` and `nginx/nginx.conf` include `script-src 'unsafe-inline'` and `style-src 'unsafe-inline'`.

Defensive remediation:

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
)
```

For production, serve a built frontend bundle and remove inline script allowances. If inline styles are temporarily required, use nonces or hashes rather than a blanket inline allowance.

### F-09 Medium: Hardcoded deployment credentials and development server patterns are present in compose

Evidence: `docker-compose.yml:13-16` uses `POSTGRES_USER=adpct` and `POSTGRES_PASSWORD=adpct`. `docker-compose.yml:53-55`, `70-72`, and `85-87` bind-mount source into backend/worker/beat containers. `docker-compose.yml:97-100` exposes the Vite dev server.

Defensive remediation:

```yaml
secrets:
  pg_user:
    file: ./secrets/pg_user
  pg_password:
    file: ./secrets/pg_password

services:
  postgres:
    environment:
      POSTGRES_USER_FILE: /run/secrets/pg_user
      POSTGRES_PASSWORD_FILE: /run/secrets/pg_password
      POSTGRES_DB: adpct
    secrets:
      - pg_user
      - pg_password
```

Use separate `docker-compose.dev.yml` and `docker-compose.prod.yml` profiles. Production should run immutable images, no source bind mounts, no Vite dev server, non-root users, and health/readiness checks.

### F-10 Medium: Dependency specifications are broad and lack automated vulnerability gates

Evidence: backend dependencies are lower-bounded only in `backend/pyproject.toml:10-39`; frontend dependencies use broad caret ranges in `frontend/package.json:11-36`. There is no visible SBOM, vulnerability scanning policy, or Dependabot/Renovate configuration in the reviewed scope.

Defensive remediation:

```toml
# pyproject.toml
[tool.pip-audit]
require-hashes = false

[dependency-groups]
security = ["pip-audit>=2.7", "cyclonedx-bom>=4.5"]
```

```json
{
  "scripts": {
    "audit:frontend": "npm audit --audit-level=high",
    "sbom:frontend": "npx @cyclonedx/cyclonedx-npm --output-file sbom-frontend.json"
  }
}
```

Pin deployable lockfiles, generate SBOMs in CI, block known high/critical vulnerabilities, and require explicit review for auth, crypto, parser, and network-client upgrades.

### F-11 Low: Sensitive request fields should use `SecretStr` and log scrubbing

Evidence: `backend/app/schemas/auth.py` models passwords and refresh tokens as plain strings. `backend/app/main.py:39-49` configures structlog but does not include a redaction processor.

Defensive remediation:

```python
from pydantic import BaseModel, Field, SecretStr


class LoginRequest(BaseModel):
    email: str = Field(max_length=255)
    password: SecretStr = Field(min_length=1, max_length=256)


def scrub_secrets(_, __, event_dict):
    for key in list(event_dict):
        if any(marker in key.lower() for marker in ("password", "secret", "token", "authorization")):
            event_dict[key] = "[redacted]"
    return event_dict
```

Use `.get_secret_value()` only at verification boundaries, and add `scrub_secrets` before JSON rendering in the structlog processor chain.

## SSDLC Recommendations

- Add security regression tests for login throttling, forced password-change enforcement, refresh-token reuse rejection, connector enrollment mismatch rejection, and upload-size rejection.
- Add a lightweight threat model document for trust boundaries: browser, backend, worker, connector agents, local vault, database, Redis, AI assistant provider.
- Add CI gates: `pytest`, frontend build/lint, dependency audit, secret scan, container scan, and SBOM generation.
- Add production deployment profiles that fail closed when `APP_ENV=prod` but local vault, dev frontend, demo users, or default database credentials are configured.
- Keep a security checklist for every new endpoint: authentication dependency, role requirement, input bounds, output encoding, audit event, rate limit, pagination cap, and test coverage.

## Closing Notes

This review did not execute exploit payloads or modify application code. Recommendations are intentionally defensive and implementation-oriented so they can be converted into backlog items, tests, and secure coding standards.
