# ADPCT — Principal Secure Code Review (Defensive Audit)

**Reviewer role**: Principal Secure Code Reviewer (defensive engineering focus)
**Subject**: Account Discovery & Privilege Classification Tool (ADPCT)
**Scope**: Backend (FastAPI / Celery), Connector Agent (Python), Frontend (React/Vite), Deployment (Docker, nginx), Vault, Connector framework
**Methodology**: SSDLC-aligned static review — code paths, configuration, trust boundaries, threat-modelled mitigations
**Approach**: Findings only — **no code changes performed**. Every finding includes the path/line evidence and a clean, refactored remediation block illustrating *how* a secure replacement should look.

> This document deliberately omits exploit strings, payloads, or any "weaponisable" detail. Every reproduction step is described abstractly; every fix is illustrated with secure-by-default code.

---

## Executive Summary

| Severity | Count | Categories |
|----------|-------|------------|
| **High** | 6 | Auth rate limiting absent, JWT crypto agility, host-key TOFU, conninfo injection surface, weak DB password in compose, in-memory bcrypt mutation |
| **Medium** | 9 | CSP `unsafe-inline`, token storage in `localStorage`, no JWT revocation, audit log incomplete fields, error detail leakage, CORS reflective, missing Pydantic constraints |
| **Low** | 7 | Filename encoding in Content-Disposition, agent FQDN trust, missing JWT `jti` / `aud`, AutoAddPolicy on first connect, missing `EmailStr`, vault store mode, Vite dev container in prod |
| **Informational** | 4 | Defence-in-depth opportunities; documentation hardening; multi-stage Docker builds; SBOM/dependency hygiene |

The architecture has many strong defensive elements: a vault abstraction (`backend/app/services/vault.py`), append-only audit log scaffolding (`backend/app/services/audit.py`), per-request security headers (`backend/app/main.py:99-117`), SHA-256 SSH host-key TOFU in `_ssh.py`, sealed AI assistant scope (`backend/app/api/v1/assistant.py`), and Pydantic v2 throughout. The findings below are improvements layered on top of an already security-conscious design.

---

## 1. Authentication, Session & Authorization

### 1.1 [**HIGH**] Login rate-limit setting declared but never enforced

**Evidence**

- `backend/app/config.py:21` — `rate_limit_login_per_min: int = Field(default=5, alias="APP_RATE_LIMIT_LOGIN_PER_MIN")`
- `backend/app/api/v1/auth.py:46-94` — login endpoint reads the user, performs `verify_password`, but no middleware, dependency, or counter ever consults `rate_limit_login_per_min`.
- `backend/app/main.py:91-97` — only `CORSMiddleware` and the security-headers middleware are registered.

**Impact** — The setting suggests rate limiting is active, but only per-account lockout (10 attempts) is implemented. Credential-spray, username enumeration via timing, and large-scale automated guessing against multiple identities go unmitigated. Lockout itself becomes a denial-of-service primitive against legitimate users.

**Defensive remediation**

```python
# backend/app/main.py  (add a per-IP and per-identifier sliding-window limiter)
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[],            # opt-in per route
    storage_uri=settings.redis_url,  # shared across replicas
)

app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RateLimitExceeded)
async def _ratelimit_handler(request, exc):
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests"},
        headers={"Retry-After": "30"},
    )
```

```python
# backend/app/api/v1/auth.py  — apply *two* keys: IP and submitted email
from slowapi import Limiter
from app.main import limiter

@router.post("/login", response_model=TokenResponse)
@limiter.limit(
    lambda req: f"{get_settings().rate_limit_login_per_min}/minute",
    key_func=lambda req: f"login-ip:{get_remote_address(req)}",
)
@limiter.limit(
    lambda req: "10/minute",
    key_func=lambda req: f"login-id:{_safe_email_from_body(req)}",
)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ...
```

Also add **constant-time email lookup**: today `User.email == body.email` short-circuits on miss. The dummy-hash branch is correct but the DB lookup time itself differs. Where possible cache hashes in memory, or always perform `verify_password` against a fixed sentinel hash when the user is None (this is partially done — make the sentinel constant rather than `None`).

---

### 1.2 [**HIGH**] JWT design lacks `aud`, `iss`, `jti`, and revocation

**Evidence**

- `backend/app/security.py:39-50` — `create_access_token` / `create_refresh_token` emit `{sub, roles, type, exp, iat}` only.
- `backend/app/security.py:53-61` — `decode_token` calls `jwt.decode(...)` without `audience=` / `issuer=` arguments; jose accepts the token if the signature and `exp` are valid.
- No table or Redis set exists for revoked `jti`s; on logout the client simply discards the token (`frontend/src/lib/auth.ts:29`).

**Impact** — Tokens stolen from any client (XSS, malicious browser extension, backup of `localStorage`) are accepted until natural expiry (60 min access, 12 hours refresh). Cross-tenant or cross-environment token reuse is possible if the same `secret_key` is reused. Forced logout (admin disables user) only takes effect on the *next* request (the `is_active` check in `get_current_principal` saves it, but refresh tokens still mint fresh access tokens for inactive users — see `auth.py:97-110` re-issues without rechecking `must_change_password`).

**Defensive remediation**

```python
# backend/app/security.py
import secrets

_ISSUER = f"adpct:{_settings.env}"
_AUDIENCE = "adpct-api"

def create_access_token(sub: str, roles: list[str], extra=None) -> tuple[str, str]:
    jti = secrets.token_urlsafe(16)
    payload = {
        "iss": _ISSUER,
        "aud": _AUDIENCE,
        "sub": sub,
        "roles": roles,
        "type": "access",
        "jti": jti,
        "exp": _now() + timedelta(minutes=_settings.access_token_ttl_min),
        "iat": _now(),
        "nbf": _now(),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, _settings.secret_key, algorithm=_settings.jwt_alg), jti


def decode_token(token: str, expected_type: str = "access") -> dict:
    try:
        data = jwt.decode(
            token,
            _settings.secret_key,
            algorithms=[_settings.jwt_alg],
            audience=_AUDIENCE,
            issuer=_ISSUER,
            options={"require": ["exp", "iat", "sub", "type", "jti"]},
        )
    except JWTError as e:
        raise HTTPException(401, "Invalid token", headers={"WWW-Authenticate": "Bearer"}) from e
    if data["type"] != expected_type:
        raise HTTPException(401, "Wrong token type")
    if _revocation_store.is_revoked(data["jti"]):
        raise HTTPException(401, "Token revoked")
    return data
```

```python
# A minimal denylist (refresh-token rotation also requires this)
class RevocationStore:
    """Keys are JTIs; values are revocation deadlines (token exp).
    Backed by Redis with TTL equal to the original token's remaining lifetime."""
    def revoke(self, jti: str, exp_ts: int) -> None: ...
    def is_revoked(self, jti: str) -> bool: ...
```

Also: in `refresh_token` (`auth.py:97-110`) **rotate** the JTI and *revoke the presented refresh token* before issuing a new one (refresh-token reuse detection).

---

### 1.3 [**MEDIUM**] Refresh tokens not bound to session / device fingerprint, no rotation enforcement

**Evidence** — `backend/app/api/v1/auth.py:97-110` returns a fresh access+refresh pair on every `/auth/refresh` call but does **not** invalidate the presented refresh token. A captured refresh token therefore yields an unbounded session.

**Remediation** — Track a `session_id` on the refresh token, persist it in a `sessions` table (`session_id`, `user_id`, `device_hash`, `issued_at`, `last_used_at`, `revoked_at`), and reject any reuse of an already-rotated refresh token, optionally flagging the user (defensive token theft detection). Pseudocode:

```python
def refresh_token(body, db):
    data = decode_token(body.refresh_token, expected_type="refresh")
    sess = db.query(Session).get(data["sid"])
    if not sess or sess.revoked_at or sess.current_jti != data["jti"]:
        # Suspected token reuse — revoke the entire session family
        sessions_revoke_family(db, sess.user_id, sess.id)
        log_action(db, "auth.refresh.reuse_detected", actor_id=str(sess.user_id))
        db.commit()
        raise HTTPException(401, "Refresh token invalid")
    new_jti = secrets.token_urlsafe(16)
    sess.current_jti = new_jti
    sess.last_used_at = _now()
    ...
```

---

### 1.4 [**MEDIUM**] `LoginRequest.email` lacks `EmailStr` validation

**Evidence** — `backend/app/schemas/auth.py:7-9`:

```python
class LoginRequest(BaseModel):
    email: str = Field(max_length=255)
```

`email-validator` is already a backend dependency. Accepting arbitrary strings means malformed inputs reach the DB query (`User.email == body.email`) and the audit-log writer. Combined with the unused rate limit, this widens the enumeration surface.

**Remediation**

```python
from pydantic import BaseModel, EmailStr, Field

class LoginRequest(BaseModel):
    email: EmailStr = Field(max_length=255)
    password: str = Field(min_length=1, max_length=256)
```

Apply the same change to seed/admin scripts and any user-creation DTO.

---

### 1.5 [**HIGH**] `must_change_password` flag not enforced server-side

**Evidence** — `backend/app/api/v1/auth.py:73-94` issues access+refresh tokens on a successful login *even if* `user.must_change_password` is `True`; the response simply includes a boolean for the UI. The frontend (`Login.tsx:22-25`) only displays a toast.

**Impact** — Operationally weak: an attacker who phishes a forced-rotation account can use the access token to perform any privileged action (export, scan launch) *without* changing the password. The UI hint is advisory.

**Defensive remediation**

```python
# backend/app/api/v1/auth.py
if user.must_change_password:
    # Issue a *single-purpose* token that may only call /auth/change-password.
    pwchange_token = create_pwchange_token(str(user.id))
    return TokenResponse(
        access_token=pwchange_token,
        refresh_token="",
        expires_in=900,
        must_change_password=True,
    )
```

```python
# backend/app/security.py — change-password scope dependency
def require_pwchange_token(token: str = Depends(oauth2)) -> Principal:
    data = decode_token(token, expected_type="pwchange")
    return Principal(id=data["sub"], email="", roles=[])
```

Apply `require_pwchange_token` to the `/auth/change-password` endpoint and reject the `pwchange` type everywhere else via the `expected_type` check in `decode_token`.

---

### 1.6 [**MEDIUM**] Wide CORS configuration and reflected `WWW-Authenticate`

**Evidence**

- `backend/app/main.py:91-97` — `allow_methods=["*"]`, `allow_headers=["*"]`, with `allow_credentials=True`. While `allow_origins` is restricted, the combination is risky because any allow-listed origin can probe any header.
- `backend/app/security.py:60` — `headers={"WWW-Authenticate": "Bearer"}` together with `detail=f"Invalid token: {e}"` echoes the raw JOSE exception text to the caller, which can include internal token-shape clues.

**Remediation**

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With"],
    max_age=600,
)
```

```python
# backend/app/security.py
def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, _settings.secret_key, algorithms=[_settings.jwt_alg], ...)
    except JWTError:
        # Do NOT echo the JWTError message; it can leak signature/header diagnostics.
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )
```

---

## 2. Input Validation, Encoding, Injection

### 2.1 [**HIGH**] PostgreSQL conninfo string built via interpolation

**Evidence** — `backend/app/collectors/postgresql.py:172-176`:

```python
conninfo = (
    f"host={host} port={port} dbname={dbname} "
    f"user={credential.username} password={credential.secret or ''} "
    f"connect_timeout=20 sslmode={sslmode}"
)
with psycopg.connect(conninfo, autocommit=True) as conn:
```

`username`, `password`, `dbname`, and even `host` originate from operator-managed fields and the vault. A literal space, quote, or `\` in a vault-stored password (or a future bring-your-own asset record) silently breaks the connect string and may *leak* credentials into the error message (psycopg surfaces the offending conninfo on parse failure).

**Defensive remediation** — pass parameters as keywords so psycopg performs its own quoting:

```python
with psycopg.connect(
    host=host,
    port=port,
    dbname=dbname,
    user=credential.username,
    password=credential.secret or "",
    connect_timeout=20,
    sslmode=sslmode,
    autocommit=True,
) as conn:
    ...
```

Also raise the default `sslmode` to `verify-full` when the asset's CA chain is known, and `require` otherwise. The current default of `"disable"` (line 170) silently degrades TLS — fine for explicit lab targets, not for general use. Make the default `require` and force operators to explicitly downgrade per asset.

---

### 2.2 [**HIGH**] MySQL `SHOW GRANTS FOR` built via f-string with target identifiers

**Evidence** — `backend/app/collectors/mysql.py:161`:

```python
cur.execute(f"SHOW GRANTS FOR '{u['User']}'@'{u['Host']}'")
```

While `User`/`Host` come from `mysql.user` rows on the *target* (so the trust path is "we asked the DB → it gave back its own data"), an account with a crafted name (containing `'`) is a plausible adversarial primitive on multi-tenant or compromised targets, and any downstream change to seed this from external CSV import would immediately become an injection sink.

**Defensive remediation** — use MySQL identifier-quoting helpers:

```python
import pymysql

def _q_identifier(s: str) -> str:
    # Replicate mysql_real_escape_string + backtick wrapping for identifiers.
    return "'" + s.replace("\\", "\\\\").replace("'", "''") + "'"

cur.execute(
    "SHOW GRANTS FOR " + _q_identifier(u["User"]) + "@" + _q_identifier(u["Host"])
)
```

Better: rebuild grants from `mysql.user`, `mysql.db`, `mysql.tables_priv`, `mysql.columns_priv` directly (parameterised SELECTs) rather than re-running `SHOW GRANTS` for each user — that avoids the lexically-special-name class of issues entirely.

---

### 2.3 [**HIGH**] Windows collector executes PowerShell scripts via WinRM

**Evidence** — `backend/app/collectors/windows.py:794-816` — `_run(script)` calls `session.run_ps(...)` with a literal script. The current scripts are static constants (`_PS_USERS`, `_PS_GROUPS`, …) so there is no immediate operator-controlled interpolation, but future probes that interpolate hostnames, asset options, or filter strings into the PS body must guard against PowerShell injection. There is no centralised "render PS" helper that enforces parameter passing.

**Defensive remediation** — adopt a single PS execution helper that **always** uses parameters / `-EncodedCommand` rather than concatenation:

```python
import base64

def _ps_encode(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()

def _run_ps_param(session, script: str, **params: str | int | bool) -> bytes:
    # Compose a parameterised script that reads $env vars (never interpolation).
    env_lines = "\n".join(f'$env:{k} = $env:{k}' for k in params)
    wrapped = env_lines + "\n" + script
    encoded = _ps_encode(wrapped)
    # pywinrm exposes run_cmd; pass parameters via the OS env, not the script body.
    return session.run_cmd(
        f"powershell.exe -NoProfile -NonInteractive -EncodedCommand {encoded}",
        env=params,
    ).std_out
```

Also constrain the `transport`, `scheme`, and `cert_validation` fields from `target.options` against an allow-list (today `transport = target.options.get("winrm_transport", "ntlm")` will accept any string; pywinrm validates internally but defence-in-depth is cheap).

---

### 2.4 [**MEDIUM**] CSV export does not neutralise spreadsheet-formula prefixes

**Evidence** — `backend/app/api/v1/exports.py:73-78` and `_accounts_to_rows` (line 32) write `account.account_name`, `owner`, and `last_login_source` straight to CSV. If a discovered Windows account name begins with `=`, `+`, `-`, `@`, `\t`, or `\r`, Excel/LibreOffice will treat the cell as a formula on open ("CSV injection" / "Formula Injection").

**Defensive remediation**

```python
_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

def _csv_safe(value: object) -> str:
    s = "" if value is None else str(value)
    if s and s[0] in _DANGEROUS_PREFIXES:
        return "'" + s   # prepend literal apostrophe — Excel renders as text
    return s

def _accounts_to_rows(accounts):
    return [
        {k: _csv_safe(v) for k, v in {
            "account_id": str(a.id),
            "account_name": a.account_name,
            ...
        }.items()}
        for a in accounts
    ]
```

Apply the same sanitisation to the Excel writer (`export_accounts_excel`, line 113-118).

---

### 2.5 [**LOW**] `Content-Disposition` filename uses unescaped strftime

**Evidence** — `backend/app/api/v1/exports.py:83, 127`:

```python
filename = f"accounts_{'privileged_' if only_privileged else ''}export_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.csv"
return StreamingResponse(..., headers={"Content-Disposition": f'attachment; filename="{filename}"'})
```

Here the filename is server-generated so the actual risk is nil, but the pattern is brittle. Adopt `RFC 5987` to be safe against future operator-controlled filenames:

```python
from urllib.parse import quote
fn = quote(filename, safe="")
headers={"Content-Disposition": f"attachment; filename=\"{filename}\"; filename*=UTF-8''{fn}"}
```

---

### 2.6 [**MEDIUM**] Free-text `search` columns use `LIKE %s%` without bounding length

**Evidence** — `backend/app/api/v1/accounts.py:76`, `connector_agents.py:262-266` — `Account.account_name.ilike(f"%{search}%")` without `Field(max_length=...)` on the query parameter. An adversary with valid credentials can submit very long search strings to drive a full-table scan repeatedly.

**Remediation**

```python
from fastapi import Query

@router.get("", ...)
def list_accounts(
    search: str | None = Query(default=None, max_length=128, pattern=r"^[\w@.\-_ ]*$"),
    ...
):
    ...
```

Combine with the rate limiter (1.1) and a global query timeout (`statement_timeout` in Postgres).

---

### 2.7 [**LOW**] Audit log omits `ip` and `user_agent` on most call-sites

**Evidence** — `backend/app/services/audit.py:12-37` accepts `ip` and `user_agent` parameters, but `log_action(...)` is invoked from `accounts.py`, `exports.py`, `scans.py`, etc. without forwarding the `Request` context. Only `auth.py` populates the IP. The audit log is therefore weaker than it appears for forensic correlation.

**Remediation** — add a small dependency that builds a `RequestContext`:

```python
# backend/app/security.py
@dataclass(slots=True)
class RequestContext:
    ip: str | None
    user_agent: str | None

def request_context(request: Request) -> RequestContext:
    fwd = request.headers.get("x-forwarded-for", "")
    ip = (fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else None))
    return RequestContext(ip=ip, user_agent=request.headers.get("user-agent"))
```

Then in every endpoint that calls `log_action`, also accept `rc: RequestContext = Depends(request_context)` and forward `ip=rc.ip, user_agent=rc.user_agent`.

---

## 3. Secrets, Vault, and Credential Lifecycle

### 3.1 [**HIGH**] `docker-compose.yml` ships PostgreSQL with literal credentials `adpct:adpct`

**Evidence** — `docker-compose.yml:13-16`:

```yaml
POSTGRES_USER: adpct
POSTGRES_PASSWORD: adpct
POSTGRES_DB: adpct
```

Combined with the comment "do not expose 5432" — but the dev-only ports comment is the only protection. A misread of comments has caused real incidents.

**Defensive remediation** — read from Docker secrets / env:

```yaml
secrets:
  pg_password:
    file: ./secrets/pg_password

services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_USER_FILE: /run/secrets/pg_username
      POSTGRES_PASSWORD_FILE: /run/secrets/pg_password
      POSTGRES_DB: adpct
    secrets:
      - pg_password
      - pg_username
```

Generate `secrets/pg_password` during deployment (`openssl rand -base64 48`). The `.env.example` should illustrate this pattern and **never** include a literal password.

---

### 3.2 [**HIGH**] Bcrypt hash returns same `password_hash` field used in DB; no in-memory zeroisation

**Evidence** — `backend/app/security.py:22-30` returns `bcrypt.hashpw(...).decode()`. The plaintext `plain: str` argument lingers in the interpreter as a Python str (immutable, cannot be wiped). This is unavoidable for bcrypt, but downstream callers (`auth.py:51, 120-123`) keep the `LoginRequest.password` field on the request object until garbage collection. Combined with `structlog` console-renderer dev mode (`main.py:48`), an exception during password verification can dump the request body into stdout.

**Defensive remediation**

```python
# backend/app/schemas/auth.py — opt the secret field out of repr & dict
from pydantic import SecretStr

class LoginRequest(BaseModel):
    email: EmailStr = Field(max_length=255)
    password: SecretStr = Field(min_length=1, max_length=256)


# backend/app/api/v1/auth.py — use .get_secret_value() at use site only
ok = verify_password(body.password.get_secret_value(), user.password_hash) if user else False
```

`SecretStr.__repr__` returns `"**********"`, eliminating accidental log leaks. Combine with structlog processors that strip `password`, `secret`, `token`, `secret_material` keys from event dicts.

```python
# backend/app/main.py
def _scrub_secrets(_, __, event_dict):
    for k in list(event_dict):
        if any(s in k.lower() for s in ("password", "secret", "token", "bearer", "fernet")):
            event_dict[k] = "***"
    return event_dict

structlog.configure(processors=[_scrub_secrets, ...])
```

---

### 3.3 [**MEDIUM**] Local Fernet vault: ephemeral-key fallback warns but still runs

**Evidence** — `backend/app/services/vault.py:62-72`:

```python
else:
    key = Fernet.generate_key()
    self._fernet = Fernet(key)
    warnings.warn(...)
```

The intent is dev-friendliness, but the `LocalVaultProvider` will silently accept `store()` calls and silently lose them on restart. This is a footgun if anyone enables `live` mode (`COLLECTOR_MODE=live`) on a host whose env wasn't fully provisioned.

**Defensive remediation** — refuse to construct the provider when running outside `dev`:

```python
def __init__(self) -> None:
    settings = get_settings()
    raw = self._load_key(settings)
    if not raw:
        if settings.env != "dev":
            raise RuntimeError(
                "Local vault requires VAULT_LOCAL_FERNET_KEY (or Docker secret) "
                "in env != dev."
            )
        # Dev only — still warn, but also write a marker file so an operator
        # can find that they're on the throw-away key path.
        key = Fernet.generate_key()
        Path("/tmp/adpct-ephemeral-fernet").write_text("ephemeral")
        self._fernet = Fernet(key)
        warnings.warn(...)
    else:
        self._fernet = Fernet(raw.encode() if isinstance(raw, str) else raw)
```

---

### 3.4 [**MEDIUM**] Local vault file mode set only after write — race window

**Evidence** — `backend/app/services/vault.py:103-106`:

```python
def _save_store(self, store: dict) -> None:
    _LOCAL_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    _LOCAL_STORE_PATH.write_bytes(json.dumps(store).encode())
    _LOCAL_STORE_PATH.chmod(0o600)
```

Between `write_bytes` and `chmod`, the file inherits the process umask. On a multi-user container or shared volume, an adversary running as the same UID can read the in-progress file.

**Defensive remediation** — write to a temp file with the desired mode, then atomically rename:

```python
import os, tempfile

def _save_store(self, store: dict) -> None:
    _LOCAL_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".local_vault.", dir=_LOCAL_STORE_PATH.parent)
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(json.dumps(store).encode())
        os.replace(tmp, _LOCAL_STORE_PATH)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
```

Also `_load_store` does not validate JSON structure — a malformed file would surface as a generic `JSONDecodeError`. Catch and raise a `VaultCorrupted` error with operator guidance.

---

### 3.5 [**MEDIUM**] `Credential.username` and metadata round-trip from request bodies without canonicalisation

**Evidence** — `backend/app/api/v1/credentials.py:46-57` mass-assigns `body.{name,description,...}` to the ORM model. The Pydantic DTO (not shown here but referenced) governs sanitisation. Recommend explicit allow-list copies plus length caps to prevent future field additions from auto-propagating.

**Defensive remediation**

```python
_CRED_FIELDS = ("name", "description", "vault_backend", "vault_ref",
                "username", "auth_method", "rotation_policy_days", "is_active")

cred = Credential(**{k: getattr(body, k) for k in _CRED_FIELDS})
```

This guards against the "Pydantic model grows a sensitive field, ORM silently absorbs it" failure mode.

---

### 3.6 [**LOW**] Vault adapter NotImplementedErrors leak class names

**Evidence** — `backend/app/services/vault.py:139-174` — all four enterprise providers raise `NotImplementedError`. If a user mis-configures `VAULT_PROVIDER=cyberark` in `dev`, the exception bubbles to the worker logs at `error` level and into the API response detail. Acceptable but mention provider feature flags in the response with a stable error code.

---

## 4. Connector Agent / Trust Boundary

### 4.1 [**HIGH**] Auto-approval enrollment trusts client-provided `hostname` / `ip_address` / FQDN

**Evidence**

- Console-side `EnrollRequest` is populated from the agent's `socket.getfqdn()` (`connector-agent/adpct_agent/client.py:88-92`).
- Server reads the values verbatim and stores them on the `ConnectorAgent` row (`connector_agents.py:688-700`).
- `expected_hostname` (`generate_enrollment_token`, line 227) is **stored but never compared**.

**Impact** — A stolen registration token can be redeemed from a different host than intended, and the `expected_hostname` operator guard is silently bypassed.

**Defensive remediation**

```python
# backend/app/api/v1/connector_agents.py — enroll_agent
if et.expected_hostname and et.expected_hostname.lower() != (body.hostname or "").lower():
    et.is_revoked = True
    db.add(ConnectorAgentLog(
        agent_id=None, level="warn",
        message="Enrollment hostname mismatch — token revoked",
        context={"expected": et.expected_hostname, "received": body.hostname},
    ))
    db.commit()
    raise HTTPException(status_code=403, detail="Hostname mismatch for this enrollment token")
```

Also require the connecting client's source-IP CIDR to be on an allow-list configured at token issuance (`expected_source_cidr` on `ConnectorEnrollmentToken`). At minimum, log the enrollment source-IP into the audit trail.

---

### 4.2 [**MEDIUM**] No token rotation enforcement / no replay window

**Evidence** — `connector_agents.py:362-377` ("approve_connector") issues a bearer token and stores its hash. Agent runtime endpoints accept the token forever (`_authenticate_agent`, line 176-199). There is a `token_rotation_days` setting (`settings.token_rotation_days`) that is *served* to the agent but never *enforced* on the server side.

**Defensive remediation** — store `token_issued_at` and `token_expires_at`, then in `_authenticate_agent`:

```python
if agent.token_expires_at and agent.token_expires_at < datetime.now(UTC):
    raise HTTPException(401, "Connector token expired — rotate via /rotate-token")
```

Provide a `rotate-token` endpoint that takes the agent's current token and returns the new one, with replay protection: a one-time rotation nonce stored on the agent row.

---

### 4.3 [**LOW**] Result chunk reassembly does not bound chunk count or total size

**Evidence** — `connector_agents.py:1027-1041` accepts arbitrary `chunk_count` set by the agent on its first chunk POST. A malicious or buggy agent could announce `chunk_count = 2**31` and exhaust the chunk table.

**Defensive remediation**

```python
_MAX_RESULT_CHUNKS = 1024
_MAX_RESULT_BYTES = 256 * 1024 * 1024   # 256 MiB before decompression

if body.chunk_count <= 0 or body.chunk_count > _MAX_RESULT_CHUNKS:
    raise HTTPException(400, f"chunk_count must be 1..{_MAX_RESULT_CHUNKS}")
if result.bytes_received + len(chunk_bytes) > _MAX_RESULT_BYTES:
    raise HTTPException(413, "Result exceeds maximum upload size")
```

Track `result.bytes_received` incrementally on the result row.

---

### 4.4 [**MEDIUM**] Heartbeat trusts agent-supplied `agent_version`

**Evidence** — `connector_agents.py:809-810` overwrites `agent.agent_version` with whatever the agent reports. An attacker controlling a compromised agent can spoof a "current" version to evade upgrade/downgrade alerting.

**Remediation** — verify the reported version against a signed manifest published by the console (signed with an internal release key, retrieved at enrollment). If the version is not in the allow-list, log a `connector.version.unknown` audit event and treat the agent as `stale`.

---

### 4.5 [**LOW**] SSH `AutoAddPolicy` accepts unknown keys on first connection

**Evidence** — `backend/app/collectors/_ssh.py:55-57`:

```python
self._client = paramiko.SSHClient()
self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
```

The TOFU logic afterwards (line 84-95) compares to the stored fingerprint, so the practical risk is only on **first** asset use. That window is acceptable for many threat models but should be acknowledged and optionally hardened by requiring operators to pre-stage the expected fingerprint on the asset record:

```python
if expected_fingerprint is None and not target.options.get("allow_tofu", False):
    raise SSHHostKeyMismatch(
        "Asset has no stored fingerprint and TOFU is not allowed. "
        "Pre-stage the fingerprint or enable allow_tofu on the asset."
    )
```

Default `allow_tofu=False` for `prod`, `True` for `dev`.

---

## 5. Configuration, Hardening, and Build Hygiene

### 5.1 [**MEDIUM**] CSP allows `'unsafe-inline'` for both script and style

**Evidence** — `backend/app/main.py:105-114` and `nginx/nginx.conf:64`:

```
script-src 'self' 'unsafe-inline';
style-src  'self' 'unsafe-inline';
```

This neutralises CSP's XSS containment. While `dangerouslySetInnerHTML` is not used today (confirmed by grep), any future regression instantly becomes exploitable. The Vite dev server uses inline `<script>` blocks; the **prod build** does not.

**Defensive remediation** — produce nonce-based CSP for production:

```python
import secrets

@app.middleware("http")
async def security_headers(request: Request, call_next):
    nonce = secrets.token_urlsafe(16)
    request.state.csp_nonce = nonce
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; "
        "object-src 'none'; require-trusted-types-for 'script';"
    )
    ...
```

Also build the frontend with `vite build` and serve the static bundle from nginx (`try_files`) in production, removing the need to proxy to `vite dev`.

---

### 5.2 [**MEDIUM**] Frontend persists tokens in `localStorage`

**Evidence** — `frontend/src/lib/auth.ts:21-32` — `zustand persist({name: 'adpct-auth', ...})` defaults to `localStorage`. JWTs there are accessible to any script that escapes the (presently weak) CSP.

**Defensive remediation** — store the **refresh** token in an `HttpOnly; Secure; SameSite=Strict` cookie set by the API, keep the **access** token in memory only. Outline:

```python
# backend/app/api/v1/auth.py
from fastapi.responses import JSONResponse

@router.post("/login")
def login(body: LoginRequest, response: Response, ...):
    ...
    response.set_cookie(
        key="adpct_refresh",
        value=refresh,
        max_age=_settings.refresh_token_ttl_min * 60,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/api/v1/auth",
    )
    return {"access_token": access, "expires_in": ttl, ...}
```

```ts
// frontend/src/lib/auth.ts  — drop persist; reload happens via /auth/refresh
export const useAuthStore = create<AuthState>()((set) => ({
  accessToken: null,
  user: null,
  setTokens: (access) => set({ accessToken: access }),
  setUser: (u) => set({ user: u }),
  logout: () => set({ accessToken: null, user: null }),
}))
```

On page reload the client calls `POST /auth/refresh` (cookie travels automatically) and obtains a new access token. This eliminates the XSS-steals-refresh-token risk.

---

### 5.3 [**HIGH**] Backend Docker image: dev tooling installed; root user; bind mount overwrites image

**Evidence**

- `backend/Dockerfile:7-22` runs `pip install --no-cache-dir -e .` which keeps `build-essential` in the final image and runs the process as root.
- `docker-compose.yml:54-55, 70-71, 86-87` bind-mounts `./backend:/app` over the container's image content for all of backend, worker, and beat. In production this means the image's audited contents are replaced by whatever lives on the host volume.

**Defensive remediation** — split dev and prod compose files, and use a multi-stage Dockerfile:

```dockerfile
# backend/Dockerfile
FROM python:3.11-slim AS build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libpq-dev && rm -rf /var/lib/apt/lists/*
COPY pyproject.toml ./
RUN pip install --no-cache-dir --target /install .

FROM python:3.11-slim AS runtime
RUN groupadd -r adpct && useradd -r -g adpct -s /usr/sbin/nologin adpct
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 openssh-client tini && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /install /usr/local/lib/python3.11/site-packages
COPY --chown=adpct:adpct app /app/app
USER adpct
EXPOSE 8000
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```yaml
# docker-compose.prod.yml — no bind mounts, no port exposure
services:
  backend:
    build: { context: ./backend }
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true
    cap_drop: ["ALL"]
```

---

### 5.4 [**LOW**] Compose version `"3.9"` is obsolete; healthchecks present but workers lack one

**Evidence** — `docker-compose.yml:1` (Docker emits a warning). The `backend`, `worker`, and `beat` services have no healthcheck.

**Remediation** — drop the `version` line and add:

```yaml
backend:
  healthcheck:
    test: ["CMD", "curl", "-fsS", "http://localhost:8000/health"]
    interval: 15s
    timeout: 5s
    retries: 5
worker:
  healthcheck:
    test: ["CMD", "celery", "-A", "app.workers.celery_app", "inspect", "ping", "-d", "celery@$$HOSTNAME"]
    interval: 30s
```

---

### 5.5 [**INFO**] No SBOM, no dependency-pin, no vulnerability scanning gates

**Evidence** — `backend/pyproject.toml` declares `>=` lower bounds; no lock file. Frontend has `package.json` but `package-lock.json` was not reviewed for pinning.

**Defensive remediation**

- Generate a lock file: `pip-compile --generate-hashes` (or migrate to `uv` / `poetry`).
- Run `pip-audit` and `npm audit --omit=dev` in CI on every PR and on a nightly schedule, gating merges on no `HIGH`/`CRITICAL`.
- Publish an SBOM with `syft packages dir:./backend -o cyclonedx-json` and attach it to the release artifact.
- Pin base images by digest: `FROM python:3.11-slim@sha256:...`.

---

### 5.6 [**INFO**] `python-jose` library is in maintenance-only mode

**Evidence** — `backend/pyproject.toml:18` pins `python-jose[cryptography]>=3.3`. The library is unmaintained and has historical CVEs; the active fork is `pyjwt` or `authlib`. The implementation is correct as written, but the dependency should be reconsidered.

**Defensive remediation** — switch to `PyJWT`:

```python
import jwt

def create_access_token(...):
    return jwt.encode(payload, _settings.secret_key, algorithm="HS256")

def decode_token(token):
    return jwt.decode(token, _settings.secret_key, algorithms=["HS256"],
                      audience="adpct-api", issuer=f"adpct:{settings.env}",
                      options={"require": ["exp", "iat", "jti"]})
```

---

### 5.7 [**INFO**] `HS256` JWT signing with a single shared secret

**Evidence** — `config.py:17` defaults to `HS256`. This works for a single API instance; for horizontally scaled deployments, an asymmetric signature (`RS256` / `EdDSA`) decouples token verification from token minting and is preferable when external clients (the connector agent ecosystem, future SAML federation) may need to verify tokens without seeing the secret.

**Remediation** — add `APP_JWT_PRIVATE_KEY` / `APP_JWT_PUBLIC_KEY` (PEM) options, default to `EdDSA` (`Ed25519`) in `prod`. Verifiers (other internal services) load only the public key.

---

## 6. Logging, Error Handling, and Observability

### 6.1 [**MEDIUM**] `request.error` middleware exposes 500s without correlation IDs

**Evidence** — `backend/app/main.py:128-146` returns `{"detail": "Internal server error", "type": "server_error"}` on any exception. The corresponding log line has no correlation ID, so operators cannot map a user's complaint to a specific stack trace.

**Defensive remediation**

```python
import uuid

@app.middleware("http")
async def access_log(request, call_next):
    rid = request.headers.get("x-request-id") or uuid.uuid4().hex
    structlog.contextvars.bind_contextvars(request_id=rid)
    start = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        log.exception("request.error", path=request.url.path, method=request.method)
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error", "request_id": rid},
            headers={"X-Request-ID": rid},
        )
    elapsed_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Request-ID"] = rid
    log.info("request", method=request.method, path=request.url.path,
             status=response.status_code, ms=round(elapsed_ms, 2))
    structlog.contextvars.unbind_contextvars("request_id")
    return response
```

---

### 6.2 [**LOW**] Structlog dev console renderer can output passwords

**Evidence** — `backend/app/main.py:48` selects `ConsoleRenderer` when `LOG_JSON=false`. If an exception occurs mid-login with `LoginRequest.password` still in scope, FastAPI's default error handler can dump request body to the console.

**Defensive remediation** — combine `SecretStr` (3.2) with a structlog processor (3.2 shows the helper) and ensure `LOG_JSON=true` is the default in `staging`/`prod`. Refuse to start with `LOG_JSON=false` outside `dev`:

```python
def _enforce_log_json() -> None:
    if settings.env in ("staging", "prod") and not settings.log_json:
        raise RuntimeError("LOG_JSON must be true in staging/prod")
```

---

### 6.3 [**INFO**] Audit log table not enforced append-only at DB level

**Evidence** — `backend/app/services/audit.py` and `backend/app/models/audit.py` do not declare a row-level security rule or trigger. The architectural intent (`ARCHITECTURE.md:204` — "append-only audit log") relies entirely on application code paths.

**Defensive remediation** — add a PostgreSQL trigger:

```sql
CREATE OR REPLACE FUNCTION audit_log_append_only() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_append_only();

-- Optional: REVOKE UPDATE, DELETE on audit_log FROM adpct;
```

Apply the same pattern to `privilege_findings` (also documented as append-only).

---

## 7. AI Assistant Endpoint

### 7.1 [**LOW**] Prompt-injection mitigation via length caps only

**Evidence** — `backend/app/api/v1/assistant.py:175-185` caps each context key/value at 64/256 chars and limits history to 20 turns. The system prompt itself (line 76-95) explicitly forbids tool topics. This is reasonable but the API does not strip control characters or zero-width whitespace from user content.

**Defensive remediation**

```python
import unicodedata
_CTRL_CHARS = "".join(chr(c) for c in range(32) if c not in (9, 10, 13))

def _sanitise_text(s: str, *, limit: int) -> str:
    s = unicodedata.normalize("NFKC", s)
    s = "".join(ch for ch in s if ch not in _CTRL_CHARS)
    return s[:limit]
```

Apply in `chat` to every `req.message`, every `turn.content`, and every context value.

---

### 7.2 [**LOW**] Anthropic API key read from `.env` and passed verbatim

**Evidence** — `assistant.py:167` — `anthropic.Anthropic(api_key=settings.anthropic_api_key)`. Long-lived. No revocation path inside the app.

**Defensive remediation** — wrap the key in a `SecretStr` and pull via the vault interface (3.x) rather than `.env`. Rotate weekly via the same job that rotates other operator-issued secrets, and log usage to the audit table (`ai_assistant.invoked`, including the role of the requester and a truncated message hash for later audit reconciliation — *not* the message itself).

---

## 8. Rules Engine

The declarative predicate evaluator (`backend/app/rules_engine/predicates.py`) is a strong design: no `eval`/`exec`, closed vocabulary, structured evidence. Two defensive observations:

### 8.1 [**INFO**] Predicate parsing surface

The dispatcher selects the operator by the first matching key. Pydantic-validated predicate models would constrain unknown / typo'd operators to fail fast at write-time rather than at evaluation-time. This is a maintainability and authorization hardening play more than a vulnerability.

```python
# backend/app/rules_engine/predicates.py
from pydantic import BaseModel, Field, RootModel
from typing import Union, Annotated, Literal

class UidEqualsP(BaseModel): uid_equals: int
class EntitlementKindIsP(BaseModel): entitlement_kind_is: str
class AllOfP(BaseModel): all_of: list["Predicate"]
class AnyOfP(BaseModel): any_of: list["Predicate"]
class NotP(BaseModel): not_: "Predicate" = Field(alias="not")

Predicate = Annotated[
    Union[UidEqualsP, EntitlementKindIsP, AllOfP, AnyOfP, NotP, ...],
    Field(discriminator=None),
]
```

### 8.2 [**INFO**] Confidence/risk scores not bounded at the API edge

Where rules can be authored or imported (YAML), reject scores outside `0..100` rather than rely on UI clamping. Combine with audit logging of "rule.imported" with the actor and a hash of the rule body.

---

## 9. Threat-Modelled Defence-in-Depth Recommendations

| Layer | Existing | Missing |
|-------|----------|---------|
| Network | nginx TLS 1.2/1.3, HSTS | mTLS between agent and console; per-asset IP allow-lists |
| Identity | bcrypt, lockout, RBAC | MFA (TOTP/WebAuthn), per-role 2FA enforcement, JWT denylist |
| Application | Pydantic v2, security headers | nonce-CSP, rate-limit, request IDs, output-encoded exports |
| Data | append-only design | DB-level append-only triggers, row-level encryption on `Credential.username`, `last_login_source` |
| Operations | append-only audit (app-layer) | SIEM forwarding, alerting on `auth.refresh.reuse_detected`, periodic key rotation jobs |

---

## 10. Action Summary (defensive priorities)

1. **Rate-limit auth endpoints** (`/auth/login`, `/auth/refresh`) per-IP and per-identifier (§1.1).
2. **Switch JWT to PyJWT** with `aud`, `iss`, `jti`, denylist, refresh-token rotation, and refresh-reuse detection (§1.2, §1.3, §5.6).
3. **`SecretStr` everywhere** + log-scrubbing processor + `LOG_JSON=true` in non-dev (§3.2, §6.2).
4. **Remediate conninfo / `SHOW GRANTS` injection surfaces** in DB collectors by using parameter-style connect calls and identifier-quoting helpers (§2.1, §2.2).
5. **Neutralise CSV/Excel formula prefixes** on export (§2.4).
6. **Enforce `expected_hostname`** during connector enrollment and shorten token TTL (§4.1, §4.2).
7. **Production Docker image**: non-root user, multi-stage build, no bind mount of `./backend`, image digest pinning (§5.3, §5.5).
8. **Move refresh tokens** to `HttpOnly; Secure; SameSite=Strict` cookies; keep access token in memory (§5.2).
9. **Nonce-based CSP**, drop `'unsafe-inline'` (§5.1).
10. **DB-level append-only triggers** on `audit_log` and `privilege_findings` (§6.3).

Each remediation block above is **illustrative** — adapt naming, dependency versions, and observability hooks to your release process. No code in the repository was modified as part of this review.

---

## Appendix A — Files reviewed (non-exhaustive)

- `backend/app/main.py` (FastAPI app, middlewares, CSP)
- `backend/app/config.py` (Settings)
- `backend/app/security.py` (JWT, bcrypt, RBAC)
- `backend/app/api/v1/auth.py` (login, refresh, change-password)
- `backend/app/api/v1/accounts.py` (filter surface, search)
- `backend/app/api/v1/exports.py` (CSV/Excel exports)
- `backend/app/api/v1/credentials.py` (vault metadata API)
- `backend/app/api/v1/assistant.py` (AI assistant)
- `backend/app/api/v1/connector_agents.py` (enrollment, runtime, results)
- `backend/app/schemas/auth.py` (Pydantic DTOs)
- `backend/app/services/audit.py`
- `backend/app/services/vault.py`
- `backend/app/collectors/_ssh.py` (TOFU, paramiko)
- `backend/app/collectors/postgresql.py` (conninfo)
- `backend/app/collectors/mysql.py` (`SHOW GRANTS`)
- `backend/app/collectors/windows.py` (WinRM / PowerShell)
- `backend/app/rules_engine/predicates.py`
- `backend/app/models/user.py`
- `frontend/src/api/client.ts` (token interceptor)
- `frontend/src/lib/auth.ts` (zustand persist)
- `frontend/src/pages/Login.tsx`
- `connector-agent/adpct_agent/client.py`
- `docker-compose.yml`
- `nginx/nginx.conf`
- `backend/Dockerfile`, `frontend/Dockerfile`
- `backend/pyproject.toml`, `frontend/package.json`
- `.gitignore`, `.env.example`
- `ARCHITECTURE.md`, `CONNECTOR_FRAMEWORK.md`, `README.md`

## Appendix B — Conventions used in this report

- **Evidence** sections cite exact file path + line numbers as observed at review time.
- **Defensive remediation** code blocks are *new* code illustrating the secure shape; the existing code was not modified.
- Findings classed as **HIGH** materially weaken a stated security guarantee in `ARCHITECTURE.md §8` or `§9`.
- Findings classed as **MEDIUM** create avoidable risk if downstream code changes.
- **LOW** and **INFO** findings are defence-in-depth recommendations.

*End of review.*
