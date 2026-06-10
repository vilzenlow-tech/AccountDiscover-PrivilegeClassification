# ADPCT — Defensive Security & Architectural Review

**Document:** `Fable5_review.md`
**Subject:** Account Discovery & Privilege Classification Tool (ADPCT)
**Review type:** Purely defensive security and SSDLC architectural audit
**Reviewer role:** Principal Secure Code Reviewer
**Date:** 2026-06-10
**Disposition:** Documentation only — **no code was modified**. All code blocks below are *illustrative remediation patterns*, not applied changes. This report contains **no exploit strings and no proof-of-concept attack vectors**, consistent with the requested defensive-engineering scope.

---

## How to read this report

Each finding carries a stable ID (`F-NN`), a severity, the precise `file:line` evidence, a plain-language explanation of the defensive weakness, and a clean refactored code block demonstrating the hardened pattern. Severities follow a defensive-risk lens (likelihood of a control gap being relied upon × blast radius if it is), not a CVSS exploit score.

| Severity | Meaning (defensive lens) |
|----------|--------------------------|
| **High** | A security control is missing, unenforced, or bypassable in a way that materially weakens the SSDLC posture; fix before production exposure. |
| **Medium** | A control is present but incomplete, or a safer default exists; schedule within the current hardening cycle. |
| **Low** | Defense-in-depth refinement or hygiene improvement. |
| **Info** | Confirmed strength or an observation worth recording; no action required. |

---

## Executive summary

ADPCT is a well-structured FastAPI + SQLAlchemy + React platform with several mature security foundations already in place: a declarative (eval-free) rules engine, SSH Trust-On-First-Use host-key pinning, an append-only audit log, a credential-vault abstraction that never returns secrets through the API, a layered security-header middleware, and a sealed-scope AI assistant. These are genuine strengths and are recorded as Informational findings so they are not regressed.

The weaknesses that warrant attention cluster in four areas:

1. **Session & token lifecycle.** JWTs are stateless with no revocation path, refresh tokens are long-lived and unbound, the declared login rate-limit setting is never wired into the login handler, and forced password rotation (`must_change_password`) is advisory rather than enforced server-side.
2. **Query construction in DB collectors.** A handful of collectors assemble connection strings and `SHOW GRANTS` statements with f-strings rather than parameterized drivers or quoted identifiers. The inputs are operator-controlled today, but the pattern is the kind of thing that becomes a vulnerability the moment an untrusted value reaches it.
3. **Configuration & build hygiene.** Hardcoded `adpct/adpct` Postgres credentials, a weak default JWT secret, a permissive CORS-with-credentials posture, a root-running backend image with build toolchain retained, and a source bind-mount over the image in Compose.
4. **Frontend token storage.** Access and refresh tokens persisted to `localStorage` via the zustand `persist` middleware, which broadens their exposure surface relative to in-memory or cookie-based handling.

### Severity tally

| Severity | Count |
|----------|-------|
| High | 6 |
| Medium | 9 |
| Low | 6 |
| Info | 5 |
| **Total** | **26** |

### Top defensive priorities (detail in §6)

1. Wire the already-declared login rate limit into the login handler (**F-01**).
2. Add token revocation + `jti` and bind/rotate refresh tokens (**F-02**).
3. Enforce `must_change_password` server-side on protected routes (**F-03**).
4. Replace f-string SQL/conninfo construction with parameterized/quoted identifiers (**F-09, F-10**).
5. Remove hardcoded DB credentials and harden the weak-secret guard (**F-13, F-14**).
6. Harden the backend container (non-root, drop build toolchain, no bind-mount in prod) (**F-17, F-18**).

---

# 1. Data Validation & Sanitization

## F-09 — PostgreSQL collector builds `conninfo` via f-string `[High]`

**Evidence:** [backend/app/collectors/postgresql.py:172](backend/app/collectors/postgresql.py)
```python
conninfo = (
    f"host={host} port={port} dbname={dbname} "
    f"user={credential.username} password={credential.secret or ''} "
    f"connect_timeout=20 sslmode={sslmode}"
)
with psycopg.connect(conninfo, autocommit=True) as conn:
```

**Defensive concern.** `host`, `dbname`, and `sslmode` derive from `target.ip_address`/`target.hostname`/`target.options` and `dbname` from `target.instance`. A value containing a space or a `keyword=value` token would be parsed by libpq as additional connection parameters — a parameter-injection class of bug. Even though those inputs are operator-managed today, the secure-by-construction approach is to pass connection parameters as discrete keyword arguments so the driver, not string concatenation, owns the encoding. This also keeps the password out of a single interpolated string that is easy to accidentally log.

**Illustrative remediation (NOT applied):**
```python
# psycopg3 accepts discrete connection parameters as keyword args; libpq
# escaping is handled by the driver, and no value can "leak" into another field.
conn = psycopg.connect(
    host=host,
    port=int(port),
    dbname=dbname,
    user=credential.username,
    password=credential.secret or "",
    connect_timeout=20,
    sslmode=sslmode,            # validate against an allow-list first (see below)
    autocommit=True,
)
```
```python
# Validate operator-supplied sslmode against the libpq-defined set before use.
_ALLOWED_SSLMODES = {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
sslmode = target.options.get("sslmode", "require")
if sslmode not in _ALLOWED_SSLMODES:
    raise ValueError(f"Unsupported sslmode: {sslmode!r}")
```
> Defensive note: prefer a default of `require` (or stronger) over `disable` so that the safe path is the one taken when nobody overrides it. See **F-12**.

---

## F-10 — MySQL collector interpolates identifiers into `SHOW GRANTS` `[High]`

**Evidence:** [backend/app/collectors/mysql.py:161](backend/app/collectors/mysql.py)
```python
cur.execute(f"SHOW GRANTS FOR '{u['User']}'@'{u['Host']}'")
```

**Defensive concern.** `User` and `Host` come back from `mysql.user` rows on the scanned host. `SHOW GRANTS` cannot bind an account name as a normal parameter, so the safe construction is to **escape the identifier values** using the driver's own quoting rather than wrapping them in literal single quotes by hand. A username or host containing a quote character would otherwise break out of the quoting.

**Illustrative remediation (NOT applied):**
```python
import pymysql

def _quote_account(user: str, host: str, conn) -> str:
    # pymysql.converters.escape_string handles embedded quotes/backslashes.
    # Identifiers in SHOW GRANTS are string literals, so escape as strings.
    safe_user = pymysql.converters.escape_string(user)
    safe_host = pymysql.converters.escape_string(host)
    return f"'{safe_user}'@'{safe_host}'"

# usage
cur.execute("SHOW GRANTS FOR " + _quote_account(u["User"], u["Host"], conn))
```
> Even better where the driver supports it: `cur.execute("SHOW GRANTS FOR %s@%s", (user, host))` — confirm the installed `pymysql` accepts parameterized account specs for this statement; if not, fall back to the escape helper above.

---

## F-11 — MySQL connection omits TLS configuration `[Medium]`

**Evidence:** [backend/app/collectors/mysql.py:146](backend/app/collectors/mysql.py)
```python
conn = pymysql.connect(
    host=target.ip_address or target.hostname, port=port,
    user=credential.username, password=credential.secret or "",
    db="mysql", connect_timeout=20, cursorclass=pymysql.cursors.DictCursor,
)
```

**Defensive concern.** The scan authenticates with a privileged DB credential but does not request TLS, so the credential and the harvested grant data can traverse the network in cleartext if the server permits it. The MongoDB collector (`mongodb.py:176`) and the WinRM collector expose transport options; MySQL should too, defaulting to a secure transport where available.

**Illustrative remediation (NOT applied):**
```python
ssl_opts = None
if target.options.get("require_tls", True):
    ssl_opts = {"ca": target.options.get("tls_ca")} if target.options.get("tls_ca") else {"ssl": {}}

conn = pymysql.connect(
    host=target.ip_address or target.hostname,
    port=port,
    user=credential.username,
    password=credential.secret or "",
    db="mysql",
    connect_timeout=20,
    cursorclass=pymysql.cursors.DictCursor,
    ssl=ssl_opts,                      # enable encrypted transport
)
```

---

## F-12 — PostgreSQL collector defaults `sslmode` to `disable` `[Medium]`

**Evidence:** [backend/app/collectors/postgresql.py:170](backend/app/collectors/postgresql.py)
```python
sslmode = target.options.get("sslmode", "disable")
```

**Defensive concern.** An unset option yields cleartext transport for a privileged DB session. Insecure-by-default is the anti-pattern; the secure default should be `require` (or `verify-full` where a CA is pinned), with an explicit operator opt-out for legacy servers. The accompanying comment in the file documents the convenience trade-off, which is exactly the place SSDLC asks us to flip the default.

**Illustrative remediation (NOT applied):**
```python
# Secure default; operators must consciously downgrade for legacy targets.
sslmode = target.options.get("sslmode", "require")
```

---

## F-05 — Search filters interpolate raw input into `ILIKE` patterns `[Low]`

**Evidence:** [backend/app/api/v1/accounts.py:76](backend/app/api/v1/accounts.py), [backend/app/api/v1/connector_agents.py:264](backend/app/api/v1/connector_agents.py)
```python
q = q.filter(Account.account_name.ilike(f"%{search}%"))
```

**Defensive concern.** This is **not** SQL injection — SQLAlchemy parameterizes the bound value, so it is safe against injection. The residual concern is functional/DoS hygiene: `%` and `_` in user input are treated as wildcards, and unbounded `search` length lets a caller craft expensive leading-wildcard scans. Escaping LIKE metacharacters and capping length makes the filter behave predictably.

**Illustrative remediation (NOT applied):**
```python
def _like_escape(term: str) -> str:
    # Escape LIKE wildcards so user input matches literally.
    return term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

if search:
    term = _like_escape(search.strip())[:128]
    q = q.filter(Account.account_name.ilike(f"%{term}%", escape="\\"))
```
> Apply the same helper to the connector-agent `name`/`hostname` search at `connector_agents.py:264`.

---

## F-06 — Result-ingestion trusts agent-supplied counts and JSON shape `[Medium]`

**Evidence:** [backend/app/api/v1/connector_agents.py:101-129](backend/app/api/v1/connector_agents.py)
```python
payload = json.loads(raw.decode("utf-8"))
...
result.accounts_discovered = int(payload.get("accounts_discovered") or 0)
result.assets_scanned = int(payload.get("assets_scanned") or 0)
```

**Defensive concern.** The connector agent is a separate trust boundary (it runs on a remote host and authenticates with a bearer token). Decompressed payloads are parsed and partially trusted before structural validation. The checksum guarantees integrity-in-transit, not *schema* validity. A malformed or oversized payload (decompression of an attacker-influenced gzip stream, deeply nested JSON, enormous arrays) should be bounded and schema-validated with Pydantic before any field is read, and `gzip.decompress` should be size-capped to resist decompression-bomb resource exhaustion.

**Illustrative remediation (NOT applied):**
```python
from pydantic import BaseModel, Field, ValidationError

_MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024  # cap to bound memory

class _TargetResult(BaseModel):
    status: str | None = None
    accounts_discovered: int = 0

class _ResultPayload(BaseModel):
    accounts_discovered: int = Field(default=0, ge=0)
    assets_scanned: int = Field(default=0, ge=0)
    target_results: list[_TargetResult] = Field(default_factory=list, max_length=100_000)

def _safe_gunzip(blob: bytes) -> bytes:
    import zlib
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(blob, _MAX_DECOMPRESSED_BYTES + 1)
    if len(out) > _MAX_DECOMPRESSED_BYTES or d.unconsumed_tail:
        raise HTTPException(status_code=413, detail="Result payload too large")
    return out + d.flush()

try:
    payload = _ResultPayload.model_validate_json(raw.decode("utf-8"))
except ValidationError:
    result.processing_error = "Result schema validation failed"
    result.processed_at = datetime.now(UTC)
    return
```

---

## F-07 — Upstream AI error detail forwarded verbatim to clients `[Low]`

**Evidence:** [backend/app/api/v1/assistant.py:201-205](backend/app/api/v1/assistant.py)
```python
except anthropic.APIStatusError as exc:
    raise HTTPException(
        status_code=502,
        detail=f"Upstream AI API error: {exc.status_code} — {exc.message}",
    ) from exc
```

**Defensive concern.** Reflecting an upstream provider's raw message back to the caller can disclose internal request shape or quota/account hints. Log the detail server-side; return a generic message to the client.

**Illustrative remediation (NOT applied):**
```python
except anthropic.APIStatusError as exc:
    log.warning("assistant.upstream_error", status=exc.status_code, message=exc.message)
    raise HTTPException(status_code=502, detail="The assistant is temporarily unavailable.") from exc
```

**Informational strengths in this area (already present):**

- **F-INFO-A — Sealed AI assistant scope.** [backend/app/api/v1/assistant.py:130-185](backend/app/api/v1/assistant.py) caps context to 10 keys × 256 chars and prefixes it as page context rather than into the system prompt; history is length- and size-bounded; the system prompt refuses prompt-injection ("act as"). This is a solid bounded-LLM pattern.
- **F-INFO-B — Pydantic v2 schemas at every boundary.** Login (`schemas/auth.py`), assets (`schemas/asset.py`), and chat (`assistant.py`) constrain types and lengths, giving consistent input validation across the API.
- **F-INFO-C — Eval-free rules engine.** [backend/app/rules_engine/predicates.py:1-4](backend/app/rules_engine/predicates.py) explicitly avoids `eval`/`exec` and evaluates a closed predicate vocabulary — the correct design for a data-driven classification engine.

---

# 2. Authentication & Authorization

## F-01 — Declared login rate limit is never enforced `[High]`

**Evidence:** declared at [backend/app/config.py:21](backend/app/config.py) (`rate_limit_login_per_min`), never referenced in [backend/app/api/v1/auth.py:46-94](backend/app/api/v1/auth.py) or [backend/app/main.py](backend/app/main.py).

**Defensive concern.** The login endpoint has per-account lockout after 10 failures (`auth.py:27,56`) but **no IP/credential-stuffing rate limit**, despite the setting existing. Per-account lockout alone is also a self-inflicted lockout vector and does nothing against spraying across many accounts from one source. Wire a real limiter (e.g. `slowapi`, or a Redis fixed-window counter — Redis is already a dependency) keyed on client IP + email.

**Illustrative remediation (NOT applied):**
```python
# Redis-backed fixed-window limiter (reuses existing redis_url).
import redis
from app.config import get_settings

_r = redis.from_url(get_settings().redis_url)

def _enforce_login_rate(ip: str, email: str) -> None:
    limit = get_settings().rate_limit_login_per_min
    window_key = f"login:{ip}:{email}:{int(time.time() // 60)}"
    count = _r.incr(window_key)
    if count == 1:
        _r.expire(window_key, 60)
    if count > limit:
        raise HTTPException(status_code=429, detail="Too many login attempts. Try again shortly.")

@router.post("/login", response_model=TokenResponse)
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    _enforce_login_rate(ip, body.email)
    ...
```
> Pair this with a soft, time-decaying lockout instead of a permanent `is_active = False` (see **F-04**) so the account-lockout branch cannot be weaponized to disable accounts.

---

## F-02 — Stateless JWTs: no revocation, `jti`, `aud`/`iss`, or refresh rotation `[High]`

**Evidence:** [backend/app/security.py:39-61](backend/app/security.py)
```python
def create_access_token(sub, roles, extra=None):
    payload = {"sub": sub, "roles": roles, "type": "access", "exp": exp, "iat": _now()}
    ...
def decode_token(token):
    return jwt.decode(token, _settings.secret_key, algorithms=[_settings.jwt_alg])
```
and refresh issuance at [backend/app/api/v1/auth.py:97-110](backend/app/api/v1/auth.py).

**Defensive concern.** Several stateless-JWT hardening controls are absent:
- **No revocation list / `jti`.** A leaked or post-logout token remains valid until `exp`. Logout is client-side only.
- **No `aud`/`iss` claims or validation.** Tokens are not bound to this audience/issuer.
- **Refresh tokens carry only `sub`** and a new refresh is minted on every refresh without invalidating the prior one (`auth.py:107`), so a stolen refresh token is a long-lived bearer (default 12h, `config.py:19`) that cannot be cut off.
- **Roles are embedded in the access token**, so a role downgrade does not take effect until expiry.

**Illustrative remediation (NOT applied):**
```python
import uuid

def create_access_token(sub, roles, extra=None):
    now = _now()
    payload = {
        "sub": sub, "roles": roles, "type": "access",
        "iat": now, "exp": now + timedelta(minutes=_settings.access_token_ttl_min),
        "iss": _settings.token_issuer, "aud": _settings.token_audience,
        "jti": str(uuid.uuid4()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, _settings.secret_key, algorithm=_settings.jwt_alg)

def decode_token(token, expected_type="access"):
    try:
        data = jwt.decode(
            token, _settings.secret_key, algorithms=[_settings.jwt_alg],
            audience=_settings.token_audience, issuer=_settings.token_issuer,
        )
    except JWTError as e:
        raise HTTPException(status_code=401, detail="Invalid token",
                            headers={"WWW-Authenticate": "Bearer"}) from e
    if data.get("type") != expected_type:
        raise HTTPException(status_code=401, detail="Wrong token type")
    if _is_revoked(data.get("jti")):          # Redis set / DB denylist
        raise HTTPException(status_code=401, detail="Token revoked")
    return data
```
```python
# Refresh rotation with reuse detection: store the active refresh jti per user.
def rotate_refresh(old_jti: str, sub: str) -> str:
    if not _consume_refresh(sub, old_jti):    # invalidates the old one atomically
        _revoke_all_sessions(sub)             # reuse => possible theft, kill the family
        raise HTTPException(status_code=401, detail="Refresh reuse detected")
    return create_refresh_token(sub)          # new jti, recorded as the active one
```
> A logout endpoint can then add the access `jti` to the denylist until its `exp`, giving true server-side session termination.

---

## F-03 — `must_change_password` is advisory, not enforced server-side `[High]`

**Evidence:** flag is returned to the client at [backend/app/api/v1/auth.py:93](backend/app/api/v1/auth.py) and surfaced in `/me` (`auth.py:139`), but a full access token is issued on login regardless, and no dependency blocks normal API calls while the flag is set. Seed users ship with `must_change_password=True` ([backend/app/seed.py:78](backend/app/seed.py)).

**Defensive concern.** A user (or anyone with the shared seed password `ChangeMe!123`, `seed.py:49-51`) can authenticate and use the full API without ever changing their password, because enforcement lives only in the frontend. The server must refuse protected operations until the password is rotated.

**Illustrative remediation (NOT applied):**
```python
def require_password_current(
    p: Principal = Depends(get_current_principal),
    db: Session = Depends(get_db),
) -> Principal:
    user = db.query(User).filter(User.id == p.id).first()
    if user and user.must_change_password:
        raise HTTPException(
            status_code=403,
            detail="Password change required before continuing.",
        )
    return p
```
```python
# Apply as the default principal dependency for all routers EXCEPT
# /auth/change-password, /auth/me, and /auth/logout. Optionally, issue a
# restricted "password_change_only" scoped token at login when the flag is set.
```

---

## F-04 — Permanent account disable on failed logins is a lockout/DoS vector `[Medium]`

**Evidence:** [backend/app/api/v1/auth.py:54-57](backend/app/api/v1/auth.py)
```python
user.failed_login_attempts += 1
if user.failed_login_attempts >= _MAX_FAILED_ATTEMPTS:
    user.is_active = False
```

**Defensive concern.** Ten failed attempts permanently disable the account (`is_active = False`) with no automatic recovery — an availability risk that an outsider can trigger against any known email, and it requires admin intervention to undo. Prefer a **time-boxed** lockout that self-heals, combined with the IP rate limit from **F-01**.

**Illustrative remediation (NOT applied):**
```python
from datetime import timedelta

_LOCK_THRESHOLD = 10
_LOCK_WINDOW = timedelta(minutes=15)

def _is_locked(user) -> bool:
    return bool(user.locked_until and user.locked_until > datetime.now(UTC))

# on failure:
user.failed_login_attempts += 1
if user.failed_login_attempts >= _LOCK_THRESHOLD:
    user.locked_until = datetime.now(UTC) + _LOCK_WINDOW
    user.failed_login_attempts = 0   # reset the counter for the next window
# on success: clear failed_login_attempts AND locked_until
```

---

## F-08 — Auto-approve enrollment mints a bearer token with no second factor `[Medium]`

**Evidence:** [backend/app/api/v1/connector_agents.py:703-710](backend/app/api/v1/connector_agents.py)
```python
if et.auto_approve:
    token, token_hash_new, token_prefix = _generate_token()
    agent.token_hash = token_hash_new
    agent.status = ConnectorAgentStatus.approved
    agent.approved_by = "auto-approve"
    bearer_token = token
```

**Defensive concern.** Anyone presenting a valid one-time enrollment token (which is, by design, transmitted out-of-band to an operator) immediately receives a long-lived agent bearer token and `approved` status, with no binding to the `expected_hostname` the token was scoped to. The enrollment token already records `expected_hostname`/`expected_site`/`expected_environment` (`connector_agents.py:228-230`) — enforce them. The token verification itself is well done (`_verify_token` uses `hmac.compare_digest`, `connector_agents.py:145-146`; hashes are stored, not plaintext), so this is about tightening the *auto-approve* path specifically.

**Illustrative remediation (NOT applied):**
```python
if et.expected_hostname and body.hostname != et.expected_hostname:
    raise HTTPException(status_code=409, detail="Hostname does not match enrollment scope")

if et.auto_approve:
    # Restrict auto-approve to enrollment tokens explicitly marked low-risk
    # AND matching the pre-registered hostname/site; otherwise force manual review.
    if not (et.expected_hostname and et.expected_site):
        raise HTTPException(status_code=409,
            detail="Auto-approve requires a hostname- and site-scoped enrollment token")
    token, token_hash_new, token_prefix = _generate_token()
    ...
```
> Consider also issuing agent tokens with an expiry (the rotate endpoint computes `expires_at` at `connector_agents.py:465` but the stored hash itself is not time-bound) and recording an `approved_by` that identifies the scoping token rather than the literal string `"auto-approve"`.

**Informational strengths in this area (already present):**

- **F-INFO-D — Token verification before status disclosure.** [backend/app/api/v1/connector_agents.py:194-204](backend/app/api/v1/connector_agents.py) verifies the token *before* checking administrative status, avoiding status oracles for unauthenticated callers, and uses constant-time comparison.
- **F-INFO-E — Append-only audit trail.** [backend/app/services/audit.py:12-37](backend/app/services/audit.py) only ever `add`s rows; every privileged mutation in the connector and credential routers calls `log_action` with actor, subject, and context.
- **F-INFO-F — RBAC consistently applied.** Every state-changing endpoint reviewed carries `require_roles(...)`; read endpoints carry `get_current_principal`. The factory pattern (`security.py:99-110`) centralizes the check.
- **F-INFO-G — Timing-safe login.** [backend/app/api/v1/auth.py:50-51](backend/app/api/v1/auth.py) performs a hash check even when the user is absent, reducing user-enumeration timing signal.

---

# 3. Dependency & Configuration Risks

## F-13 — Hardcoded `adpct/adpct` Postgres credentials `[High]`

**Evidence:** [docker-compose.yml:13-16](docker-compose.yml) and the matching default DSN at [backend/app/config.py:23-26](backend/app/config.py)
```yaml
environment:
  POSTGRES_USER: adpct
  POSTGRES_PASSWORD: adpct
  POSTGRES_DB: adpct
```
```python
database_url: str = Field(
    default="postgresql+psycopg://adpct:adpct@postgres:5432/adpct", ...)
```

**Defensive concern.** A guessable, committed database credential is a textbook hardcoded-secret finding. Even though Postgres is not port-exposed in the compose file (`docker-compose.yml:19`), the value lives in source control and becomes the production default if `.env`/`DATABASE_URL` is not overridden. Source the password from an env var / Docker secret with no insecure fallback.

**Illustrative remediation (NOT applied):**
```yaml
postgres:
  image: postgres:16
  environment:
    POSTGRES_USER: ${POSTGRES_USER:?set in .env}
    POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password   # Docker secret
    POSTGRES_DB: ${POSTGRES_DB:?set in .env}
  secrets:
    - postgres_password
```
```python
# Remove the credential-bearing default; fail closed if unset in non-dev.
database_url: str = Field(default="", alias="DATABASE_URL")
# ...validated in _enforce_secret_key-style startup guard for staging/prod.
```

---

## F-14 — Weak default JWT secret; guard only covers staging/prod `[High]`

**Evidence:** default at [backend/app/config.py:16](backend/app/config.py) (`secret_key="dev-only-change-me"`); guard at [backend/app/main.py:62-70](backend/app/main.py).

**Defensive concern.** `_enforce_secret_key()` is a good control, but it only fires when `APP_ENV in ("staging","prod")`. Because `APP_ENV` defaults to `dev` (`config.py:15`), a deployment that simply forgets to set `APP_ENV` runs with the publicly known signing key and the guard never triggers — JWTs would be forgeable. Make the guard fail-closed: treat any non-`dev` *or unset/unknown* env as requiring a strong secret, and verify the secret length unconditionally with a loud warning in dev.

**Illustrative remediation (NOT applied):**
```python
def _enforce_secret_key() -> None:
    weak = settings.secret_key in _WEAK_SECRET_SENTINELS or len(settings.secret_key) < 32
    if settings.env != "dev":
        if weak:
            raise RuntimeError("APP_SECRET_KEY must be a 32+ char random secret outside dev.")
    elif weak:
        log.warning("adpct.weak_secret_key",
                    detail="Running with a known-weak APP_SECRET_KEY — dev only.")
```
> Also ensure deployment templates set `APP_ENV` explicitly so "unset" can never silently mean "dev".

---

## F-15 — CORS allows credentials with wildcard methods/headers `[Medium]`

**Evidence:** [backend/app/main.py:91-97](backend/app/main.py)
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Defensive concern.** `allow_credentials=True` combined with `allow_methods=["*"]` / `allow_headers=["*"]` is broader than necessary. The origin list is bounded (good), but the wildcards relax preflight beyond what the app uses. Tokens are currently sent as `Authorization` bearer headers (not cookies), which limits the practical impact, but the principle of least privilege favors enumerating the methods and headers actually in use.

**Illustrative remediation (NOT applied):**
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,   # keep the explicit allow-list
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
    max_age=600,
)
```

---

## F-16 — CSP relies on `'unsafe-inline'` for scripts and styles `[Medium]`

**Evidence:** [backend/app/main.py:105-114](backend/app/main.py) and the mirrored header in [nginx/nginx.conf:64](nginx/nginx.conf)
```python
"script-src 'self' 'unsafe-inline'; "
"style-src 'self' 'unsafe-inline'; "
```

**Defensive concern.** `'unsafe-inline'` in `script-src` substantially weakens the XSS mitigation the CSP is meant to provide. React escapes by default (so the app is not obviously XSS-prone), but the CSP is the backstop for when that assumption fails. Move to a nonce/hash-based policy for scripts and drop `'unsafe-inline'` there; inline styles are lower-risk but ideally also nonce'd.

**Illustrative remediation (NOT applied):**
```python
# Generate a per-response nonce and inject it into both the CSP and the
# served HTML <script nonce="..."> tags (requires build/template cooperation).
nonce = secrets.token_urlsafe(16)
csp = (
    "default-src 'self'; "
    f"script-src 'self' 'nonce-{nonce}'; "
    "style-src 'self' 'unsafe-inline'; "   # tighten later with hashed styles
    "img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
)
```
> Keep the FastAPI and nginx CSP definitions in sync — currently both must be edited (`main.py` and `nginx.conf`); consider a single source of truth.

---

## F-17 — Backend image runs as root with build toolchain retained `[High]`

**Evidence:** [backend/Dockerfile:1-22](backend/Dockerfile)
```dockerfile
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev curl openssh-client ...
COPY . .
CMD ["uvicorn", "app.main:app", ...]
```

**Defensive concern.** The container runs as `root` (no `USER` directive) and keeps `build-essential` in the final image, enlarging the runtime attack surface. A compromised process inside the container has root and a compiler. Use a non-root user and a multi-stage build that drops the toolchain from the runtime layer.

**Illustrative remediation (NOT applied):**
```dockerfile
# ---- build stage ----
FROM python:3.11-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libpq-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pyproject.toml ./
RUN pip install --no-cache-dir --prefix=/install -e .

# ---- runtime stage ----
FROM python:3.11-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 openssh-client && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --no-create-home appuser
COPY --from=build /install /usr/local
WORKDIR /app
COPY . .
USER 10001
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## F-18 — Source bind-mount overlays the built image in Compose `[Medium]`

**Evidence:** [docker-compose.yml:54-55](docker-compose.yml) (backend), `:71-72` (worker), `:86-87` (beat)
```yaml
volumes:
  - ./backend:/app
```

**Defensive concern.** Mounting host source over `/app` is convenient for dev hot-reload but, if carried into production, means the running code is whatever is on the host disk (bypassing the immutable, scanned image) and that writes by the container land on the host filesystem. The local vault store path even depends on this mount ([backend/app/services/vault.py:46](backend/app/services/vault.py)). Provide a separate production compose/override that omits the bind-mount and uses a named volume only for the vault data.

**Illustrative remediation (NOT applied):**
```yaml
# docker-compose.prod.yml — no source bind-mount; named volume for vault only.
services:
  backend:
    volumes:
      - vault_data:/app/vault_data
volumes:
  vault_data:
```

---

## F-19 — Frontend `npm install` without a locked, reproducible install `[Low]`

**Evidence:** [frontend/Dockerfile:5](frontend/Dockerfile)
```dockerfile
RUN npm install
```

**Defensive concern.** `npm install` can drift from the lockfile and resolve newer transitive versions at build time, undermining build reproducibility and supply-chain integrity. Use `npm ci` against a committed `package-lock.json`, and run the frontend as a non-root user.

**Illustrative remediation (NOT applied):**
```dockerfile
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci                      # reproducible, lockfile-faithful
COPY . .
RUN npm run build
# serve the static build behind nginx in prod rather than `npm run dev`
```

**Informational strength (already present):**

- **F-INFO-H — Secrets are git-ignored and Docker-secret-mounted.** [.gitignore](.gitignore) excludes `.env*` (except the example), `secrets/`, and `nginx/certs/`; the Fernet key is a Docker secret (`docker-compose.yml:6-8`) with the vault loader preferring `/run/secrets/...` and `chmod 600` on disk ([backend/app/services/vault.py:73-106](backend/app/services/vault.py)). The dependency pins use floors (`>=`) which aids patching; consider a lock/constraints file for full reproducibility (relates to **F-19**).

---

# 4. Frontend Security Posture

## F-20 — Access & refresh tokens persisted to `localStorage` `[Medium]`

**Evidence:** [frontend/src/lib/auth.ts:21-33](frontend/src/lib/auth.ts)
```ts
export const useAuthStore = create<AuthState>()(
  persist((set) => ({ ... }),
    { name: 'adpct-auth', partialize: (s) => ({ accessToken: s.accessToken, refreshToken: s.refreshToken, user: s.user }) }),
)
```

**Defensive concern.** Persisting both tokens to `localStorage` makes them readable by any script running in the page and keeps the long-lived refresh token on disk across sessions. Given the CSP still allows `'unsafe-inline'` scripts (**F-16**), this is the higher-impact half of that pairing. Preferred patterns: keep the access token in memory only, and hold the refresh token in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie set by the backend so JavaScript cannot read it.

**Illustrative remediation (NOT applied):**
```ts
// Keep tokens out of persisted storage; hold access token in memory only.
export const useAuthStore = create<AuthState>()((set) => ({
  accessToken: null,            // memory only; lost on reload (re-auth via refresh cookie)
  user: null,
  setAccessToken: (t) => set({ accessToken: t }),
  logout: () => set({ accessToken: null, user: null }),
}))
// Refresh token lives in an HttpOnly cookie issued by /auth/login; the
// /auth/refresh call relies on the cookie, not a value readable by JS.
```
> If a full cookie redesign is out of scope near-term, an interim step is to persist *only* non-sensitive `user` profile data and keep both tokens in memory.

---

## F-21 — Debug `console.log` of request parameters in the API client `[Low]`

**Evidence:** [frontend/src/api/client.ts:18-21](frontend/src/api/client.ts)
```ts
if (config.params?.tag_ids) {
  console.log('[API] GET with tag_ids:', config.params.tag_ids)
}
```

**Defensive concern.** Leftover debug logging writes request parameters to the browser console in production builds. It is low-risk here (tag IDs), but the pattern can grow to log sensitive filters, and it is noise that should be stripped from production bundles.

**Illustrative remediation (NOT applied):**
```ts
if (import.meta.env.DEV && config.params?.tag_ids) {
  console.debug('[API] GET with tag_ids:', config.params.tag_ids)
}
```

---

## F-22 — Hard redirect on auth failure can mask refresh-loop edge cases `[Low]`

**Evidence:** [frontend/src/api/client.ts:24-52](frontend/src/api/client.ts)

**Defensive concern.** The 401 interceptor retries once via `/auth/refresh` and otherwise `window.location.href = '/login'`. This is reasonable, but because refresh tokens are not rotated server-side (**F-02**) and live in `localStorage` (**F-20**), a stale refresh token can drive repeated silent refresh attempts. Once server-side rotation + reuse detection exists, the client should clear local auth state on any refresh failure and avoid retrying a refresh that was itself rejected (the `includes('/auth/refresh')` guard already helps).

**Illustrative remediation (NOT applied):**
```ts
// On refresh failure, fully clear persisted state before redirecting.
catch {
  useAuthStore.getState().logout()
  localStorage.removeItem('adpct-auth')   // ensure stale tokens are gone
  window.location.href = '/login'
}
```

---

# 5. Connector Agent Trust Boundary (cross-cutting)

## F-23 — Agent TLS verification can be disabled by an env var `[Medium]`

**Evidence:** [connector-agent/adpct_agent/config.py:95-96](connector-agent/adpct_agent/config.py)
```python
if os.environ.get("VERIFY_TLS", "").lower() in ("0", "false", "no"):
    cfg.verify_tls = False
```
and the HTTP client honoring it at [connector-agent/adpct_agent/client.py:47,99,109](connector-agent/adpct_agent/client.py).

**Defensive concern.** A single env var disables certificate verification for the agent↔console channel, over which bearer tokens and scan results flow. This exists for self-signed dev certs, which is legitimate, but it is the kind of switch that silently rides into production. Gate it behind an explicit dev flag and emit a loud, persistent warning when verification is off; prefer pinning the console CA bundle (`console_ca_bundle`, `config.py:51`) or fingerprint (the console already serves `console_fingerprint` in config, `connector_agents.py:866`) over disabling verification entirely.

**Illustrative remediation (NOT applied):**
```python
allow_insecure = os.environ.get("ADPCT_DEV_ALLOW_INSECURE_TLS") == "1"
if allow_insecure and os.environ.get("VERIFY_TLS", "").lower() in ("0", "false", "no"):
    cfg.verify_tls = False
    log.warning(
        "TLS verification DISABLED for console channel — development only. "
        "Pin console_ca_bundle or console_fingerprint instead for any real deployment."
    )
elif os.environ.get("VERIFY_TLS", "").lower() in ("0", "false", "no"):
    log.error("Refusing to disable TLS verification without ADPCT_DEV_ALLOW_INSECURE_TLS=1")
```

## F-24 — Console-pushed config is merged with minimal validation `[Low]`

**Evidence:** [connector-agent/adpct_agent/config.py:110-142](connector-agent/adpct_agent/config.py)

**Defensive concern.** `update_from_console` copies numeric/list settings from the console response into local config and persists them (`save_config`) with light `.get()`-based defaulting. Since the agent already trusts the console as its control plane this is acceptable, but bounding the values (e.g. interval floors, list lengths, `max_targets_per_job` ceiling) defends against a compromised or buggy console pushing pathological settings.

**Illustrative remediation (NOT applied):**
```python
def _clamp(v, lo, hi, default):
    try:
        return max(lo, min(int(v), hi))
    except (TypeError, ValueError):
        return default

if "execution" in console_cfg:
    e = console_cfg["execution"]
    cfg.job_timeout_seconds = _clamp(e.get("job_timeout_seconds"), 30, 86_400, cfg.job_timeout_seconds)
    cfg.max_concurrent_jobs = _clamp(e.get("max_concurrent_jobs"), 1, 16, cfg.max_concurrent_jobs)
```

**Informational strength (already present):**

- **F-INFO-I — Agent config cache hardened on disk.** [connector-agent/adpct_agent/config.py:101-107](connector-agent/adpct_agent/config.py) writes the config (including the bearer token) with `chmod 0o600`, and the dataclass documents the token as "never logged."

---

# 6. Action Summary (prioritized)

| # | ID | Finding | Severity | Area |
|---|------|---------|----------|------|
| 1 | F-01 | Wire the declared login rate limit into the login handler | High | AuthN |
| 2 | F-02 | Add JWT `jti`/revocation, `aud`/`iss`, rotate refresh tokens | High | Session |
| 3 | F-03 | Enforce `must_change_password` server-side | High | AuthN |
| 4 | F-09 | Parameterize PostgreSQL `conninfo` construction | High | Injection hygiene |
| 5 | F-10 | Escape identifiers in MySQL `SHOW GRANTS` | High | Injection hygiene |
| 6 | F-13 | Remove hardcoded `adpct/adpct` DB credentials | High | Config/secrets |
| 7 | F-14 | Make the weak-secret guard fail-closed for unset `APP_ENV` | High | Config/secrets |
| 8 | F-17 | Run backend container non-root; drop build toolchain | High | Build hygiene |
| 9 | F-04 | Replace permanent lockout with time-boxed lockout | Medium | AuthN |
| 10 | F-06 | Schema-validate + size-cap agent result payloads | Medium | Validation |
| 11 | F-08 | Bind auto-approve enrollment to hostname/site scope | Medium | AuthZ |
| 12 | F-11 | Enable TLS on MySQL collector connections | Medium | Transport |
| 13 | F-12 | Default PostgreSQL `sslmode` to `require` | Medium | Transport |
| 14 | F-15 | Narrow CORS methods/headers under credentials | Medium | Config |
| 15 | F-16 | Remove `'unsafe-inline'` from `script-src` (nonce/hash) | Medium | Frontend/CSP |
| 16 | F-18 | Drop source bind-mount in production compose | Medium | Build hygiene |
| 17 | F-20 | Move tokens off `localStorage` (memory + HttpOnly cookie) | Medium | Frontend |
| 18 | F-23 | Gate agent TLS-verification opt-out behind explicit dev flag | Medium | Agent transport |
| 19 | F-05 | Escape LIKE metacharacters + cap search length | Low | Validation |
| 20 | F-07 | Stop reflecting upstream AI error detail to clients | Low | Error handling |
| 21 | F-19 | Use `npm ci` against a committed lockfile | Low | Supply chain |
| 22 | F-21 | Strip debug `console.log` from production builds | Low | Frontend hygiene |
| 23 | F-22 | Fully clear local auth state on refresh failure | Low | Frontend |
| 24 | F-24 | Clamp console-pushed agent config values | Low | Agent config |

**Confirmed strengths (no action):** F-INFO-A sealed AI assistant scope · F-INFO-B Pydantic v2 at boundaries · F-INFO-C eval-free rules engine · F-INFO-D token-before-status ordering · F-INFO-E append-only audit · F-INFO-F consistent RBAC · F-INFO-G timing-safe login · F-INFO-H git-ignored / Docker-secret secrets · F-INFO-I 0600 agent config cache.

---

## Appendix A — Files reviewed

**Backend (core):** `app/main.py`, `app/config.py`, `app/security.py`, `app/db.py`, `app/seed.py`, `app/models/__init__.py`.
**Backend (API):** `api/v1/auth.py`, `accounts.py`, `credentials.py`, `exports.py`, `assistant.py`, `connector_agents.py`; RBAC survey across all 20 routers.
**Backend (schemas):** `schemas/auth.py`, `schemas/asset.py`.
**Backend (services):** `services/vault.py`, `services/audit.py`.
**Backend (collectors):** `collectors/_ssh.py`, `postgresql.py`, `mysql.py`, `mongodb.py`, `windows.py`.
**Backend (rules engine):** `rules_engine/predicates.py`, `engine.py` (eval-free confirmation).
**Connector agent:** `adpct_agent/config.py`, `client.py`, executor/scanner survey.
**Frontend:** `src/lib/auth.ts`, `src/api/client.ts`.
**Deployment:** `docker-compose.yml`, `backend/Dockerfile`, `frontend/Dockerfile`, `nginx/nginx.conf`, `.gitignore`, `secrets/` layout, `pyproject.toml`.

## Appendix B — Review conventions

- **Defensive scope only.** This document recommends hardening; it contains no exploit strings, payloads, or proof-of-concept attack vectors.
- **No code changed.** Every code block is an *illustrative* secure pattern. The live codebase was read but not modified, consistent with the documentation-only instruction.
- **Evidence-anchored.** Every finding cites `file:line` so it can be independently verified before any remediation work is scheduled.
- **Severity is advisory.** Ratings reflect defensive-control risk and blast radius, intended to order a hardening backlog rather than to score exploitability.

*End of report.*
