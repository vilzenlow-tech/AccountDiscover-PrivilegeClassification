# Data Integrity & Inactivity Housekeeping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make last-login data real in every live collector, add password-age/expiry fields to the account model, and build a configurable 30/90-day inactivity engine with a monthly housekeeping export — implementing the MVP scope (§10) of the 2026-06-10 Identity Security Architecture review.

**Architecture:** Pure, unit-testable parsers (`_unix_parsers.py`) and a pure activity-tiering service (`services/activity.py`) feed new nullable columns on `accounts_normalized` (migration 0012). Collectors populate the new `NormalizedAccount` fields; `scan_service` persists them; an APScheduler nightly job recomputes `activity_status`; the API gains filters and a `/exports/housekeeping/csv` endpoint that applies the governance risk matrix.

**Tech Stack:** FastAPI, SQLAlchemy 2.0, Alembic, Pydantic v2, paramiko/pymssql/oracledb collectors, pytest (SQLite in-memory via `Base.metadata.create_all` — no Postgres needed for tests).

**Out of scope (separate plans):** security hardening (rate limit, lockout DoS, JWT revocation — tracked in `Fable5_review.md`), Active Directory collector, HR/PAM integrations, frontend changes (new API fields are additive and backward-compatible).

**Review findings addressed:** G-01 (synthetic Linux last-login), G-02 (Oracle discards `LAST_LOGIN`), G-03 (MSSQL invalid `last_login_date` column), G-04 (mock-mode provenance), §4.3 (missing password-age fields and `expired` status), §4.5 (single hardcoded 90-day threshold, `None`-equals-dormant conflation, no housekeeping report).

---

## File Structure

| File | Action | Responsibility |
|---|---|---|
| `backend/app/models/enums.py` | Modify | Add `ActivityStatus` enum; add `EnabledStatus.expired` |
| `backend/app/models/account.py` | Modify | 7 new columns on `Account` |
| `backend/alembic/versions/0012_activity_password_age.py` | Create | DDL for new columns + enum values |
| `backend/app/collectors/base.py` | Modify | 5 new `NormalizedAccount` fields |
| `backend/app/services/scan_service.py` | Modify | Persist new fields + provenance + activity status |
| `backend/app/schemas/account.py` | Modify | Expose new fields on `AccountOut` |
| `backend/app/config.py` | Modify | `inactivity_warn_days`, `inactivity_critical_days` |
| `backend/app/services/activity.py` | Create | Pure activity tiering + risk matrix + nightly recompute |
| `backend/app/collectors/_unix_parsers.py` | Create | Pure lastlog + shadow parsers (no I/O) |
| `backend/app/collectors/rhel.py` | Modify | Real lastlog/shadow evidence in live path |
| `backend/app/collectors/_linux_ssh.py` | Modify | Same fix — covers CentOS, Ubuntu, SLES |
| `backend/app/collectors/oracle_db.py` | Modify | Use real `LAST_LOGIN`; status + profile expiry mapping |
| `backend/app/collectors/mssql.py` | Modify | Fix invalid column; `LOGINPROPERTY` + `dm_exec_sessions` |
| `backend/app/collectors/windows.py` | Modify | Wire `PasswordLastSet`; `never_logged_in` |
| `backend/app/main.py` | Modify | Refuse `COLLECTOR_MODE=mock` in staging/prod |
| `backend/app/services/scheduler.py` | Modify | Nightly activity recompute job |
| `backend/app/api/v1/accounts.py` | Modify | `activity_status` + `inactive_days` filters |
| `backend/app/api/v1/exports.py` | Modify | Hostname columns + housekeeping CSV endpoint |
| `backend/tests/test_unix_parsers.py` | Create | Parser unit tests |
| `backend/tests/test_activity.py` | Create | Activity engine + risk matrix tests |
| `backend/tests/test_api.py` | Modify | Housekeeping export API test |

**Baseline before starting:** run `cd backend && python -m pytest tests/ -q` and record any pre-existing failures. Only failures you introduce are yours to fix.

---

### Task 1: Foundation — enums, model columns, migration

**Files:**
- Modify: `backend/app/models/enums.py`
- Modify: `backend/app/models/account.py`
- Create: `backend/alembic/versions/0012_activity_password_age.py`

- [ ] **Step 1: Add `ActivityStatus` and `EnabledStatus.expired` to enums**

In `backend/app/models/enums.py`, change `EnabledStatus` (currently lines 58-62) to:

```python
class EnabledStatus(str, enum.Enum):
    enabled = "enabled"
    disabled = "disabled"
    locked = "locked"
    expired = "expired"
    unknown = "unknown"
```

Immediately after the `EnabledStatus` class, add:

```python
class ActivityStatus(str, enum.Enum):
    """Inactivity tier computed from last-login evidence.

    'no_evidence' (collection could not determine logins) is deliberately
    distinct from 'never_logged_in' (positive evidence of zero logins).
    """
    active = "active"
    inactive_30d = "inactive_30d"      # last login older than warn threshold
    inactive_90d = "inactive_90d"      # last login older than critical threshold
    never_logged_in = "never_logged_in"
    no_evidence = "no_evidence"
```

- [ ] **Step 2: Add columns to the `Account` model**

In `backend/app/models/account.py`, add `ActivityStatus` to the existing `from app.models.enums import (...)` block, and insert after the `password_never_expires` column (line 117):

```python
    # ── Password / account aging evidence (review §4.3) ───────────────────────
    password_last_changed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    password_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    account_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    platform_created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # True = positive evidence of zero logins; None = no evidence either way.
    never_logged_in: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    # 'mock' | 'live' — provenance stamp (review G-04).
    collection_mode: Mapped[str | None] = mapped_column(String(8), nullable=True)
    activity_status: Mapped[ActivityStatus] = mapped_column(
        PgEnum(ActivityStatus, name="activity_status_enum", create_type=False),
        nullable=False,
        default=ActivityStatus.no_evidence,
        index=True,
    )
```

- [ ] **Step 3: Create migration 0012**

First open `backend/alembic/versions/0011_scan_profile_target_scope.py` and copy its `revision` value — use it as `down_revision` below (do not guess; the id string may not literally be `"0011"`).

Create `backend/alembic/versions/0012_activity_password_age.py`:

```python
"""Activity status, password aging, and collection provenance.

Revision ID: 0012
Revises: <revision value copied from 0011_scan_profile_target_scope.py>
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0012"
down_revision = "<revision value copied from 0011>"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # PG 12+ permits ADD VALUE inside a transaction as long as the new value
    # is not used within the same migration.
    op.execute("ALTER TYPE enabled_status_enum ADD VALUE IF NOT EXISTS 'expired'")
    op.execute(
        "CREATE TYPE activity_status_enum AS ENUM "
        "('active','inactive_30d','inactive_90d','never_logged_in','no_evidence')"
    )
    op.add_column("accounts_normalized", sa.Column("password_last_changed", sa.DateTime(timezone=True), nullable=True))
    op.add_column("accounts_normalized", sa.Column("password_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("accounts_normalized", sa.Column("account_expires_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("accounts_normalized", sa.Column("platform_created_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("accounts_normalized", sa.Column("never_logged_in", sa.Boolean(), nullable=True))
    op.add_column("accounts_normalized", sa.Column("collection_mode", sa.String(8), nullable=True))
    op.add_column(
        "accounts_normalized",
        sa.Column(
            "activity_status",
            postgresql.ENUM(name="activity_status_enum", create_type=False),
            nullable=False,
            server_default="no_evidence",
        ),
    )
    op.create_index("ix_accounts_normalized_activity_status", "accounts_normalized", ["activity_status"])


def downgrade() -> None:
    op.drop_index("ix_accounts_normalized_activity_status", table_name="accounts_normalized")
    for col in (
        "activity_status", "collection_mode", "never_logged_in", "platform_created_at",
        "account_expires_at", "password_expires_at", "password_last_changed",
    ):
        op.drop_column("accounts_normalized", col)
    op.execute("DROP TYPE activity_status_enum")
    # The 'expired' value stays on enabled_status_enum — Postgres cannot drop enum values.
```

- [ ] **Step 4: Run the test suite (models must still load; SQLite tests use `create_all`, not alembic)**

Run: `cd backend && python -m pytest tests/ -q`
Expected: same pass/fail count as baseline (no new failures).

- [ ] **Step 5: Commit**

```bash
git add backend/app/models/enums.py backend/app/models/account.py backend/alembic/versions/0012_activity_password_age.py
git commit -m "feat: add activity status, password aging, and provenance columns

Co-Authored-By: RuFlo <ruv@ruv.net>"
```

---

### Task 2: Plumbing — NormalizedAccount fields, persistence, API schema

**Files:**
- Modify: `backend/app/collectors/base.py:85-98`
- Modify: `backend/app/services/scan_service.py` (anchor: `acc.last_login = na.last_login`, ~line 390)
- Modify: `backend/app/schemas/account.py` (class `AccountOut`, ~line 32)

- [ ] **Step 1: Extend `NormalizedAccount`**

In `backend/app/collectors/base.py`, after `password_never_expires: bool = False` (line 95), add:

```python
    password_last_changed: datetime | None = None
    password_expires_at: datetime | None = None
    account_expires_at: datetime | None = None
    platform_created_at: datetime | None = None
    never_logged_in: bool | None = None   # True = positive "never" evidence
```

- [ ] **Step 2: Persist the new fields**

In `backend/app/services/scan_service.py`, find this existing block (~lines 388-393):

```python
        acc.enabled_status = na.enabled_status
        ...
        acc.last_login = na.last_login
        acc.last_login_source = na.last_login_source
        ...
        acc.password_never_expires = na.password_never_expires
```

Immediately after `acc.password_never_expires = na.password_never_expires`, add:

```python
        acc.password_last_changed = na.password_last_changed
        acc.password_expires_at = na.password_expires_at
        acc.account_expires_at = na.account_expires_at
        acc.platform_created_at = na.platform_created_at
        acc.never_logged_in = na.never_logged_in
        acc.collection_mode = get_settings().collector_mode
```

`get_settings` is already imported in this module (it gates mock mode at lines 62 and 130).

- [ ] **Step 3: Expose fields on `AccountOut`**

In `backend/app/schemas/account.py`, add `ActivityStatus` to the enums import, and after `password_never_expires: bool` add:

```python
    password_last_changed: datetime | None = None
    password_expires_at: datetime | None = None
    account_expires_at: datetime | None = None
    platform_created_at: datetime | None = None
    never_logged_in: bool | None = None
    activity_status: ActivityStatus = ActivityStatus.no_evidence
    collection_mode: str | None = None
```

- [ ] **Step 4: Run tests**

Run: `cd backend && python -m pytest tests/ -q`
Expected: no new failures.

- [ ] **Step 5: Commit**

```bash
git add backend/app/collectors/base.py backend/app/services/scan_service.py backend/app/schemas/account.py
git commit -m "feat: plumb password-aging and provenance fields through persistence and API

Co-Authored-By: RuFlo <ruv@ruv.net>"
```

---

### Task 3: Activity engine (TDD)

**Files:**
- Create: `backend/tests/test_activity.py`
- Create: `backend/app/services/activity.py`
- Modify: `backend/app/config.py` (after `rate_limit_login_per_min`, line 21)

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_activity.py`:

```python
"""Unit tests for the activity tiering engine and housekeeping risk matrix."""
from datetime import UTC, datetime, timedelta

from app.models.enums import ActivityStatus, PrivilegeClass
from app.services.activity import compute_activity_status, housekeeping_risk

NOW = datetime(2026, 6, 10, tzinfo=UTC)


def _login(days_ago: int) -> datetime:
    return NOW - timedelta(days=days_ago)


def test_active_within_warn_window():
    s = compute_activity_status(_login(10), False, now=NOW, warn_days=30, critical_days=90)
    assert s == ActivityStatus.active


def test_inactive_30d_tier():
    s = compute_activity_status(_login(45), False, now=NOW, warn_days=30, critical_days=90)
    assert s == ActivityStatus.inactive_30d


def test_inactive_90d_tier():
    s = compute_activity_status(_login(120), False, now=NOW, warn_days=30, critical_days=90)
    assert s == ActivityStatus.inactive_90d


def test_never_logged_in_beats_no_evidence():
    s = compute_activity_status(None, True, now=NOW, warn_days=30, critical_days=90)
    assert s == ActivityStatus.never_logged_in


def test_no_evidence_when_login_unknown():
    s = compute_activity_status(None, None, now=NOW, warn_days=30, critical_days=90)
    assert s == ActivityStatus.no_evidence


def test_risk_matrix_privileged_90d_critical():
    rating, action = housekeeping_risk(ActivityStatus.inactive_90d, PrivilegeClass.full_admin)
    assert rating == "critical"


def test_risk_matrix_nonprivileged_90d_high():
    rating, _ = housekeeping_risk(ActivityStatus.inactive_90d, PrivilegeClass.non_privileged)
    assert rating == "high"


def test_risk_matrix_privileged_30d_high():
    rating, _ = housekeeping_risk(ActivityStatus.inactive_30d, PrivilegeClass.admin_equivalent)
    assert rating == "high"


def test_risk_matrix_nonprivileged_30d_medium():
    rating, _ = housekeeping_risk(ActivityStatus.inactive_30d, PrivilegeClass.non_privileged)
    assert rating == "medium"


def test_risk_matrix_no_evidence_review_required():
    rating, _ = housekeeping_risk(ActivityStatus.no_evidence, PrivilegeClass.non_privileged)
    assert rating == "review_required"


def test_risk_matrix_never_logged_in_by_privilege():
    high, _ = housekeeping_risk(ActivityStatus.never_logged_in, PrivilegeClass.full_admin)
    med, _ = housekeeping_risk(ActivityStatus.never_logged_in, PrivilegeClass.non_privileged)
    assert (high, med) == ("high", "medium")
```

- [ ] **Step 2: Run to verify failure**

Run: `cd backend && python -m pytest tests/test_activity.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.services.activity'`

- [ ] **Step 3: Add threshold settings**

In `backend/app/config.py`, after `rate_limit_login_per_min` (line 21), add:

```python
    # Inactivity tiering thresholds (days). Governance defaults: 30 warn / 90 critical.
    inactivity_warn_days: int = Field(default=30, alias="INACTIVITY_WARN_DAYS")
    inactivity_critical_days: int = Field(default=90, alias="INACTIVITY_CRITICAL_DAYS")
```

- [ ] **Step 4: Implement the engine**

Create `backend/app/services/activity.py`:

```python
"""Account activity tiering, housekeeping risk matrix, and nightly recompute.

Pure functions — `compute_activity_status` and `housekeeping_risk` take all
inputs as arguments so they are unit-testable without a database or settings.
"""
from __future__ import annotations

from datetime import UTC, datetime

from app.config import get_settings
from app.models.enums import ActivityStatus, PrivilegeClass

PRIVILEGED_CLASSES = {
    PrivilegeClass.full_admin,
    PrivilegeClass.admin_equivalent,
    PrivilegeClass.operator_high_impact,
    PrivilegeClass.delegated_admin,
    PrivilegeClass.privileged_service,
    PrivilegeClass.dormant_privileged,
}


def compute_activity_status(
    last_login: datetime | None,
    never_logged_in: bool | None,
    *,
    now: datetime | None = None,
    warn_days: int | None = None,
    critical_days: int | None = None,
) -> ActivityStatus:
    """Tier an account's activity. 'no evidence' is distinct from 'never logged in'."""
    settings = get_settings()
    warn = warn_days if warn_days is not None else settings.inactivity_warn_days
    critical = critical_days if critical_days is not None else settings.inactivity_critical_days
    now = now or datetime.now(UTC)

    if never_logged_in:
        return ActivityStatus.never_logged_in
    if last_login is None:
        return ActivityStatus.no_evidence
    age_days = (now - last_login).days
    if age_days > critical:
        return ActivityStatus.inactive_90d
    if age_days > warn:
        return ActivityStatus.inactive_30d
    return ActivityStatus.active


def housekeeping_risk(
    activity: ActivityStatus, privilege: PrivilegeClass
) -> tuple[str, str]:
    """Governance risk matrix → (risk_rating, recommended_action).

    >30d: Medium / housekeeping. >90d: High / disable-or-delete review.
    Privileged >30d: High / immediate review. Privileged >90d: Critical.
    No evidence: review required. Never logged in: Medium/High by privilege.
    """
    privileged = privilege in PRIVILEGED_CLASSES
    if activity == ActivityStatus.inactive_90d:
        if privileged:
            return "critical", "Disable, remove privilege, or PAM review required"
        return "high", "Disable or delete review required"
    if activity == ActivityStatus.inactive_30d:
        if privileged:
            return "high", "Immediate review required"
        return "medium", "Housekeeping required"
    if activity == ActivityStatus.never_logged_in:
        if privileged:
            return "high", "Validate provisioning; likely removable"
        return "medium", "Aging-based cleanup candidate"
    if activity == ActivityStatus.no_evidence:
        return "review_required", "Evidence incomplete — verify collection source"
    return "low", "No action"


def recompute_all_activity(db) -> int:
    """Recompute activity_status for every account. Returns count changed."""
    from app.models.account import Account

    changed = 0
    for acc in db.query(Account).yield_per(500):
        new_status = compute_activity_status(acc.last_login, acc.never_logged_in)
        if acc.activity_status != new_status:
            acc.activity_status = new_status
            changed += 1
    db.commit()
    return changed
```

- [ ] **Step 5: Run to verify pass**

Run: `cd backend && python -m pytest tests/test_activity.py -q`
Expected: 11 passed.

- [ ] **Step 6: Commit**

```bash
git add backend/tests/test_activity.py backend/app/services/activity.py backend/app/config.py
git commit -m "feat: configurable 30/90-day activity tiering engine with risk matrix

Co-Authored-By: RuFlo <ruv@ruv.net>"
```

---

### Task 4: Unix evidence parsers (TDD)

**Files:**
- Create: `backend/tests/test_unix_parsers.py`
- Create: `backend/app/collectors/_unix_parsers.py`

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_unix_parsers.py`:

```python
"""Unit tests for pure lastlog / shadow parsers."""
from datetime import UTC, datetime

from app.collectors._unix_parsers import (
    parse_lastlog,
    parse_lastlog_line,
    parse_shadow_line,
    shadow_days_to_datetime,
)


def test_lastlog_line_with_timezone():
    user, dt, never = parse_lastlog_line(
        "jdoe   pts/0   10.0.12.5   Wed Apr 22 16:11:08 +0000 2026"
    )
    assert user == "jdoe"
    assert never is False
    assert dt == datetime(2026, 4, 22, 16, 11, 8, tzinfo=UTC)


def test_lastlog_line_without_timezone_assumes_utc():
    user, dt, never = parse_lastlog_line("jdoe pts/0 10.0.12.5 Wed Apr 22 16:11:08 2026")
    assert dt == datetime(2026, 4, 22, 16, 11, 8, tzinfo=UTC)


def test_lastlog_never_logged_in():
    user, dt, never = parse_lastlog_line("tomcat                     **Never logged in**")
    assert (user, dt, never) == ("tomcat", None, True)


def test_lastlog_header_skipped():
    user, _, _ = parse_lastlog_line("Username         Port     From             Latest")
    assert user is None


def test_lastlog_full_output():
    text = (
        "Username         Port     From             Latest\n"
        "root                                       **Never logged in**\n"
        "jdoe             pts/0    10.0.12.5        Wed Apr 22 16:11:08 +0000 2026\n"
    )
    result = parse_lastlog(text)
    assert result["root"] == (None, True)
    assert result["jdoe"][0].year == 2026


def test_shadow_days_to_datetime():
    # 1970-01-01 + 20000 days = 2024-10-04
    assert shadow_days_to_datetime("20000") == datetime(2024, 10, 4, tzinfo=UTC)
    assert shadow_days_to_datetime("") is None
    assert shadow_days_to_datetime("0") is None
    assert shadow_days_to_datetime("-1") is None
    assert shadow_days_to_datetime("garbage") is None


def test_shadow_locked_account():
    e = parse_shadow_line("svc1:!$6$abc$hash:20000:90::")
    assert e.password_status == "locked"
    assert e.password_last_changed == datetime(2024, 10, 4, tzinfo=UTC)
    assert e.max_days == 90
    assert e.never_expires is False


def test_shadow_disabled_variants():
    assert parse_shadow_line("daemon:*:20000:::").password_status == "disabled"
    assert parse_shadow_line("newuser:!!:20000:::").password_status == "disabled"


def test_shadow_active_never_expires():
    e = parse_shadow_line("oracle:$6$abc$hash:20000:99999::")
    assert e.password_status == "active"
    assert e.never_expires is True
    assert e.max_days is None


def test_shadow_account_expiry():
    e = parse_shadow_line("temp:$6$abc$hash:20000:90:20100")
    assert e.account_expires_at == shadow_days_to_datetime("20100")


def test_shadow_malformed_line_returns_none():
    assert parse_shadow_line("garbage-no-colons") is None
```

- [ ] **Step 2: Run to verify failure**

Run: `cd backend && python -m pytest tests/test_unix_parsers.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'app.collectors._unix_parsers'`

- [ ] **Step 3: Implement the parsers**

Create `backend/app/collectors/_unix_parsers.py`:

```python
"""Pure parsers for Unix login/aging evidence (lastlog, /etc/shadow).

No I/O and no SSH — fully unit-testable. Collectors feed raw command output
in and copy structured evidence out.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)

# glibc lastlog with timezone: "Wed Apr 22 16:11:08 +0000 2026" (6 tokens)
_LASTLOG_FMT_TZ = "%a %b %d %H:%M:%S %z %Y"
# busybox/older variants without timezone: "Wed Apr 22 16:11:08 2026" (5 tokens)
_LASTLOG_FMT_NOTZ = "%a %b %d %H:%M:%S %Y"


def parse_lastlog_line(line: str) -> tuple[str | None, datetime | None, bool]:
    """Parse one `lastlog` output line → (username, last_login, never_logged_in).

    Returns (None, None, False) for the header, blank, or unparseable lines.
    Timestamps without a timezone are assumed UTC (last_login_source records
    the command so reviewers can trace precision).
    """
    if not line.strip() or line.startswith("Username"):
        return None, None, False
    parts = line.split()
    username = parts[0]
    if "Never logged in" in line:
        return username, None, True
    for n_tokens, fmt in ((6, _LASTLOG_FMT_TZ), (5, _LASTLOG_FMT_NOTZ)):
        if len(parts) >= n_tokens + 1:  # +1 for the username column
            candidate = " ".join(parts[-n_tokens:])
            try:
                dt = datetime.strptime(candidate, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                return username, dt, False
            except ValueError:
                continue
    return username, None, False


def parse_lastlog(text: str) -> dict[str, tuple[datetime | None, bool]]:
    """Parse full `lastlog` output → {username: (last_login, never_logged_in)}."""
    result: dict[str, tuple[datetime | None, bool]] = {}
    for line in text.splitlines():
        username, dt, never = parse_lastlog_line(line)
        if username:
            result[username] = (dt, never)
    return result


def shadow_days_to_datetime(days_str: str) -> datetime | None:
    """Convert a shadow days-since-epoch field to an aware datetime (UTC)."""
    s = (days_str or "").strip()
    if not s or s.startswith("-"):
        return None
    try:
        days = int(s)
    except ValueError:
        return None
    if days <= 0:
        return None
    return _EPOCH + timedelta(days=days)


@dataclass
class ShadowEntry:
    user: str
    password_status: str                 # active | locked | disabled
    password_last_changed: datetime | None
    never_expires: bool
    max_days: int | None
    account_expires_at: datetime | None


def parse_shadow_line(line: str) -> ShadowEntry | None:
    """Parse one colon-separated shadow line: user:pw:lastchg:max:expire.

    Expects output of: awk -F: 'BEGIN{OFS=":"}{print $1,$2,$3,$5,$8}' /etc/shadow
    (colon-joined so empty fields survive — space-joined awk output collapses them).

    Status semantics:
      '!<hash>'        → locked   (passwd -l / usermod -L prefix on a real hash)
      '*', '!', '!!',  → disabled (no usable password — service accounts /
      ''                            never-set passwords)
      anything else    → active
    """
    parts = line.split(":")
    if len(parts) < 2:
        return None
    user, pw = parts[0], parts[1]
    if pw.startswith("!") and pw not in ("!", "!!"):
        status = "locked"
    elif pw in ("*", "!", "!!", ""):
        status = "disabled"
    else:
        status = "active"

    last_changed = shadow_days_to_datetime(parts[2]) if len(parts) > 2 else None

    max_days: int | None = None
    never_expires = False
    if len(parts) > 3:
        raw = parts[3].strip()
        # 99999, 0, empty, or negative are the conventional "never expires" encodings.
        if raw in ("", "0", "99999") or raw.startswith("-"):
            never_expires = True
        else:
            try:
                max_days = int(raw)
            except ValueError:
                pass

    expires = shadow_days_to_datetime(parts[4]) if len(parts) > 4 else None
    return ShadowEntry(user, status, last_changed, never_expires, max_days, expires)
```

- [ ] **Step 4: Run to verify pass**

Run: `cd backend && python -m pytest tests/test_unix_parsers.py -q`
Expected: 11 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/tests/test_unix_parsers.py backend/app/collectors/_unix_parsers.py
git commit -m "feat: pure lastlog and shadow parsers for real Unix login evidence

Co-Authored-By: RuFlo <ruv@ruv.net>"
```

---

### Task 5: RHEL live collector — real evidence (fixes G-01 for RHEL)

**Files:**
- Modify: `backend/app/collectors/rhel.py` (live path lines 235-394; mock lines 197-228)

- [ ] **Step 1: Collect 5 shadow fields, colon-separated**

In `collect_live`, replace (line 255):

```python
            shadow_raw = ssh.run("awk -F: '{print $1,$2,$5}' /etc/shadow 2>/dev/null || true").splitlines()
```

with:

```python
            # Fields: 1 user, 2 pw, 3 lastchg, 5 max, 8 expire. Colon-joined so
            # empty fields survive (space-joined awk output collapses them).
            shadow_raw = ssh.run(
                "awk -F: 'BEGIN{OFS=\":\"}{print $1,$2,$3,$5,$8}' /etc/shadow 2>/dev/null || true"
            ).splitlines()
```

- [ ] **Step 2: Replace the shadow/lastlog parsing blocks**

Replace the whole block from `shadow_status: dict[str, str] = {}` (line 279) through the end of the `lastlog_map` loop (line 309) with:

```python
        from app.collectors._unix_parsers import ShadowEntry, parse_lastlog, parse_shadow_line

        shadow_entries: dict[str, ShadowEntry] = {}
        for line in shadow_raw:
            entry = parse_shadow_line(line)
            if entry:
                shadow_entries[entry.user] = entry

        sudoers_parsed: dict[str, list[str]] = {
            "/etc/sudoers": [l for l in sudoers_main.splitlines() if l.strip() and not l.startswith("#")]
        }
        sudoers_parsed.update(sudoers_d)

        lastlog_map = parse_lastlog(lastlog_text)
```

Update the `probes_out` entries so evidence remains JSON-serialisable:

```python
        probes_out = [
            probe("getent_passwd", "getent passwd", passwd_raw),
            probe("getent_group", "getent group", group_raw),
            probe(
                "shadow_status",
                "awk -F: 'BEGIN{OFS=\":\"}{print $1,$2,$3,$5,$8}' /etc/shadow",
                {u: e.password_status for u, e in shadow_entries.items()},
            ),
            probe("sudoers", "cat /etc/sudoers + sudoers.d", sudoers_parsed),
            probe(
                "lastlog", "lastlog",
                {u: (dt.isoformat() if dt else ("never" if never else "unknown"))
                 for u, (dt, never) in lastlog_map.items()},
            ),
        ]
```

- [ ] **Step 3: Use real evidence in account assembly**

In the live per-account loop, replace the status/last-login logic (lines 327, 358-373) so it reads:

```python
            from datetime import UTC as _UTC, datetime as _dt, timedelta as _td

            entry = shadow_entries.get(name)
            if entry is None:
                enabled = EnabledStatus.unknown
            elif entry.password_status == "locked":
                enabled = EnabledStatus.locked
            elif entry.password_status == "disabled":
                enabled = EnabledStatus.disabled
            elif entry.account_expires_at and entry.account_expires_at < _dt.now(_UTC):
                enabled = EnabledStatus.expired
            else:
                enabled = EnabledStatus.enabled
```

(keep the existing `interactive` shell check), and where the account is appended:

```python
            last_login, never_logged = lastlog_map.get(name, (None, False)) if lastlog_map else (None, None)
            pwd_changed = entry.password_last_changed if entry else None
            pwd_expires = (
                pwd_changed + _td(days=entry.max_days)
                if entry and pwd_changed and entry.max_days and not entry.never_expires
                else None
            )
            accounts.append(NormalizedAccount(
                account_name=name, source_type="linux_local", principal_type=principal_type,
                auth_source=AuthSource.local, enabled_status=enabled, interactive_status=interactive,
                last_login=last_login, last_login_source="lastlog",
                never_logged_in=never_logged,
                password_last_changed=pwd_changed,
                password_expires_at=pwd_expires,
                account_expires_at=entry.account_expires_at if entry else None,
                is_shared=False,
                password_never_expires=entry.never_expires if entry else False,
                evidence_summary={
                    "uid": uid_i, "gid": gid_i, "shell": shell, "home": home,
                    "shadow_status": entry.password_status if entry else "unknown",
                    "shadow_max_days_never_expires": entry.never_expires if entry else None,
                    "sudo_broad": sudo_broad,
                },
                entitlements=ents,
            ))
```

Delete the old fabrication lines entirely (the `from app.collectors._mockutil import last_login_days_ago` inside `collect_live` and the `last_login_days_ago(seed=...)` call). The `shadow_never_expires` dict and old `lastlog_map` text logic are now dead — remove them.

- [ ] **Step 4: Flag never-logged-in in the mock path too**

In `collect_mock` (lines 197-204), replace the last-login block with:

```python
            last_text = lastlog_raw.get(name, "")
            never_logged = "Never" in last_text
            last_login = (
                last_login_days_ago(seed=f"{host}:{name}", min_days=1, max_days=400)
                if last_text and not never_logged
                else None
            )
```

and pass `never_logged_in=never_logged,` in the mock `NormalizedAccount(...)` call.

- [ ] **Step 5: Verify no fabrication remains in any live path for this file**

Run: `grep -n "last_login_days_ago" backend/app/collectors/rhel.py`
Expected: exactly one hit, inside `collect_mock`.

Run: `cd backend && python -m pytest tests/ -q`
Expected: no new failures.

- [ ] **Step 6: Commit**

```bash
git add backend/app/collectors/rhel.py
git commit -m "fix: RHEL live scan parses real lastlog/shadow evidence (G-01)

Co-Authored-By: RuFlo <ruv@ruv.net>"
```

---

### Task 6: Shared Linux SSH collector — same fix (covers CentOS, Ubuntu, SLES)

**Files:**
- Modify: `backend/app/collectors/_linux_ssh.py` (shadow command line 61, parse blocks 93-136, account assembly 215-240)

- [ ] **Step 1: Collect 5 shadow fields, colon-separated**

In `collect_live`, replace the shadow command (line 61):

```python
            shadow_raw = ssh.run(
                "awk -F: '{print $1,$2,$5}' /etc/shadow 2>/dev/null || true"
            ).splitlines()
```

with:

```python
            # Fields: 1 user, 2 pw, 3 lastchg, 5 max, 8 expire. Colon-joined so
            # empty fields survive (space-joined awk output collapses them).
            shadow_raw = ssh.run(
                "awk -F: 'BEGIN{OFS=\":\"}{print $1,$2,$3,$5,$8}' /etc/shadow 2>/dev/null || true"
            ).splitlines()
```

- [ ] **Step 2: Replace the shadow and lastlog parse blocks**

Replace the shadow-parse block (lines 93-115, from `shadow_status: dict[str, str] = {}` through the `shadow_never_expires[user] = False` else-branch) and the lastlog block (lines 126-136) with:

```python
        from app.collectors._unix_parsers import ShadowEntry, parse_lastlog, parse_shadow_line

        shadow_entries: dict[str, ShadowEntry] = {}
        for line in shadow_raw:
            entry = parse_shadow_line(line)
            if entry:
                shadow_entries[entry.user] = entry

        lastlog_map = parse_lastlog(lastlog_text)
```

(keep the existing sudoers-parse block between them unchanged). Update this file's `probes_out` shadow/lastlog entries the same way as Task 5:

```python
            probe(
                "shadow_status",
                "awk -F: 'BEGIN{OFS=\":\"}{print $1,$2,$3,$5,$8}' /etc/shadow",
                {u: e.password_status for u, e in shadow_entries.items()},
            ),
            probe(
                "lastlog", "lastlog",
                {u: (dt.isoformat() if dt else ("never" if never else "unknown"))
                 for u, (dt, never) in lastlog_map.items()},
            ),
```

- [ ] **Step 3: Use real evidence in account assembly**

In the per-account loop, replace the `enabled` derivation and the fabricated last-login block (lines 215-219) plus the `NormalizedAccount(...)` call (lines 220-240) with:

```python
            from datetime import UTC as _UTC, datetime as _dt, timedelta as _td

            entry = shadow_entries.get(name)
            if entry is None:
                enabled = EnabledStatus.unknown
            elif entry.password_status == "locked":
                enabled = EnabledStatus.locked
            elif entry.password_status == "disabled":
                enabled = EnabledStatus.disabled
            elif entry.account_expires_at and entry.account_expires_at < _dt.now(_UTC):
                enabled = EnabledStatus.expired
            else:
                enabled = EnabledStatus.enabled

            last_login, never_logged = lastlog_map.get(name, (None, False)) if lastlog_map else (None, None)
            pwd_changed = entry.password_last_changed if entry else None
            pwd_expires = (
                pwd_changed + _td(days=entry.max_days)
                if entry and pwd_changed and entry.max_days and not entry.never_expires
                else None
            )
            accounts.append(
                NormalizedAccount(
                    account_name=name,
                    source_type=self._source_type,
                    principal_type=principal_type,
                    auth_source=AuthSource.local,
                    enabled_status=enabled,
                    interactive_status=interactive,
                    last_login=last_login,
                    last_login_source="lastlog",
                    never_logged_in=never_logged,
                    password_last_changed=pwd_changed,
                    password_expires_at=pwd_expires,
                    account_expires_at=entry.account_expires_at if entry else None,
                    is_shared=False,
                    password_never_expires=entry.never_expires if entry else False,
                    evidence_summary={
                        "uid": uid_i, "gid": gid_i, "shell": shell, "home": home,
                        "shadow_status": entry.password_status if entry else "unknown",
                        "shadow_max_days_never_expires": entry.never_expires if entry else None,
                        "sudo_broad": sudo_broad,
                    },
                    entitlements=ents,
                )
            )
```

(keep the existing `interactive` shell check above this block). Delete the now-dead `last_login_days_ago` import and the old `shadow_status` / `shadow_never_expires` / `lastlog_map` text-based dicts.

- [ ] **Step 2: Verify**

Run: `grep -rn "last_login_days_ago" backend/app/collectors/_linux_ssh.py`
Expected: no hits (this file has no mock path).

Run: `cd backend && python -m pytest tests/ -q`
Expected: no new failures.

- [ ] **Step 3: Commit**

```bash
git add backend/app/collectors/_linux_ssh.py
git commit -m "fix: shared Linux live scan parses real lastlog/shadow (CentOS/Ubuntu/SLES)

Co-Authored-By: RuFlo <ruv@ruv.net>"
```

---

### Task 7: Oracle — stop discarding LAST_LOGIN; map real statuses (fixes G-02)

**Files:**
- Modify: `backend/app/collectors/oracle_db.py` (live path lines 181-268)

- [ ] **Step 1: Keep raw datetimes and collect profile lifetimes**

Replace the `dba_users` query block (lines 184-200) with:

```python
            cur.execute("""
                SELECT username, account_status, created, last_login, profile,
                       oracle_maintained, common, expiry_date, lock_date
                FROM dba_users
                ORDER BY username
            """)
            users = []
            for row in cur.fetchall():
                users.append({
                    "username": row[0], "status": row[1],
                    "created": row[2],            # datetime | None (kept raw)
                    "last_login": row[3],         # datetime | None (kept raw)
                    "profile": row[4],
                    "oracle_maintained": row[5],
                    "common": row[6],
                    "expiry_date": row[7],        # password expiry datetime | None
                    "lock_date": row[8],
                })

            # Profile password lifetimes: UNLIMITED = password never expires.
            cur.execute("""
                SELECT profile, limit
                FROM dba_profiles
                WHERE resource_name = 'PASSWORD_LIFE_TIME'
            """)
            profile_lifetime = {row[0]: row[1] for row in cur.fetchall()}
```

- [ ] **Step 2: JSON-safe probe output**

Replace the `probes_out` `dba_users` entry (line 224) with:

```python
            probe("dba_users", "SELECT * FROM dba_users",
                  [{**u, "created": str(u["created"]) if u["created"] else None,
                    "last_login": str(u["last_login"]) if u["last_login"] else None,
                    "expiry_date": str(u["expiry_date"]) if u["expiry_date"] else None,
                    "lock_date": str(u["lock_date"]) if u["lock_date"] else None}
                   for u in users]),
```

- [ ] **Step 3: Map status and aging onto the normalized account**

Replace the status line (232) and the `NormalizedAccount` call (255-266) with:

```python
            raw_status = (u.get("status") or "").upper()
            if "LOCKED" in raw_status:
                enabled = EnabledStatus.locked          # LOCKED, LOCKED(TIMED), EXPIRED & LOCKED
            elif "EXPIRED" in raw_status:
                enabled = EnabledStatus.expired         # EXPIRED, EXPIRED(GRACE)
            elif raw_status == "OPEN":
                enabled = EnabledStatus.enabled
            else:
                enabled = EnabledStatus.unknown
```

```python
            from datetime import UTC as _UTC

            def _aware(dt):
                return dt.replace(tzinfo=_UTC) if dt is not None and dt.tzinfo is None else dt

            lifetime = profile_lifetime.get(u.get("profile"), "")
            accounts.append(NormalizedAccount(
                account_name=name, source_type="oracle_db",
                principal_type=principal_type, auth_source=AuthSource.db_native,
                enabled_status=enabled, interactive_status=InteractiveStatus.non_interactive,
                last_login=_aware(u.get("last_login")),
                last_login_source="DBA_USERS.LAST_LOGIN",
                never_logged_in=(u.get("last_login") is None),
                password_expires_at=_aware(u.get("expiry_date")),
                platform_created_at=_aware(u.get("created")),
                is_shared=False,
                password_never_expires=(str(lifetime).upper() == "UNLIMITED"),
                evidence_summary={
                    "status": u.get("status"), "profile": u.get("profile"),
                    "common": u.get("common"), "oracle_maintained": u.get("oracle_maintained"),
                    "profile_password_life_time": str(lifetime) if lifetime else None,
                },
                entitlements=ents,
            ))
```

Note: `DBA_USERS.LAST_LOGIN` exists from Oracle 12c. On 11g the first query fails — acceptable: the job error surfaces and the asset can be scanned with a reduced query later; do not silently fabricate.
`never_logged_in=True` for NULL `LAST_LOGIN` is correct for 12c+: Oracle populates it on every successful login.

- [ ] **Step 4: Verify**

Run: `grep -n "last_login=None" backend/app/collectors/oracle_db.py`
Expected: no hits in `collect_live` (mock may keep its synthetic values).

Run: `cd backend && python -m pytest tests/ -q`
Expected: no new failures.

- [ ] **Step 5: Commit**

```bash
git add backend/app/collectors/oracle_db.py
git commit -m "fix: Oracle live scan uses real LAST_LOGIN, status, and profile expiry (G-02)

Co-Authored-By: RuFlo <ruv@ruv.net>"
```

---

### Task 8: MSSQL — remove invalid column; honest last-login source (fixes G-03)

**Files:**
- Modify: `backend/app/collectors/mssql.py` (live query lines 179-192, normalization lines 230-280)

- [ ] **Step 1: Fix the principals query**

`sys.server_principals` has **no** `last_login_date` column in any SQL Server version — the current query fails on a real instance. Replace lines 179-192 with:

```python
            # sys.server_principals has NO last-login column. Sources used instead:
            #  - LOGINPROPERTY(name,'PasswordLastSetTime'): SQL logins only (NULL for Windows logins)
            #  - sys.dm_exec_sessions: most recent session login_time — ONLY since the
            #    last instance restart (requires VIEW SERVER STATE). Recorded in
            #    last_login_source so reviewers know the precision window.
            cur.execute(
                "SELECT sp.name, sp.type_desc, sp.is_disabled, sp.default_database_name, "
                "CONVERT(datetime2, LOGINPROPERTY(sp.name, 'PasswordLastSetTime')) AS password_last_set, "
                "s.last_session_login, "
                "COALESCE(sl.is_policy_checked,     1) AS is_policy_checked, "
                "COALESCE(sl.is_expiration_checked, 1) AS is_expiration_checked "
                "FROM sys.server_principals sp "
                "LEFT JOIN sys.sql_logins sl ON sl.principal_id = sp.principal_id "
                "LEFT JOIN (SELECT login_name, MAX(login_time) AS last_session_login "
                "           FROM sys.dm_exec_sessions GROUP BY login_name) s "
                "       ON s.login_name = sp.name "
                "WHERE sp.type IN ('S','U','G') AND sp.name NOT LIKE '##%'"
            )
            logins = list(cur.fetchall())
```

- [ ] **Step 2: Update normalization**

In the per-login loop, replace the `raw_dt = login.get("last_login_date")` block (lines 235-242) with:

```python
            raw_dt = login.get("last_session_login")
            last_login = None
            if raw_dt is not None:
                last_login = raw_dt.replace(tzinfo=_tz.utc) if raw_dt.tzinfo is None else raw_dt

            raw_pls = login.get("password_last_set")
            pwd_last_set = None
            if raw_pls is not None:
                pwd_last_set = raw_pls.replace(tzinfo=_tz.utc) if raw_pls.tzinfo is None else raw_pls
```

and in the `NormalizedAccount(...)` call change:

```python
                    last_login=last_login,
                    last_login_source="sys.dm_exec_sessions (since instance restart)",
                    password_last_changed=pwd_last_set,
                    never_logged_in=None,  # absence of a session is NOT proof of never
```

(`never_logged_in=None` is deliberate: `dm_exec_sessions` only covers the period since restart, so a missing row is *no evidence*, not *never*.)

- [ ] **Step 3: Verify**

Run: `grep -n "last_login_date" backend/app/collectors/mssql.py`
Expected: no hits in `collect_live` (the mock path keeps its own synthetic data).

Run: `cd backend && python -m pytest tests/ -q`
Expected: no new failures.

- [ ] **Step 4: Commit**

```bash
git add backend/app/collectors/mssql.py
git commit -m "fix: MSSQL live scan drops nonexistent column; honest session-based last login (G-03)

Co-Authored-By: RuFlo <ruv@ruv.net>"
```

---

### Task 9: Windows — wire PasswordLastSet and never-logged-in

**Files:**
- Modify: `backend/app/collectors/windows.py` (local-user loop ~lines 1368-1412)

- [ ] **Step 1: Populate the new fields**

Find the local-user normalization block (anchor: `last_logon = _windate(u.get("LastLogon"))`, line 1373). After that statement add:

```python
            pwd_last_set = _windate(u.get("PasswordLastSet"))
            # Get-LocalUser returns LastLogon=$null for accounts that have never
            # logged on to the local SAM — positive "never" evidence in live mode.
            never_logged = (u.get("LastLogon") in (None, "")) if not is_mock else None
```

In the `NormalizedAccount(...)` call for this block (lines ~1396-1412), add:

```python
                password_last_changed=pwd_last_set,
                never_logged_in=never_logged,
```

(`PasswordLastSet` is already selected by the existing Get-LocalUser probe at line 171 — no PowerShell change needed.)

- [ ] **Step 2: Verify**

Run: `cd backend && python -m pytest tests/ -q`
Expected: no new failures.

- [ ] **Step 3: Commit**

```bash
git add backend/app/collectors/windows.py
git commit -m "feat: Windows collector wires PasswordLastSet and never-logged-in evidence

Co-Authored-By: RuFlo <ruv@ruv.net>"
```

---

### Task 10: Refuse mock mode in staging/prod (fixes G-04)

**Files:**
- Modify: `backend/app/main.py` (next to `_enforce_secret_key`, lines 62-70)

- [ ] **Step 1: Add the guard**

In `backend/app/main.py`, directly below the `_enforce_secret_key` function, add:

```python
def _enforce_collector_mode(settings=None) -> None:
    """Mock collectors fabricate accounts — never allow them outside dev (G-04)."""
    s = settings or get_settings()
    if s.env in ("staging", "prod") and s.collector_mode == "mock":
        raise RuntimeError(
            "COLLECTOR_MODE=mock is not permitted when APP_ENV=staging/prod. "
            "Mock mode fabricates discovery data; set COLLECTOR_MODE=live."
        )
```

Call it immediately after the existing `_enforce_secret_key()` call site.

- [ ] **Step 2: Test the guard**

Append to `backend/tests/test_activity.py`:

```python
def test_mock_mode_rejected_in_prod():
    import pytest
    from app.main import _enforce_collector_mode

    class _S:
        env = "prod"
        collector_mode = "mock"

    with pytest.raises(RuntimeError, match="COLLECTOR_MODE=mock"):
        _enforce_collector_mode(_S())


def test_mock_mode_allowed_in_dev():
    from app.main import _enforce_collector_mode

    class _S:
        env = "dev"
        collector_mode = "mock"

    _enforce_collector_mode(_S())  # must not raise
```

- [ ] **Step 3: Run tests**

Run: `cd backend && python -m pytest tests/test_activity.py -q`
Expected: all pass (13 tests now).

- [ ] **Step 4: Commit**

```bash
git add backend/app/main.py backend/tests/test_activity.py
git commit -m "feat: refuse mock collector mode in staging/prod (G-04)

Co-Authored-By: RuFlo <ruv@ruv.net>"
```

---

### Task 11: Compute activity status at persist time + nightly recompute

**Files:**
- Modify: `backend/app/services/scan_service.py` (the block added in Task 2)
- Modify: `backend/app/services/scheduler.py:71-76` (`build_scheduler`)

- [ ] **Step 1: Persist-time computation**

In `backend/app/services/scan_service.py`, after the `acc.collection_mode = ...` line added in Task 2, add:

```python
        from app.services.activity import compute_activity_status
        acc.activity_status = compute_activity_status(na.last_login, na.never_logged_in)
```

(Import placement: move the import to the module's top-level imports if the file style prefers it — it does for app-internal modules.)

- [ ] **Step 2: Nightly recompute job**

In `backend/app/services/scheduler.py`, add below `process_due_schedules`:

```python
def recompute_activity_statuses() -> None:
    """Nightly re-tiering: accounts age into 30/90-day buckets between scans."""
    from app.services.activity import recompute_all_activity

    with SessionLocal() as db:
        recompute_all_activity(db)
```

and in `build_scheduler()` add before `return scheduler`:

```python
    scheduler.add_job(
        recompute_activity_statuses,
        CronTrigger(hour=1, minute=15, timezone=SCHEDULE_TIMEZONE),
        id="activity-status-recompute",
        max_instances=1,
        replace_existing=True,
    )
```

- [ ] **Step 3: Run tests**

Run: `cd backend && python -m pytest tests/ -q`
Expected: no new failures.

- [ ] **Step 4: Commit**

```bash
git add backend/app/services/scan_service.py backend/app/services/scheduler.py
git commit -m "feat: activity status computed at persist and re-tiered nightly

Co-Authored-By: RuFlo <ruv@ruv.net>"
```

---

### Task 12: API filters + housekeeping export

**Files:**
- Modify: `backend/app/api/v1/accounts.py` (list endpoint filters, lines 40-80)
- Modify: `backend/app/api/v1/exports.py`
- Modify: `backend/tests/test_api.py`

- [ ] **Step 1: Write the failing API test**

Append to `backend/tests/test_api.py` (fixtures `client` and `admin_token` already exist in this file):

```python
class TestHousekeepingExport:
    def test_housekeeping_csv_requires_auth(self, client):
        r = client.get("/api/v1/exports/housekeeping/csv")
        assert r.status_code == 401

    def test_housekeeping_csv_returns_csv(self, client, admin_token):
        r = client.get(
            "/api/v1/exports/housekeeping/csv",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        # Header row is always written, even with zero matching accounts.
        assert "risk_rating" in r.text.splitlines()[0]

    def test_accounts_filter_by_activity_status(self, client, admin_token):
        r = client.get(
            "/api/v1/accounts?activity_status=inactive_90d",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
```

- [ ] **Step 2: Run to verify failure**

Run: `cd backend && python -m pytest tests/test_api.py -k Housekeeping -q`
Expected: FAIL — 404 on the housekeeping route (and possibly 422 on the filter).

- [ ] **Step 3: Add account list filters**

In `backend/app/api/v1/accounts.py`, add to the imports:

```python
from datetime import UTC, datetime, timedelta

from app.models.enums import ActivityStatus
```

(merge into existing import lines if present). Add these parameters to the list endpoint signature alongside the existing optional filters:

```python
    activity_status: ActivityStatus | None = None,
    inactive_days: int | None = None,
```

and these filters in the existing filter chain (after the `enabled_status` filter at line 58):

```python
    if activity_status:
        q = q.filter(Account.activity_status == activity_status)
    if inactive_days and inactive_days > 0:
        cutoff = datetime.now(UTC) - timedelta(days=inactive_days)
        q = q.filter(Account.last_login.is_not(None), Account.last_login < cutoff)
```

- [ ] **Step 4: Enrich standard exports and add the housekeeping endpoint**

In `backend/app/api/v1/exports.py`:

a) Add to imports:

```python
from app.models.asset import Asset
from app.models.enums import ActivityStatus, EnabledStatus
from app.services.activity import housekeeping_risk
```

b) In `_accounts_to_rows`, after `"account_name": a.account_name,` add (the `Account.asset` relationship is `lazy="joined"` — no extra queries):

```python
            "hostname": a.asset.hostname if a.asset else "",
            "ip_address": (a.asset.ip_address or "") if a.asset else "",
            "activity_status": a.activity_status.value,
            "password_last_changed": a.password_last_changed.isoformat() if a.password_last_changed else "",
            "never_logged_in": a.never_logged_in if a.never_logged_in is not None else "",
            "collection_mode": a.collection_mode or "",
```

c) Add the housekeeping endpoint at the end of the file:

```python
_HOUSEKEEPING_STATUSES = [
    ActivityStatus.inactive_30d,
    ActivityStatus.inactive_90d,
    ActivityStatus.never_logged_in,
    ActivityStatus.no_evidence,
]


@router.get("/housekeeping/csv")
def export_housekeeping_csv(
    limit: int = Query(default=_EXPORT_MAX_ROWS, ge=1, le=_EXPORT_MAX_ROWS),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    p: Principal = Depends(require_roles("admin", "security_analyst", "auditor")),
):
    """Monthly housekeeping report: enabled accounts with stale or missing login evidence.

    Risk ratings follow the governance matrix (30d=medium, 90d=high,
    privileged 30d=high, privileged 90d=critical, no evidence=review required).
    """
    import csv

    accounts = (
        db.query(Account)
        .filter(Account.enabled_status == EnabledStatus.enabled)
        .filter(Account.activity_status.in_(_HOUSEKEEPING_STATUSES))
        .order_by(Account.last_login.asc().nullsfirst())
        .offset(offset)
        .limit(limit)
        .all()
    )

    rows = []
    for a in accounts:
        rating, action = housekeeping_risk(a.activity_status, a.privilege_classification)
        rows.append({
            "hostname": a.asset.hostname if a.asset else "",
            "ip_address": (a.asset.ip_address or "") if a.asset else "",
            "platform": a.platform.value,
            "account_name": a.account_name,
            "principal_type": a.principal_type.value,
            "privilege_classification": a.privilege_classification.value,
            "activity_status": a.activity_status.value,
            "last_login": a.last_login.isoformat() if a.last_login else "",
            "last_login_source": a.last_login_source or "",
            "never_logged_in": a.never_logged_in if a.never_logged_in is not None else "",
            "password_never_expires": a.password_never_expires,
            "password_last_changed": a.password_last_changed.isoformat() if a.password_last_changed else "",
            "owner": a.owner or "",
            "risk_rating": rating,
            "recommended_action": action,
            "collection_mode": a.collection_mode or "",
            "discovered_at": a.discovered_at.isoformat() if a.discovered_at else "",
        })

    buf = io.StringIO()
    fieldnames = list(rows[0].keys()) if rows else [
        "hostname", "ip_address", "platform", "account_name", "principal_type",
        "privilege_classification", "activity_status", "last_login", "last_login_source",
        "never_logged_in", "password_never_expires", "password_last_changed", "owner",
        "risk_rating", "recommended_action", "collection_mode", "discovered_at",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(rows)

    log_action(db, "export.housekeeping.csv", actor_id=p.id, actor_email=p.email,
               context={"count": len(rows)})
    db.commit()

    buf.seek(0)
    filename = f"housekeeping_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
```

- [ ] **Step 5: Run to verify pass**

Run: `cd backend && python -m pytest tests/test_api.py -q`
Expected: all pass, including the 3 new tests.

Run: `cd backend && python -m pytest tests/ -q`
Expected: full suite — no new failures vs baseline.

- [ ] **Step 6: Commit**

```bash
git add backend/app/api/v1/accounts.py backend/app/api/v1/exports.py backend/tests/test_api.py
git commit -m "feat: activity filters and monthly housekeeping CSV export with risk matrix

Co-Authored-By: RuFlo <ruv@ruv.net>"
```

---

## Acceptance Checklist (maps back to review §10 MVP)

- [ ] `grep -rn "last_login_days_ago" backend/app/collectors/` shows hits **only** inside `collect_mock` functions and `_mockutil.py`
- [ ] A live RHEL scan stores real `lastlog` timestamps, `never_logged_in`, `password_last_changed`, and `expired`/`disabled`/`locked` distinctions
- [ ] A live Oracle scan stores `LAST_LOGIN`, profile-derived `password_never_expires`, and EXPIRED/LOCKED statuses
- [ ] A live MSSQL scan executes without invalid-column errors; `last_login_source` discloses the since-restart window
- [ ] Starting the API with `APP_ENV=prod COLLECTOR_MODE=mock` fails fast
- [ ] `GET /api/v1/accounts?activity_status=inactive_90d` and `?inactive_days=90` filter correctly
- [ ] `GET /api/v1/exports/housekeeping/csv` returns the risk-rated report and writes an audit log entry
- [ ] Thresholds adjustable via `INACTIVITY_WARN_DAYS` / `INACTIVITY_CRITICAL_DAYS` without code changes

## Known Limitations (documented, not bugs)

- PostgreSQL and MySQL have no native last-login; their accounts will surface as `no_evidence` (correct per the matrix: "Review Required / Evidence Incomplete"). Log-based ingestion is a Phase 2 item.
- MSSQL last login covers only the period since instance restart; the `last_login_source` string discloses this. Login auditing integration is Phase 2.
- AIX/Solaris/HP-UX live paths currently report `last_login=None` (honest `no_evidence`, no fabrication) — platform-specific parsers (`lsuser ... time_last_login`, Solaris `last`, HP-UX `logins -ax`) are a fast-follow after this plan.
- MySQL exposes `mysql.user.password_last_changed` (5.7+); wiring it into the MySQL collector is a small fast-follow not included in these 12 tasks.
- `sys.dm_exec_sessions` requires VIEW SERVER STATE; add it to the documented least-privilege scan account for MSSQL.
