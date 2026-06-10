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
