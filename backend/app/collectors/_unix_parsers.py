"""Pure parsers for Unix login/aging evidence (lastlog, /etc/shadow).

No I/O and no SSH — fully unit-testable. Collectors feed raw command output
in and copy structured evidence out.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
import re

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_WEEKDAYS = {"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
_SYSLOG_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
_AUTH_PATTERNS = (
    re.compile(r"Accepted \\S+ for (?P<user>\\S+) from "),
    re.compile(r"session opened for user (?P<user>[^\\s(]+)"),
)

# glibc lastlog with timezone: "Wed Apr 22 16:11:08 +0000 2026" (6 tokens)
_LASTLOG_FMT_TZ = "%a %b %d %H:%M:%S %z %Y"
# busybox/older variants without timezone: "Wed Apr 22 16:11:08 2026" (5 tokens)
_LASTLOG_FMT_NOTZ = "%a %b %d %H:%M:%S %Y"


def _tz_from_offset(offset: str | None):
    if not offset:
        return UTC
    match = re.fullmatch(r"([+-])(\d{2})(\d{2})", offset.strip())
    if not match:
        return UTC
    sign = 1 if match.group(1) == "+" else -1
    delta = timedelta(hours=int(match.group(2)), minutes=int(match.group(3)))
    return timezone(sign * delta)


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


def parse_wtmp_last(text: str, *, tz_offset: str | None = None) -> dict[str, datetime]:
    """Parse `last -F -w` output → {username: latest_login}.

    `lastlog` is not always updated by PAM on modern Linux builds.  wtmp is
    often the fresher source for SSH sessions, so collectors use this as a
    second evidence source and keep the newest timestamp.
    """
    result: dict[str, datetime] = {}
    tzinfo = _tz_from_offset(tz_offset)
    for line in text.splitlines():
        parts = line.split()
        if not parts or parts[0] in {"reboot", "shutdown", "wtmp", "btmp"}:
            continue
        username = parts[0]
        start = next((i for i, part in enumerate(parts) if part in _WEEKDAYS), None)
        if start is None or len(parts) < start + 5:
            continue
        candidate = " ".join(parts[start:start + 5])
        try:
            dt = datetime.strptime(candidate, _LASTLOG_FMT_NOTZ).replace(tzinfo=tzinfo).astimezone(UTC)
        except ValueError:
            continue
        current = result.get(username)
        if current is None or dt > current:
            result[username] = dt
    return result


def parse_authlog_last(
    text: str,
    *,
    now: datetime | None = None,
    tz_offset: str | None = None,
) -> dict[str, datetime]:
    """Parse Linux auth log snippets → {username: latest_auth_activity}.

    This catches SSH accepted logins and PAM session-open events such as
    `su - root`, which do not always update `lastlog` or wtmp for the target
    account.
    """
    tzinfo = _tz_from_offset(tz_offset)
    now = (now or datetime.now(UTC)).astimezone(tzinfo)
    result: dict[str, datetime] = {}
    for line in text.splitlines():
        parts = line.split(maxsplit=3)
        if len(parts) < 4 or parts[0] not in _SYSLOG_MONTHS:
            continue
        matched_user = None
        for pattern in _AUTH_PATTERNS:
            match = pattern.search(line)
            if match:
                matched_user = match.group("user")
                break
        if not matched_user:
            continue
        try:
            month = _SYSLOG_MONTHS[parts[0]]
            day = int(parts[1])
            hour, minute, second = (int(value) for value in parts[2].split(":"))
            dt = datetime(now.year, month, day, hour, minute, second, tzinfo=tzinfo)
            if dt > now + timedelta(days=1):
                dt = dt.replace(year=dt.year - 1)
        except (ValueError, TypeError):
            continue
        current = result.get(matched_user)
        dt_utc = dt.astimezone(UTC)
        if current is None or dt_utc > current:
            result[matched_user] = dt_utc
    return result


def merge_login_evidence(
    lastlog: dict[str, tuple[datetime | None, bool]],
    wtmp: dict[str, datetime],
    authlog: dict[str, datetime] | None = None,
) -> dict[str, tuple[datetime | None, bool, str]]:
    """Merge lastlog and wtmp, preferring the newest positive login evidence."""
    authlog = authlog or {}
    users = set(lastlog) | set(wtmp) | set(authlog)
    merged: dict[str, tuple[datetime | None, bool, str]] = {}
    for user in users:
        lastlog_dt, never = lastlog.get(user, (None, None))
        wtmp_dt = wtmp.get(user)
        authlog_dt = authlog.get(user)
        if authlog_dt and (lastlog_dt is None or authlog_dt > lastlog_dt) and (wtmp_dt is None or authlog_dt > wtmp_dt):
            merged[user] = (authlog_dt, False, "authlog")
        elif wtmp_dt and (lastlog_dt is None or wtmp_dt > lastlog_dt):
            merged[user] = (wtmp_dt, False, "wtmp")
        elif lastlog_dt:
            merged[user] = (lastlog_dt, False, "lastlog")
        else:
            merged[user] = (None, bool(never), "lastlog" if never is not None else "unknown")
    return merged


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
