"""Unit tests for pure lastlog / shadow parsers."""
from datetime import UTC, datetime

from app.collectors._unix_parsers import (
    merge_login_evidence,
    parse_authlog_last,
    parse_lastlog,
    parse_lastlog_line,
    parse_wtmp_last,
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


def test_wtmp_last_full_output_parses_latest_login():
    text = (
        "root     pts/0        192.168.7.10     Sun Jun 28 22:55:12 2026 - Sun Jun 28 23:01:02 2026  (00:05)\n"
        "root     pts/1        192.168.7.11     Thu Jun 11 18:36:20 2026 - Thu Jun 11 18:40:01 2026  (00:03)\n"
        "wtmp begins Thu Jun 11 17:00:00 2026\n"
    )
    result = parse_wtmp_last(text)
    assert result["root"] == datetime(2026, 6, 28, 22, 55, 12, tzinfo=UTC)


def test_wtmp_evidence_overrides_stale_lastlog():
    lastlog = {"root": (datetime(2026, 6, 11, 18, 36, 20, tzinfo=UTC), False)}
    wtmp = {"root": datetime(2026, 6, 28, 22, 55, 12, tzinfo=UTC)}
    merged = merge_login_evidence(lastlog, wtmp)
    assert merged["root"] == (datetime(2026, 6, 28, 22, 55, 12, tzinfo=UTC), False, "wtmp")


def test_authlog_su_session_counts_as_account_activity():
    text = "Jun 28 22:58:01 rhel su[1234]: pam_unix(su-l:session): session opened for user root(uid=0) by admin(uid=1000)"
    result = parse_authlog_last(text, now=datetime(2026, 6, 28, 15, 0, 0, tzinfo=UTC), tz_offset="+0800")
    assert result["root"] == datetime(2026, 6, 28, 14, 58, 1, tzinfo=UTC)


def test_wtmp_uses_host_timezone_offset_when_available():
    text = "root     pts/0        192.168.7.10     Sun Jun 28 22:55:12 2026 - Sun Jun 28 23:01:02 2026  (00:05)"
    result = parse_wtmp_last(text, tz_offset="+0800")
    assert result["root"] == datetime(2026, 6, 28, 14, 55, 12, tzinfo=UTC)


def test_authlog_evidence_overrides_wtmp_when_newer():
    lastlog = {"root": (datetime(2026, 6, 11, 18, 36, 20, tzinfo=UTC), False)}
    wtmp = {"root": datetime(2026, 6, 11, 18, 36, 20, tzinfo=UTC)}
    authlog = {"root": datetime(2026, 6, 28, 22, 58, 1, tzinfo=UTC)}
    merged = merge_login_evidence(lastlog, wtmp, authlog)
    assert merged["root"] == (datetime(2026, 6, 28, 22, 58, 1, tzinfo=UTC), False, "authlog")


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
