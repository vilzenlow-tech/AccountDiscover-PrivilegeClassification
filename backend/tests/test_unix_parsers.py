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
