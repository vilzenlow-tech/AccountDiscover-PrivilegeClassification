"""Helpers shared by mock collector implementations."""
from __future__ import annotations

import hashlib
import random
from datetime import UTC, datetime, timedelta

from app.collectors.base import ProbeResult


def _rng(seed: str) -> random.Random:
    h = hashlib.sha256(seed.encode()).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def probe(
    key: str,
    command: str,
    output,
    *,
    exit_code: int = 0,
    duration_ms: int | None = None,
    stderr: str | None = None,
    now: datetime | None = None,
) -> ProbeResult:
    if duration_ms is None:
        duration_ms = 20 + (hash(key) % 200)
    return ProbeResult(
        probe_key=key,
        command=command,
        exit_code=exit_code,
        stderr_excerpt=stderr,
        output=output,
        duration_ms=duration_ms,
        collected_at=now or datetime.now(UTC),
    )


def last_login_days_ago(seed: str, min_days: int = 0, max_days: int = 400) -> datetime | None:
    rng = _rng(seed + ":last_login")
    if rng.random() < 0.15:
        return None
    days = rng.randint(min_days, max_days)
    return datetime.now(UTC) - timedelta(days=days, hours=rng.randint(0, 23))
