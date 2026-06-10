from __future__ import annotations

from datetime import datetime, timezone

from app.services.scheduler import _next_run


def test_next_run_interprets_cron_in_gmt_plus_8():
    previous = datetime(2030, 1, 1, 18, 0, tzinfo=timezone.utc)

    next_run = _next_run("0 2 * * *", previous=previous)

    assert next_run is not None
    assert next_run.astimezone(timezone.utc) == datetime(2030, 1, 2, 18, 0, tzinfo=timezone.utc)
