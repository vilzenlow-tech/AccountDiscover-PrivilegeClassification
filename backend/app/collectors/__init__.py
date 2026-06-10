"""Per-platform discovery collectors.

Each collector exposes a `collect(target, credential)` method that returns a
`CollectionResult`. Collectors must be read-only. In `mock` mode, a realistic
fixture is returned; in `live` mode, real connections are opened.
"""
from __future__ import annotations

from app.collectors.aix import AIXCollector
from app.collectors.base import BaseCollector, CollectionResult, ProbeResult, Target
from app.collectors.centos import CentOSCollector
from app.collectors.hpux import HPUXCollector
from app.collectors.mongodb import MongoCollector
from app.collectors.mssql import MSSQLCollector
from app.collectors.mysql import MySQLCollector
from app.collectors.oracle_db import OracleDBCollector
from app.collectors.postgresql import PostgreSQLCollector
from app.collectors.redis_db import RedisCollector
from app.collectors.rhel import RHELCollector
from app.collectors.sles import SLESCollector
from app.collectors.solaris import SolarisCollector
from app.collectors.ubuntu import UbuntuCollector
from app.collectors.windows import WindowsCollector
from app.models.enums import Platform


COLLECTOR_REGISTRY: dict[Platform, type[BaseCollector]] = {
    # Unix / Linux
    Platform.rhel:       RHELCollector,
    Platform.centos:     CentOSCollector,
    Platform.ubuntu:     UbuntuCollector,
    Platform.sles:       SLESCollector,
    Platform.solaris:    SolarisCollector,
    Platform.aix:        AIXCollector,
    Platform.hpux:       HPUXCollector,
    # Windows
    Platform.windows:    WindowsCollector,
    # Databases
    Platform.mysql:      MySQLCollector,
    Platform.mssql:      MSSQLCollector,
    Platform.mongodb:    MongoCollector,
    Platform.oracle_db:  OracleDBCollector,
    Platform.postgresql: PostgreSQLCollector,
    Platform.redis:      RedisCollector,
}


def get_collector(platform: Platform) -> BaseCollector:
    cls = COLLECTOR_REGISTRY.get(platform)
    if cls is None:
        raise ValueError(
            f"No collector registered for platform '{platform.value}'. "
            "Supported: " + ", ".join(p.value for p in COLLECTOR_REGISTRY)
        )
    return cls()


__all__ = [
    "BaseCollector",
    "CollectionResult",
    "ProbeResult",
    "Target",
    "COLLECTOR_REGISTRY",
    "get_collector",
]
