"""Scan profile CRUD."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db import get_db
from app.models.job import ScanProfile
from app.schemas.common import Page
from app.schemas.scan import ScanProfileIn, ScanProfileOut
from app.security import Principal, get_current_principal, require_roles

router = APIRouter(prefix="/scan-profiles", tags=["scan-profiles"])

_DEFAULTS = [
    # ── Catch-all ─────────────────────────────────────────────────────────────
    {"name": "Full Scan",           "description": "All enabled assets across all platforms",                                           "platforms": [],                                                              "mode": "safe"},
    # ── OS groups ─────────────────────────────────────────────────────────────
    {"name": "OS Scan",             "description": "All operating systems (no databases): Linux, Unix, Windows",                        "platforms": ["rhel","centos","ubuntu","sles","solaris","aix","hpux","windows"], "mode": "safe"},
    {"name": "Unix / Linux Scan",   "description": "All SSH-based Unix/Linux: RHEL, CentOS, Ubuntu, SLES, Solaris, AIX, HP-UX",        "platforms": ["rhel","centos","ubuntu","sles","solaris","aix","hpux"],         "mode": "safe"},
    {"name": "Linux Scan",          "description": "Linux distributions: RHEL, CentOS, Ubuntu, SLES",                                  "platforms": ["rhel","centos","ubuntu","sles"],                                "mode": "safe"},
    {"name": "RHEL / CentOS Scan",  "description": "Red Hat Enterprise Linux and CentOS",                                              "platforms": ["rhel","centos"],                                               "mode": "safe"},
    {"name": "Ubuntu Scan",         "description": "Ubuntu Server",                                                                    "platforms": ["ubuntu"],                                                      "mode": "safe"},
    {"name": "SLES Scan",           "description": "SUSE Linux Enterprise Server",                                                     "platforms": ["sles"],                                                        "mode": "safe"},
    {"name": "Legacy Unix Scan",    "description": "Legacy Unix platforms: Oracle Solaris, IBM AIX, HP-UX",                            "platforms": ["solaris","aix","hpux"],                                        "mode": "safe"},
    {"name": "Windows Scan",        "description": "Windows Server",                                                                   "platforms": ["windows"],                                                     "mode": "safe"},
    # ── DB groups ─────────────────────────────────────────────────────────────
    {"name": "Database Scan",       "description": "All databases: MySQL, MSSQL, MongoDB, Oracle DB, PostgreSQL, Redis",               "platforms": ["mysql","mssql","mongodb","oracle_db","postgresql","redis"],     "mode": "safe"},
    {"name": "Relational DB Scan",  "description": "Relational databases: MySQL, MSSQL, Oracle DB, PostgreSQL",                        "platforms": ["mysql","mssql","oracle_db","postgresql"],                      "mode": "safe"},
    {"name": "NoSQL / Cache Scan",  "description": "NoSQL and in-memory stores: MongoDB, Redis",                                       "platforms": ["mongodb","redis"],                                             "mode": "safe"},
    # ── Individual DB ─────────────────────────────────────────────────────────
    {"name": "MySQL / MariaDB Scan","description": "MySQL and MariaDB database instances",                                             "platforms": ["mysql"],                                                       "mode": "safe"},
    {"name": "MSSQL Scan",          "description": "Microsoft SQL Server instances",                                                   "platforms": ["mssql"],                                                       "mode": "safe"},
    {"name": "MongoDB Scan",        "description": "MongoDB instances",                                                                "platforms": ["mongodb"],                                                     "mode": "safe"},
    {"name": "Oracle DB Scan",      "description": "Oracle Database instances",                                                        "platforms": ["oracle_db"],                                                   "mode": "safe"},
    {"name": "PostgreSQL Scan",     "description": "PostgreSQL database instances",                                                    "platforms": ["postgresql"],                                                  "mode": "safe"},
    {"name": "Redis Scan",          "description": "Redis instances",                                                                  "platforms": ["redis"],                                                       "mode": "safe"},
]


@router.get("", response_model=Page[ScanProfileOut])
def list_profiles(
    limit: int = 50, offset: int = 0,
    db: Session = Depends(get_db),
    _: Principal = Depends(get_current_principal),
):
    q = db.query(ScanProfile)
    total = q.count()
    items = q.order_by(ScanProfile.name).offset(offset).limit(limit).all()
    return Page(items=[ScanProfileOut.model_validate(p) for p in items], total=total, limit=limit, offset=offset)


@router.post("", response_model=ScanProfileOut, status_code=201)
def create_profile(
    body: ScanProfileIn,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("admin", "security_analyst")),
):
    p = ScanProfile(**{k: v for k, v in body.model_dump().items() if k != "platforms"}, platforms=[x.value for x in body.platforms])
    db.add(p)
    db.commit()
    db.refresh(p)
    return ScanProfileOut.model_validate(p)


@router.get("/{profile_id}", response_model=ScanProfileOut)
def get_profile(profile_id: uuid.UUID, db: Session = Depends(get_db), _: Principal = Depends(get_current_principal)):
    row = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not row:
        raise HTTPException(404, "Not found")
    return ScanProfileOut.model_validate(row)


@router.put("/{profile_id}", response_model=ScanProfileOut)
def update_profile(
    profile_id: uuid.UUID,
    body: ScanProfileIn,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("admin", "security_analyst")),
):
    p = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not p:
        raise HTTPException(404, "Profile not found")
    for k, v in body.model_dump().items():
        setattr(p, k, v if k != "platforms" else [x.value for x in body.platforms])
    db.commit()
    db.refresh(p)
    return ScanProfileOut.model_validate(p)


@router.delete("/{profile_id}", status_code=204)
def delete_profile(
    profile_id: uuid.UUID,
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("admin")),
):
    p = db.query(ScanProfile).filter(ScanProfile.id == profile_id).first()
    if not p:
        raise HTTPException(404, "Profile not found")
    db.delete(p)
    db.commit()


@router.post("/seed-defaults", status_code=201)
def seed_defaults(
    db: Session = Depends(get_db),
    _: Principal = Depends(require_roles("admin", "security_analyst")),
):
    created = []
    for d in _DEFAULTS:
        if not db.query(ScanProfile).filter(ScanProfile.name == d["name"]).first():
            from app.models.enums import ScanMode
            p = ScanProfile(
                name=d["name"], description=d["description"],
                platforms=d["platforms"], mode=ScanMode(d["mode"]),
                target_scope={"all_enabled": True},
                timeout_seconds=300, retry_count=1, concurrency_limit=10, throttle_ms=0,
                credential_strategy="asset",
            )
            db.add(p)
            created.append(d["name"])
    db.commit()
    return {"created": created, "message": f"{len(created)} profile(s) created"}
