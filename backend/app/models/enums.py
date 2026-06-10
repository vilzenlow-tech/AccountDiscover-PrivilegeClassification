"""Enumerations used across models."""
from __future__ import annotations

import enum


class Platform(str, enum.Enum):
    # Unix / Linux
    rhel = "rhel"               # Red Hat Enterprise Linux
    centos = "centos"           # CentOS (RHEL-compatible)
    ubuntu = "ubuntu"           # Ubuntu Server
    sles = "sles"               # SUSE Linux Enterprise Server
    solaris = "solaris"         # Oracle Solaris
    aix = "aix"                 # IBM AIX
    hpux = "hpux"               # HP-UX
    # Windows
    windows = "windows"
    # Databases
    mysql = "mysql"             # MySQL / MariaDB
    mssql = "mssql"             # Microsoft SQL Server
    mongodb = "mongodb"         # MongoDB
    oracle_db = "oracle_db"     # Oracle Database
    postgresql = "postgresql"   # PostgreSQL
    redis = "redis"             # Redis


class ConnectorKind(str, enum.Enum):
    ssh = "ssh"
    winrm = "winrm"
    wmi = "wmi"
    mysql = "mysql"
    mssql = "mssql"
    mongodb = "mongodb"
    oracle = "oracle"           # Oracle Database (OCI / thin mode)
    postgresql = "postgresql"   # PostgreSQL native protocol
    redis = "redis"             # Redis protocol


class AuthSource(str, enum.Enum):
    local = "local"
    ad = "ad"
    ldap = "ldap"
    db_native = "db_native"
    os_integrated = "os_integrated"
    unknown = "unknown"


class PrincipalType(str, enum.Enum):
    human = "human"
    service = "service"
    shared = "shared"
    built_in = "built_in"
    system = "system"
    application = "application"
    unknown = "unknown"


class EnabledStatus(str, enum.Enum):
    enabled = "enabled"
    disabled = "disabled"
    locked = "locked"
    unknown = "unknown"


class InteractiveStatus(str, enum.Enum):
    # Generic values used by non-Windows collectors
    interactive = "interactive"
    non_interactive = "non_interactive"
    unknown = "unknown"
    # Windows-specific values (populated by the interactive classification engine)
    interactive_capable    = "interactive_capable"     # URA / event log confirms interactive
    non_interactive_only   = "non_interactive_only"    # URA explicitly denies interactive
    service_or_batch_only  = "service_or_batch_only"   # gMSA / computer / service run-as
    network_only           = "network_only"            # only network logon types observed
    unknown_review_required = "unknown_review_required" # insufficient evidence; needs review


class PrivilegeClass(str, enum.Enum):
    full_admin = "full_admin"
    admin_equivalent = "admin_equivalent"
    operator_high_impact = "operator_high_impact"
    delegated_admin = "delegated_admin"
    privileged_service = "privileged_service"
    sensitive_non_admin = "sensitive_non_admin"
    dormant_privileged = "dormant_privileged"
    non_privileged = "non_privileged"
    unknown_review_required = "unknown_review_required"


# Severity ordering for picking the "winning" classification.
PRIVILEGE_SEVERITY: dict[PrivilegeClass, int] = {
    PrivilegeClass.full_admin: 100,
    PrivilegeClass.admin_equivalent: 90,
    PrivilegeClass.operator_high_impact: 80,
    PrivilegeClass.delegated_admin: 70,
    PrivilegeClass.privileged_service: 75,
    PrivilegeClass.sensitive_non_admin: 50,
    PrivilegeClass.dormant_privileged: 85,
    PrivilegeClass.unknown_review_required: 40,
    PrivilegeClass.non_privileged: 10,
}


class JobStatus(str, enum.Enum):
    pending = "pending"
    queued = "queued"
    running = "running"
    success = "success"
    partial_success = "partial_success"
    failed = "failed"
    timed_out = "timed_out"
    unreachable = "unreachable"
    auth_failed = "auth_failed"
    cancelled = "cancelled"


class ScanMode(str, enum.Enum):
    safe = "safe"
    deep = "deep"


class ReviewState(str, enum.Enum):
    unreviewed = "unreviewed"
    acknowledged = "acknowledged"
    risk_accepted = "risk_accepted"
    remediated = "remediated"
    false_positive = "false_positive"


class ExceptionScope(str, enum.Enum):
    account = "account"
    asset = "asset"
    group = "group"
    global_ = "global"


class VaultBackend(str, enum.Enum):
    local = "local"
    cyberark = "cyberark"
    hashicorp = "hashicorp"
    azure = "azure"
    aws = "aws"


class TagCategory(str, enum.Enum):
    application  = "application"
    environment  = "environment"
    business_unit = "business_unit"
    criticality  = "criticality"
    compliance   = "compliance"
    ownership    = "ownership"
    technology   = "technology"
    custom       = "custom"


class TagStatus(str, enum.Enum):
    active   = "active"
    inactive = "inactive"


# ── Connector Agent Framework ─────────────────────────────────────────────────

class ConnectorAgentStatus(str, enum.Enum):
    pending  = "pending"    # enrolled, awaiting approval
    approved = "approved"   # approved, not yet seen
    online   = "online"     # heartbeat within stale threshold
    offline  = "offline"    # missed heartbeats, still enabled
    stale    = "stale"      # degraded / behind on heartbeat
    disabled = "disabled"   # administratively disabled
    revoked  = "revoked"    # permanently revoked
    error    = "error"      # in error state


class ConnectorAgentJobStatus(str, enum.Enum):
    pending        = "pending"
    accepted       = "accepted"
    running        = "running"
    partial_success = "partial_success"
    success        = "success"
    failed         = "failed"
    cancelled      = "cancelled"
    timed_out      = "timed_out"


class ConnectorAgentJobType(str, enum.Enum):
    discovery_basic       = "discovery_basic"       # no credentials
    discovery_credentialed = "discovery_credentialed"  # with credentials
    bulk_scan             = "bulk_scan"
    scheduled             = "scheduled"
    on_demand             = "on_demand"
    config_sync           = "config_sync"            # pull fresh config
    health_check          = "health_check"


# ── Password Policy Discovery ─────────────────────────────────────────────────

class PolicySource(str, enum.Enum):
    local_policy    = "local_policy"     # Windows Local Security Policy (secpol.msc)
    domain_policy   = "domain_policy"    # AD Default Domain Policy (GPO)
    fine_grained_ad = "fine_grained_ad"  # AD Fine-Grained Password Policy (PSO)
    pam_module      = "pam_module"       # Linux PAM (pam_pwquality, pam_cracklib)
    pam_tally       = "pam_tally"        # pam_tally2 / pam_faillock (lockout)
    login_defs      = "login_defs"       # /etc/login.defs (aging)
    database_native = "database_native"  # DB-native policy (SQL Server, MySQL, etc.)
    external_idp    = "external_idp"     # External IdP (LDAP, Kerberos, SAML, OIDC)
    unknown         = "unknown"


class PolicyScope(str, enum.Enum):
    host           = "host"            # applies to the local machine
    domain         = "domain"          # applies to entire AD domain
    database       = "database"        # applies to a DB instance
    database_login = "database_login"  # per-login DB policy
    account        = "account"         # per-account override
    group          = "group"           # AD group / PSO target
    global_        = "global"          # global / system-wide


class PolicyFindingSeverity(str, enum.Enum):
    critical = "critical"
    high     = "high"
    medium   = "medium"
    low      = "low"
    info     = "info"


class PolicyFindingReviewState(str, enum.Enum):
    open           = "open"
    acknowledged   = "acknowledged"
    risk_accepted  = "risk_accepted"
    remediated     = "remediated"
    false_positive = "false_positive"
