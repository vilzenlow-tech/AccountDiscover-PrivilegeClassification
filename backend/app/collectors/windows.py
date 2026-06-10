"""Windows collector (WinRM / PowerShell).

Covers
------
- Local SAM accounts                  (Get-LocalUser)
- Local group membership              (Get-LocalGroupMember)
  - Direct local user members
  - Direct domain user members
  - Domain group members (emitted as group-principal accounts)
  - gMSA accounts         (AD User, name ends with '$')
  - Computer accounts     (AD Computer ObjectClass)
  - Unresolved / orphaned SIDs        (PrincipalSource=Unknown)
- Nested AD group expansion           (Get-ADGroupMember, requires RSAT; gracefully skipped)
- Windows service logon accounts      (Win32_Service.StartName)
- Scheduled task run-as principals    (Get-ScheduledTask.Principal.UserId)
- Interactive capability              (secedit User Rights Assignment + Event 4624 logon history)

source_type values emitted
--------------------------
  windows_local        Local SAM user account
  windows_builtin      BUILTIN local account  (Administrator, Guest, DefaultAccount, WDAGUtilityAccount)
  windows_domain_user  AD user visible via local group membership or service run-as
  windows_domain_group AD group directly present in a local group
  windows_gmsa         Group Managed Service Account  (AD User, name ends with '$')
  windows_computer     AD computer/machine account   (ObjectClass = Computer)
  windows_service      NT SERVICE\\* virtual accounts
  windows_system       NT AUTHORITY\\* well-known accounts
  windows_unresolved   Orphaned or unresolvable SID in a local group

Principal classification uses, in priority order
-------------------------------------------------
  1. Well-known SID prefix  (S-1-5-18, S-1-5-32-*, S-1-5-80-*, …)
  2. Account name prefix    (NT AUTHORITY\\, NT SERVICE\\)
  3. PrincipalSource field  (Local | ActiveDirectory | Unknown)
  4. ObjectClass field      (User | Group | Computer | Unknown)
  5. Name heuristics        (trailing '$' → gMSA; service name patterns)

WinRM connector options  (target.options)
-----------------------------------------
  winrm_transport          ntlm (default) | basic | kerberos | credssp
  winrm_scheme             http (default) | https
  winrm_port               5985 (http default) | 5986 (https default)
  winrm_cert_validation    ignore (default) | validate
  winrm_read_timeout       60  (seconds)
  winrm_op_timeout         50  (seconds)

Enable WinRM on the target server
----------------------------------
  winrm quickconfig
  Set-Item WSMan:\\localhost\\Service\\Auth\\Negotiate 1
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import NamedTuple

from app.collectors._mockutil import last_login_days_ago, probe
from app.collectors._win_interactive import (
    WinInteractiveEvidence,
    classify_interactive,
)
from app.collectors.base import (
    BaseCollector,
    CollectionResult,
    Credential,
    NormalizedAccount,
    NormalizedEntitlement,
    Target,
)
from app.models.enums import (
    AuthSource,
    EnabledStatus,
    InteractiveStatus,
    Platform,
    PrincipalType,
)

# ── Privilege / sensitivity sets ─────────────────────────────────────────────

HIGH_IMPACT_GROUPS: set[str] = {
    "Administrators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "Account Operators",
    "Replicator",
    "Hyper-V Administrators",
    "Remote Desktop Users",
    "Remote Management Users",
    "Distributed COM Users",
    "Network Configuration Operators",
    "Cryptographic Operators",
}

DOMAIN_ADMIN_GROUPS: set[str] = {
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
}

# ── Local built-in account names ──────────────────────────────────────────────

_BUILTIN_LOCAL_NAMES: set[str] = {
    "Administrator",
    "Guest",
    "DefaultAccount",
    "WDAGUtilityAccount",
}

# ── Local groups to ALWAYS query (they may not appear in Get-LocalGroup on DCs) ──

_MUST_CHECK_GROUPS: list[str] = [
    "Administrators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "Account Operators",
    "Replicator",
    "Remote Desktop Users",
    "Remote Management Users",
    "Hyper-V Administrators",
    "Distributed COM Users",
    "Event Log Readers",
    "Network Configuration Operators",
    "Cryptographic Operators",
    "Performance Log Users",
    "Performance Monitor Users",
]

# ── Well-known SID → (canonical_name, source_type) ───────────────────────────

_WELLKNOWN_SID: dict[str, tuple[str, str]] = {
    "S-1-5-2":  ("NT AUTHORITY\\NETWORK",              "windows_system"),
    "S-1-5-4":  ("NT AUTHORITY\\INTERACTIVE",          "windows_system"),
    "S-1-5-6":  ("NT AUTHORITY\\SERVICE",              "windows_system"),
    "S-1-5-11": ("NT AUTHORITY\\Authenticated Users",  "windows_system"),
    "S-1-5-18": ("NT AUTHORITY\\SYSTEM",               "windows_system"),
    "S-1-5-19": ("NT AUTHORITY\\LOCAL SERVICE",        "windows_system"),
    "S-1-5-20": ("NT AUTHORITY\\NETWORK SERVICE",      "windows_system"),
}

# ── BUILTIN group name → SID  (used for User Rights Assignment matching) ──────

_BUILTIN_GROUP_SIDS: dict[str, str] = {
    "Administrators":              "S-1-5-32-544",
    "Users":                       "S-1-5-32-545",
    "Guests":                      "S-1-5-32-546",
    "Backup Operators":            "S-1-5-32-551",
    "Replicator":                  "S-1-5-32-552",
    "Account Operators":           "S-1-5-32-548",
    "Server Operators":            "S-1-5-32-549",
    "Print Operators":             "S-1-5-32-550",
    "IIS_IUSRS":                   "S-1-5-32-568",
    "Distributed COM Users":       "S-1-5-32-562",
    "Cryptographic Operators":     "S-1-5-32-569",
    "Event Log Readers":           "S-1-5-32-573",
    "Network Configuration Operators": "S-1-5-32-556",
    "Performance Log Users":       "S-1-5-32-559",
    "Performance Monitor Users":   "S-1-5-32-558",
    "Remote Desktop Users":        "S-1-5-32-555",
    "Remote Management Users":     "S-1-5-32-580",
    "Hyper-V Administrators":      "S-1-5-32-578",
}

# ── PowerShell script templates ───────────────────────────────────────────────

_PS_USERS = r"""
try {
    @(Get-LocalUser | Select-Object Name, SID, Enabled, PasswordRequired,
      PasswordNeverExpires, LastLogon, Description, PasswordLastSet) |
    ConvertTo-Json -Depth 3 -Compress
} catch { '[]' }
""".strip()

_PS_GROUPS = r"""
$hostname = $env:COMPUTERNAME
$out=[ordered]@{}; $errs=@{}; $expanded=@{}
$must=@('Administrators','Backup Operators','Server Operators','Print Operators',
        'Account Operators','Replicator','Remote Desktop Users',
        'Remote Management Users','Hyper-V Administrators','Distributed COM Users',
        'Event Log Readers','Network Configuration Operators',
        'Cryptographic Operators','Performance Log Users','Performance Monitor Users')
$all=($must+@(try{Get-LocalGroup|Select-Object -ExpandProperty Name}catch{@()}))|Sort-Object -Unique
foreach($g in $all){
    try{
        $m=@(Get-LocalGroupMember -Group $g -EA Stop|
             Select-Object Name,SID,ObjectClass,PrincipalSource)
        $out[$g]=$m
        foreach($mem in $m){
            if($mem.ObjectClass -eq 'Group' -and $mem.PrincipalSource -eq 'ActiveDirectory'){
                $k=$mem.Name
                if(-not $expanded.ContainsKey($k)){
                    try{
                        $expanded[$k]=@(Get-ADGroupMember -Identity $k -Recursive -EA Stop|
                                        Select-Object Name,SamAccountName,SID,objectClass,DistinguishedName)
                    }catch{ $expanded[$k]=$null }
                }
            }
        }
    }catch{ $out[$g]=@(); $errs[$g]=$_.Exception.Message }
}
[PSCustomObject]@{groups=$out;errors=$errs;expanded=$expanded;hostname=$hostname}|
ConvertTo-Json -Depth 6 -Compress
""".strip()

_PS_SERVICES = r"""
try {
    @(Get-CimInstance Win32_Service | Where-Object { $_.StartName } |
      Select-Object Name, DisplayName, StartName, State, StartMode) |
    ConvertTo-Json -Depth 2 -Compress
} catch { '[]' }
""".strip()

_PS_TASKS = r"""
try {
    @(Get-ScheduledTask | Where-Object { $_.Principal.UserId } |
      Select-Object TaskName, TaskPath,
        @{N='UserId';   E={$_.Principal.UserId}},
        @{N='RunLevel'; E={$_.Principal.RunLevel.ToString()}},
        @{N='LogonType';E={$_.Principal.LogonType.ToString()}}) |
    ConvertTo-Json -Depth 2 -Compress
} catch { '[]' }
""".strip()

# Returns: { "SeInteractiveLogonRight": ["S-1-5-32-544", ...], ... }
# SIDs have the leading '*' stripped; names are left as-is.
_PS_USER_RIGHTS = r"""
$tmp = [System.IO.Path]::GetTempFileName() + '.inf'
try {
    secedit /export /areas USER_RIGHTS /cfg $tmp /quiet 2>$null | Out-Null
    if (-not (Test-Path $tmp)) { '{}'; return }
    $content = Get-Content $tmp -Raw -Encoding Unicode
    $rights = @{}
    $keys = @(
        'SeInteractiveLogonRight','SeRemoteInteractiveLogonRight',
        'SeDenyInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight',
        'SeServiceLogonRight','SeBatchLogonRight','SeNetworkLogonRight'
    )
    foreach ($key in $keys) {
        $m = [regex]::Match($content, "(?m)^$key\s*=\s*(.*)$")
        if ($m.Success) {
            $val = $m.Groups[1].Value.Trim()
            if ($val) {
                $entries = @($val -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ -ne '' })
                $rights[$key] = $entries
            } else {
                $rights[$key] = @()
            }
        }
    }
    $rights | ConvertTo-Json -Compress
} catch { '{}' }
finally { if (Test-Path $tmp) { Remove-Item $tmp -Force -EA SilentlyContinue } }
""".strip()

# Returns: { "username": [2, 3, 10], "DOMAIN\\user": [10], ... }
# Only users with at least one Event 4624 entry in the last 30 days are included.
# Machine accounts (name ends '$') and system/service domain entries are filtered.
_PS_LOGON_TYPES = r"""
try {
    $cutoff = (Get-Date).AddDays(-30)
    $acc = @{}
    Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=$cutoff} -MaxEvents 10000 -EA Stop |
    ForEach-Object {
        $p = $_.Properties
        if ($p.Count -lt 9) { return }
        $user = [string]$p[5].Value
        $dom  = [string]$p[6].Value
        $lt   = [int]$p[8].Value
        if (-not $user -or $user -eq '-' -or $user -eq 'ANONYMOUS LOGON') { return }
        if ($user -match '\$$') { return }
        if ($dom -in @('NT AUTHORITY','Font Driver Host','Window Manager','UMFD-0','UMFD-1','DWM-1','DWM-2')) { return }
        $key = if ($dom -and $dom -ne $env:COMPUTERNAME -and $dom -ne 'WORKGROUP') { "$dom\$user" } else { $user }
        if (-not $acc[$key]) { $acc[$key] = [System.Collections.Generic.HashSet[int]]::new() }
        [void]$acc[$key].Add($lt)
    }
    $out = @{}
    foreach ($k in $acc.Keys) { $out[$k] = @($acc[$k]) }
    $out | ConvertTo-Json -Compress
} catch { '{}' }
""".strip()


# ── Principal classification helper ──────────────────────────────────────────

class _PInfo(NamedTuple):
    source_type: str
    principal_type: PrincipalType
    auth_source: AuthSource
    domain: str | None
    short: str


def _extract_sid(val: object) -> str:
    """Handle SID as plain string or as PS-serialised SecurityIdentifier object."""
    if not val:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, dict):
        return val.get("Value") or val.get("value") or ""
    return str(val)


def _ps_bool(val: object) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, int):
        return val != 0
    if isinstance(val, str):
        return val.strip().lower() == "true"
    return bool(val)


def _windate(val: object) -> datetime | None:
    if not val:
        return None
    s = str(val)
    m = re.search(r"/Date\((\d+)\)/", s)
    if m:
        return datetime.fromtimestamp(int(m.group(1)) / 1000, tz=timezone.utc)
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None


# PowerShell enum integer → canonical string for ObjectClass / PrincipalSource.
# ConvertTo-Json serialises these as the raw underlying integer on some Windows
# Server / PowerShell versions instead of the human-readable name.
_PS_OBJ_CLASS: dict[int, str] = {
    0: "unknown",
    1: "user",
    2: "group",
    3: "computer",
}
_PS_PRINCIPAL_SRC: dict[int, str] = {
    0: "unknown",
    1: "local",
    2: "activedirectory",
    4: "azureactivedirectory",
}


def _coerce_str(val: object, int_map: dict | None = None) -> str:
    """Return *val* as a plain string, mapping PS enum integers via *int_map* when given.

    PowerShell's ConvertTo-Json serialises enum fields (ObjectClass,
    PrincipalSource, RunLevel, …) as their underlying integer value on some
    Windows Server / PS versions.  Pass the relevant ``_PS_*`` dict so the
    integer is resolved to its canonical name before comparison.
    """
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, int) and int_map is not None:
        return int_map.get(val, str(val))
    return str(val)


def _short(full: str) -> str:
    return full.split("\\")[-1] if "\\" in full else full


def _domain_of(full: str) -> str | None:
    if "\\" in full:
        return full.split("\\")[0]
    return None


def _is_domain_admin_group(name: str) -> bool:
    return _short(name) in DOMAIN_ADMIN_GROUPS


def _infer_service_type(name: str) -> bool:
    n = name.lower()
    keywords = ("svc", "_svc", "svc_", "service", "agent", "task",
                "daemon", "deamon", "worker", "batch", "job", "scheduler")
    return any(k in n for k in keywords)


def _classify_principal(
    name: str,
    sid: str,
    obj_class: str,
    principal_source: str,
    hostname: str,
) -> _PInfo:
    """Classify a Windows security principal by SID, PrincipalSource, ObjectClass and name."""
    sid_u = (sid or "").upper()
    oc = _coerce_str(obj_class, _PS_OBJ_CLASS).lower()
    ps = _coerce_str(principal_source, _PS_PRINCIPAL_SRC).lower()
    name_u = (name or "").upper()
    short = _short(name)
    domain = _domain_of(name)

    # 1. Well-known individual SIDs
    if sid_u in _WELLKNOWN_SID:
        _, st = _WELLKNOWN_SID[sid_u]
        return _PInfo(st, PrincipalType.system, AuthSource.local, None, short)

    # 2. SID-prefix rules
    if sid_u.startswith("S-1-5-80-"):          # NT SERVICE\*
        return _PInfo("windows_service", PrincipalType.system, AuthSource.local, None, short)
    if sid_u.startswith("S-1-5-32-"):          # BUILTIN\*
        return _PInfo("windows_builtin", PrincipalType.built_in, AuthSource.local, None, short)

    # 3. Name-prefix rules (catch NT AUTHORITY / NT SERVICE not captured by SID)
    if name_u.startswith("NT AUTHORITY\\") or name_u.startswith("NT SERVICE\\"):
        return _PInfo("windows_system", PrincipalType.system, AuthSource.local, None, short)

    # 4. Unresolved / orphaned SID
    if ps == "unknown" or oc in ("unknown", ""):
        return _PInfo("windows_unresolved", PrincipalType.unknown, AuthSource.unknown, domain, short)

    # 5. ActiveDirectory principals
    if ps == "activedirectory":
        if oc == "group":
            return _PInfo("windows_domain_group", PrincipalType.unknown, AuthSource.ad, domain, short)
        if oc == "computer":
            return _PInfo("windows_computer", PrincipalType.unknown, AuthSource.ad, domain, short)
        # AD User — distinguish gMSA (name ends with '$') from ordinary user
        if short.endswith("$"):
            return _PInfo("windows_gmsa", PrincipalType.service, AuthSource.ad, domain, short)
        return _PInfo("windows_domain_user", PrincipalType.human, AuthSource.ad, domain, short)

    # 6. Local principals
    if short in _BUILTIN_LOCAL_NAMES:
        return _PInfo("windows_builtin", PrincipalType.built_in, AuthSource.local, None, short)
    pt = PrincipalType.service if _infer_service_type(short) else PrincipalType.human
    return _PInfo("windows_local", pt, AuthSource.local, None, short)


# ── Interactive evidence builder ─────────────────────────────────────────────


def _build_interactive_evidence(
    account: NormalizedAccount,
    user_rights_data: dict,
    logon_types_data: dict,
) -> WinInteractiveEvidence:
    """Assemble a WinInteractiveEvidence for one account.

    Combines:
    - Account identity flags (source_type → is_gmsa etc.)
    - User Rights Assignment match (account SID / group BUILTIN SIDs vs secedit data)
    - Event 4624 logon type history (account name lookup)
    - Service / task run-as entitlement presence
    """
    ev = WinInteractiveEvidence()

    # --- Account identity -------------------------------------------------------
    st = account.source_type
    ev.is_gmsa           = (st == "windows_gmsa")
    ev.is_computer_account = (st == "windows_computer")
    ev.is_domain_group   = (st == "windows_domain_group")
    ev.is_unresolved_sid = (st == "windows_unresolved")

    # Built-in accounts: mark name so Rule 5 can check the specific sub-list.
    # Also catch accounts whose source_type was stored as windows_local by old
    # collector versions but whose name is a known BUILTIN (DefaultAccount, etc.)
    short_name = _short(account.account_name)
    if st == "windows_builtin" or short_name in _BUILTIN_LOCAL_NAMES:
        ev.builtin_name = short_name.lower()

    # --- Build the set of SIDs that represent this account ----------------------
    # Own SID + SIDs of every BUILTIN local group the account belongs to.
    own_sid = ((account.evidence_summary or {}).get("sid") or "").upper()
    sids: set[str] = set()
    if own_sid:
        sids.add(own_sid)

    for ent in account.entitlements:
        if ent.kind == "windows_local_group":
            grp_sid = _BUILTIN_GROUP_SIDS.get(ent.name)
            if grp_sid:
                sids.add(grp_sid.upper())

    # Account name forms for name-based entries in secedit (e.g. "NT SERVICE\…")
    short_upper = _short(account.account_name).upper()
    name_upper  = account.account_name.upper()

    # --- User Rights Assignment -------------------------------------------------
    if user_rights_data:
        ev.user_rights_available = True

        def _has_right(right_name: str) -> bool:
            entries = user_rights_data.get(right_name)
            if not entries:
                return False
            eu = {str(e).upper() for e in entries}
            return bool(eu & sids) or short_upper in eu or name_upper in eu

        ev.has_interactive_logon_right = _has_right("SeInteractiveLogonRight")
        ev.has_rdp_logon_right         = _has_right("SeRemoteInteractiveLogonRight")
        ev.deny_interactive            = _has_right("SeDenyInteractiveLogonRight")
        ev.deny_rdp                    = _has_right("SeDenyRemoteInteractiveLogonRight")
        ev.has_service_logon_right     = _has_right("SeServiceLogonRight")
        ev.has_batch_logon_right       = _has_right("SeBatchLogonRight")
        ev.has_network_logon_right     = _has_right("SeNetworkLogonRight")

    # --- Event 4624 logon types -------------------------------------------------
    if logon_types_data:
        ev.event_log_available = True
        # Try several name forms: full "DOMAIN\user", short "user", upper variants
        types_list = (
            logon_types_data.get(account.account_name)
            or logon_types_data.get(_short(account.account_name))
            or logon_types_data.get(account.account_name.upper())
            or logon_types_data.get(short_upper)
        )
        if types_list:
            ev.observed_logon_types = frozenset(int(t) for t in types_list)
            if ev.observed_logon_types:
                ev.last_observed_logon_type = max(ev.observed_logon_types)

    # --- Service / task run-as --------------------------------------------------
    for ent in account.entitlements:
        if ent.kind == "windows_service_runas":
            ev.runs_service = True
        elif ent.kind == "windows_scheduled_task_runas":
            ev.runs_scheduled_task = True

    # --- Service principal type hint (Rule 8.5 fallback) ----------------------
    # Only activate when no harder evidence (URA, event log, run-as) is present;
    # the classifier itself checks ordering so this is just informational.
    ev.is_service_principal = (account.principal_type == PrincipalType.service)

    return ev


def _apply_interactive_classification(
    account: NormalizedAccount,
    user_rights_data: dict,
    logon_types_data: dict,
) -> NormalizedAccount:
    """Run the interactive classifier and update ``account`` in place."""
    ev  = _build_interactive_evidence(account, user_rights_data, logon_types_data)
    clf = classify_interactive(ev)

    # Map the classifier's status string to the InteractiveStatus enum.
    # Falls back to ``unknown`` if a future value isn't in the enum yet.
    try:
        account.interactive_status = InteractiveStatus(clf.status)
    except ValueError:
        account.interactive_status = InteractiveStatus.unknown

    account.win_interactive_confidence       = clf.confidence
    account.win_interactive_detection_method = clf.detection_method
    account.win_allows_local_logon           = clf.allows_local_logon
    account.win_allows_remote_interactive    = clf.allows_remote_interactive_logon
    account.win_allows_service_logon         = clf.allows_service_logon
    account.win_allows_batch_logon           = clf.allows_batch_logon
    account.win_allows_network_logon         = clf.allows_network_logon
    account.win_last_observed_logon_type     = clf.last_observed_logon_type
    account.win_review_required_reason       = clf.review_required_reason

    # Serialise evidence for the JSONB column (frozensets → lists for JSON)
    account.win_interactive_evidence = {
        "is_gmsa":                   ev.is_gmsa,
        "is_computer_account":       ev.is_computer_account,
        "is_domain_group":           ev.is_domain_group,
        "is_unresolved_sid":         ev.is_unresolved_sid,
        "builtin_name":              ev.builtin_name,
        "user_rights_available":     ev.user_rights_available,
        "has_interactive_logon_right": ev.has_interactive_logon_right,
        "has_rdp_logon_right":       ev.has_rdp_logon_right,
        "deny_interactive":          ev.deny_interactive,
        "deny_rdp":                  ev.deny_rdp,
        "has_service_logon_right":   ev.has_service_logon_right,
        "has_batch_logon_right":     ev.has_batch_logon_right,
        "has_network_logon_right":   ev.has_network_logon_right,
        "event_log_available":       ev.event_log_available,
        "observed_logon_types":      sorted(ev.observed_logon_types),
        "last_observed_logon_type":  ev.last_observed_logon_type,
        "runs_service":              ev.runs_service,
        "runs_scheduled_task":       ev.runs_scheduled_task,
        "is_service_principal":      ev.is_service_principal,
        "detection_method":          clf.detection_method,
        "explanation":               clf.explanation,
    }

    # Record the raw principal source for filtering
    account.principal_source = (account.evidence_summary or {}).get("principal_source")

    return account


# ── WindowsCollector ─────────────────────────────────────────────────────────

class WindowsCollector(BaseCollector):
    """Collects from Windows Server targets via WinRM / PowerShell."""

    platform = Platform.windows
    probes = (
        "get_localusers",
        "get_localgroups_members",
        "services_runas",
        "scheduled_tasks_runas",
        "user_rights_assignment",
        "logon_type_history",
    )

    # ── Mock collection ───────────────────────────────────────────────────────

    def collect_mock(self, target: Target) -> CollectionResult:
        hostname = target.hostname or "WIN-SRV01"

        users_raw: list[dict] = [
            # Test case 4 — built-in account (disabled)
            {"Name": "Administrator", "SID": "S-1-5-21-1111111111-2222222222-3333333333-500",
             "Enabled": False, "PasswordRequired": True, "PasswordNeverExpires": True,
             "LastLogon": None, "Description": "Built-in administrator account",
             "PasswordLastSet": "2020-01-15T10:30:00Z"},
            {"Name": "Guest", "SID": "S-1-5-21-1111111111-2222222222-3333333333-501",
             "Enabled": False, "PasswordRequired": False, "PasswordNeverExpires": True,
             "LastLogon": None, "Description": "Built-in guest account",
             "PasswordLastSet": None},
            # Service account in Backup Operators
            {"Name": "svc_backup", "SID": "S-1-5-21-1111111111-2222222222-3333333333-1001",
             "Enabled": True, "PasswordRequired": True, "PasswordNeverExpires": True,
             "LastLogon": "2026-04-25T02:00:00Z", "Description": "Backup service account",
             "PasswordLastSet": "2023-01-01T00:00:00Z"},
            # Test case 7 — disabled but still in privileged group → dormant_privileged
            {"Name": "svc_legacy", "SID": "S-1-5-21-1111111111-2222222222-3333333333-1002",
             "Enabled": False, "PasswordRequired": True, "PasswordNeverExpires": True,
             "LastLogon": None, "Description": "Decommissioned legacy service account",
             "PasswordLastSet": "2019-06-01T00:00:00Z"},
            # Test case 1 — local-only human account
            {"Name": "ops_local", "SID": "S-1-5-21-1111111111-2222222222-3333333333-1003",
             "Enabled": True, "PasswordRequired": True, "PasswordNeverExpires": False,
             "LastLogon": "2026-04-24T08:00:00Z", "Description": "Operations local user",
             "PasswordLastSet": "2026-01-01T00:00:00Z"},
        ]

        groups_data: dict = {
            "hostname": hostname,
            "groups": {
                "Administrators": [
                    # Test case 2 — domain user directly in local Administrators
                    {"Name": "CORP\\alice",        "SID": "S-1-5-21-9999999999-8888888888-7777777777-1105",
                     "ObjectClass": "User",  "PrincipalSource": "ActiveDirectory"},
                    # Test case 3 — domain group → members (bob, charlie) inherit full_admin
                    {"Name": "CORP\\Domain Admins","SID": "S-1-5-21-9999999999-8888888888-7777777777-512",
                     "ObjectClass": "Group", "PrincipalSource": "ActiveDirectory"},
                    {"Name": f"{hostname}\\Administrator",
                     "SID": "S-1-5-21-1111111111-2222222222-3333333333-500",
                     "ObjectClass": "User",  "PrincipalSource": "Local"},
                ],
                "Backup Operators": [
                    {"Name": f"{hostname}\\svc_backup",
                     "SID": "S-1-5-21-1111111111-2222222222-3333333333-1001",
                     "ObjectClass": "User", "PrincipalSource": "Local"},
                    # Test case 7 — disabled privileged account
                    {"Name": f"{hostname}\\svc_legacy",
                     "SID": "S-1-5-21-1111111111-2222222222-3333333333-1002",
                     "ObjectClass": "User", "PrincipalSource": "Local"},
                    # Test case 6 — unresolved / orphaned SID
                    {"Name": "S-1-5-21-9999999999-8888888888-7777777777-1200",
                     "SID":  "S-1-5-21-9999999999-8888888888-7777777777-1200",
                     "ObjectClass": "Unknown", "PrincipalSource": "Unknown"},
                ],
                "Server Operators": [
                    # Test case 5 — gMSA account (AD User with trailing '$')
                    {"Name": "CORP\\WebApp$",      "SID": "S-1-5-21-9999999999-8888888888-7777777777-2100",
                     "ObjectClass": "User",    "PrincipalSource": "ActiveDirectory"},
                ],
                "Remote Desktop Users": [
                    {"Name": "CORP\\AppOwners",    "SID": "S-1-5-21-9999999999-8888888888-7777777777-1150",
                     "ObjectClass": "Group",   "PrincipalSource": "ActiveDirectory"},
                    {"Name": f"{hostname}\\ops_local",
                     "SID": "S-1-5-21-1111111111-2222222222-3333333333-1003",
                     "ObjectClass": "User",    "PrincipalSource": "Local"},
                ],
                "Users": [
                    {"Name": "NT AUTHORITY\\Authenticated Users", "SID": "S-1-5-11",
                     "ObjectClass": "User", "PrincipalSource": "Unknown"},
                    {"Name": "CORP\\Domain Users", "SID": "S-1-5-21-9999999999-8888888888-7777777777-513",
                     "ObjectClass": "Group",  "PrincipalSource": "ActiveDirectory"},
                ],
            },
            "errors": {},
            "expanded": {
                # Test case 3 — nested Domain Admins members → inherit full_admin via Administrators
                "CORP\\Domain Admins": [
                    {"Name": "bob",     "SamAccountName": "bob",
                     "SID": "S-1-5-21-9999999999-8888888888-7777777777-1106", "objectClass": "user"},
                    {"Name": "charlie", "SamAccountName": "charlie",
                     "SID": "S-1-5-21-9999999999-8888888888-7777777777-1107", "objectClass": "user"},
                ],
                "CORP\\AppOwners": [
                    {"Name": "dave",    "SamAccountName": "dave",
                     "SID": "S-1-5-21-9999999999-8888888888-7777777777-1108", "objectClass": "user"},
                ],
            },
        }

        svcs_raw: list[dict] = [
            {"Name": "TomcatApp1",    "DisplayName": "Apache Tomcat",    "StartName": "CORP\\svc_app1",       "State": "Running", "StartMode": "Auto"},
            {"Name": "BackupAgent",   "DisplayName": "Backup Agent",     "StartName": f"{hostname}\\svc_backup", "State": "Running", "StartMode": "Auto"},
            {"Name": "LegacyService", "DisplayName": "Legacy Svc",       "StartName": f"{hostname}\\svc_legacy", "State": "Stopped", "StartMode": "Manual"},
            {"Name": "SQLServer",     "DisplayName": "SQL Server (MSSQLSERVER)", "StartName": "NT SERVICE\\MSSQLSERVER", "State": "Running", "StartMode": "Auto"},
        ]

        tasks_raw: list[dict] = [
            {"TaskName": "NightlyBackup", "TaskPath": "\\Custom\\",
             "UserId": f"{hostname}\\svc_backup", "RunLevel": "Highest", "LogonType": "Password"},
            {"TaskName": "AppHealthCheck", "TaskPath": "\\App\\",
             "UserId": "CORP\\svc_app1",   "RunLevel": "Limited",  "LogonType": "Password"},
            {"TaskName": "PatchCheck",     "TaskPath": "\\System\\",
             "UserId": "NT AUTHORITY\\SYSTEM", "RunLevel": "Highest", "LogonType": "ServiceAccount"},
        ]

        # ── Mock User Rights Assignment (secedit) ─────────────────────────
        # Reflects a typical member-server policy:
        #   Administrators and Remote Desktop Users may do interactive logon.
        #   svc_backup / svc_legacy have only SeServiceLogonRight.
        mock_user_rights: dict = {
            "SeInteractiveLogonRight": [
                "S-1-5-32-544",   # Administrators
            ],
            "SeRemoteInteractiveLogonRight": [
                "S-1-5-32-544",   # Administrators
                "S-1-5-32-555",   # Remote Desktop Users
            ],
            "SeDenyInteractiveLogonRight":       [],
            "SeDenyRemoteInteractiveLogonRight":  [],
            "SeServiceLogonRight": [
                # svc_backup and svc_legacy have service logon right
                "S-1-5-21-1111111111-2222222222-3333333333-1001",
                "S-1-5-21-1111111111-2222222222-3333333333-1002",
            ],
            "SeBatchLogonRight": [
                "S-1-5-32-551",   # Backup Operators
            ],
            "SeNetworkLogonRight": [
                "S-1-5-32-544",   # Administrators
                "S-1-5-11",       # Authenticated Users
            ],
        }

        # ── Mock Event 4624 logon types ────────────────────────────────────
        # ops_local has done interactive + RDP sessions.  No events for domain
        # accounts (domain controller holds those logs, not this server).
        mock_logon_types: dict = {
            "ops_local": [2, 3, 10],
        }

        accounts, probe_results = WindowsCollector._assemble_collection(
            hostname, users_raw, groups_data, svcs_raw, tasks_raw,
            is_mock=True,
            user_rights_data=mock_user_rights,
            logon_types_data=mock_logon_types,
        )
        policies = []
        if target.options.get("collect_password_policy"):
            policies = WindowsCollector._collect_policy_mock(target, users_raw)
        return CollectionResult(platform=self.platform, probes=probe_results, accounts=accounts, password_policies=policies)

    # ── Live collection ───────────────────────────────────────────────────────

    def collect_live(self, target: Target, credential: Credential | None) -> CollectionResult:
        if not credential:
            raise RuntimeError(
                f"Live scan of Windows at {target.hostname} requires a credential."
            )
        try:
            import winrm
        except ImportError:
            raise RuntimeError(
                "pywinrm package is not installed. "
                "Add 'pywinrm>=0.4' to pyproject.toml and rebuild the image."
            ) from None

        host = target.ip_address or target.hostname
        transport = target.options.get("winrm_transport", "ntlm")
        scheme = target.options.get("winrm_scheme", "http")
        default_port = 5986 if scheme == "https" else 5985
        port = int(target.port or target.options.get("winrm_port", default_port))
        cert_validation = target.options.get("winrm_cert_validation", "ignore")

        session = winrm.Session(
            target=f"{scheme}://{host}:{port}/wsman",
            auth=(credential.username, credential.secret or ""),
            transport=transport,
            server_cert_validation=cert_validation,
            read_timeout_sec=int(target.options.get("winrm_read_timeout", 60)),
            operation_timeout_sec=int(target.options.get("winrm_op_timeout", 50)),
        )

        def _run(script: str) -> list | dict | None:
            r = session.run_ps(script)
            raw = r.std_out.decode("utf-8", errors="replace").strip()
            if not raw or raw.lower() in ("null", ""):
                return None
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return None

        users_raw = _run(_PS_USERS) or []
        if isinstance(users_raw, dict):
            users_raw = [users_raw]

        groups_data = _run(_PS_GROUPS) or {}
        if not isinstance(groups_data, dict):
            groups_data = {}

        svcs_raw = _run(_PS_SERVICES) or []
        if isinstance(svcs_raw, dict):
            svcs_raw = [svcs_raw]

        tasks_raw = _run(_PS_TASKS) or []
        if isinstance(tasks_raw, dict):
            tasks_raw = [tasks_raw]

        # Interactive classification probes (best-effort; failures are silent)
        user_rights_data: dict = {}
        logon_types_data: dict = {}
        try:
            raw = _run(_PS_USER_RIGHTS)
            if isinstance(raw, dict):
                user_rights_data = raw
        except Exception:
            pass
        try:
            raw = _run(_PS_LOGON_TYPES)
            if isinstance(raw, dict):
                logon_types_data = raw
        except Exception:
            pass

        hostname: str = (
            groups_data.get("hostname")
            or target.hostname
            or host
        )

        accounts, probe_results = WindowsCollector._assemble_collection(
            hostname, users_raw, groups_data, svcs_raw, tasks_raw,
            is_mock=False,
            user_rights_data=user_rights_data,
            logon_types_data=logon_types_data,
        )
        policies = []
        if target.options.get("collect_password_policy"):
            try:
                policies = WindowsCollector._collect_policy_live(session, target, users_raw)
            except NotImplementedError as exc:
                from app.collectors.base import NormalizedPasswordPolicy
                policies = [NormalizedPasswordPolicy(
                    policy_source="local_policy",
                    policy_scope="host",
                    policy_name="Local Security Policy",
                    collection_error=str(exc)[:512],
                    confidence_score=0,
                )]
            except Exception as exc:
                from app.collectors.base import NormalizedPasswordPolicy
                policies = [NormalizedPasswordPolicy(
                    policy_source="local_policy",
                    policy_scope="host",
                    policy_name="Local Security Policy",
                    collection_error=f"Policy collection failed: {str(exc)[:400]}",
                    confidence_score=0,
                )]
        return CollectionResult(platform=self.platform, probes=probe_results, accounts=accounts, password_policies=policies)

    # ── Password policy collection ────────────────────────────────────────────

    @staticmethod
    def _collect_policy_mock(
        target: Target, users_raw: list[dict]
    ) -> "list[NormalizedPasswordPolicy]":
        """Return a realistic Local Security Policy for a mock Windows scan.

        Mimics a typical unhardened Windows Server with default settings:
        minimum length 7, no lockout, no password history.  Accounts that
        have PasswordNeverExpires=True are recorded as AccountPolicyExceptions.
        """
        from app.collectors.base import NormalizedPasswordPolicy, NormalizedPolicyException

        _PRIVILEGED_LOCAL = {"Administrator", "svc_backup", "svc_legacy"}

        account_exceptions = [
            NormalizedPolicyException(
                account_name=u["Name"],
                exception_type="password_never_expires",
                evidence={
                    "is_privileged": u["Name"] in _PRIVILEGED_LOCAL,
                    "enabled": u.get("Enabled", True),
                    "source": "Get-LocalUser.PasswordNeverExpires",
                },
            )
            for u in users_raw
            if u.get("PasswordNeverExpires") is True
        ]

        return [
            NormalizedPasswordPolicy(
                policy_source="local_policy",
                policy_scope="host",
                policy_name="Local Security Policy",
                is_effective_policy=True,
                # Typical Windows Server defaults — deliberately weak to show findings
                min_password_length=7,
                complexity_enabled=True,
                password_history_count=0,     # no history
                max_password_age_days=42,
                min_password_age_days=0,
                lockout_threshold=0,           # no lockout — triggers PWPOL-006
                lockout_duration_minutes=30,
                reset_lockout_counter_after_minutes=30,
                reversible_encryption_enabled=False,
                evidence_summary={
                    "source": "secedit /export /cfg /areas SECURITYPOLICY",
                    "host": target.hostname,
                },
                confidence_score=90,
                account_exceptions=account_exceptions,
            )
        ]

    @staticmethod
    def _collect_policy_live(
        session: object, target: Target, users_raw: list[dict]
    ) -> "list[NormalizedPasswordPolicy]":
        """Live Windows password policy collection via WinRM.

        Runs three probes (each best-effort):
          1. secedit /export /cfg  — local Security Policy (works on any Windows host)
          2. Get-ADDefaultDomainPasswordPolicy — domain-level policy (requires RSAT + domain)
          3. Get-ADFineGrainedPasswordPolicy   — FGPPs (requires RSAT + domain admin read)

        Account exceptions (PasswordNeverExpires) are derived directly from
        ``users_raw`` which was already collected by the main scan.
        """
        import re as _re
        from app.collectors.base import NormalizedPasswordPolicy, NormalizedPolicyException

        def _ps(script: str) -> str:
            """Run a PowerShell snippet and return stdout as a plain string."""
            try:
                r = session.run_ps(script)  # type: ignore[attr-defined]
                return r.std_out.decode("utf-8", errors="replace").strip()
            except Exception:
                return ""

        def _ps_json(script: str) -> dict | list | None:
            raw = _ps(script)
            if not raw or raw.startswith("ERROR:") or raw.lower() in ("null", ""):
                return None
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return None

        # ── Build account exceptions from already-collected users_raw ─────────
        def _account_exceptions() -> list:
            return [
                NormalizedPolicyException(
                    account_name=u["Name"],
                    exception_type="password_never_expires",
                    evidence={
                        "is_privileged": u.get("Name") in {"Administrator", "admin"},
                        "enabled": u.get("Enabled", True),
                        "source": "Get-LocalUser.PasswordNeverExpires",
                    },
                )
                for u in (users_raw or [])
                if u.get("PasswordNeverExpires") is True and u.get("Enabled", True)
            ]

        policies: list = []

        # ── 1. Local Security Policy via secedit ──────────────────────────────
        # Export to a temp file, read it back, then delete.
        secedit_raw = _ps(r"""
$tmp = [System.IO.Path]::GetTempFileName() + ".cfg"
try {
    secedit /export /cfg $tmp /quiet 2>$null | Out-Null
    if (Test-Path $tmp) { Get-Content $tmp -Raw }
} catch { "" }
finally { if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue } }
""")

        if secedit_raw:
            def _sec(key: str, default: int | None = None) -> int | None:
                m = _re.search(rf"^\s*{key}\s*=\s*(-?\d+)", secedit_raw, _re.MULTILINE | _re.IGNORECASE)
                if m:
                    return int(m.group(1))
                return default

            raw_max_age = _sec("MaximumPasswordAge")
            # secedit uses 0 = never expires AND 99999 = never expires depending on version
            max_age = 0 if (raw_max_age is None or raw_max_age <= 0 or raw_max_age >= 99998) else raw_max_age
            min_age = _sec("MinimumPasswordAge", 0)
            min_len = _sec("MinimumPasswordLength", 0)
            complexity = _sec("PasswordComplexity", None)
            history = _sec("PasswordHistorySize", None)
            lockout = _sec("LockoutBadCount", None)
            lockout_dur = _sec("LockoutDuration", None)   # -1 = admin unlock required
            reset_ctr = _sec("ResetLockoutCount", None)
            cleartext = _sec("ClearTextPassword", None)

            policies.append(NormalizedPasswordPolicy(
                policy_source="local_policy",
                policy_scope="host",
                policy_name="Local Security Policy",
                is_effective_policy=True,
                min_password_length=min_len,
                complexity_enabled=bool(complexity) if complexity is not None else None,
                password_history_count=history,
                max_password_age_days=max_age,
                min_password_age_days=min(_age if (_age := min_age) is not None else 0, 32767),
                lockout_threshold=lockout,
                lockout_duration_minutes=(
                    -1 if lockout_dur == -1
                    else lockout_dur if lockout_dur is not None
                    else None
                ),
                reset_lockout_counter_after_minutes=reset_ctr,
                reversible_encryption_enabled=bool(cleartext) if cleartext is not None else None,
                evidence_summary={
                    "source": "secedit /export /cfg",
                    "host": target.hostname,
                    "secedit_snippet": secedit_raw[:800],
                },
                confidence_score=90,
                account_exceptions=_account_exceptions(),
            ))

        # ── 2. AD Domain Password Policy (best-effort; fails on non-domain hosts) ──
        domain_data = _ps_json(r"""
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Get-ADDefaultDomainPasswordPolicy | Select-Object `
        @{n='MinPasswordLength';e={$_.MinPasswordLength}},
        @{n='PasswordHistoryCount';e={$_.PasswordHistoryCount}},
        @{n='MaxPasswordAgeDays';e={[int]$_.MaxPasswordAge.TotalDays}},
        @{n='MinPasswordAgeDays';e={[int]$_.MinPasswordAge.TotalDays}},
        @{n='LockoutDurationMinutes';e={[int]$_.LockoutDuration.TotalMinutes}},
        @{n='LockoutObservationMinutes';e={[int]$_.LockoutObservationWindow.TotalMinutes}},
        @{n='LockoutThreshold';e={$_.LockoutThreshold}},
        @{n='ComplexityEnabled';e={$_.ComplexityEnabled}},
        @{n='ReversibleEncryptionEnabled';e={$_.ReversibleEncryptionEnabled}},
        @{n='DistinguishedName';e={$_.DistinguishedName}} |
    ConvertTo-Json -Depth 2
} catch { Write-Output "ERROR: $($_.Exception.Message)" }
""")
        if isinstance(domain_data, dict) and "LockoutThreshold" in domain_data:
            raw_max = domain_data.get("MaxPasswordAgeDays", 0)
            max_age_d = 0 if raw_max >= 99998 else raw_max
            policies.append(NormalizedPasswordPolicy(
                policy_source="domain_policy",
                policy_scope="domain",
                policy_name="Default Domain Password Policy",
                is_effective_policy=not bool(policies),  # domain wins if no local found
                min_password_length=domain_data.get("MinPasswordLength"),
                complexity_enabled=domain_data.get("ComplexityEnabled"),
                password_history_count=domain_data.get("PasswordHistoryCount"),
                max_password_age_days=max_age_d,
                min_password_age_days=domain_data.get("MinPasswordAgeDays"),
                lockout_threshold=domain_data.get("LockoutThreshold"),
                lockout_duration_minutes=domain_data.get("LockoutDurationMinutes"),
                reset_lockout_counter_after_minutes=domain_data.get("LockoutObservationMinutes"),
                reversible_encryption_enabled=domain_data.get("ReversibleEncryptionEnabled"),
                evidence_summary={
                    "source": "Get-ADDefaultDomainPasswordPolicy",
                    "host": target.hostname,
                    "distinguished_name": domain_data.get("DistinguishedName", ""),
                },
                confidence_score=95,
            ))

        # ── 3. Fine-Grained Password Policies (best-effort) ───────────────────
        fgpp_data = _ps_json(r"""
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $pp = Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop
    if ($pp) {
        $pp | Select-Object Name, Precedence,
            @{n='MinPasswordLength';e={$_.MinPasswordLength}},
            @{n='PasswordHistoryCount';e={$_.PasswordHistoryCount}},
            @{n='MaxPasswordAgeDays';e={[int]$_.MaxPasswordAge.TotalDays}},
            @{n='MinPasswordAgeDays';e={[int]$_.MinPasswordAge.TotalDays}},
            @{n='LockoutThreshold';e={$_.LockoutThreshold}},
            @{n='LockoutDurationMinutes';e={[int]$_.LockoutDuration.TotalMinutes}},
            @{n='ComplexityEnabled';e={$_.ComplexityEnabled}},
            @{n='ReversibleEncryptionEnabled';e={$_.ReversibleEncryptionEnabled}},
            @{n='AppliesTo';e={($_.AppliesTo | ForEach-Object { $_.ToString() }) -join ","}} |
        ConvertTo-Json -Depth 2
    }
} catch { Write-Output "ERROR: $($_.Exception.Message)" }
""")
        if fgpp_data:
            fgpp_list = fgpp_data if isinstance(fgpp_data, list) else [fgpp_data]
            for fg in fgpp_list:
                if not isinstance(fg, dict) or "Name" not in fg:
                    continue
                raw_max = fg.get("MaxPasswordAgeDays", 0)
                max_age_fg = 0 if raw_max >= 99998 else raw_max
                policies.append(NormalizedPasswordPolicy(
                    policy_source="fine_grained_ad",
                    policy_scope="group",
                    policy_name=fg.get("Name", "FGPP"),
                    is_effective_policy=False,
                    precedence=fg.get("Precedence"),
                    applies_to={"type": "group_or_user", "name": fg.get("AppliesTo", "")},
                    min_password_length=fg.get("MinPasswordLength"),
                    complexity_enabled=fg.get("ComplexityEnabled"),
                    password_history_count=fg.get("PasswordHistoryCount"),
                    max_password_age_days=max_age_fg,
                    min_password_age_days=fg.get("MinPasswordAgeDays"),
                    lockout_threshold=fg.get("LockoutThreshold"),
                    lockout_duration_minutes=fg.get("LockoutDurationMinutes"),
                    reversible_encryption_enabled=fg.get("ReversibleEncryptionEnabled"),
                    evidence_summary={
                        "source": "Get-ADFineGrainedPasswordPolicy",
                        "host": target.hostname,
                        "precedence": fg.get("Precedence"),
                        "applies_to": fg.get("AppliesTo", ""),
                    },
                    confidence_score=90,
                ))

        # ── Fallback: return a stub if nothing collected ───────────────────────
        if not policies:
            policies = [NormalizedPasswordPolicy(
                policy_source="local_policy",
                policy_scope="host",
                policy_name="Local Security Policy",
                collection_error=(
                    "secedit did not return data and no AD module was available. "
                    "Ensure the scan account has local admin rights and secedit is accessible."
                ),
                confidence_score=0,
            )]

        return policies

    # ── Shared assembly logic ─────────────────────────────────────────────────

    @staticmethod
    def _assemble_collection(
        hostname: str,
        users_raw: list[dict],
        groups_data: dict,
        svcs_raw: list[dict],
        tasks_raw: list[dict],
        *,
        is_mock: bool,
        user_rights_data: dict | None = None,
        logon_types_data: dict | None = None,
    ) -> tuple[list[NormalizedAccount], list]:
        """
        Parse all raw data and build the canonical account list.
        Returns (accounts, probe_results).
        """
        # ── Unpack groups JSON ────────────────────────────────────────────
        groups_full: dict[str, list[dict]] = {}
        group_errors: dict[str, str] = {}
        nested_expanded: dict[str, list[dict] | None] = {}

        if isinstance(groups_data, dict) and "groups" in groups_data:
            raw_grps = groups_data.get("groups") or {}
            for g, members in raw_grps.items():
                if isinstance(members, list):
                    groups_full[g] = members
                elif members:
                    groups_full[g] = [members]
                else:
                    groups_full[g] = []
            group_errors = groups_data.get("errors") or {}
            raw_exp = groups_data.get("expanded") or {}
            for k, v in raw_exp.items():
                nested_expanded[k] = v if isinstance(v, list) else None

        # ── Build service / task entitlement indices (keyed by short name) ─
        svc_ents_by_short: dict[str, list[NormalizedEntitlement]] = {}
        svc_ents_by_full:  dict[str, list[NormalizedEntitlement]] = {}
        for svc in svcs_raw:
            if not svc or not svc.get("StartName"):
                continue
            start_name: str = svc["StartName"]
            short = _short(start_name)
            ent = NormalizedEntitlement(
                kind="windows_service_runas",
                name=svc.get("Name", ""),
                source="Win32_Service",
                attributes={
                    "run_as": start_name,
                    "state": svc.get("State"),
                    "start_mode": svc.get("StartMode"),
                    "display_name": svc.get("DisplayName"),
                },
            )
            svc_ents_by_short.setdefault(short, []).append(ent)
            svc_ents_by_full.setdefault(start_name, []).append(ent)

        task_ents_by_short: dict[str, list[NormalizedEntitlement]] = {}
        task_ents_by_full:  dict[str, list[NormalizedEntitlement]] = {}
        for task in tasks_raw:
            if not task or not task.get("UserId"):
                continue
            user_id: str = task["UserId"]
            short = _short(user_id)
            ent = NormalizedEntitlement(
                kind="windows_scheduled_task_runas",
                name=task.get("TaskName", ""),
                source="Get-ScheduledTask",
                attributes={
                    "run_as": user_id,
                    "run_level": task.get("RunLevel"),
                    "logon_type": task.get("LogonType"),
                    "task_path": task.get("TaskPath"),
                },
            )
            task_ents_by_short.setdefault(short, []).append(ent)
            task_ents_by_full.setdefault(user_id, []).append(ent)

        # ── Collect all group entitlements per principal key ──────────────
        # key:  local users  → short name
        #       domain users → full "DOMAIN\name"
        #       unresolved   → SID string
        grp_ents_by_key: dict[str, list[NormalizedEntitlement]] = {}
        # principal registry: key → {name, sid, source_type, principal_type, auth_source, domain, short}
        principals: dict[str, dict] = {}

        def _register(key: str, name: str, sid: str, info: _PInfo) -> None:
            if key and key not in principals:
                principals[key] = {
                    "name": name, "sid": sid,
                    "source_type": info.source_type,
                    "principal_type": info.principal_type,
                    "auth_source": info.auth_source,
                    "domain": info.domain,
                    "short": info.short,
                }

        def _add_ent(key: str, ent: NormalizedEntitlement) -> None:
            if key:
                grp_ents_by_key.setdefault(key, []).append(ent)

        # Direct group members
        for grp_name, members in groups_full.items():
            high_impact = grp_name in HIGH_IMPACT_GROUPS
            is_admin = grp_name == "Administrators"

            for m in members:
                if not m:
                    continue
                name: str = _coerce_str(m.get("Name") or "").strip()
                sid: str = _extract_sid(m.get("SID"))
                oc: str = _coerce_str(m.get("ObjectClass") or "User", _PS_OBJ_CLASS)
                ps: str = _coerce_str(m.get("PrincipalSource") or "Local", _PS_PRINCIPAL_SRC)

                if not name:
                    continue

                info = _classify_principal(name, sid, oc, ps, hostname)

                # Skip pure system well-known accounts (SYSTEM, LocalService, etc.)
                if info.source_type == "windows_system":
                    continue

                # Canonical dedup key
                if info.source_type in ("windows_local", "windows_builtin"):
                    key = info.short
                elif info.source_type == "windows_unresolved":
                    key = sid or name
                else:
                    key = name  # full DOMAIN\name for domain principals

                _register(key, name, sid, info)
                _add_ent(key, NormalizedEntitlement(
                    kind="windows_local_group",
                    name=grp_name,
                    source=f"Get-LocalGroupMember:{hostname}\\{grp_name}",
                    inherited=False,
                    via=None,
                    attributes={
                        "high_impact": high_impact,
                        "is_administrators": is_admin,
                        "direct": True,
                        "member_sid": sid,
                        "principal_source": ps,
                        "object_class": oc,
                        "domain_admin_path": _is_domain_admin_group(name) and is_admin,
                    },
                ))

        # Nested expanded members (domain group → individual AD users)
        for domain_grp, members in nested_expanded.items():
            if not members:
                continue

            # Which local groups contain this domain group?
            containing: list[tuple[str, bool]] = []   # (local_group, is_high_impact)
            for grp_name, grp_members in groups_full.items():
                for m in grp_members:
                    if (m.get("Name") or "").lower() == domain_grp.lower():
                        containing.append((grp_name, grp_name in HIGH_IMPACT_GROUPS))

            if not containing:
                continue

            is_dap = _is_domain_admin_group(domain_grp)
            dom = _domain_of(domain_grp) or ""

            for m in members:
                mem_name: str = (m.get("Name") or m.get("SamAccountName") or "").strip()
                mem_sid: str  = _extract_sid(m.get("SID") or m.get("sid"))
                mem_oc: str   = _coerce_str(
                    m.get("objectClass") or m.get("ObjectClass") or "user",
                    _PS_OBJ_CLASS,
                ).lower()

                if not mem_name:
                    continue

                if mem_oc == "computer":
                    st = "windows_computer"
                    pt = PrincipalType.unknown
                elif mem_oc == "group":
                    st = "windows_domain_group"
                    pt = PrincipalType.unknown
                else:
                    st = "windows_gmsa" if mem_name.endswith("$") else "windows_domain_user"
                    pt = PrincipalType.service if st == "windows_gmsa" else PrincipalType.human

                # Build full name: reuse existing DOMAIN\ prefix if present
                full_name = mem_name if "\\" in mem_name else (f"{dom}\\{mem_name}" if dom else mem_name)
                short = _short(full_name)
                key = full_name

                _register(key, full_name, mem_sid, _PInfo(st, pt, AuthSource.ad, dom or None, short))

                for cont_grp, cont_high in containing:
                    cont_is_admin = cont_grp == "Administrators"
                    _add_ent(key, NormalizedEntitlement(
                        kind="windows_local_group",
                        name=cont_grp,
                        source=f"Get-ADGroupMember:{domain_grp}",
                        inherited=True,
                        via=domain_grp,
                        attributes={
                            "high_impact": cont_high,
                            "is_administrators": cont_is_admin,
                            "direct": False,
                            "domain_admin_path": is_dap and cont_is_admin,
                            "privilege_path": [domain_grp, cont_grp],
                            "member_sid": mem_sid,
                            "principal_source": "ActiveDirectory",
                        },
                    ))

        # ── Emit local accounts (from Get-LocalUser) ──────────────────────
        accounts: list[NormalizedAccount] = []
        emitted: set[str] = set()

        for u in users_raw:
            if not u or not u.get("Name"):
                continue
            name: str = u["Name"].strip()
            sid: str  = _extract_sid(u.get("SID"))
            enabled = _ps_bool(u.get("Enabled", True))
            pwd_never = _ps_bool(u.get("PasswordNeverExpires", False))
            pwd_required = _ps_bool(u.get("PasswordRequired", True))
            last_logon = _windate(u.get("LastLogon")) or (
                last_login_days_ago(f"{hostname}:{name}") if is_mock else None
            )
            pwd_last_set = _windate(u.get("PasswordLastSet"))
            # Get-LocalUser returns LastLogon=$null for accounts that have never
            # logged on to the local SAM — positive "never" evidence in live mode.
            never_logged = (u.get("LastLogon") in (None, "")) if not is_mock else None
            description: str = u.get("Description") or ""

            info = _classify_principal(name, sid, "User", "Local", hostname)
            key = info.short

            ents: list[NormalizedEntitlement] = []
            ents += grp_ents_by_key.get(key, [])
            ents += svc_ents_by_short.get(key, [])
            ents += task_ents_by_short.get(key, [])

            if info.principal_type == PrincipalType.service:
                ents.append(NormalizedEntitlement(
                    kind="windows_identity",
                    name="service_account",
                    source="Get-LocalUser",
                    attributes={"source_type": info.source_type, "sid": sid},
                ))

            accounts.append(NormalizedAccount(
                account_name=name,
                source_type=info.source_type,
                principal_type=info.principal_type,
                auth_source=info.auth_source,
                enabled_status=EnabledStatus.enabled if enabled else EnabledStatus.disabled,
                # interactive_status is overwritten below by _apply_interactive_classification
                interactive_status=InteractiveStatus.unknown,
                last_login=last_logon,
                last_login_source="Get-LocalUser.LastLogon",
                password_last_changed=pwd_last_set,
                never_logged_in=never_logged,
                is_shared=(name in _BUILTIN_LOCAL_NAMES),
                password_never_expires=pwd_never,
                evidence_summary={
                    "sid": sid,
                    "description": description,
                    "password_required": pwd_required,
                    "pwd_never_expires": pwd_never,
                    "is_local": True,
                    "principal_source": "Local",
                },
                entitlements=ents,
            ))
            emitted.add(key)

        # ── Emit domain / gMSA / computer / unresolved accounts ───────────
        for key, pdata in principals.items():
            if key in emitted:
                continue  # Local user already emitted above

            st = pdata["source_type"]
            # Skip pure well-known system principals (not useful as individual rows)
            if st == "windows_system":
                continue

            pt: PrincipalType = pdata["principal_type"]
            auth: AuthSource  = pdata["auth_source"]
            name: str         = pdata["name"]
            sid: str          = pdata["sid"]
            domain: str       = pdata["domain"] or ""
            short: str        = pdata["short"]

            ents: list[NormalizedEntitlement] = list(grp_ents_by_key.get(key, []))
            ents += svc_ents_by_short.get(short, [])
            ents += task_ents_by_short.get(short, [])

            # Identity markers for specialist types
            if st == "windows_gmsa":
                ents.append(NormalizedEntitlement(
                    kind="windows_identity",
                    name="gMSA",
                    source="Get-LocalGroupMember",
                    attributes={"source_type": "windows_gmsa", "sid": sid, "domain": domain},
                ))
            elif st == "windows_unresolved":
                orphan_groups = [e.name for e in ents if e.kind == "windows_local_group"]
                ents.append(NormalizedEntitlement(
                    kind="windows_unresolved_sid",
                    name=sid or name,
                    source="Get-LocalGroupMember",
                    attributes={
                        "sid": sid,
                        "groups": orphan_groups,
                        "high_impact": any(g in HIGH_IMPACT_GROUPS for g in orphan_groups),
                    },
                ))
            elif st == "windows_computer":
                ents.append(NormalizedEntitlement(
                    kind="windows_identity",
                    name="computer_account",
                    source="Get-LocalGroupMember",
                    attributes={"source_type": "windows_computer", "sid": sid, "domain": domain},
                ))

            accounts.append(NormalizedAccount(
                account_name=name,
                source_type=st,
                principal_type=pt,
                auth_source=auth,
                enabled_status=EnabledStatus.unknown,
                # interactive_status overwritten below
                interactive_status=InteractiveStatus.unknown,
                last_login=None,
                last_login_source=None,
                is_shared=(st == "windows_domain_group"),
                password_never_expires=False,
                evidence_summary={
                    "sid": sid,
                    "domain": domain,
                    "is_local": False,
                    "principal_source": (
                        "ActiveDirectory" if auth == AuthSource.ad else "Unknown"
                    ),
                },
                entitlements=ents,
            ))
            emitted.add(key)

        # ── Emit domain service/task accounts not in any local group ──────
        # (e.g., CORP\svc_app1 runs a service but is not a local group member)
        for full_name, ent_list in {**svc_ents_by_full, **task_ents_by_full}.items():
            upper = full_name.upper()
            if (upper.startswith("NT AUTHORITY\\") or upper.startswith("NT SERVICE\\")
                    or upper in ("LOCALSYSTEM", "LOCAL SYSTEM")):
                continue
            short = _short(full_name)
            dom = _domain_of(full_name)
            if not dom:
                continue   # Local accounts handled via Get-LocalUser
            # HOSTNAME\user is also a local account — already emitted via Get-LocalUser
            if dom.upper() == hostname.upper():
                continue
            key = full_name
            if key in emitted:
                continue

            ents = list(svc_ents_by_full.get(full_name, []))
            ents += task_ents_by_full.get(full_name, [])
            is_svc = _infer_service_type(short) or short.endswith("$")
            st = "windows_gmsa" if short.endswith("$") else "windows_domain_user"
            pt = PrincipalType.service if is_svc else PrincipalType.human

            if st == "windows_gmsa":
                ents.append(NormalizedEntitlement(
                    kind="windows_identity",
                    name="gMSA",
                    source="Win32_Service/Get-ScheduledTask",
                    attributes={"source_type": "windows_gmsa", "domain": dom},
                ))

            accounts.append(NormalizedAccount(
                account_name=full_name,
                source_type=st,
                principal_type=pt,
                auth_source=AuthSource.ad,
                enabled_status=EnabledStatus.unknown,
                # interactive_status overwritten below
                interactive_status=InteractiveStatus.unknown,
                last_login=None,
                last_login_source=None,
                is_shared=False,
                password_never_expires=False,
                evidence_summary={
                    "domain": dom,
                    "is_local": False,
                    "discovered_via": "service_or_task_runas",
                },
                entitlements=ents,
            ))
            emitted.add(key)

        # ── Interactive classification pass ───────────────────────────────
        urd = user_rights_data or {}
        ltd = logon_types_data or {}
        for acc in accounts:
            _apply_interactive_classification(acc, urd, ltd)

        # ── Build probe results ───────────────────────────────────────────
        probe_results = [
            probe("get_localusers",
                  "Get-LocalUser | Select Name,SID,Enabled,PasswordRequired,PasswordNeverExpires,LastLogon,Description,PasswordLastSet",
                  users_raw),
            probe("get_localgroups_members",
                  "Get-LocalGroupMember (with nested AD expansion)",
                  {"groups": {g: len(m) for g, m in groups_full.items()},
                   "enumeration_errors": group_errors,
                   "nested_groups_expanded": list(nested_expanded.keys())}),
            probe("services_runas",
                  "Get-CimInstance Win32_Service | Select Name,StartName,State,StartMode",
                  {s["Name"]: s.get("StartName") for s in svcs_raw if s and s.get("Name")}),
            probe("scheduled_tasks_runas",
                  "Get-ScheduledTask | Select TaskName,Principal",
                  {t["TaskName"]: t.get("UserId") for t in tasks_raw if t and t.get("TaskName")}),
            probe("user_rights_assignment",
                  "secedit /export /areas USER_RIGHTS",
                  {k: len(v) for k, v in urd.items()} if urd else None),
            probe("logon_type_history",
                  "Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 10000",
                  {"accounts_with_events": len(ltd)} if ltd else None),
        ]

        return accounts, probe_results
