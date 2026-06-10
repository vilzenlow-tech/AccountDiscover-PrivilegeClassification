"""Windows discovery scanner for connector-agent jobs.

The backend has a richer Windows collector for in-console scans.  The agent
cannot import that package when deployed standalone, so this module keeps a
small WinRM implementation that emits a stable JSON-friendly result contract.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable


class WindowsScanError(RuntimeError):
    """Raised when a Windows target cannot be scanned."""


@dataclass(frozen=True)
class WindowsCredential:
    username: str
    secret: str
    auth_method: str = "password"
    extra: dict[str, Any] | None = None


def credential_from_payload(target: dict, payload: dict) -> WindowsCredential | None:
    """Resolve transient credential material from job payload.

    Supported shapes are intentionally permissive because jobs may be created
    manually today:
      {"credential": {"username": "...", "secret": "..."}}
      {"credentials": {"windows": {...}}}
      target["credential"] / target["credentials"]
    """
    candidates = [
        target.get("credential"),
        target.get("credentials"),
        payload.get("credential"),
        payload.get("credentials", {}).get("windows") if isinstance(payload.get("credentials"), dict) else None,
        payload.get("credentials"),
    ]
    for item in candidates:
        if not isinstance(item, dict):
            continue
        username = item.get("username") or item.get("user")
        secret = item.get("secret") or item.get("password") or item.get("token")
        if username and secret:
            return WindowsCredential(
                username=str(username),
                secret=str(secret),
                auth_method=str(item.get("auth_method") or item.get("method") or "password"),
                extra=dict(item.get("extra") or {}),
            )
    return None


def scan_options(target: dict, payload: dict) -> dict[str, Any]:
    options: dict[str, Any] = {}
    if isinstance(payload.get("options"), dict):
        options.update(payload["options"])
    if isinstance(target.get("options"), dict):
        options.update(target["options"])
    return options


class WindowsScanner:
    """Collect local Windows users, groups, services and scheduled-task run-as."""

    def __init__(self, session_factory: Callable[..., Any] | None = None) -> None:
        self._session_factory = session_factory

    def scan(self, target: dict, payload: dict) -> dict:
        credential = credential_from_payload(target, payload)
        if not credential:
            raise WindowsScanError("Windows credentialed discovery requires username and secret in the job payload")

        options = scan_options(target, payload)
        host = target.get("ip_address") or target.get("hostname")
        if not host:
            raise WindowsScanError("Windows target requires hostname or ip_address")

        session = self._make_session(str(host), target, options, credential)
        started = time.monotonic()

        users = _as_list(self._run_json(session, _PS_USERS))
        groups = _as_dict(self._run_json(session, _PS_GROUPS))
        services = _as_list(self._run_json(session, _PS_SERVICES))
        tasks = _as_list(self._run_json(session, _PS_TASKS))
        user_rights = self._run_best_effort_dict(session, _PS_USER_RIGHTS)
        logon_types = self._run_best_effort_dict(session, _PS_LOGON_TYPES)

        hostname = str(groups.get("hostname") or target.get("hostname") or host)
        accounts = build_accounts(hostname, users, groups, services, tasks, user_rights, logon_types)
        duration_ms = int((time.monotonic() - started) * 1000)

        return {
            "asset_id": target.get("asset_id"),
            "hostname": hostname,
            "platform": "windows",
            "status": "success",
            "accounts_discovered": len(accounts),
            "accounts": accounts,
            "evidence": {
                "collector": "connector-agent.winrm",
                "probes": {
                    "local_users": len(users),
                    "local_groups": len(groups.get("groups") or {}),
                    "services_runas": len(services),
                    "scheduled_tasks_runas": len(tasks),
                    "user_rights": len(user_rights),
                    "logon_type_accounts": len(logon_types),
                },
                "duration_ms": duration_ms,
            },
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    def _make_session(
        self,
        host: str,
        target: dict,
        options: dict[str, Any],
        credential: WindowsCredential,
    ) -> Any:
        if self._session_factory:
            return self._session_factory(host=host, target=target, options=options, credential=credential)
        try:
            import winrm
        except ImportError as exc:
            raise WindowsScanError("pywinrm package is not installed on the connector agent") from exc

        scheme = str(options.get("winrm_scheme") or "http")
        default_port = 5986 if scheme == "https" else 5985
        port = int(target.get("port") or options.get("winrm_port") or default_port)
        transport = str(options.get("winrm_transport") or "ntlm")
        cert_validation = str(options.get("winrm_cert_validation") or "ignore")
        return winrm.Session(
            target=f"{scheme}://{host}:{port}/wsman",
            auth=(credential.username, credential.secret),
            transport=transport,
            server_cert_validation=cert_validation,
            read_timeout_sec=int(options.get("winrm_read_timeout") or 60),
            operation_timeout_sec=int(options.get("winrm_op_timeout") or 50),
        )

    def _run_json(self, session: Any, script: str) -> Any:
        result = session.run_ps(script)
        status_code = int(getattr(result, "status_code", 0))
        stderr = getattr(result, "std_err", b"") or b""
        if status_code != 0:
            msg = stderr.decode("utf-8", errors="replace").strip()
            raise WindowsScanError(msg or f"PowerShell probe failed with exit code {status_code}")
        raw = (getattr(result, "std_out", b"") or b"").decode("utf-8", errors="replace").strip()
        if not raw or raw.lower() == "null":
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise WindowsScanError("PowerShell probe returned invalid JSON") from exc

    def _run_best_effort_dict(self, session: Any, script: str) -> dict:
        try:
            return _as_dict(self._run_json(session, script))
        except Exception:
            return {}


def build_accounts(
    hostname: str,
    users: list[dict],
    groups_data: dict,
    services: list[dict],
    tasks: list[dict],
    user_rights_data: dict | None = None,
    logon_types_data: dict | None = None,
) -> list[dict]:
    accounts: dict[str, dict] = {}
    user_rights_data = user_rights_data or {}
    logon_types_data = logon_types_data or {}

    def ensure(name: str, source_type: str = "windows") -> dict:
        key = name.lower()
        if key not in accounts:
            accounts[key] = {
                "account_name": name,
                "source_type": source_type,
                "principal_type": "unknown",
                "auth_source": "unknown",
                "enabled_status": "unknown",
                "interactive_status": "unknown",
                "password_never_expires": False,
                "evidence_summary": {},
                "entitlements": [],
            }
        return accounts[key]

    for user in users:
        name = str(user.get("Name") or "").strip()
        if not name:
            continue
        qualified = name if "\\" in name else f"{hostname}\\{name}"
        account = ensure(qualified)
        account.update({
            "principal_type": _principal_type(name, user),
            "auth_source": "local",
            "enabled_status": _enabled_status(user.get("Enabled")),
            "last_login": user.get("LastLogon"),
            "password_never_expires": bool(user.get("PasswordNeverExpires")),
            "evidence_summary": {
                "sid": _sid_value(user.get("SID")),
                "description": user.get("Description"),
                "password_required": user.get("PasswordRequired"),
                "password_last_set": user.get("PasswordLastSet"),
            },
        })

    group_map = groups_data.get("groups") if isinstance(groups_data.get("groups"), dict) else {}
    for group_name, members in group_map.items():
        if not isinstance(members, list):
            continue
        for member in members:
            if not isinstance(member, dict):
                continue
            name = str(member.get("Name") or member.get("SID") or "").strip()
            if not name:
                continue
            name = _qualify_local_name(hostname, name)
            account = ensure(name)
            source = member.get("PrincipalSource")
            account["auth_source"] = _auth_source(source, name)
            account["principal_type"] = _member_principal_type(member)
            account["principal_source"] = _principal_source(source)
            account["evidence_summary"].setdefault("sid", _sid_value(member.get("SID")))
            account["entitlements"].append({
                "kind": "windows_local_group",
                "name": str(group_name),
                "scope": hostname,
                "source": "Get-LocalGroupMember",
                "inherited": False,
                "attributes": {
                    "sid": _sid_value(member.get("SID")),
                    "object_class": member.get("ObjectClass"),
                    "principal_source": _principal_source(source),
                },
            })

    for service in services:
        run_as = _interesting_run_as(service.get("StartName"))
        if not run_as:
            continue
        account = ensure(run_as)
        account["principal_type"] = "service"
        account["interactive_status"] = "service_or_batch_only"
        account["entitlements"].append({
            "kind": "windows_service_logon",
            "name": str(service.get("Name") or service.get("DisplayName") or "service"),
            "scope": hostname,
            "source": "Win32_Service",
            "attributes": {
                "display_name": service.get("DisplayName"),
                "state": service.get("State"),
                "start_mode": service.get("StartMode"),
            },
        })

    for task in tasks:
        run_as = _interesting_run_as(task.get("UserId"))
        if not run_as:
            continue
        account = ensure(run_as)
        account["principal_type"] = "service"
        account["interactive_status"] = "service_or_batch_only"
        account["entitlements"].append({
            "kind": "windows_scheduled_task",
            "name": f"{task.get('TaskPath') or ''}{task.get('TaskName') or 'task'}",
            "scope": hostname,
            "source": "ScheduledTasks",
            "attributes": {
                "run_level": task.get("RunLevel"),
                "logon_type": task.get("LogonType"),
            },
            })

    _apply_interactive_classification(hostname, accounts, user_rights_data, logon_types_data)

    return list(accounts.values())


def _as_list(value: Any) -> list[dict]:
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _as_dict(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def _enabled_status(value: Any) -> str:
    if value is True:
        return "enabled"
    if value is False:
        return "disabled"
    return "unknown"


def _principal_type(name: str, user: dict) -> str:
    lower = name.lower()
    if lower in {"administrator", "guest"}:
        return "built_in"
    if lower.endswith("$"):
        return "application"
    if "svc" in lower or "service" in lower:
        return "service"
    if user.get("PasswordRequired") is False:
        return "built_in"
    return "human"


def _member_principal_type(member: dict) -> str:
    name = str(member.get("Name") or "")
    object_class = str(member.get("ObjectClass") or "").lower()
    if object_class == "group":
        return "unknown"
    if name.endswith("$"):
        return "application"
    if object_class == "user":
        return "human"
    return "unknown"


def _auth_source(principal_source: Any, name: str) -> str:
    source = _principal_source(principal_source).lower()
    if source == "local":
        return "local"
    if source == "activedirectory" or ("\\" in name and not name.upper().startswith("NT ")):
        return "ad"
    return "unknown"


def _principal_source(value: Any) -> str:
    if isinstance(value, int):
        return {
            0: "unknown",
            1: "local",
            2: "activedirectory",
            3: "microsoftaccount",
            4: "azuread",
        }.get(value, "unknown")
    return str(value or "unknown")


def _sid_value(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        raw = value.get("Value") or value.get("value")
        return str(raw) if raw else None
    return str(value)


def _interesting_run_as(value: Any) -> str | None:
    if not value:
        return None
    name = str(value).strip()
    upper = name.upper()
    if upper in {"LOCAL SYSTEM", "NT AUTHORITY\\SYSTEM", "NT AUTHORITY\\LOCAL SERVICE", "NT AUTHORITY\\NETWORK SERVICE"}:
        return None
    if upper.startswith("NT SERVICE\\"):
        return None
    return name


def _qualify_local_name(hostname: str, name: str) -> str:
    """Qualify bare local account names returned by net localgroup fallback."""
    if "\\" in name or "@" in name:
        return name
    upper = name.upper()
    if upper.startswith("S-1-") or upper in {
        "SYSTEM",
        "LOCAL SERVICE",
        "NETWORK SERVICE",
        "LOCAL SYSTEM",
    }:
        return name
    return f"{hostname}\\{name}"


_GROUP_RIGHT_SIDS = {
    "Administrators": "S-1-5-32-544",
    "Backup Operators": "S-1-5-32-551",
    "Remote Desktop Users": "S-1-5-32-555",
    "Users": "S-1-5-32-545",
}


def _apply_interactive_classification(
    hostname: str,
    accounts: dict[str, dict],
    user_rights_data: dict,
    logon_types_data: dict,
) -> None:
    group_membership: dict[str, set[str]] = {}
    for account in accounts.values():
        groups = {
            ent.get("name")
            for ent in account.get("entitlements", [])
            if ent.get("kind") == "windows_local_group" and ent.get("name")
        }
        group_membership[account["account_name"].lower()] = {str(g) for g in groups}

    for account in accounts.values():
        account_name = account["account_name"]
        short_name = account_name.split("\\")[-1]
        sid = _sid_value((account.get("evidence_summary") or {}).get("sid"))
        groups = group_membership.get(account_name.lower(), set())
        rights = _rights_for_account(sid, groups, user_rights_data)
        logon_types = _logon_types_for_account(hostname, account_name, short_name, logon_types_data)
        runs_service = any(ent.get("kind") == "windows_service_logon" for ent in account.get("entitlements", []))
        runs_task = any(ent.get("kind") == "windows_scheduled_task" for ent in account.get("entitlements", []))

        classification = _classify_interactive(
            principal_type=str(account.get("principal_type") or "unknown"),
            account_name=account_name,
            rights=rights,
            user_rights_available=bool(user_rights_data),
            logon_types=logon_types,
            event_log_available=bool(logon_types_data),
            runs_service=runs_service,
            runs_task=runs_task,
        )
        account.update(classification)


def _rights_for_account(sid: str | None, groups: set[str], user_rights_data: dict) -> dict[str, bool]:
    effective_ids = {sid} if sid else set()
    for group in groups:
        group_sid = _GROUP_RIGHT_SIDS.get(group)
        if group_sid:
            effective_ids.add(group_sid)

    def has(right: str) -> bool:
        values = {str(v).strip().lstrip("*") for v in user_rights_data.get(right, [])}
        return bool(effective_ids & values)

    return {
        "interactive": has("SeInteractiveLogonRight"),
        "rdp": has("SeRemoteInteractiveLogonRight"),
        "deny_interactive": has("SeDenyInteractiveLogonRight"),
        "deny_rdp": has("SeDenyRemoteInteractiveLogonRight"),
        "service": has("SeServiceLogonRight"),
        "batch": has("SeBatchLogonRight"),
        "network": has("SeNetworkLogonRight"),
    }


def _logon_types_for_account(hostname: str, account_name: str, short_name: str, logon_types_data: dict) -> list[int]:
    candidates = {
        account_name,
        short_name,
        f"{hostname}\\{short_name}",
        account_name.upper(),
        short_name.upper(),
        f"{hostname}\\{short_name}".upper(),
    }
    for key, value in logon_types_data.items():
        if str(key) in candidates or str(key).upper() in candidates:
            if isinstance(value, list):
                return sorted({int(v) for v in value if str(v).isdigit() or isinstance(v, int)})
    return []


def _classify_interactive(
    *,
    principal_type: str,
    account_name: str,
    rights: dict[str, bool],
    user_rights_available: bool,
    logon_types: list[int],
    event_log_available: bool,
    runs_service: bool,
    runs_task: bool,
) -> dict:
    both_denied = rights["deny_interactive"] and rights["deny_rdp"]
    has_interactive = rights["interactive"] or rights["rdp"]
    has_service_batch = rights["service"] or rights["batch"]
    last_type = logon_types[-1] if logon_types else None

    base = {
        "win_interactive_evidence": {
            "user_rights_available": user_rights_available,
            "event_log_available": event_log_available,
            "observed_logon_types": logon_types,
            "runs_service": runs_service,
            "runs_scheduled_task": runs_task,
        },
        "win_allows_local_logon": rights["interactive"] if user_rights_available else None,
        "win_allows_remote_interactive": rights["rdp"] if user_rights_available else None,
        "win_allows_service_logon": rights["service"] if user_rights_available else None,
        "win_allows_batch_logon": rights["batch"] if user_rights_available else None,
        "win_allows_network_logon": rights["network"] if user_rights_available else None,
        "win_last_observed_logon_type": last_type,
        "win_review_required_reason": None,
    }

    if account_name.endswith("$") or principal_type == "application":
        return {
            **base,
            "interactive_status": "service_or_batch_only",
            "win_interactive_confidence": 93,
            "win_interactive_detection_method": "account_identity",
            "win_allows_local_logon": False,
            "win_allows_remote_interactive": False,
        }
    if both_denied:
        return {
            **base,
            "interactive_status": "non_interactive_only",
            "win_interactive_confidence": 97,
            "win_interactive_detection_method": "user_rights_assignment",
            "win_allows_local_logon": False,
            "win_allows_remote_interactive": False,
        }
    if user_rights_available and has_interactive:
        return {
            **base,
            "interactive_status": "interactive_capable",
            "win_interactive_confidence": 95,
            "win_interactive_detection_method": "user_rights_assignment",
        }
    if user_rights_available and has_service_batch:
        return {
            **base,
            "interactive_status": "service_or_batch_only",
            "win_interactive_confidence": 80,
            "win_interactive_detection_method": "user_rights_assignment",
            "win_allows_local_logon": False,
            "win_allows_remote_interactive": False,
        }

    interactive_obs = bool({2, 10, 11} & set(logon_types))
    service_obs = bool({4, 5} & set(logon_types))
    network_obs = bool({3, 8, 9} & set(logon_types))
    if event_log_available and interactive_obs:
        return {
            **base,
            "interactive_status": "interactive_capable",
            "win_interactive_confidence": 97,
            "win_interactive_detection_method": "event_log_4624",
            "win_allows_local_logon": 2 in logon_types or 11 in logon_types,
            "win_allows_remote_interactive": 10 in logon_types,
            "win_allows_service_logon": service_obs,
            "win_allows_network_logon": network_obs,
        }
    if event_log_available and service_obs and not interactive_obs:
        return {
            **base,
            "interactive_status": "service_or_batch_only",
            "win_interactive_confidence": 88,
            "win_interactive_detection_method": "event_log_4624",
            "win_allows_service_logon": 5 in logon_types,
            "win_allows_batch_logon": 4 in logon_types,
            "win_allows_local_logon": False,
            "win_allows_remote_interactive": False,
        }
    if event_log_available and network_obs and not service_obs:
        return {
            **base,
            "interactive_status": "network_only",
            "win_interactive_confidence": 82,
            "win_interactive_detection_method": "event_log_4624",
            "win_allows_network_logon": True,
            "win_allows_local_logon": False,
            "win_allows_remote_interactive": False,
        }
    if runs_service or runs_task:
        return {
            **base,
            "interactive_status": "service_or_batch_only",
            "win_interactive_confidence": 72 if runs_service and runs_task else 65 if runs_service else 60,
            "win_interactive_detection_method": "service_task_runas",
        }
    return {
        **base,
        "interactive_status": "unknown_review_required",
        "win_interactive_confidence": 30,
        "win_interactive_detection_method": "insufficient_data",
        "win_review_required_reason": "No user-rights, event-log, service, or scheduled-task evidence established interactive capability.",
    }


_PS_USERS = r"""
Get-LocalUser | Select-Object Name,SID,Enabled,PasswordRequired,PasswordNeverExpires,LastLogon,Description,PasswordLastSet |
ConvertTo-Json -Depth 4 -Compress
"""

_PS_GROUPS = r"""
function Convert-NetLocalGroupMember {
  param([string]$GroupName)
  $raw = net localgroup $GroupName 2>$null
  $members = @()
  $inMembers = $false
  foreach ($line in $raw) {
    $trimmed = $line.Trim()
    if ($trimmed -match '^-{3,}$') {
      $inMembers = -not $inMembers
      continue
    }
    if (-not $inMembers) { continue }
    if (-not $trimmed) { continue }
    if ($trimmed -match 'command completed successfully') { continue }
    $members += [PSCustomObject]@{
      Name = $trimmed
      SID = $null
      ObjectClass = "Unknown"
      PrincipalSource = "Unknown"
      FallbackSource = "net localgroup"
    }
  }
  return $members
}

$out = [ordered]@{ hostname = $env:COMPUTERNAME; groups = [ordered]@{}; errors = [ordered]@{} }
Get-LocalGroup | ForEach-Object {
  $group = $_.Name
  try {
    $out.groups[$group] = @(Get-LocalGroupMember -Group $group | Select-Object Name,SID,ObjectClass,PrincipalSource)
  } catch {
    $out.errors[$group] = $_.Exception.Message
    $out.groups[$group] = @(Convert-NetLocalGroupMember -GroupName $group)
  }
}
$out | ConvertTo-Json -Depth 6 -Compress
"""

_PS_SERVICES = r"""
Get-CimInstance Win32_Service |
Select-Object Name,DisplayName,StartName,State,StartMode |
ConvertTo-Json -Depth 4 -Compress
"""

_PS_TASKS = r"""
Get-ScheduledTask | ForEach-Object {
  [PSCustomObject]@{
    TaskName = $_.TaskName
    TaskPath = $_.TaskPath
    UserId = $_.Principal.UserId
    RunLevel = [string]$_.Principal.RunLevel
    LogonType = [string]$_.Principal.LogonType
  }
} | ConvertTo-Json -Depth 4 -Compress
"""

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
      $rights[$key] = @($val -split ',' | ForEach-Object { $_.Trim().TrimStart('*') } | Where-Object { $_ -ne '' })
    }
  }
  $rights | ConvertTo-Json -Compress
} catch { '{}' }
finally { if (Test-Path $tmp) { Remove-Item $tmp -Force -EA SilentlyContinue } }
"""

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
"""
