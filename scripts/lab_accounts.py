#!/usr/bin/env python3
"""Lab account seed/cleanup helpers for ADPCT integration testing."""
from __future__ import annotations

import argparse
import os
import shlex
import socket
import sys
from getpass import getpass


ALLOWED_LAB_TARGETS = {"192.168.7.130", "192.168.7.131"}
RHEL_DEFAULT_HOST = "192.168.7.130"
WIN_DEFAULT_HOST = "192.168.7.131"
LAB_PASSWORD_ENV = "LAB_TARGET_PASSWORD"

RHEL_ACCOUNTS = (
    "adt_linux_interactive",
    "adt_linux_noninteractive",
    "adt_linux_service",
    "adt_linux_app",
    "adt_linux_generic",
    "adt_linux_disabled",
    "adt_linux_expired",
    "adt_linux_pwd_expired",
    "adt_linux_pwd_never_expire",
    "adt_linux_sudo",
    "adt_linux_never_login",
    "adt_linux_no_owner",
)

WINDOWS_ACCOUNTS = (
    "adt_win_interactive",
    "adt_win_local_admin",
    "adt_win_disabled",
    "adt_win_pwd_no_exp",
    "adt_win_pwd_expired",
    "adt_win_service",
    "adt_win_sched_task",
    "adt_win_generic",
    "adt_win_never_login",
    "adt_win_no_owner",
)

MYSQL_ACCOUNTS = (
    "adt_mysql_interactive",
    "adt_mysql_interactive_expired",
    "adt_mysql_svc_expired",
    "adt_mysql_interactive_expiring",
    "adt_mysql_app_expiring",
    "adt_mysql_admin",
    "adt_mysql_app_rw",
    "adt_mysql_readonly",
    "adt_mysql_backup_svc",
    "adt_mysql_locked",
    "adt_mysql_generic",
)
MYSQL_EXPECTED_ACCOUNT_NAMES = tuple(f"{name}@%" for name in MYSQL_ACCOUNTS)

MONGO_ACCOUNTS = (
    "adt_mongo_interactive",
    "adt_mongo_root_admin",
    "adt_mongo_backup_svc",
    "adt_mongo_monitor",
    "adt_mongo_app_rw",
    "adt_mongo_app_owner",
    "adt_mongo_generic",
)
MONGO_EXPECTED_ACCOUNT_NAMES = (
    "adt_mongo_interactive@admin",
    "adt_mongo_root_admin@admin",
    "adt_mongo_backup_svc@admin",
    "adt_mongo_monitor@admin",
    "adt_mongo_app_rw@adpct_lab_app",
    "adt_mongo_app_owner@adpct_lab_app",
    "adt_mongo_generic@admin",
)


class LabSafetyError(RuntimeError):
    """Raised when a requested target is outside the controlled lab range."""


def require_lab_target(host: str, allow_non_lab: bool = False) -> str:
    if host in ALLOWED_LAB_TARGETS or allow_non_lab:
        return host
    raise LabSafetyError(
        f"{host} is not an allowed lab target. Set ALLOW_NON_LAB_TARGET=true "
        "only for an explicitly approved non-production test host."
    )


def is_reachable(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _allow_non_lab_from_env() -> bool:
    return os.getenv("ALLOW_NON_LAB_TARGET", "").strip().lower() == "true"


def _quote_ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _remote_password(args: argparse.Namespace, env_name: str) -> str:
    password = os.getenv(env_name) or os.getenv(LAB_PASSWORD_ENV)
    if password:
        return password
    if not sys.stdin.isatty():
        raise RuntimeError(f"{env_name} is not set and no TTY is available for password input.")
    return getpass("Lab target password: ")


def build_rhel_seed_plan() -> list[str]:
    users = {
        "adt_linux_interactive": ("/bin/bash", "ADPCT lab interactive owner=iam"),
        "adt_linux_noninteractive": ("/sbin/nologin", "ADPCT lab noninteractive owner=iam"),
        "adt_linux_service": ("/sbin/nologin", "ADPCT lab service owner=platform"),
        "adt_linux_app": ("/bin/false", "ADPCT lab application owner=appteam"),
        "adt_linux_generic": ("/bin/bash", "ADPCT lab shared generic owner=unknown"),
        "adt_linux_disabled": ("/bin/bash", "ADPCT lab disabled owner=iam"),
        "adt_linux_expired": ("/bin/bash", "ADPCT lab expired owner=iam"),
        "adt_linux_pwd_expired": ("/bin/bash", "ADPCT lab password expired owner=iam"),
        "adt_linux_pwd_never_expire": ("/bin/bash", "ADPCT lab password never expires owner=iam"),
        "adt_linux_sudo": ("/bin/bash", "ADPCT lab sudo owner=iam"),
        "adt_linux_never_login": ("/bin/bash", "ADPCT lab never login owner=iam"),
        "adt_linux_no_owner": ("/bin/bash", "ADPCT lab no owner"),
    }
    lines = [
        "set -euo pipefail",
        "lab_pwd=\"$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 20)Aa1!\"",
        "getent group adpct_lab >/dev/null || groupadd adpct_lab",
    ]
    for name, (shell, comment) in users.items():
        lines.append(
            f"id {name} >/dev/null 2>&1 || "
            f"useradd -m -g adpct_lab -s {shell} -c '{comment}' {name}"
        )
        lines.append(f"printf '%s:%s\\n' {name} \"$lab_pwd\" | chpasswd")
        lines.append(f"chage -M 90 -E -1 {name}")
    lines.extend(
        [
            "usermod -L adt_linux_disabled",
            "chage -E 1970-01-02 adt_linux_expired",
            "chage -d 0 adt_linux_pwd_expired",
            "chage -M 99999 adt_linux_pwd_never_expire",
            "usermod -aG wheel adt_linux_sudo",
            "install -d -m 0750 /etc/sudoers.d",
            "printf '%s\\n' 'adt_linux_sudo ALL=(ALL) NOPASSWD: ALL' "
            "> /etc/sudoers.d/adpct-lab-adt_linux_sudo",
            "chmod 0440 /etc/sudoers.d/adpct-lab-adt_linux_sudo",
            "visudo -cf /etc/sudoers >/dev/null",
            "adpct_login_users='adt_linux_interactive adt_linux_generic adt_linux_sudo adt_linux_pwd_never_expire'",
            "for login_user in $adpct_login_users; do\n"
            "  if id \"$login_user\" >/dev/null 2>&1; then\n"
            "    su - \"$login_user\" -c true >/dev/null 2>&1 || runuser -l \"$login_user\" -c true >/dev/null 2>&1 || true\n"
            "  fi\n"
            "done",
        ]
    )
    return lines


def build_rhel_cleanup_plan() -> list[str]:
    lines = ["set -euo pipefail", "rm -f /etc/sudoers.d/adpct-lab-adt_linux_sudo"]
    lines.extend(f"id {name} >/dev/null 2>&1 && userdel -r {name} || true" for name in RHEL_ACCOUNTS)
    lines.append("getent group adpct_lab >/dev/null && groupdel adpct_lab || true")
    return lines


def build_rhel_database_seed_plan() -> list[str]:
    mysql_users = ", ".join(f"'{name}'@'%'" for name in MYSQL_ACCOUNTS)
    mongo_users = ", ".join(f"'{name}'" for name in MONGO_ACCOUNTS)
    return [
        "set -euo pipefail",
        "if [ -z \"${ADPCT_DB_ADMIN_PASSWORD:-}\" ]; then echo 'ADPCT_DB_ADMIN_PASSWORD is required' >&2; exit 19; fi",
        "if command -v podman >/dev/null 2>&1; then\n"
        "  if ! podman container exists adpct-lab-mysql; then\n"
        "    podman run -d --name adpct-lab-mysql --restart=always -p 0.0.0.0:3306:3306 -e MYSQL_ROOT_PASSWORD=\"$ADPCT_DB_ADMIN_PASSWORD\" docker.io/library/mysql:8.4 >/dev/null\n"
        "  else\n"
        "    podman start adpct-lab-mysql >/dev/null\n"
        "  fi\n"
        "  if ! podman container exists adpct-lab-mongo; then\n"
        "    podman run -d --name adpct-lab-mongo --restart=always -p 0.0.0.0:27017:27017 -e MONGO_INITDB_ROOT_USERNAME=adpct_admin -e MONGO_INITDB_ROOT_PASSWORD=\"$ADPCT_DB_ADMIN_PASSWORD\" docker.io/library/mongo:7 >/dev/null\n"
        "  else\n"
        "    podman start adpct-lab-mongo >/dev/null\n"
        "  fi\n"
        "fi",
        "for i in $(seq 1 90); do podman exec adpct-lab-mysql mysqladmin ping -uroot -p\"$ADPCT_DB_ADMIN_PASSWORD\" --silent >/dev/null 2>&1 && break; sleep 2; done",
        "for i in $(seq 1 90); do podman exec adpct-lab-mongo mongosh admin -u adpct_admin -p \"$ADPCT_DB_ADMIN_PASSWORD\" --authenticationDatabase admin --quiet --eval 'db.runCommand({ping:1}).ok' >/dev/null 2>&1 && break; sleep 2; done",
        "db_pwd=\"$(openssl rand -base64 32 | tr -dc 'A-Za-z0-9' | head -c 24)Aa1!\"",
        "mysql_exec=\"\"",
        "if command -v mysql >/dev/null 2>&1; then mysql_exec='mysql --protocol=socket -uroot'; fi",
        "if [ -z \"$mysql_exec\" ] && command -v mariadb >/dev/null 2>&1; then mysql_exec='mariadb --protocol=socket -uroot'; fi",
        "if [ -z \"$mysql_exec\" ] && command -v podman >/dev/null 2>&1 && podman container exists adpct-lab-mysql; then mysql_exec='podman exec -i adpct-lab-mysql mysql -uroot -p\"$ADPCT_DB_ADMIN_PASSWORD\"'; fi",
        "if [ -z \"$mysql_exec\" ]; then echo 'mysql/mariadb client or adpct-lab-mysql container not found' >&2; exit 20; fi",
        "if ! eval \"$mysql_exec\" -Nse \"\\\"SELECT 1 FROM mysql.component WHERE component_urn = 'file://component_validate_password'\\\"\" | grep -q 1; then\n"
        "  eval \"$mysql_exec\" -e \"\\\"INSTALL COMPONENT 'file://component_validate_password'\\\"\"\n"
        "fi",
        "eval \"$mysql_exec\" <<SQL\n"
        "SET PERSIST validate_password.policy = MEDIUM;\n"
        "SET PERSIST validate_password.length = 14;\n"
        "SET PERSIST validate_password.mixed_case_count = 1;\n"
        "SET PERSIST validate_password.number_count = 1;\n"
        "SET PERSIST validate_password.special_char_count = 1;\n"
        "SET PERSIST default_password_lifetime = 0;\n"
        "SET PERSIST password_history = 0;\n"
        "CREATE DATABASE IF NOT EXISTS adpct_lab_app;\n"
        "CREATE TABLE IF NOT EXISTS adpct_lab_app.adpct_lab_account_login_events (\n"
        "  account_name VARCHAR(128) PRIMARY KEY,\n"
        "  last_login_at TIMESTAMP NOT NULL,\n"
        "  source VARCHAR(64) NOT NULL\n"
        ");\n"
        "DELETE FROM adpct_lab_app.adpct_lab_account_login_events;\n"
        "CREATE USER IF NOT EXISTS 'adt_mysql_interactive'@'%' IDENTIFIED BY '${db_pwd}';\n"
        "CREATE USER IF NOT EXISTS 'adt_mysql_interactive_expired'@'%' IDENTIFIED BY '${db_pwd}';\n"
        "CREATE USER IF NOT EXISTS 'adt_mysql_svc_expired'@'%' IDENTIFIED BY '${db_pwd}';\n"
        "CREATE USER IF NOT EXISTS 'adt_mysql_interactive_expiring'@'%' IDENTIFIED BY '${db_pwd}';\n"
        "CREATE USER IF NOT EXISTS 'adt_mysql_app_expiring'@'%' IDENTIFIED BY '${db_pwd}';\n"
        "CREATE USER IF NOT EXISTS 'adt_mysql_admin'@'%' IDENTIFIED BY '${db_pwd}';\n"
        "CREATE USER IF NOT EXISTS 'adt_mysql_app_rw'@'%' IDENTIFIED BY '${db_pwd}';\n"
        "CREATE USER IF NOT EXISTS 'adt_mysql_readonly'@'%' IDENTIFIED BY '${db_pwd}';\n"
        "CREATE USER IF NOT EXISTS 'adt_mysql_backup_svc'@'%' IDENTIFIED BY '${db_pwd}';\n"
        "CREATE USER IF NOT EXISTS 'adt_mysql_locked'@'%' IDENTIFIED BY '${db_pwd}';\n"
        "CREATE USER IF NOT EXISTS 'adt_mysql_generic'@'%' IDENTIFIED BY '${db_pwd}';\n"
        "ALTER USER 'adt_mysql_interactive'@'%' IDENTIFIED BY '${db_pwd}' ACCOUNT UNLOCK;\n"
        "ALTER USER 'adt_mysql_interactive_expired'@'%' IDENTIFIED BY '${db_pwd}' ACCOUNT UNLOCK;\n"
        "ALTER USER 'adt_mysql_svc_expired'@'%' IDENTIFIED BY '${db_pwd}' ACCOUNT UNLOCK;\n"
        "ALTER USER 'adt_mysql_interactive_expiring'@'%' IDENTIFIED BY '${db_pwd}' ACCOUNT UNLOCK;\n"
        "ALTER USER 'adt_mysql_app_expiring'@'%' IDENTIFIED BY '${db_pwd}' ACCOUNT UNLOCK;\n"
        "ALTER USER 'adt_mysql_admin'@'%' IDENTIFIED BY '${db_pwd}' ACCOUNT UNLOCK;\n"
        "ALTER USER 'adt_mysql_app_rw'@'%' IDENTIFIED BY '${db_pwd}' ACCOUNT UNLOCK;\n"
        "ALTER USER 'adt_mysql_readonly'@'%' IDENTIFIED BY '${db_pwd}' ACCOUNT UNLOCK;\n"
        "ALTER USER 'adt_mysql_backup_svc'@'%' IDENTIFIED BY '${db_pwd}' ACCOUNT UNLOCK;\n"
        "ALTER USER 'adt_mysql_generic'@'%' IDENTIFIED BY '${db_pwd}' ACCOUNT UNLOCK;\n"
        "GRANT SELECT ON *.* TO 'adt_mysql_interactive'@'%';\n"
        "GRANT SELECT ON *.* TO 'adt_mysql_interactive_expired'@'%';\n"
        "GRANT SELECT ON *.* TO 'adt_mysql_svc_expired'@'%';\n"
        "GRANT SELECT ON *.* TO 'adt_mysql_interactive_expiring'@'%';\n"
        "GRANT SELECT ON adpct_lab_app.* TO 'adt_mysql_app_expiring'@'%';\n"
        "GRANT ALL PRIVILEGES ON *.* TO 'adt_mysql_admin'@'%' WITH GRANT OPTION;\n"
        "GRANT SELECT, INSERT, UPDATE, DELETE ON adpct_lab_app.* TO 'adt_mysql_app_rw'@'%';\n"
        "GRANT SELECT ON *.* TO 'adt_mysql_readonly'@'%';\n"
        "GRANT SELECT, RELOAD, LOCK TABLES, REPLICATION CLIENT, SHOW VIEW, EVENT, TRIGGER ON *.* TO 'adt_mysql_backup_svc'@'%';\n"
        "GRANT SELECT ON adpct_lab_app.* TO 'adt_mysql_generic'@'%';\n"
        "ALTER USER 'adt_mysql_interactive_expired'@'%' PASSWORD EXPIRE;\n"
        "ALTER USER 'adt_mysql_svc_expired'@'%' PASSWORD EXPIRE;\n"
        "ALTER USER 'adt_mysql_interactive_expiring'@'%' PASSWORD EXPIRE INTERVAL 7 DAY;\n"
        "ALTER USER 'adt_mysql_app_expiring'@'%' PASSWORD EXPIRE INTERVAL 7 DAY;\n"
        "ALTER USER 'adt_mysql_locked'@'%' ACCOUNT LOCK;\n"
        "SET PERSIST default_password_lifetime = 90;\n"
        "SET PERSIST password_history = 5;\n"
        "FLUSH PRIVILEGES;\n"
        "SQL",
        "mysql_login_users='adt_mysql_interactive adt_mysql_interactive_expiring adt_mysql_app_expiring adt_mysql_admin adt_mysql_app_rw adt_mysql_readonly adt_mysql_backup_svc adt_mysql_generic'",
        "for mysql_user in $mysql_login_users; do\n"
        "  if podman exec adpct-lab-mysql mysql -u\"$mysql_user\" -p\"$db_pwd\" -e 'SELECT 1' >/dev/null 2>&1; then\n"
        "    eval \"$mysql_exec\" -e \"\\\"REPLACE INTO adpct_lab_app.adpct_lab_account_login_events(account_name,last_login_at,source) VALUES ('$mysql_user@%', UTC_TIMESTAMP(), 'seed_login')\\\"\"\n"
        "  fi\n"
        "done",
        f"echo seeded mysql lab users: {mysql_users} >/dev/null",
        "mongo_exec=\"\"",
        "if command -v mongosh >/dev/null 2>&1; then mongo_exec='mongosh admin --quiet'; elif command -v mongo >/dev/null 2>&1; then mongo_exec='mongo admin --quiet'; fi",
        "if [ -z \"$mongo_exec\" ] && command -v podman >/dev/null 2>&1 && podman container exists adpct-lab-mongo; then mongo_exec='podman exec -i adpct-lab-mongo mongosh admin -u adpct_admin -p \"$ADPCT_DB_ADMIN_PASSWORD\" --authenticationDatabase admin --quiet'; fi",
        "if [ -z \"$mongo_exec\" ]; then echo 'mongosh/mongo client or adpct-lab-mongo container not found' >&2; exit 21; fi",
        "eval \"$mongo_exec\" <<JS\n"
        "const pwd = '$db_pwd';\n"
        "function upsert(dbName, user, roles, customData) {\n"
        "  const target = db.getSiblingDB(dbName);\n"
        "  if (target.getUser(user)) {\n"
        "    target.updateUser(user, {pwd, roles, customData});\n"
        "  } else {\n"
        "    target.createUser({user, pwd, roles, customData});\n"
        "  }\n"
        "}\n"
        "db.getSiblingDB('adpct_lab_app').adpct_lab_marker.updateOne({_id: 'seed'}, {\\$set: {seeded: true}}, {upsert: true});\n"
        "upsert('admin', 'adt_mongo_root_admin', [{role: 'root', db: 'admin'}], {owner: 'iam', purpose: 'adpct lab root admin'});\n"
        "upsert('admin', 'adt_mongo_interactive', [{role: 'read', db: 'admin'}], {owner: 'iam', purpose: 'adpct lab interactive human'});\n"
        "upsert('admin', 'adt_mongo_backup_svc', [{role: 'backup', db: 'admin'}, {role: 'restore', db: 'admin'}], {owner: 'platform', purpose: 'adpct lab backup service'});\n"
        "upsert('admin', 'adt_mongo_monitor', [{role: 'clusterMonitor', db: 'admin'}], {owner: 'platform', purpose: 'adpct lab monitor'});\n"
        "upsert('admin', 'adt_mongo_generic', [{role: 'readAnyDatabase', db: 'admin'}], {owner: null, purpose: 'adpct lab shared generic'});\n"
        "upsert('adpct_lab_app', 'adt_mongo_app_rw', [{role: 'readWrite', db: 'adpct_lab_app'}], {owner: 'appteam', purpose: 'adpct lab app readwrite'});\n"
        "upsert('adpct_lab_app', 'adt_mongo_app_owner', [{role: 'dbOwner', db: 'adpct_lab_app'}], {owner: 'appteam', purpose: 'adpct lab app owner'});\n"
        "db.getSiblingDB('adpct_lab_app').adpct_lab_account_login_events.deleteMany({});\n"
        "JS",
        "mongo_login_specs='adt_mongo_interactive|admin|adt_mongo_interactive@admin adt_mongo_root_admin|admin|adt_mongo_root_admin@admin adt_mongo_backup_svc|admin|adt_mongo_backup_svc@admin adt_mongo_monitor|admin|adt_mongo_monitor@admin adt_mongo_generic|admin|adt_mongo_generic@admin adt_mongo_app_rw|adpct_lab_app|adt_mongo_app_rw@adpct_lab_app adt_mongo_app_owner|adpct_lab_app|adt_mongo_app_owner@adpct_lab_app'",
        "for mongo_spec in $mongo_login_specs; do\n"
        "  mongo_user=\"${mongo_spec%%|*}\"\n"
        "  mongo_rest=\"${mongo_spec#*|}\"\n"
        "  mongo_auth_db=\"${mongo_rest%%|*}\"\n"
        "  mongo_account=\"${mongo_rest#*|}\"\n"
        "  if podman exec adpct-lab-mongo mongosh \"$mongo_auth_db\" -u \"$mongo_user\" -p \"$db_pwd\" --authenticationDatabase \"$mongo_auth_db\" --quiet --eval 'db.runCommand({ping:1}).ok' >/dev/null 2>&1; then\n"
        "    eval \"$mongo_exec\" --eval \"\\\"db.getSiblingDB('adpct_lab_app').adpct_lab_account_login_events.replaceOne({account_name: '$mongo_account'}, {account_name: '$mongo_account', last_login_at: new Date(), source: 'seed_login'}, {upsert: true})\\\"\" >/dev/null\n"
        "  fi\n"
        "done",
        f"echo seeded mongo lab users: {mongo_users} >/dev/null",
    ]


def build_rhel_database_cleanup_plan() -> list[str]:
    mysql_drop = "\n".join(f"DROP USER IF EXISTS '{name}'@'%';" for name in MYSQL_ACCOUNTS)
    mongo_drop = "\n".join(
        [
            "db.getSiblingDB('admin').dropUser('adt_mongo_root_admin');",
            "db.getSiblingDB('admin').dropUser('adt_mongo_interactive');",
            "db.getSiblingDB('admin').dropUser('adt_mongo_backup_svc');",
            "db.getSiblingDB('admin').dropUser('adt_mongo_monitor');",
            "db.getSiblingDB('admin').dropUser('adt_mongo_generic');",
            "db.getSiblingDB('adpct_lab_app').dropUser('adt_mongo_app_rw');",
            "db.getSiblingDB('adpct_lab_app').dropUser('adt_mongo_app_owner');",
        ]
    )
    return [
        "set -euo pipefail",
        "mysql_exec=\"\"",
        "if command -v mysql >/dev/null 2>&1; then mysql_exec='mysql --protocol=socket -uroot'; elif command -v mariadb >/dev/null 2>&1; then mysql_exec='mariadb --protocol=socket -uroot'; fi",
        "if [ -z \"$mysql_exec\" ] && command -v podman >/dev/null 2>&1 && podman container exists adpct-lab-mysql; then mysql_exec='podman exec -i adpct-lab-mysql mysql -uroot -p\"$ADPCT_DB_ADMIN_PASSWORD\"'; fi",
        "if [ -n \"$mysql_exec\" ]; then eval \"$mysql_exec\" <<SQL\n"
        f"{mysql_drop}\n"
        "DROP TABLE IF EXISTS adpct_lab_app.adpct_lab_account_login_events;\n"
        "DROP DATABASE IF EXISTS adpct_lab_app;\n"
        "FLUSH PRIVILEGES;\n"
        "SQL\nfi",
        "mongo_exec=\"\"",
        "if command -v mongosh >/dev/null 2>&1; then mongo_exec='mongosh admin --quiet'; elif command -v mongo >/dev/null 2>&1; then mongo_exec='mongo admin --quiet'; fi",
        "if [ -z \"$mongo_exec\" ] && command -v podman >/dev/null 2>&1 && podman container exists adpct-lab-mongo; then mongo_exec='podman exec -i adpct-lab-mongo mongosh admin -u adpct_admin -p \"$ADPCT_DB_ADMIN_PASSWORD\" --authenticationDatabase admin --quiet'; fi",
        "if [ -n \"$mongo_exec\" ]; then eval \"$mongo_exec\" <<JS\n"
        f"{mongo_drop}\n"
        "db.getSiblingDB('adpct_lab_app').adpct_lab_account_login_events.drop();\n"
        "JS\nfi",
    ]


def build_windows_seed_script() -> str:
    names = ", ".join(_quote_ps(name) for name in WINDOWS_ACCOUNTS)
    return f"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$accountPasswordPlain = ([guid]::NewGuid().ToString('N') + 'aA1!')
$password = ConvertTo-SecureString $accountPasswordPlain -AsPlainText -Force
$accounts = @({names})
foreach ($name in $accounts) {{
    if (Get-LocalUser -Name $name -ErrorAction SilentlyContinue) {{
        Set-LocalUser -Name $name -Password $password
        Enable-LocalUser -Name $name
    }} else {{
        New-LocalUser -Name $name -Password $password -Description "ADPCT lab account" | Out-Null
    }}
}}
Disable-LocalUser -Name 'adt_win_disabled'
Set-LocalUser -Name 'adt_win_pwd_no_exp' -PasswordNeverExpires $true
$adsiNoExpire = [ADSI]("WinNT://$env:COMPUTERNAME/adt_win_pwd_no_exp,user")
$adsiNoExpire.UserFlags = ($adsiNoExpire.UserFlags.Value -bor 0x10000)
$adsiNoExpire.SetInfo()
Set-LocalUser -Name 'adt_win_pwd_expired' -UserMayChangePassword $true
cmd /c "net user adt_win_pwd_expired /logonpasswordchg:yes" | Out-Null
Add-LocalGroupMember -Group 'Administrators' -Member 'adt_win_local_admin' -ErrorAction SilentlyContinue
Add-LocalGroupMember -Group 'Remote Desktop Users' -Member 'adt_win_interactive' -ErrorAction SilentlyContinue
$loginEvidenceUsers = @('adt_win_interactive', 'adt_win_local_admin', 'adt_win_generic', 'adt_win_pwd_no_exp')
foreach ($loginUser in $loginEvidenceUsers) {{
    try {{
        $loginTaskName = "ADPCTLabLoginEvidence_$loginUser"
        $loginAction = New-ScheduledTaskAction -Execute "$env:SystemRoot\\System32\\cmd.exe" -Argument "/c whoami > nul"
        $loginPrincipal = New-ScheduledTaskPrincipal -UserId "$env:COMPUTERNAME\\$loginUser" -LogonType Password
        $loginTask = New-ScheduledTask -Action $loginAction -Principal $loginPrincipal
        Register-ScheduledTask -TaskName $loginTaskName -InputObject $loginTask `
            -User "$env:COMPUTERNAME\\$loginUser" -Password $accountPasswordPlain -Force | Out-Null
        Start-ScheduledTask -TaskName $loginTaskName
        Start-Sleep -Seconds 2
        Unregister-ScheduledTask -TaskName $loginTaskName -Confirm:$false -ErrorAction SilentlyContinue
    }} catch {{ }}
}}
$svcCredential = New-Object System.Management.Automation.PSCredential(".\\adt_win_service", $password)
New-Service -Name 'ADPCTLabService' -BinaryPathName "$env:SystemRoot\\System32\\cmd.exe /c exit 0" `
    -Credential $svcCredential -StartupType Manual -ErrorAction SilentlyContinue
$action = New-ScheduledTaskAction -Execute "$env:SystemRoot\\System32\\cmd.exe" -Argument "/c exit 0"
$taskUser = "$env:COMPUTERNAME\\adt_win_sched_task"
$principal = New-ScheduledTaskPrincipal -UserId $taskUser -LogonType Password
$task = New-ScheduledTask -Action $action -Principal $principal
Register-ScheduledTask -TaskName 'ADPCTLabScheduledTask' -InputObject $task `
    -User $taskUser -Password $accountPasswordPlain -Force | Out-Null
""".strip()


def build_windows_cleanup_script() -> str:
    names = ", ".join(_quote_ps(name) for name in WINDOWS_ACCOUNTS)
    return f"""
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
Unregister-ScheduledTask -TaskName 'ADPCTLabScheduledTask' -Confirm:$false -ErrorAction SilentlyContinue
Stop-Service -Name 'ADPCTLabService' -ErrorAction SilentlyContinue
sc.exe delete ADPCTLabService | Out-Null
$accounts = @({names})
foreach ($name in $accounts) {{
    Remove-LocalGroupMember -Group 'Administrators' -Member $name -ErrorAction SilentlyContinue
    Remove-LocalGroupMember -Group 'Remote Desktop Users' -Member $name -ErrorAction SilentlyContinue
    Remove-LocalUser -Name $name -ErrorAction SilentlyContinue
}}
exit 0
""".strip()


def run_rhel(host: str, username: str, password: str, cleanup: bool = False) -> None:
    require_lab_target(host, _allow_non_lab_from_env())
    import paramiko

    plan = build_rhel_cleanup_plan() if cleanup else build_rhel_seed_plan()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=username, password=password, timeout=15)
    try:
        command = "bash -lc " + shlex.quote("\n".join(plan))
        _, stdout, stderr = client.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if exit_code:
            raise RuntimeError(f"RHEL lab command failed with exit {exit_code}: {err}")
    finally:
        client.close()


def run_rhel_databases(host: str, username: str, password: str, cleanup: bool = False) -> None:
    require_lab_target(host, _allow_non_lab_from_env())
    import paramiko

    plan = build_rhel_database_cleanup_plan() if cleanup else build_rhel_database_seed_plan()
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, username=username, password=password, timeout=15)
    try:
        command = "ADPCT_DB_ADMIN_PASSWORD=" + shlex.quote(password) + " bash -lc " + shlex.quote("\n".join(plan))
        _, stdout, stderr = client.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()
        err = stderr.read().decode("utf-8", errors="replace").strip()
        if exit_code:
            raise RuntimeError(f"RHEL database lab command failed with exit {exit_code}: {err}")
    finally:
        client.close()


def run_windows(host: str, username: str, password: str, cleanup: bool = False) -> None:
    require_lab_target(host, _allow_non_lab_from_env())
    import winrm

    script = build_windows_cleanup_script() if cleanup else build_windows_seed_script()
    session = winrm.Session(
        f"http://{host}:5985/wsman",
        auth=(username, password),
        transport=os.getenv("WIN11_TEST_TRANSPORT", "ntlm"),
        server_cert_validation="ignore",
    )
    result = session.run_ps(script)
    if result.status_code:
        err = result.std_err.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Windows lab command failed with exit {result.status_code}: {err}")


def parse_args(platform: str, cleanup: bool) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    default_host = RHEL_DEFAULT_HOST if platform in {"rhel", "databases"} else WIN_DEFAULT_HOST
    default_user = "root" if platform in {"rhel", "databases"} else r"demo\administrator"
    env_prefix = "RHEL" if platform in {"rhel", "databases"} else "WIN11"
    parser.add_argument("--host", default=os.getenv(f"{env_prefix}_TEST_HOST", default_host))
    parser.add_argument("--username", default=os.getenv(f"{env_prefix}_TEST_USERNAME", default_user))
    parser.add_argument("--password-env", default=f"{env_prefix}_TEST_PASSWORD")
    parser.add_argument("--allow-non-lab-target", action="store_true")
    parser.set_defaults(cleanup=cleanup, platform=platform)
    return parser.parse_args()


def main(platform: str, cleanup: bool) -> int:
    args = parse_args(platform, cleanup)
    if args.allow_non_lab_target:
        os.environ["ALLOW_NON_LAB_TARGET"] = "true"
    password = _remote_password(args, args.password_env)
    if platform == "rhel":
        run_rhel(args.host, args.username, password, cleanup=cleanup)
    elif platform == "databases":
        run_rhel_databases(args.host, args.username, password, cleanup=cleanup)
    else:
        run_windows(args.host, args.username, password, cleanup=cleanup)
    action = "cleanup" if cleanup else "seed"
    print(f"{platform} lab {action} completed for {args.host}")
    return 0
