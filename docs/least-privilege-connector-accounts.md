# Least-Privilege Discovery Accounts by Connector Type

This document defines the recommended least-privilege accounts for running Account Discovery Tool connectors in an enterprise production environment.

The goal is to let the platform discover accounts, group or role memberships, privilege evidence, password policy evidence, and last-login indicators without granting broad administrative control to the discovery account.

## General Rules

- Create one dedicated discovery account per platform or security zone.
- Store credentials only in the configured vault. Do not place passwords in `.env`, shell history, agent config files, or job payloads in production.
- Prefer key/certificate authentication where supported.
- Disable interactive login unless the protocol requires it.
- Deny privilege escalation beyond the exact read-only commands or metadata views listed below.
- Scope each account to the assets assigned to that connector or agent.
- Rotate credentials and connector tokens regularly.
- Send connector and authentication logs to SIEM.

## Connector Agent Host Account

The connector agent is the Linux service that polls the console and runs scanner workers near the target systems.

| Item | Recommendation |
|---|---|
| Local OS account | Dedicated non-root account, for example `adpct-agent` |
| Required local privilege | Ability to run the agent service and read its own config/log directories |
| Network access | Outbound HTTPS TCP 443 to the console/API |
| Target access | Only to approved target ports such as SSH 22, WinRM 5985/5986, or database ports |
| Not required | Root on the agent server, inbound listener from console, broad network admin rights |

The agent host account is separate from target discovery credentials. The agent should not permanently store target passwords.

## Summary Matrix

| Connector Type | Platforms | Protocol | Least-Privilege Discovery Account |
|---|---|---|---|
| SSH Linux | RHEL, CentOS, Ubuntu, SLES | SSH 22 | Local read-only user with tightly scoped `sudo` for account, group, sudoers, shadow, last-login, and password-policy reads |
| SSH Solaris | Solaris | SSH 22 | Local read-only user with read access to `/etc/passwd`, `/etc/shadow`, `/etc/group`, Solaris RBAC files, sudoers, and last-login commands |
| SSH AIX | AIX | SSH 22 | Local read-only user allowed to run `lsuser`, `lsgroup`, `lsrole`, `lsauth`, and last-login commands |
| SSH HP-UX | HP-UX | SSH 22 | Local read-only user allowed to read account/group files and run `logins -ax`; trusted mode may require controlled root-equivalent read access |
| WinRM / WMI | Windows | WinRM 5985/5986 | Dedicated domain or local account with remote management and read-only local account, group, service, scheduled task, event log, and security policy access |
| MySQL | MySQL / MariaDB | 3306 | Database user with read-only access to `mysql` account metadata and ability to run `SHOW GRANTS` |
| MSSQL | SQL Server | 1433 | Login with server metadata visibility and read-only database metadata visibility |
| MongoDB | MongoDB | 27017 | Custom role with `viewUser`, `viewRole`, and metadata/list privileges, preferably scoped to `admin` and target databases |
| Oracle DB | Oracle Database | 1521 | User with `CREATE SESSION` and catalog read access, usually `SELECT_CATALOG_ROLE` or explicit SELECT grants on required DBA views |
| PostgreSQL | PostgreSQL | 5432 | Login role with `pg_monitor`; do not grant superuser unless collecting `pg_shadow` is explicitly required |
| Redis | Redis 6+ | 6379 | Redis ACL user with only ACL and server-info read commands |

## SSH Linux Connectors

Applies to:

- `rhel`
- `centos`
- `ubuntu`
- `sles`

The collector reads local account data, group membership, sudo rules, password lock/expiry status, last-login data, and optional password-policy files.

Recommended account:

| Setting | Value |
|---|---|
| Account name | `adpct_discovery` or zone-specific equivalent |
| Login shell | `/sbin/nologin` if SSH forced-command is used; otherwise restricted shell where feasible |
| Authentication | SSH key preferred |
| Sudo | No broad sudo; allow only specific read commands |
| Write access | None |

Required read evidence:

- `getent passwd`
- `getent group`
- `/etc/shadow` fields for lock status and max password age
- `/etc/sudoers`
- `/etc/sudoers.d/*`
- `lastlog`
- Optional password policy files:
  - `/etc/security/pwquality.conf`
  - `/etc/pam.d/system-auth`
  - `/etc/pam.d/password-auth`
  - `/etc/login.defs`

Example sudoers shape:

```sudoers
User_Alias ADPCT = adpct_discovery
Cmnd_Alias ADPCT_READ = \
  /usr/bin/getent passwd, \
  /usr/bin/getent group, \
  /usr/bin/awk -F\: * /etc/shadow, \
  /usr/bin/cat /etc/sudoers, \
  /usr/bin/ls /etc/sudoers.d/, \
  /usr/bin/cat /etc/sudoers.d/*, \
  /usr/bin/lastlog, \
  /usr/bin/cat /etc/security/pwquality.conf, \
  /usr/bin/grep * /etc/pam.d/system-auth, \
  /usr/bin/grep * /etc/pam.d/password-auth, \
  /usr/bin/grep * /etc/login.defs

ADPCT ALL=(root) NOPASSWD: ADPCT_READ
```

Production note: test command paths per distribution. Some systems use `/bin/cat`, `/bin/grep`, or different sudo command matching behavior.

## SSH Solaris Connector

Applies to `solaris`.

Required read evidence:

- `getent passwd`
- `getent group`
- `/etc/shadow`
- `/etc/user_attr`
- `/etc/security/prof_attr`
- `/etc/security/auth_attr`
- `/etc/sudoers`
- last-login evidence such as `last`

Recommended account:

| Setting | Value |
|---|---|
| Account name | `adpct_discovery` |
| Privilege | Read-only account with explicit read access or tightly scoped RBAC/sudo profile |
| Write access | None |

Minimum Solaris RBAC shape:

- Permit read-only access to account and RBAC metadata.
- Do not grant `Primary Administrator`, `All`, or unrestricted `solaris.*`.
- If file permissions block `/etc/shadow`, use a tightly scoped profile or command wrapper that returns only lock/status fields.

## SSH AIX Connector

Applies to `aix`.

Required read evidence:

- `lsuser -a id account_locked groups roles ALL`
- `lsgroup -a users ALL`
- `lsrole ALL`
- `lsauth -f ALL`
- last-login evidence such as `last`

Recommended account:

| Setting | Value |
|---|---|
| Account name | `adpct_discovery` |
| Privilege | Read-only account allowed to execute AIX account/RBAC listing commands |
| Write access | None |

Do not grant broad administrative roles such as security administration or system configuration. If RBAC restricts command output, create a custom read-only role for account and role inventory.

## SSH HP-UX Connector

Applies to `hpux`.

Required read evidence:

- `/etc/passwd`
- `/etc/group`
- `/etc/shadow` in standard mode
- `/tcb/files/auth/*` in trusted mode, if password status is required
- `logins -ax`
- `/etc/sudoers`
- `/etc/sudoers.d/*`

Recommended account:

| Setting | Value |
|---|---|
| Account name | `adpct_discovery` |
| Privilege | Read-only user plus tightly scoped privilege for protected account files |
| Write access | None |

Trusted mode often protects account metadata behind root-only files. In that case, use a controlled wrapper or sudo rule that returns only the needed status fields, not full password hashes.

## Windows WinRM / WMI Connector

Applies to `windows`.

The Windows connector currently collects:

- Local users
- Local groups and local group members, including Administrators
- Services run-as accounts
- Scheduled task run-as principals
- User Rights Assignment via `secedit`
- Event 4624 logon history for interactive classification
- Optional local/domain password policy evidence

Recommended account:

| Setting | Value |
|---|---|
| Account name | `DOMAIN\adpct_discovery` for domain environments, or local `adpct_discovery` for isolated machines |
| Authentication | Kerberos or NTLM over WinRM HTTPS where possible |
| Required groups | `Remote Management Users`, `Event Log Readers`, and read access to local account/group/service/task metadata |
| Optional groups | `Performance Monitor Users` if performance or service metadata access requires it |
| Avoid | Domain Admins, Enterprise Admins, local Administrators as the default posture |

Important production note:

Some Windows APIs and environments restrict `Get-LocalUser`, `Get-LocalGroupMember`, `secedit`, scheduled task details, or service run-as details to local Administrators. The clean enterprise approach is to use a constrained PowerShell JEA endpoint that exposes only the discovery commands. If JEA is not available, a local Administrators membership may be required for complete evidence, but that should be treated as an exception and scoped to only the target hosts being scanned.

Recommended Windows controls:

- Enable WinRM over HTTPS on TCP 5986.
- Use Kerberos where domain trust allows it.
- Restrict logon rights for the discovery account to remote management only.
- Deny interactive desktop logon where possible.
- Audit all WinRM logons and PowerShell execution.
- Prefer a JEA endpoint exposing only:
  - `Get-LocalUser`
  - `Get-LocalGroup`
  - `Get-LocalGroupMember`
  - `Get-CimInstance Win32_Service`
  - `Get-ScheduledTask`
  - `wevtutil` or `Get-WinEvent` for security log read
  - `secedit /export` for security policy read

## MySQL / MariaDB Connector

Applies to `mysql`.

The collector queries:

- `mysql.user`
- `mysql.role_edges`, where available
- `SHOW GRANTS FOR '<user>'@'<host>'`
- Account lock and authentication plugin metadata

Recommended account:

```sql
CREATE USER 'adpct_discovery'@'%' IDENTIFIED BY '<vault-managed-secret>';

GRANT SELECT ON mysql.user TO 'adpct_discovery'@'%';
GRANT SELECT ON mysql.db TO 'adpct_discovery'@'%';
GRANT SELECT ON mysql.tables_priv TO 'adpct_discovery'@'%';
GRANT SELECT ON mysql.columns_priv TO 'adpct_discovery'@'%';
GRANT SELECT ON mysql.procs_priv TO 'adpct_discovery'@'%';
GRANT SELECT ON mysql.role_edges TO 'adpct_discovery'@'%';

FLUSH PRIVILEGES;
```

Avoid granting:

- `SUPER`
- `CREATE USER`
- `GRANT OPTION`
- `ALL PRIVILEGES`
- write privileges on application schemas

If `SHOW GRANTS FOR` is blocked by server version or policy, the scan may return users but incomplete grant evidence.

## Microsoft SQL Server Connector

Applies to `mssql`.

The collector queries:

- `sys.server_principals`
- `sys.sql_logins`
- `sys.server_role_members`
- Database role membership views
- Optional SQL login password-policy flags

Recommended login:

```sql
USE master;
CREATE LOGIN [adpct_discovery] WITH PASSWORD = '<vault-managed-secret>', CHECK_POLICY = ON, CHECK_EXPIRATION = ON;

GRANT VIEW ANY DEFINITION TO [adpct_discovery];
GRANT VIEW SERVER STATE TO [adpct_discovery];
GRANT CONNECT ANY DATABASE TO [adpct_discovery];
```

For older SQL Server versions where `CONNECT ANY DATABASE` is unavailable, map the login as a user in each database and grant metadata visibility only:

```sql
USE [TargetDatabase];
CREATE USER [adpct_discovery] FOR LOGIN [adpct_discovery];
GRANT VIEW DEFINITION TO [adpct_discovery];
```

Avoid granting:

- `sysadmin`
- `securityadmin`
- `serveradmin`
- `db_owner`
- `ALTER ANY LOGIN`
- `CONTROL SERVER`

## MongoDB Connector

Applies to `mongodb`.

The collector uses:

- `usersInfo`
- Role metadata from user role assignments
- Database/user inventory from the `admin` authentication database

Recommended custom role:

```javascript
use admin

db.createRole({
  role: "adpctDiscoveryRead",
  privileges: [
    { resource: { db: "", collection: "" }, actions: ["listDatabases"] },
    { resource: { db: "", collection: "" }, actions: ["listCollections"] },
    { resource: { db: "", collection: "" }, actions: ["viewUser", "viewRole"] }
  ],
  roles: []
})

db.createUser({
  user: "adpct_discovery",
  pwd: "<vault-managed-secret>",
  roles: [{ role: "adpctDiscoveryRead", db: "admin" }]
})
```

Avoid granting:

- `root`
- `userAdminAnyDatabase`
- `dbAdminAnyDatabase`
- `clusterAdmin`
- `readWriteAnyDatabase`
- `backup` unless backup account discovery is explicitly required and approved

MongoDB deployments using external authentication should map the same custom role to the external principal.

## Oracle Database Connector

Applies to `oracle_db`.

The collector queries:

- `DBA_USERS`
- `DBA_SYS_PRIVS`
- `DBA_ROLE_PRIVS`
- `DBA_TAB_PRIVS`
- `DBA_PROFILES`
- `SESSION_PRIVS`

Recommended user:

```sql
CREATE USER ADPCT_DISCOVERY IDENTIFIED BY "<vault-managed-secret>";
GRANT CREATE SESSION TO ADPCT_DISCOVERY;
GRANT SELECT_CATALOG_ROLE TO ADPCT_DISCOVERY;
```

More restrictive alternative using explicit grants:

```sql
GRANT SELECT ON SYS.DBA_USERS TO ADPCT_DISCOVERY;
GRANT SELECT ON SYS.DBA_SYS_PRIVS TO ADPCT_DISCOVERY;
GRANT SELECT ON SYS.DBA_ROLE_PRIVS TO ADPCT_DISCOVERY;
GRANT SELECT ON SYS.DBA_TAB_PRIVS TO ADPCT_DISCOVERY;
GRANT SELECT ON SYS.DBA_PROFILES TO ADPCT_DISCOVERY;
```

Avoid granting:

- `DBA`
- `SYSDBA`
- `SYSOPER`
- `SYSBACKUP`
- `SYSKM`
- `GRANT ANY PRIVILEGE`
- `CREATE USER`

## PostgreSQL Connector

Applies to `postgresql`.

The collector queries:

- `pg_roles`
- `pg_auth_members`
- Role flags such as superuser, create role, create DB, replication, login, and valid-until

Recommended role:

```sql
CREATE ROLE adpct_discovery LOGIN PASSWORD '<vault-managed-secret>';
GRANT pg_monitor TO adpct_discovery;
```

Optional visibility:

```sql
GRANT CONNECT ON DATABASE postgres TO adpct_discovery;
```

Avoid granting:

- `SUPERUSER`
- `CREATEROLE`
- `CREATEDB`
- `REPLICATION`
- `pg_read_server_files`
- `pg_write_server_files`
- `pg_execute_server_program`

Important note:

Reading `pg_shadow` requires superuser. Do not grant superuser only for password-hash visibility. The production recommendation is to skip `pg_shadow` and rely on `pg_roles`, `pg_auth_members`, and policy evidence where available.

## Redis Connector

Applies to `redis`.

The collector uses:

- `ACL LIST`
- `ACL WHOAMI`
- `INFO server`
- `CONFIG GET requirepass` for legacy password mode

Recommended Redis 6+ ACL user:

```text
ACL SETUSER adpct_discovery on >'<vault-managed-secret>' ~* \
  +acl|list +acl|whoami +info +config|get
```

Avoid granting:

- `+@all`
- `+@write`
- `+@admin` beyond the specific ACL/config read commands above
- unrestricted operational commands such as `FLUSHALL`, `CONFIG SET`, `SHUTDOWN`, `MODULE`, or `EVAL`

For Redis versions before ACL support, the legacy `requirepass` model does not provide true per-user least privilege. Treat scans of legacy Redis as a controlled exception and restrict by network source, firewall, maintenance window, and vault-controlled credential access.

## Production Approval Checklist

Before enabling a connector account in production, confirm:

- The account is dedicated to discovery only.
- The account has no write, create-user, grant-option, sysadmin, domain-admin, or root-equivalent rights unless explicitly approved as an exception.
- The account is scoped to only required assets, databases, or zones.
- The credential is stored in the enterprise vault with rotation enabled.
- The connector-agent can reach only approved target ports.
- The target can log and alert on use of the discovery account.
- A test scan confirms that required evidence is collected without privileged side effects.
- Any exception requiring local Administrator, root, DBA, or superuser is time-bound, documented, and approved by the system owner.

## Appendix A: Account Creation Command Examples

These examples are starting points. Validate paths, package names, shell paths, domain policy, and database version behavior in a lower environment before applying them in production.

### RHEL / CentOS / Rocky / AlmaLinux

Create a locked-down SSH discovery user:

```bash
sudo useradd --create-home --shell /bin/bash --comment "ADPCT discovery account" adpct_discovery
sudo passwd -l adpct_discovery
sudo mkdir -p /home/adpct_discovery/.ssh
sudo install -m 700 -o adpct_discovery -g adpct_discovery -d /home/adpct_discovery/.ssh
sudo install -m 600 -o adpct_discovery -g adpct_discovery authorized_keys /home/adpct_discovery/.ssh/authorized_keys
```

Add tightly scoped sudoers access:

```bash
sudo visudo -f /etc/sudoers.d/adpct-discovery
```

```sudoers
Defaults:adpct_discovery !requiretty
adpct_discovery ALL=(root) NOPASSWD: \
  /usr/bin/getent passwd, \
  /usr/bin/getent group, \
  /usr/bin/awk -F\: * /etc/shadow, \
  /usr/bin/cat /etc/sudoers, \
  /usr/bin/ls /etc/sudoers.d/, \
  /usr/bin/cat /etc/sudoers.d/*, \
  /usr/bin/lastlog, \
  /usr/bin/cat /etc/security/pwquality.conf, \
  /usr/bin/grep * /etc/pam.d/system-auth, \
  /usr/bin/grep * /etc/pam.d/password-auth, \
  /usr/bin/grep * /etc/login.defs
```

Validate:

```bash
sudo -l -U adpct_discovery
```

### Ubuntu

Create the account:

```bash
sudo adduser --disabled-password --gecos "ADPCT discovery account" adpct_discovery
sudo passwd -l adpct_discovery
sudo mkdir -p /home/adpct_discovery/.ssh
sudo install -m 700 -o adpct_discovery -g adpct_discovery -d /home/adpct_discovery/.ssh
sudo install -m 600 -o adpct_discovery -g adpct_discovery authorized_keys /home/adpct_discovery/.ssh/authorized_keys
```

Add sudoers:

```bash
sudo visudo -f /etc/sudoers.d/adpct-discovery
```

```sudoers
adpct_discovery ALL=(root) NOPASSWD: \
  /usr/bin/getent passwd, \
  /usr/bin/getent group, \
  /usr/bin/awk -F\: * /etc/shadow, \
  /usr/bin/cat /etc/sudoers, \
  /usr/bin/ls /etc/sudoers.d/, \
  /usr/bin/cat /etc/sudoers.d/*, \
  /usr/bin/lastlog, \
  /usr/bin/cat /etc/security/pwquality.conf, \
  /usr/bin/grep * /etc/pam.d/common-password, \
  /usr/bin/grep * /etc/login.defs
```

### SUSE Linux Enterprise Server

Create the account:

```bash
sudo useradd -m -s /bin/bash -c "ADPCT discovery account" adpct_discovery
sudo passwd -l adpct_discovery
sudo mkdir -p /home/adpct_discovery/.ssh
sudo install -m 700 -o adpct_discovery -g adpct_discovery -d /home/adpct_discovery/.ssh
sudo install -m 600 -o adpct_discovery -g adpct_discovery authorized_keys /home/adpct_discovery/.ssh/authorized_keys
```

Add sudoers:

```bash
sudo visudo -f /etc/sudoers.d/adpct-discovery
```

```sudoers
adpct_discovery ALL=(root) NOPASSWD: \
  /usr/bin/getent passwd, \
  /usr/bin/getent group, \
  /usr/bin/awk -F\: * /etc/shadow, \
  /usr/bin/cat /etc/sudoers, \
  /usr/bin/ls /etc/sudoers.d/, \
  /usr/bin/cat /etc/sudoers.d/*, \
  /usr/bin/lastlog, \
  /usr/bin/cat /etc/security/pwquality.conf, \
  /usr/bin/grep * /etc/pam.d/common-password, \
  /usr/bin/grep * /etc/login.defs
```

### Solaris

Create the account:

```bash
sudo useradd -m -s /bin/bash -c "ADPCT discovery account" adpct_discovery
sudo passwd -N adpct_discovery
sudo mkdir -p /export/home/adpct_discovery/.ssh
sudo chown adpct_discovery:staff /export/home/adpct_discovery/.ssh
sudo chmod 700 /export/home/adpct_discovery/.ssh
sudo install -m 600 -o adpct_discovery -g staff authorized_keys /export/home/adpct_discovery/.ssh/authorized_keys
```

If protected files cannot be read directly, create a restricted sudo profile:

```bash
sudo visudo -f /etc/sudoers.d/adpct-discovery
```

```sudoers
adpct_discovery ALL=(root) NOPASSWD: \
  /usr/bin/getent passwd, \
  /usr/bin/getent group, \
  /usr/bin/awk -F\: * /etc/shadow, \
  /usr/bin/cat /etc/user_attr, \
  /usr/bin/cat /etc/security/prof_attr, \
  /usr/bin/cat /etc/security/auth_attr, \
  /usr/bin/cat /etc/sudoers, \
  /usr/bin/last
```

### AIX

Create the account:

```bash
sudo mkuser gecos="ADPCT discovery account" shell=/usr/bin/ksh adpct_discovery
sudo pwdadm -c adpct_discovery
sudo mkdir -p /home/adpct_discovery/.ssh
sudo chown adpct_discovery:staff /home/adpct_discovery/.ssh
sudo chmod 700 /home/adpct_discovery/.ssh
sudo install -m 600 -o adpct_discovery -g staff authorized_keys /home/adpct_discovery/.ssh/authorized_keys
```

If command visibility is restricted, allow only inventory commands through sudo:

```sudoers
adpct_discovery ALL=(root) NOPASSWD: \
  /usr/sbin/lsuser -a id account_locked groups roles ALL, \
  /usr/sbin/lsgroup -a users ALL, \
  /usr/sbin/lsrole ALL, \
  /usr/sbin/lsauth -f ALL, \
  /usr/bin/last
```

### HP-UX

Create the account:

```bash
sudo useradd -m -s /usr/bin/sh -c "ADPCT discovery account" adpct_discovery
sudo passwd -l adpct_discovery
sudo mkdir -p /home/adpct_discovery/.ssh
sudo chown adpct_discovery:users /home/adpct_discovery/.ssh
sudo chmod 700 /home/adpct_discovery/.ssh
sudo install -m 600 -o adpct_discovery -g users authorized_keys /home/adpct_discovery/.ssh/authorized_keys
```

Allow only read commands:

```sudoers
adpct_discovery ALL=(root) NOPASSWD: \
  /usr/bin/cat /etc/passwd, \
  /usr/bin/cat /etc/group, \
  /usr/bin/cat /etc/shadow, \
  /usr/bin/logins -ax, \
  /usr/bin/cat /etc/sudoers, \
  /usr/bin/ls /etc/sudoers.d/, \
  /usr/bin/cat /etc/sudoers.d/*
```

For trusted mode, replace direct `/tcb/files/auth/*` reads with a reviewed wrapper script that outputs only account status fields.

### Windows Local Server

Create a local discovery user:

```powershell
$Password = Read-Host "Enter password" -AsSecureString
New-LocalUser -Name "adpct_discovery" -Password $Password -Description "ADPCT discovery account"
Add-LocalGroupMember -Group "Remote Management Users" -Member "adpct_discovery"
Add-LocalGroupMember -Group "Event Log Readers" -Member "adpct_discovery"
Add-LocalGroupMember -Group "Performance Monitor Users" -Member "adpct_discovery"
```

Enable WinRM HTTPS where possible:

```powershell
Enable-PSRemoting -Force
winrm quickconfig -q
```

Recommended production hardening:

```powershell
secpol.msc
```

Use Local Security Policy or GPO to deny local interactive logon for the discovery account and allow only the required remote management path.

### Windows Domain Account

Create a domain account in Active Directory:

```powershell
Import-Module ActiveDirectory

$Password = Read-Host "Enter password" -AsSecureString
New-ADUser `
  -Name "adpct_discovery" `
  -SamAccountName "adpct_discovery" `
  -UserPrincipalName "adpct_discovery@example.com" `
  -AccountPassword $Password `
  -Enabled $true `
  -Description "ADPCT discovery account"
```

On each target server, grant only required local groups:

```powershell
Add-LocalGroupMember -Group "Remote Management Users" -Member "DOMAIN\adpct_discovery"
Add-LocalGroupMember -Group "Event Log Readers" -Member "DOMAIN\adpct_discovery"
Add-LocalGroupMember -Group "Performance Monitor Users" -Member "DOMAIN\adpct_discovery"
```

For complete Windows evidence without local Administrator membership, create a PowerShell JEA endpoint that exposes only the discovery commands. Use local Administrators only as a documented exception.

### MySQL / MariaDB

```sql
CREATE USER 'adpct_discovery'@'%' IDENTIFIED BY '<vault-managed-secret>';

GRANT SELECT ON mysql.user TO 'adpct_discovery'@'%';
GRANT SELECT ON mysql.db TO 'adpct_discovery'@'%';
GRANT SELECT ON mysql.tables_priv TO 'adpct_discovery'@'%';
GRANT SELECT ON mysql.columns_priv TO 'adpct_discovery'@'%';
GRANT SELECT ON mysql.procs_priv TO 'adpct_discovery'@'%';
GRANT SELECT ON mysql.role_edges TO 'adpct_discovery'@'%';

FLUSH PRIVILEGES;
```

### Microsoft SQL Server

```sql
USE master;
CREATE LOGIN [adpct_discovery]
  WITH PASSWORD = '<vault-managed-secret>',
  CHECK_POLICY = ON,
  CHECK_EXPIRATION = ON;

GRANT VIEW ANY DEFINITION TO [adpct_discovery];
GRANT VIEW SERVER STATE TO [adpct_discovery];
GRANT CONNECT ANY DATABASE TO [adpct_discovery];
```

For older versions:

```sql
USE [TargetDatabase];
CREATE USER [adpct_discovery] FOR LOGIN [adpct_discovery];
GRANT VIEW DEFINITION TO [adpct_discovery];
```

### MongoDB

```javascript
use admin

db.createRole({
  role: "adpctDiscoveryRead",
  privileges: [
    { resource: { db: "", collection: "" }, actions: ["listDatabases"] },
    { resource: { db: "", collection: "" }, actions: ["listCollections"] },
    { resource: { db: "", collection: "" }, actions: ["viewUser", "viewRole"] }
  ],
  roles: []
})

db.createUser({
  user: "adpct_discovery",
  pwd: "<vault-managed-secret>",
  roles: [{ role: "adpctDiscoveryRead", db: "admin" }]
})
```

### Oracle Database

```sql
CREATE USER ADPCT_DISCOVERY IDENTIFIED BY "<vault-managed-secret>";
GRANT CREATE SESSION TO ADPCT_DISCOVERY;
GRANT SELECT_CATALOG_ROLE TO ADPCT_DISCOVERY;
```

More restrictive explicit grants:

```sql
GRANT SELECT ON SYS.DBA_USERS TO ADPCT_DISCOVERY;
GRANT SELECT ON SYS.DBA_SYS_PRIVS TO ADPCT_DISCOVERY;
GRANT SELECT ON SYS.DBA_ROLE_PRIVS TO ADPCT_DISCOVERY;
GRANT SELECT ON SYS.DBA_TAB_PRIVS TO ADPCT_DISCOVERY;
GRANT SELECT ON SYS.DBA_PROFILES TO ADPCT_DISCOVERY;
```

### PostgreSQL

```sql
CREATE ROLE adpct_discovery LOGIN PASSWORD '<vault-managed-secret>';
GRANT pg_monitor TO adpct_discovery;
GRANT CONNECT ON DATABASE postgres TO adpct_discovery;
```

### Redis 6+

```text
ACL SETUSER adpct_discovery on >'<vault-managed-secret>' ~* +acl|list +acl|whoami +info +config|get
```
