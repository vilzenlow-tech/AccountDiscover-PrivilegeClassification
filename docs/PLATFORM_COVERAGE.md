# Platform Coverage Guide

Version date: 2026-06-28

## Coverage Status Terms

- Implemented backend collector: registered in `backend/app/collectors`.
- Live collector: code opens a real SSH, WinRM, or database connection.
- Mock collector: deterministic fixture for development/test.
- Agent collector: implemented in standalone `connector-agent`.

## Summary

| Platform | Backend support | Agent support | Notes |
|---|---|---|---|
| Windows Server | Implemented via `windows` | Implemented | Server selector depends on asset tags. |
| Windows Desktop | Implemented via `windows` | Implemented | Desktop selector depends on asset tags. |
| RHEL | Implemented | Placeholder only | SSH live collector and PAM policy support. |
| Solaris | Implemented | Placeholder only | SSH live collector with Solaris RBAC evidence. |
| AIX | Implemented | Placeholder only | SSH live collector with AIX RBAC evidence. |
| Oracle | Implemented as `oracle_db` | Placeholder only | Uses python-oracledb thin mode. |
| MSSQL | Implemented | Placeholder only | Uses pymssql/TDS. |
| MySQL | Implemented | Placeholder only | Uses PyMySQL. |
| MongoDB | Implemented | Placeholder only | Uses pymongo. |

Backend also supports CentOS, Ubuntu, SLES, HP-UX, PostgreSQL, and Redis, although these were not in the requested platform list.

## Windows Server/Desktop

Supported: yes, as `windows`.

Collector: `WindowsCollector` in backend and `WindowsScanner` in connector agent.

Scan types: credentialed discovery, privileged account scan, password policy scan, interactive classification, full discovery. Basic discovery is accepted but meaningful live discovery requires credentials.

Credentials required: WinRM credentials for live scans.

Permissions required:

- WinRM access.
- Ability to run PowerShell commands.
- Read local users/groups, services, scheduled tasks.
- For better interactive classification, read User Rights Assignment and Security Event 4624.
- For domain expansion, RSAT/AD module access where available.

Account fields collected:

- Local users, local group members, AD domain users/groups visible through local groups, gMSA/computer accounts, service run-as, scheduled task run-as, built-in/system principals, unresolved SIDs.

Privilege logic:

- Local Administrators, Backup Operators, Server Operators, Account Operators, Print Operators, Hyper-V Administrators, Remote Desktop/Management Users, domain-admin paths, privileged service rules.

Password policy visibility:

- Local Security Policy via secedit.
- Domain and fine-grained policy best effort.
- Password-never-expires exceptions from local user data.

Interactive support:

- Detailed Windows classification with confidence and evidence.

Known limitations:

- Windows Server/Desktop split is metadata-based, not a native platform.
- Domain nested expansion may be skipped if RSAT/permissions are absent.

## RHEL

Supported: yes.

Collector: `RHELCollector`, plus shared `LinuxSSHCollector` for similar Linux live paths.

Scan types: all scan types, subject to credentials.

Credentials required: SSH credential.

Permissions required:

- Read `/etc/passwd`, `/etc/group`, `/etc/shadow` fields used by parser, sudoers files, lastlog/wtmp/auth logs where available.

Account fields collected:

- UID/GID, shell, password status, password age, last login, groups, sudo rules, password-never-expires, activity status.

Privilege logic:

- UID 0, broad sudo, sudo group inheritance, privileged service account rules, dormancy upgrade.

Password policy visibility:

- PAM pwquality/cracklib style settings, login_defs, faillock/tally best effort.

Interactive support:

- Shell-based heuristic.

Known limitations:

- Live evidence depends on file permissions. SSH host key TOFU is enforced after first connection.

## Solaris

Supported: yes.

Collector: `SolarisCollector`.

Credentials required: SSH credential.

Permissions required:

- Read passwd/group/shadow style data, sudoers, Solaris RBAC files such as user_attr, auth_attr, prof_attr where available.

Privilege logic:

- UID 0, broad sudo, Solaris RBAC broad profile and roles.

Password policy visibility:

- Partial platform-specific visibility; unknowns should be reviewed.

Interactive support:

- Shell-based heuristic.

Known limitations:

- RBAC files may be restricted, causing incomplete evidence.

## AIX

Supported: yes.

Collector: `AIXCollector`.

Credentials required: SSH credential.

Permissions required:

- Read passwd/group/security files and RBAC data where available.

Privilege logic:

- UID 0, broad sudo, AIX RBAC broad roles such as SecPolicy/SysConfig.

Password policy visibility:

- Partial platform-specific visibility.

Interactive support:

- Shell-based heuristic.

Known limitations:

- AIX RBAC data requires platform-specific read permissions.

## Oracle

Supported: yes, as `oracle_db`.

Collector: `OracleDBCollector`.

Credentials required: Oracle database credential.

Permissions required:

- `CREATE SESSION`.
- Read access to DBA views such as DBA_USERS, DBA_SYS_PRIVS, DBA_ROLE_PRIVS, DBA_TAB_PRIVS, DBA_PROFILES. Commonly via `SELECT_CATALOG_ROLE`.

Account fields collected:

- Users, account status, profile, created/last login/expiry where visible, system privileges, role grants.

Privilege logic:

- DBA/SYSDBA/SYSOPER/SYSBACKUP/SYSDG/SYSKM and broad system/role privileges.

Password policy visibility:

- Profiles through DBA_PROFILES when permissions allow.

Interactive support:

- Database accounts are classified as non-interactive by default.

Known limitations:

- Correct service name may be required in asset instance or connector options.

## MSSQL

Supported: yes.

Collector: `MSSQLCollector`.

Credentials required: SQL Server credential.

Permissions required:

- Metadata visibility over server principals, server role members, database roles, and login policy flags.

Account fields collected:

- Server logins, disabled state, SQL/Windows principal types, server roles, database roles, policy flags.

Privilege logic:

- `sysadmin`, `securityadmin`, high-impact server/database roles such as owner-style roles.

Password policy visibility:

- SQL login CHECK_POLICY and CHECK_EXPIRATION style evidence where visible.

Interactive support:

- Database-native accounts are treated as non-interactive.

Known limitations:

- Windows-authenticated login details depend on SQL Server metadata visibility.

## MySQL

Supported: yes.

Collector: `MySQLCollector`.

Credentials required: MySQL/MariaDB credential.

Permissions required:

- Read mysql user/grant metadata and relevant global variables/components.

Account fields collected:

- Users, hosts, account locked status, grants, roles where available, password expiration metadata.

Privilege logic:

- Global administrative grants, grant option, broad privileges, root-like accounts.

Password policy visibility:

- validate_password component/variables, password lifetime/history where available.

Interactive support:

- Database-native accounts are non-interactive.

Known limitations:

- Metadata differs by MySQL/MariaDB version and grant visibility.

## MongoDB

Supported: yes.

Collector: `MongoCollector`.

Credentials required: MongoDB credential.

Permissions required:

- Ability to list users and roles across relevant databases; role inheritance visibility.

Account fields collected:

- Users by auth DB, roles, custom role inheritance one level deep, custom data.

Privilege logic:

- root, userAdminAnyDatabase, clusterAdmin, dbAdminAnyDatabase, dbOwner, backup/restore, readWriteAnyDatabase, and other admin-critical roles.

Password policy visibility:

- MongoDB local password policy is limited. External authentication flags are surfaced as review-required when detected.

Interactive support:

- Principal type heuristics; database accounts generally non-interactive except human/shared heuristics.

Known limitations:

- Deep role inheritance beyond implemented depth may need future enhancement.
