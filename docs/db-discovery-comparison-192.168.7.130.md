# Database Discovery Comparison - 192.168.7.130

Date: 2026-05-15

This note compares the live database account status on `192.168.7.130` with the status shown in the Account Discovery & Privilege Classification Tool at `http://127.0.0.1:5173`.

| Account | Platform | Real DB Status | Discovery Tool Status | Logon Type In Tool | Match |
|---|---|---|---|---|---|
| `mysql.infoschema@localhost` | MySQL | `LOCKED` | `locked` | `Non-Interactive` | Yes |
| `mysql.session@localhost` | MySQL | `LOCKED` | `locked` | `Non-Interactive` | Yes |
| `mysql.sys@localhost` | MySQL | `LOCKED` | `locked` | `Non-Interactive` | Yes |
| `root@%` | MySQL | `ENABLED` | `enabled` | `Non-Interactive` | Yes |
| `root@localhost` | MySQL | `ENABLED` | `enabled` | `Non-Interactive` | Yes |
| `admin@admin` | MongoDB | `ENABLED` | `enabled` | `Non-Interactive` | Yes |
| `mongo_admin1@admin` | MongoDB | `ENABLED` | `enabled` | `Non-Interactive` | Yes |
| `mongo_admin2@admin` | MongoDB | `ENABLED` | `enabled` | `Non-Interactive` | Yes |
| `mongo_svc_app@admin` | MongoDB | `ENABLED` | `enabled` | `Non-Interactive` | Yes |
| `mongo_svc_backup@admin` | MongoDB | `ENABLED` | `enabled` | `Non-Interactive` | Yes |
| `mongo_user1@appdb` | MongoDB | `ENABLED` | `enabled` | `Non-Interactive` | Yes |
| `mongo_user2@appdb` | MongoDB | `ENABLED` | `enabled` | `Non-Interactive` | Yes |

## Notes

- MySQL internal accounts such as `mysql.session`, `mysql.sys`, and `mysql.infoschema` are locked by design.
- MongoDB does not provide a native per-user locked/disabled flag like MySQL `account_locked`; existing users are treated as enabled unless removed or role/auth configuration prevents use.
- MySQL and MongoDB accounts are database logins, not operating system shell accounts, so `Non-Interactive` is the correct discovery logon type for these DB accounts.
- The discovery tool login with `admin@local` succeeded, and the Accounts page loaded with `284 accounts`.
- The dashboard showed the latest scan time as `15 May 2026 07:26`.
- Searching `root@%` also returned `root@localhost`, but the exact `root@%` row was present and matched.
