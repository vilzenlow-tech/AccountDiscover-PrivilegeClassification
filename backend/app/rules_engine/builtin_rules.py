"""Built-in seed rules — loaded on first startup / via `make seed`.

These are the deterministic, production-quality baseline rules for all seven
supported platforms. Additional rules can be created through the UI / API
without redeploying.
"""
from __future__ import annotations

BUILTIN_RULES: list[dict] = [

    # =========================================================================
    # UNIX-common rules (apply to RHEL, Solaris, AIX via source_type check in
    # the collector layer — the rules themselves are platform-agnostic for the
    # predicates they use)
    # =========================================================================
    {
        "rule_key": "unix_uid0_full_admin",
        "name": "Unix UID 0 account",
        "description": "Any account with UID 0 has root-equivalent privileges regardless of account name.",
        "platform": "rhel",
        "predicate": {"entitlement_kind_is": "unix_uid0"},
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' has UID 0. Every UID 0 account has unrestricted root privilege.",
        "priority": 10,
    },
    {
        "rule_key": "unix_uid0_full_admin_solaris",
        "name": "Solaris UID 0 account",
        "platform": "solaris",
        "predicate": {"entitlement_kind_is": "unix_uid0"},
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' has UID 0 on Solaris — unconditional root.",
        "priority": 10,
    },
    {
        "rule_key": "unix_uid0_full_admin_aix",
        "name": "AIX UID 0 account",
        "platform": "aix",
        "predicate": {"entitlement_kind_is": "unix_uid0"},
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' has UID 0 on AIX — unconditional root.",
        "priority": 10,
    },
    {
        "rule_key": "unix_sudo_broad_admin_equivalent",
        "name": "Unix broad sudo — admin equivalent",
        "platform": "rhel",
        "predicate": {"entitlement_kind_attr_true": {"kind": "sudo_rule", "attr": "broad"}},
        "classify_as": "admin_equivalent",
        "confidence": 95,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' has a broad sudoers rule (ALL=(ALL) or equivalent): {matched}. This is effectively root.",
        "priority": 20,
    },
    {
        "rule_key": "unix_sudo_broad_solaris",
        "name": "Solaris broad sudo — admin equivalent",
        "platform": "solaris",
        "predicate": {"entitlement_kind_attr_true": {"kind": "sudo_rule", "attr": "broad"}},
        "classify_as": "admin_equivalent",
        "confidence": 95,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' on Solaris has broad sudo: {matched}.",
        "priority": 20,
    },
    {
        "rule_key": "unix_sudo_broad_aix",
        "name": "AIX broad sudo — admin equivalent",
        "platform": "aix",
        "predicate": {"entitlement_kind_attr_true": {"kind": "sudo_rule", "attr": "broad"}},
        "classify_as": "admin_equivalent",
        "confidence": 95,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' on AIX has broad sudo: {matched}.",
        "priority": 20,
    },
    {
        "rule_key": "service_account_broad_sudo_high_risk",
        "name": "Service account with broad sudo and interactive shell",
        "platform": None,
        "predicate": {
            "all_of": [
                {"principal_type_in": ["service"]},
                {"entitlement_kind_attr_true": {"kind": "sudo_rule", "attr": "broad"}},
            ]
        },
        "classify_as": "privileged_service",
        "confidence": 97,
        "risk_modifier": 8,
        "explanation_template": "Service account '{account}' has broad sudo privilege. Service accounts with unrestricted sudo are high risk.",
        "priority": 15,
    },

    # =========================================================================
    # Solaris RBAC
    # =========================================================================
    {
        "rule_key": "solaris_rbac_broad_profile_admin_equivalent",
        "name": "Solaris RBAC — broad admin profile",
        "platform": "solaris",
        "predicate": {"entitlement_kind_attr_true": {"kind": "solaris_rbac_profile", "attr": "broad"}},
        "classify_as": "admin_equivalent",
        "confidence": 92,
        "risk_modifier": 4,
        "explanation_template": "Account '{account}' has Solaris RBAC profile with broad authorization (solaris.* or solaris.grant): {matched}.",
        "priority": 25,
    },
    {
        "rule_key": "solaris_rbac_role_primary_admin",
        "name": "Solaris RBAC — Primary Administrator role",
        "platform": "solaris",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "solaris_rbac_role",
                "names": ["Primary Administrator", "System Administrator", "sysadmin"],
            }
        },
        "classify_as": "admin_equivalent",
        "confidence": 93,
        "risk_modifier": 4,
        "explanation_template": "Account '{account}' is assigned the Solaris RBAC role '{matched}', which grants broad administrative capability.",
        "priority": 25,
    },

    # =========================================================================
    # AIX RBAC
    # =========================================================================
    {
        "rule_key": "aix_rbac_broad_role",
        "name": "AIX RBAC — broad role",
        "platform": "aix",
        "predicate": {"entitlement_kind_attr_true": {"kind": "aix_rbac_role", "attr": "broad"}},
        "classify_as": "admin_equivalent",
        "confidence": 92,
        "risk_modifier": 4,
        "explanation_template": "Account '{account}' holds an AIX RBAC role with broad authorizations (aix.*): {matched}.",
        "priority": 25,
    },
    {
        "rule_key": "aix_rbac_secpolicy_role",
        "name": "AIX RBAC — SecPolicy role",
        "platform": "aix",
        "predicate": {
            "entitlement_kind_name_in": {"kind": "aix_rbac_role", "names": ["SecPolicy", "SysConfig"]}
        },
        "classify_as": "admin_equivalent",
        "confidence": 91,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' holds the AIX RBAC role '{matched}', which grants system-level configuration and security authority.",
        "priority": 26,
    },

    # =========================================================================
    # Windows
    # =========================================================================
    {
        "rule_key": "windows_local_admin_full_admin",
        "name": "Windows — member of local Administrators",
        "platform": "windows",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "windows_local_group",
                "names": ["Administrators"],
            }
        },
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' is a member of the local Administrators group on this asset (direct or via nested group: {via}).",
        "priority": 10,
    },
    {
        "rule_key": "windows_backup_operators_high_impact",
        "name": "Windows — member of Backup Operators",
        "platform": "windows",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "windows_local_group",
                "names": ["Backup Operators"],
            }
        },
        "classify_as": "operator_high_impact",
        "confidence": 95,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' is a member of Backup Operators. This group can bypass file-system ACLs to read and write any file.",
        "priority": 15,
    },
    {
        "rule_key": "windows_server_operators_high_impact",
        "name": "Windows — member of Server Operators",
        "platform": "windows",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "windows_local_group",
                "names": ["Server Operators"],
            }
        },
        "classify_as": "operator_high_impact",
        "confidence": 93,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' is in Server Operators, which allows starting/stopping services and modifying system files.",
        "priority": 16,
    },
    {
        # Fires for any account whose privilege path includes Domain Admins,
        # Enterprise Admins, or Schema Admins — direct or nested into local Administrators.
        "rule_key": "windows_domain_admin_path_full_admin",
        "name": "Windows — privilege path via Domain/Enterprise/Schema Admins",
        "platform": "windows",
        "predicate": {
            "entitlement_kind_attr_true": {
                "kind": "windows_local_group",
                "attr": "domain_admin_path",
            }
        },
        "classify_as": "full_admin",
        "confidence": 98,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' has local administrator access via a domain admin group (Domain Admins / Enterprise Admins / Schema Admins). Inheritance path: {via}.",
        "priority": 11,
    },
    {
        "rule_key": "windows_account_operators_high_impact",
        "name": "Windows — member of Account Operators",
        "platform": "windows",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "windows_local_group",
                "names": ["Account Operators"],
            }
        },
        "classify_as": "operator_high_impact",
        "confidence": 92,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' is in Account Operators, which can create and modify most user and group accounts in Active Directory.",
        "priority": 17,
    },
    {
        "rule_key": "windows_print_operators_high_impact",
        "name": "Windows — member of Print Operators",
        "platform": "windows",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "windows_local_group",
                "names": ["Print Operators"],
            }
        },
        "classify_as": "operator_high_impact",
        "confidence": 90,
        "risk_modifier": 2,
        "explanation_template": "Account '{account}' is in Print Operators. This group can load/unload device drivers and shut down domain controllers.",
        "priority": 18,
    },
    {
        "rule_key": "windows_hyper_v_admin_high_impact",
        "name": "Windows — member of Hyper-V Administrators",
        "platform": "windows",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "windows_local_group",
                "names": ["Hyper-V Administrators"],
            }
        },
        "classify_as": "operator_high_impact",
        "confidence": 88,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' is in Hyper-V Administrators, granting full control over Hyper-V virtual machines and VHD files.",
        "priority": 19,
    },
    {
        "rule_key": "windows_rdp_users_sensitive",
        "name": "Windows — member of Remote Desktop Users",
        "platform": "windows",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "windows_local_group",
                "names": ["Remote Desktop Users"],
            }
        },
        "classify_as": "sensitive_non_admin",
        "confidence": 70,
        "risk_modifier": 1,
        "explanation_template": "Account '{account}' can log in remotely via RDP. Classify and review for least-privilege compliance.",
        "priority": 30,
    },
    {
        "rule_key": "windows_remote_mgmt_users_sensitive",
        "name": "Windows — member of Remote Management Users",
        "platform": "windows",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "windows_local_group",
                "names": ["Remote Management Users"],
            }
        },
        "classify_as": "sensitive_non_admin",
        "confidence": 65,
        "risk_modifier": 1,
        "explanation_template": "Account '{account}' is in Remote Management Users, allowing WS-Management and WinRM access to this server.",
        "priority": 31,
    },
    {
        "rule_key": "windows_dist_com_users_sensitive",
        "name": "Windows — member of Distributed COM Users",
        "platform": "windows",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "windows_local_group",
                "names": ["Distributed COM Users"],
            }
        },
        "classify_as": "sensitive_non_admin",
        "confidence": 60,
        "risk_modifier": 1,
        "explanation_template": "Account '{account}' is in Distributed COM Users, allowing activation and launch of DCOM objects on this server.",
        "priority": 32,
    },
    {
        # Service principal (principal_type=service) that holds direct local admin.
        # Separate rule from domain_admin_path to give a specific privileged_service label.
        "rule_key": "windows_service_principal_in_admins",
        "name": "Windows — service account in local Administrators",
        "platform": "windows",
        "predicate": {
            "all_of": [
                {"principal_type_in": ["service"]},
                {"entitlement_kind_name_in": {
                    "kind": "windows_local_group",
                    "names": ["Administrators"],
                }},
            ]
        },
        "classify_as": "privileged_service",
        "confidence": 90,
        "risk_modifier": 4,
        "explanation_template": "Service account '{account}' is a direct member of local Administrators. Service accounts in admin groups represent a high lateral-movement risk.",
        "priority": 12,
    },
    {
        "rule_key": "windows_gmsa_in_high_impact_group",
        "name": "Windows — gMSA in high-impact local group",
        "platform": "windows",
        "predicate": {
            "all_of": [
                {"source_type_in": ["windows_gmsa"]},
                {"entitlement_kind_attr_true": {
                    "kind": "windows_local_group",
                    "attr": "high_impact",
                }},
            ]
        },
        "classify_as": "privileged_service",
        "confidence": 88,
        "risk_modifier": 3,
        "explanation_template": "gMSA '{account}' is a member of a high-impact local group ({matched}). Verify the gMSA scope is minimal and review its service SPN.",
        "priority": 13,
    },
    {
        "rule_key": "windows_unresolved_sid_in_high_impact_group",
        "name": "Windows — unresolved SID in high-impact local group",
        "platform": "windows",
        "predicate": {
            "all_of": [
                {"source_type_in": ["windows_unresolved"]},
                {"entitlement_kind_attr_true": {
                    "kind": "windows_local_group",
                    "attr": "high_impact",
                }},
            ]
        },
        "classify_as": "unknown_review_required",
        "confidence": 95,
        "risk_modifier": 4,
        "explanation_template": "Unresolved SID '{account}' occupies a seat in a high-impact local group ({matched}). The originating account may have been deleted while retaining access. Immediate removal recommended.",
        "priority": 14,
    },
    {
        "rule_key": "windows_computer_account_in_admins",
        "name": "Windows — computer account in local Administrators",
        "platform": "windows",
        "predicate": {
            "all_of": [
                {"source_type_in": ["windows_computer"]},
                {"entitlement_kind_name_in": {
                    "kind": "windows_local_group",
                    "names": ["Administrators"],
                }},
            ]
        },
        "classify_as": "unknown_review_required",
        "confidence": 90,
        "risk_modifier": 3,
        "explanation_template": "Computer account '{account}' is in local Administrators. Investigate whether this is intentional delegation (e.g. SCCM) or a misconfiguration.",
        "priority": 20,
    },

    # =========================================================================
    # MySQL
    # =========================================================================
    {
        "rule_key": "mysql_global_admin_full_admin",
        "name": "MySQL — global ALL PRIVILEGES or SUPER",
        "platform": "mysql",
        "predicate": {"entitlement_kind_attr_true": {"kind": "mysql_grant", "attr": "global_admin"}},
        "classify_as": "full_admin",
        "confidence": 98,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' holds global administrative MySQL privileges (ALL PRIVILEGES / SUPER / GRANT OPTION on *.*): {matched}.",
        "priority": 10,
    },

    # =========================================================================
    # MSSQL
    # =========================================================================
    {
        "rule_key": "mssql_sysadmin_full_admin",
        "name": "MSSQL — sysadmin server role",
        "platform": "mssql",
        "predicate": {
            "entitlement_kind_name_in": {"kind": "mssql_server_role", "names": ["sysadmin"]}
        },
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' is a member of the sysadmin fixed server role — unconditional full administrative control of the SQL Server instance.",
        "priority": 10,
    },
    {
        "rule_key": "mssql_securityadmin_admin_equivalent",
        "name": "MSSQL — securityadmin server role",
        "platform": "mssql",
        "predicate": {
            "entitlement_kind_name_in": {"kind": "mssql_server_role", "names": ["securityadmin"]}
        },
        "classify_as": "admin_equivalent",
        "confidence": 95,
        "risk_modifier": 8,
        "explanation_template": "Account '{account}' is in the securityadmin server role. securityadmin members can add themselves to sysadmin — treat as sysadmin for practical purposes.",
        "priority": 11,
    },
    {
        "rule_key": "mssql_high_risk_server_roles",
        "name": "MSSQL — other high-risk server roles",
        "platform": "mssql",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "mssql_server_role",
                "names": ["serveradmin", "dbcreator", "bulkadmin", "processadmin", "setupadmin", "diskadmin"],
            }
        },
        "classify_as": "operator_high_impact",
        "confidence": 90,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' holds high-impact MSSQL server role(s): {matched}.",
        "priority": 15,
    },
    {
        "rule_key": "mssql_db_owner_delegated_admin",
        "name": "MSSQL — db_owner database role",
        "platform": "mssql",
        "predicate": {
            "entitlement_kind_name_in": {"kind": "mssql_db_role", "names": ["db_owner"]}
        },
        "classify_as": "delegated_admin",
        "confidence": 93,
        "risk_modifier": 4,
        "explanation_template": "Account '{account}' is db_owner in database(s) {scope}. db_owner has full control within the database.",
        "priority": 20,
    },
    {
        "rule_key": "mssql_db_securityadmin_admin_equivalent",
        "name": "MSSQL — db_securityadmin or db_ddladmin",
        "platform": "mssql",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "mssql_db_role",
                "names": ["db_securityadmin", "db_ddladmin"],
            }
        },
        "classify_as": "admin_equivalent",
        "confidence": 88,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' holds {matched} in one or more databases — can modify permissions or schema.",
        "priority": 21,
    },

    # =========================================================================
    # MongoDB
    # =========================================================================
    {
        "rule_key": "mongo_root_full_admin",
        "name": "MongoDB — root role",
        "platform": "mongodb",
        "predicate": {
            "entitlement_kind_name_in": {"kind": "mongo_role", "names": ["root"]}
        },
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' holds the MongoDB 'root' role, which grants all privileges on all resources.",
        "priority": 10,
    },
    {
        "rule_key": "mongo_admin_critical_roles",
        "name": "MongoDB — admin-critical roles",
        "platform": "mongodb",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "mongo_role",
                "names": [
                    "userAdminAnyDatabase",
                    "clusterAdmin",
                    "dbAdminAnyDatabase",
                    "readWriteAnyDatabase",
                ],
            }
        },
        "classify_as": "admin_equivalent",
        "confidence": 96,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' holds the MongoDB role '{matched}', which grants database-wide administrative capability.",
        "priority": 11,
    },
    {
        "rule_key": "mongo_dbowner_delegated_admin",
        "name": "MongoDB — dbOwner on a database",
        "platform": "mongodb",
        "predicate": {
            "entitlement_kind_name_in": {"kind": "mongo_role", "names": ["dbOwner"]}
        },
        "classify_as": "delegated_admin",
        "confidence": 92,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' is dbOwner — full control of the scoped database(s).",
        "priority": 20,
    },
    {
        "rule_key": "mongo_backup_restore",
        "name": "MongoDB — backup or restore roles",
        "platform": "mongodb",
        "predicate": {
            "entitlement_kind_name_in": {"kind": "mongo_role", "names": ["backup", "restore"]}
        },
        "classify_as": "operator_high_impact",
        "confidence": 88,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' holds MongoDB backup/restore role '{matched}'. These roles allow data exfiltration and data recovery that bypasses normal access controls.",
        "priority": 22,
    },
    {
        "rule_key": "mongo_custom_role_admin_critical",
        "name": "MongoDB — custom role with inherited admin-critical actions",
        "platform": "mongodb",
        "predicate": {"entitlement_kind_attr_true": {"kind": "mongo_role", "attr": "admin_critical"}},
        "classify_as": "admin_equivalent",
        "confidence": 85,
        "risk_modifier": 4,
        "explanation_template": "Account '{account}' has a MongoDB role flagged admin-critical: {matched}. Review custom role privilege graph.",
        "priority": 18,
    },

    # =========================================================================
    # PostgreSQL
    # =========================================================================
    {
        "rule_key": "postgresql_superuser_full_admin",
        "name": "PostgreSQL — SUPERUSER attribute",
        "platform": "postgresql",
        "predicate": {"entitlement_kind_is": "pg_superuser"},
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' is a PostgreSQL superuser — bypasses all permission checks, full control of the instance.",
        "priority": 10,
    },
    {
        "rule_key": "postgresql_createrole_admin_equivalent",
        "name": "PostgreSQL — CREATEROLE attribute",
        "platform": "postgresql",
        "predicate": {"entitlement_kind_is": "pg_createrole"},
        "classify_as": "admin_equivalent",
        "confidence": 93,
        "risk_modifier": 4,
        "explanation_template": "Account '{account}' has CREATEROLE — can create, alter, and drop any non-superuser role, effectively controlling access for all other users.",
        "priority": 12,
    },
    {
        "rule_key": "postgresql_broad_role_membership_admin_equivalent",
        "name": "PostgreSQL — member of pg_read_all_data or pg_write_all_data",
        "platform": "postgresql",
        "predicate": {"entitlement_kind_attr_true": {"kind": "pg_role_membership", "attr": "broad"}},
        "classify_as": "admin_equivalent",
        "confidence": 92,
        "risk_modifier": 4,
        "explanation_template": "Account '{account}' is a member of a broad built-in PostgreSQL role (pg_read_all_data or pg_write_all_data): {matched}. This grants access to all tables and sequences across all databases.",
        "priority": 15,
    },
    {
        "rule_key": "postgresql_replication_operator_high_impact",
        "name": "PostgreSQL — REPLICATION attribute",
        "platform": "postgresql",
        "predicate": {"entitlement_kind_is": "pg_replication"},
        "classify_as": "operator_high_impact",
        "confidence": 88,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' has the REPLICATION attribute — can initiate streaming replication and read all WAL data, including sensitive rows.",
        "priority": 18,
    },
    {
        "rule_key": "postgresql_createdb_delegated_admin",
        "name": "PostgreSQL — CREATEDB attribute",
        "platform": "postgresql",
        "predicate": {"entitlement_kind_is": "pg_createdb"},
        "classify_as": "delegated_admin",
        "confidence": 82,
        "risk_modifier": 2,
        "explanation_template": "Account '{account}' has CREATEDB — can create new databases on this instance and becomes the owner (with full privileges) of any database they create.",
        "priority": 22,
    },

    # =========================================================================
    # Oracle Database
    # =========================================================================
    {
        "rule_key": "oracle_sysdba_full_admin",
        "name": "Oracle — SYSDBA system privilege",
        "platform": "oracle_db",
        "predicate": {
            "entitlement_kind_name_in": {"kind": "oracle_sys_priv", "names": ["SYSDBA"]}
        },
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' holds the SYSDBA system privilege — unconditional full administrative control of the Oracle instance, including startup/shutdown and SYS schema access.",
        "priority": 10,
    },
    {
        "rule_key": "oracle_dba_role_full_admin",
        "name": "Oracle — DBA role",
        "platform": "oracle_db",
        "predicate": {
            "entitlement_kind_name_in": {"kind": "oracle_role", "names": ["DBA"]}
        },
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' is granted the DBA role — full administrative capability including all system privileges with ADMIN OPTION.",
        "priority": 10,
    },
    {
        "rule_key": "oracle_broad_role_admin_equivalent",
        "name": "Oracle — broad DBA-class role",
        "platform": "oracle_db",
        "predicate": {
            "entitlement_kind_attr_true": {"kind": "oracle_role", "attr": "broad"}
        },
        "classify_as": "admin_equivalent",
        "confidence": 95,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' holds a broad Oracle DBA-class role (SYSDBA, SYSOPER, SYSBACKUP, SYSDG, or SYSKM): {matched}.",
        "priority": 11,
    },
    {
        "rule_key": "oracle_sysop_roles_operator_high_impact",
        "name": "Oracle — SYSOPER / SYSBACKUP / SYSDG / SYSKM privileges",
        "platform": "oracle_db",
        "predicate": {
            "entitlement_kind_name_in": {
                "kind": "oracle_sys_priv",
                "names": ["SYSOPER", "SYSBACKUP", "SYSDG", "SYSKM"],
            }
        },
        "classify_as": "operator_high_impact",
        "confidence": 90,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' holds the Oracle system privilege '{matched}' — operational control including startup/shutdown or backup/recovery operations.",
        "priority": 15,
    },
    {
        "rule_key": "oracle_resource_role_delegated_admin",
        "name": "Oracle — RESOURCE role",
        "platform": "oracle_db",
        "predicate": {
            "entitlement_kind_name_in": {"kind": "oracle_role", "names": ["RESOURCE"]}
        },
        "classify_as": "delegated_admin",
        "confidence": 78,
        "risk_modifier": 2,
        "explanation_template": "Account '{account}' holds the RESOURCE role — can create tables, indexes, procedures, and sequences. Elevated beyond read-only.",
        "priority": 25,
    },

    # =========================================================================
    # Redis
    # =========================================================================
    {
        "rule_key": "redis_unrestricted_acl_full_admin",
        "name": "Redis — unrestricted ACL (all commands + all keys)",
        "platform": "redis",
        "predicate": {
            "all_of": [
                {"entitlement_kind_attr_true": {"kind": "redis_acl_command", "attr": "broad"}},
                {"entitlement_kind_attr_true": {"kind": "redis_acl_key_pattern", "attr": "broad"}},
            ]
        },
        "classify_as": "full_admin",
        "confidence": 97,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' has unrestricted Redis ACL access — all commands (+@all) on all keys (~*). Equivalent to full admin.",
        "priority": 10,
    },
    {
        "rule_key": "redis_broad_commands_operator_high_impact",
        "name": "Redis — broad command access",
        "platform": "redis",
        "predicate": {
            "entitlement_kind_attr_true": {"kind": "redis_acl_command", "attr": "broad"}
        },
        "classify_as": "operator_high_impact",
        "confidence": 87,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' has broad Redis command access (+@all or +@write): {matched}. Can modify or flush data.",
        "priority": 15,
    },

    # =========================================================================
    # Ubuntu Server — same privilege model as RHEL (UID 0 + sudoers)
    # =========================================================================
    {
        "rule_key": "ubuntu_uid0_full_admin",
        "name": "Ubuntu — UID 0 account",
        "platform": "ubuntu",
        "predicate": {"entitlement_kind_is": "unix_uid0"},
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' has UID 0 on Ubuntu — unconditional root privilege.",
        "priority": 10,
    },
    {
        "rule_key": "ubuntu_sudo_broad_admin_equivalent",
        "name": "Ubuntu — broad sudo rule",
        "platform": "ubuntu",
        "predicate": {"entitlement_kind_attr_true": {"kind": "sudo_rule", "attr": "broad"}},
        "classify_as": "admin_equivalent",
        "confidence": 95,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' on Ubuntu has a broad sudoers rule (ALL=(ALL) or equivalent): {matched}. Effectively root.",
        "priority": 20,
    },

    # =========================================================================
    # CentOS — same privilege model as RHEL
    # =========================================================================
    {
        "rule_key": "centos_uid0_full_admin",
        "name": "CentOS — UID 0 account",
        "platform": "centos",
        "predicate": {"entitlement_kind_is": "unix_uid0"},
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' has UID 0 on CentOS — unconditional root privilege.",
        "priority": 10,
    },
    {
        "rule_key": "centos_sudo_broad_admin_equivalent",
        "name": "CentOS — broad sudo rule",
        "platform": "centos",
        "predicate": {"entitlement_kind_attr_true": {"kind": "sudo_rule", "attr": "broad"}},
        "classify_as": "admin_equivalent",
        "confidence": 95,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' on CentOS has a broad sudoers rule: {matched}. Effectively root.",
        "priority": 20,
    },

    # =========================================================================
    # SUSE Linux Enterprise Server (SLES)
    # =========================================================================
    {
        "rule_key": "sles_uid0_full_admin",
        "name": "SLES — UID 0 account",
        "platform": "sles",
        "predicate": {"entitlement_kind_is": "unix_uid0"},
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' has UID 0 on SLES — unconditional root privilege.",
        "priority": 10,
    },
    {
        "rule_key": "sles_sudo_broad_admin_equivalent",
        "name": "SLES — broad sudo rule",
        "platform": "sles",
        "predicate": {"entitlement_kind_attr_true": {"kind": "sudo_rule", "attr": "broad"}},
        "classify_as": "admin_equivalent",
        "confidence": 95,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' on SLES has a broad sudoers rule: {matched}. Effectively root.",
        "priority": 20,
    },

    # =========================================================================
    # HP-UX
    # =========================================================================
    {
        "rule_key": "hpux_uid0_full_admin",
        "name": "HP-UX — UID 0 account",
        "platform": "hpux",
        "predicate": {"entitlement_kind_is": "unix_uid0"},
        "classify_as": "full_admin",
        "confidence": 99,
        "risk_modifier": 5,
        "explanation_template": "Account '{account}' has UID 0 on HP-UX — unconditional root privilege.",
        "priority": 10,
    },
    {
        "rule_key": "hpux_sudo_broad_admin_equivalent",
        "name": "HP-UX — broad sudo rule",
        "platform": "hpux",
        "predicate": {"entitlement_kind_attr_true": {"kind": "sudo_rule", "attr": "broad"}},
        "classify_as": "admin_equivalent",
        "confidence": 95,
        "risk_modifier": 3,
        "explanation_template": "Account '{account}' on HP-UX has a broad sudoers rule: {matched}. Effectively root.",
        "priority": 20,
    },
]
