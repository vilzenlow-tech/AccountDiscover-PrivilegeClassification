# User Guide - How to Use the Tool

Version date: 2026-06-28

## Before You Start

You need an active user account. Admins and security analysts can manage assets, connectors, credentials, scans, tags, and most operational workflows. Auditors and viewers have more limited access.

## Add Assets

Use Assets to create individual assets or import a CSV.

Required fields:

- `hostname`
- `platform`

Common optional fields:

- `ip_address`
- `port`
- `environment`
- `owner`
- `business_unit`
- `criticality`
- `connector_name`

For multiple IPs, create/import one asset row per IP or hostname. Direct IP range and CIDR expansion are not implemented.

## Create Tags or Applications

1. Open Tags / Applications.
2. Create a tag with name, optional code, category, color, and status.
3. Use categories such as application, environment, business unit, criticality, compliance, ownership, technology, or custom.

Inactive tags cannot be assigned to assets.

## Assign Tags to Assets

You can assign tags from asset detail screens or use bulk assignment. Tags become available in the scan wizard as a targeting method.

## Configure Credentials and Connectors

1. Open Connectors / Agents.
2. Create credential metadata and, for local vault mode, provide secret material.
3. Create a connector with kind such as `ssh`, `winrm`, `mysql`, `mssql`, `mongodb`, `oracle`, `postgresql`, or `redis`.
4. Link the connector to the credential.
5. Assign the connector to assets or rely on the first active connector of the matching kind.
6. Use Test Connection for an asset before launching a credentialed scan.

External vault providers are planned stubs. Use local vault only for development or pilot unless a real adapter is implemented.

## Launch a Basic Discovery Scan

1. Open Scans -> New scan.
2. Select Basic discovery.
3. Select platform coverage.
4. Select target scope.
5. Choose No credentials.
6. Review resolved targets and launch.

Limitation: most live collectors require credentials for meaningful account discovery. Basic discovery is useful only where a collector can return unauthenticated data or in mock mode.

## Launch a Credentialed Account Discovery Scan

1. Open Scans -> New scan.
2. Select Credentialed discovery or Full discovery.
3. Select platform coverage.
4. Select target scope.
5. Choose Per-asset credentials or Connector credentials.
6. Confirm an active credential exists and launch.

The backend validates linked connectors, active credentials, and vault secret resolution before starting credential-required scan types.

## Scan a Single Hostname or IP

Implemented method:

1. Ensure the hostname/IP exists as an asset.
2. Open Scans -> New scan.
3. Select platform coverage.
4. Choose Selected assets and select the asset, or choose Bulk hostname / IP and paste the exact hostname/IP that already exists in inventory.
5. Launch.

The bulk field matches inventory. It does not create new assets.

## Scan an IP Range or CIDR

Not implemented as direct scan input.

Current workaround:

1. Prepare a CSV with one row per IP or hostname.
2. Import the CSV into Assets.
3. Use tags, environment, selected assets, or bulk hostname/IP matching to scan those assets.

## Scan Selected Platforms Only

1. Open Scans -> New scan.
2. Select the scan intent.
3. In Platform coverage, choose one or more platform selectors.
4. Choose target scope.
5. Launch.

The API accepts all platform enum values plus `all`, `windows`, `windows_server`, and `windows_desktop`.

## Scan Windows Only

Select Windows (all), Windows Server, or Windows Desktop in Platform coverage.

Windows Server/Desktop depends on asset tags such as `windows_role=server`, `windows_kind=desktop`, `windows_type=workstation`, or `os_role=client`. Without those tags, use Windows (all).

## Scan Database Platforms Only

Select Oracle, MSSQL, MySQL, MongoDB, or other database platform values available in API/profile configuration. The current frontend selector shows Oracle, MSSQL, MySQL, and MongoDB; backend also supports PostgreSQL and Redis.

## Review Scan Progress

1. Open Scans.
2. Open the scan detail page.
3. Review job status, target status, attempts, errors, and target stats.

Statuses include pending, queued, running, success, partial_success, failed, timed_out, unreachable, auth_failed, and cancelled.

## Review Discovered Accounts

1. Open Accounts.
2. Filter by platform, classification, enabled status, interactive status, source type, asset, activity status, privileged-only, or shared-only.
3. Open an account to inspect entitlements and evidence.

## Understand Privilege Classifications

The rules engine assigns the highest-severity matching classification:

- `full_admin`
- `admin_equivalent`
- `operator_high_impact`
- `delegated_admin`
- `privileged_service`
- `sensitive_non_admin`
- `dormant_privileged`
- `unknown_review_required`
- `non_privileged`

Each finding stores the matched rule, direct/inherited flag, inheritance path, explanation, confidence, and risk score.

## View Evidence

Account detail exposes normalized evidence and raw evidence references. Raw probe rows include command/query, output hash, output excerpt/body, exit code, duration, and collection timestamp.

## Export Results

Use Reports / Exports or direct export endpoints for accounts and housekeeping. Use Password Policy export for policy-specific reports. Exports are audit logged.

## Review Failed or Skipped Targets

Open scan detail and inspect target `error_bucket` and `error_detail`. Common causes include missing connector, inactive credential, vault secret missing, target unreachable, authentication failure, collector permissions, and unsupported agent scanner.

## Change Password

Open `/change-password` or follow the forced password-change redirect. Enter current password and new password. The backend validates strength and prevents reuse of the current password.

## Admin User Management

Admins can:

- Add users.
- Assign one role per user through the user management UI/API.
- Disable or enable users.
- Reset passwords and force password change.
- View roles and permissions.
