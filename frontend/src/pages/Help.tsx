import { PageHeader } from '@/components/PageHeader'

const pages = [
  {
    page: 'Dashboard',
    purpose: 'Executive view of discovery coverage, privileged account counts, risk classes, and latest scan time.',
    operations: 'Start here after login. Use the metrics to decide whether to review accounts, assets, findings, or launch a new scan.',
    useWhen: 'Daily operations, management review, and quick health checks after a scheduled scan.',
  },
  {
    page: 'Accounts',
    purpose: 'Central inventory of discovered identities across operating systems and databases.',
    operations: 'Filter by platform, privilege class, enabled state, or search text. Open an account to inspect classification evidence and entitlements.',
    useWhen: 'Finding who has access, reviewing privileged users, checking dormant or shared/service accounts.',
  },
  {
    page: 'Account Detail',
    purpose: 'Detailed evidence for one identity.',
    operations: 'Review identity fields, classification, risk score, rule matches, entitlements, last login, and raw evidence summary.',
    useWhen: 'Validating why an account is classified as full admin, sensitive non-admin, privileged service, or non-privileged.',
  },
  {
    page: 'Assets',
    purpose: 'Inventory of target systems and database instances to scan.',
    operations: 'Add or edit assets, set platform, hostname/IP, connector, tags, and discovery enabled status. Export asset inventory when needed.',
    useWhen: 'Onboarding new scan targets, disabling retired systems, tagging assets by site, application, environment, or owner.',
  },
  {
    page: 'Asset Detail',
    purpose: 'Asset-level view of discovered accounts, findings, and scan context.',
    operations: 'Review accounts discovered on a host or database, linked connector, platform, and scan history.',
    useWhen: 'Investigating one server/database or checking whether a target was scanned successfully.',
  },
  {
    page: 'Connectors',
    purpose: 'Manage scan protocol connectors and credential references.',
    operations: 'Create credentials using vault references, create connectors by kind, assign default ports/options, and test connector configuration.',
    useWhen: 'Configuring SSH, WinRM, or database connection methods before scanning assets.',
  },
  {
    page: 'Scans',
    purpose: 'Launch, monitor, schedule, retry, and manage scan profiles.',
    operations: 'Launch scans for all enabled assets, choose a scan profile, optionally collect password policies, view target status, cancel running jobs, retry failed targets, seed default profiles, and create schedules using Daily, Weekly, Monthly, or Custom timing in GMT+8.',
    useWhen: 'Running discovery, troubleshooting failed targets, creating recurring scans, or narrowing a scan to Windows, Linux, Unix, or database platforms.',
  },
  {
    page: 'Findings',
    purpose: 'Review privilege findings created by the rules engine.',
    operations: 'Filter and review open findings, inspect affected account/asset context, and prioritize remediation.',
    useWhen: 'Security review, weekly privileged access review, and remediation tracking.',
  },
  {
    page: 'Password Policy',
    purpose: 'Review password policy posture and exceptions collected during scans.',
    operations: 'View policy summary, findings, account-level exceptions, compare policies, review or export CSV/XLSX reports.',
    useWhen: 'Checking weak local or database password policy, password-never-expires exceptions, lockout settings, and policy drift.',
  },
  {
    page: 'Rules',
    purpose: 'Manage deterministic classification rules.',
    operations: 'Review built-in rules, add or edit custom rules, and verify rule priority, privilege class, confidence, and risk score.',
    useWhen: 'Tuning classification logic for enterprise-specific admin groups, DBA roles, service naming, or exception patterns.',
  },
  {
    page: 'Exceptions',
    purpose: 'Manage approved suppressions and risk acceptances.',
    operations: 'Create or edit privilege exceptions by account, asset, group, or global scope. Track review state and expiry.',
    useWhen: 'Suppressing known approved service accounts or accepted risks without deleting evidence.',
  },
  {
    page: 'Tags',
    purpose: 'Manage business metadata used for grouping and filtering.',
    operations: 'Create tags for application, environment, business unit, criticality, compliance, ownership, technology, or custom categories. Assign/remove tags from assets.',
    useWhen: 'Scoping scans, reporting by owner/environment, and organizing large inventories.',
  },
  {
    page: 'Agent Connectors',
    purpose: 'Manage remote connector agents deployed in segmented networks.',
    operations: 'Generate enrollment tokens, approve pending agents, register placeholders, enable/disable agents, revoke compromised/decommissioned agents, and open agent details.',
    useWhen: 'Scanning remote sites, DMZs, cloud VPCs, or networks where the console cannot directly reach targets.',
  },
  {
    page: 'Agent Connector Detail',
    purpose: 'Inspect and control one connector agent.',
    operations: 'Review heartbeat, health, configuration, logs, pending/running/completed jobs, allowed scan modes, and recent result uploads.',
    useWhen: 'Troubleshooting connector status, confirming agent reachability, and validating remote scan execution.',
  },
  {
    page: 'Audit Log',
    purpose: 'Append-only record of privileged user actions.',
    operations: 'Review who launched scans, changed credentials/connectors/rules/exceptions, approved agents, or exported sensitive reports.',
    useWhen: 'Compliance review, incident investigation, and operational accountability.',
  },
]

const scanProfiles = [
  ['Full Scan', 'All enabled assets across every platform.', 'Baseline inventory, full refresh, post-deployment validation, or monthly enterprise review.'],
  ['OS Scan', 'All operating systems: Linux, Unix, and Windows. Excludes databases.', 'Server access review when database accounts are handled by a separate DBA workflow.'],
  ['Unix / Linux Scan', 'All SSH-based Unix/Linux platforms: RHEL, CentOS, Ubuntu, SLES, Solaris, AIX, HP-UX.', 'Unix team review, SSH credential validation, sudo/RBAC review.'],
  ['Linux Scan', 'Modern Linux only: RHEL, CentOS, Ubuntu, SLES.', 'Standard Linux fleet scanning with common getent/shadow/sudoers evidence.'],
  ['RHEL / CentOS Scan', 'Red Hat compatible systems only.', 'RHEL estate review, patch window validation, or targeted Linux troubleshooting.'],
  ['Ubuntu Scan', 'Ubuntu servers only.', 'Cloud Linux or Ubuntu application server review.'],
  ['SLES Scan', 'SUSE Linux Enterprise only.', 'SAP or SUSE estate review.'],
  ['Legacy Unix Scan', 'Solaris, AIX, and HP-UX.', 'Legacy platform review where RBAC/trusted-mode evidence and specialist owners are involved.'],
  ['Windows Scan', 'Windows Server/Desktop via WinRM/WMI.', 'Local Administrators review, service/task run-as review, RDP/remote management group review, password-never-expires checks.'],
  ['Database Scan', 'All supported databases: MySQL, MSSQL, MongoDB, Oracle, PostgreSQL, Redis.', 'DBA access review, global role review, and database-native account inventory.'],
  ['Relational DB Scan', 'MySQL, MSSQL, Oracle DB, PostgreSQL.', 'Traditional database privilege review across SQL engines.'],
  ['NoSQL / Cache Scan', 'MongoDB and Redis.', 'Application platform review for document stores and cache systems.'],
  ['MySQL / MariaDB Scan', 'MySQL/MariaDB accounts and grants.', 'Review root users, global grants, grant option, locked accounts, and password policy status.'],
  ['MSSQL Scan', 'SQL Server logins and server/database roles.', 'Review sysadmin/securityadmin/db_owner and SQL login password policy flags.'],
  ['MongoDB Scan', 'MongoDB users and roles.', 'Review root, userAdminAnyDatabase, dbAdminAnyDatabase, backup/restore, and inherited roles.'],
  ['Oracle DB Scan', 'Oracle users, system privileges, role grants, and profiles.', 'Review DBA/SYS* roles, catalog privileges, locked users, and profile policy.'],
  ['PostgreSQL Scan', 'PostgreSQL roles and memberships.', 'Review superuser, createrole, createdb, replication, pg_* built-in roles, and role validity.'],
  ['Redis Scan', 'Redis ACL users and command/key-pattern permissions.', 'Review default user, +@all, nopass, broad key patterns, and dangerous command access.'],
]

const workflows = [
  ['First-time setup', 'Create credentials in Connectors, create protocol connectors, add assets, assign tags, then run a small platform-specific scan before launching Full Scan.'],
  ['Daily operations', 'Open Dashboard, review last scan time and high-risk counts, then check Findings and Accounts for newly privileged or dormant privileged accounts.'],
  ['Targeted investigation', 'Open Assets, find the host/database, open Asset Detail, review accounts and findings, then open Account Detail for evidence.'],
  ['Failed scan troubleshooting', 'Open Scans, select the job, review target error bucket/detail, fix credential/network/platform issue, then use Retry failed.'],
  ['Remote network scanning', 'Open Agent Connectors, generate token, deploy agent in the target network, approve it, confirm heartbeat, then launch the scan.'],
  ['Password policy review', 'Launch a scan with Collect password policies enabled, then open Password Policy to review findings, exceptions, and exports.'],
  ['Rules tuning', 'Review Account Detail rule matches, update Rules if needed, rerun the relevant scan profile, then confirm Findings/Accounts changed as expected.'],
  ['Audit/compliance evidence', 'Use Audit Log for operator actions, Password Policy export for policy evidence, and Account Detail evidence for account-specific decisions.'],
]

const scanModes = [
  ['Safe mode', 'Default read-only discovery. Uses normal metadata commands and avoids expensive or intrusive probes.', 'Routine scheduled scans, production business hours, broad inventory scans.'],
  ['Deep mode', 'Reserved for richer evidence where configured. May use additional probes, longer timeouts, or more complete relationship walks.', 'Controlled maintenance windows, targeted investigations, incomplete evidence from safe mode.'],
  ['Collect password policies', 'Optional scan setting that adds password-policy probes per target.', 'Policy audits, password-never-expires review, weak lockout/complexity checks.'],
  ['Scheduled scan', 'Recurring scan using a selected profile and scope. Choose Daily, Weekly, Monthly, or Custom, then set the run time in GMT+8.', 'Daily operations, weekly access review, monthly compliance scans, or advanced custom recurrence.'],
  ['Manual/on-demand scan', 'Operator-launched scan from the Scans page.', 'Immediate validation after onboarding, remediation, credential fixes, or incident response.'],
  ['Connector-agent credentialed discovery', 'Remote agent runs credentialed target scans and uploads compressed results to the console.', 'Segmented networks where the central console cannot directly reach the targets.'],
]

const scheduleOptions = [
  ['Daily', 'Run once every day at the selected GMT+8 time.', 'Routine discovery coverage and daily operational checks.'],
  ['Weekly', 'Run on one or more selected weekdays at the selected GMT+8 time.', 'Weekly privileged access review, recurring team review cycles, or weekend scan windows.'],
  ['Monthly', 'Run on the selected day of each month at the selected GMT+8 time.', 'Monthly compliance evidence, management reporting, or scheduled baseline refresh.'],
  ['Custom', 'Use a five-field cron expression for advanced recurrence. The expression is evaluated in GMT+8.', 'Patterns that do not fit daily, weekly, or monthly schedules.'],
]

const operatingFlow = [
  {
    step: 'Configure connectors and assets',
    target: 'connectors-assets-guide',
    summary: 'Prepare credentials, protocol connectors, assets, tags, and remote connector agents before scanning.',
  },
  {
    step: 'Launch or schedule scans',
    target: 'scan-schedule-guide',
    summary: 'Run on-demand scans, choose scan profiles, schedule recurring scans, and retry failed targets.',
  },
  {
    step: 'Review accounts and findings',
    target: 'review-results-guide',
    summary: 'Use Accounts, Account Detail, Asset Detail, Findings, and Password Policy to review evidence.',
  },
  {
    step: 'Tune rules and document exceptions',
    target: 'rules-exceptions-guide',
    summary: 'Adjust classification rules, record approved risk, and use Audit Log for accountability.',
  },
]

const ruleUsage = [
  ['Review existing rules', 'Open Rules, filter by platform if needed, then click a row to inspect the predicate JSON and explanation template.', 'Use this before adding custom rules so you do not duplicate built-in logic.'],
  ['Add a custom rule', 'Click Add Rule, enter a stable Rule Key, name, platform, classification, confidence, priority, risk modifier, explanation template, and predicate JSON.', 'Use this when your environment has a group, role, naming pattern, or account type that should classify differently.'],
  ['Set priority carefully', 'Rules with stronger business meaning should get higher precedence. Keep broad fallback rules lower priority than precise admin or DBA rules.', 'Use this when two rules could match the same account.'],
  ['Use confidence and risk modifier', 'Confidence explains how reliable the match is. Risk modifier adjusts the resulting risk score up or down for reporting.', 'Use high confidence for direct admin evidence and lower confidence for naming or indirect hints.'],
  ['Rerun a scan after changes', 'Rules apply during scan result evaluation, so rerun the relevant scan profile after creating or editing rules.', 'Use this to confirm Accounts and Findings change as expected.'],
  ['Disable before deleting', 'Turn a rule off first if you are testing impact. Delete only when you are sure it is no longer needed.', 'Use this for controlled rule tuning and auditability.'],
]

const predicateOperators = [
  ['uid_equals', '{"uid_equals": 0}', 'Matches Unix/Linux accounts with UID 0 evidence.'],
  ['entitlement_kind_is', '{"entitlement_kind_is": "unix_uid0"}', 'Matches when any entitlement of that kind exists.'],
  ['entitlement_kind_name_in', '{"entitlement_kind_name_in": {"kind": "windows_local_group", "names": ["Administrators"]}}', 'Matches entitlement kind and one of the listed names.'],
  ['entitlement_kind_attr_true', '{"entitlement_kind_attr_true": {"kind": "sudo_rule", "attr": "nopasswd"}}', 'Matches entitlement attributes collected by scanners.'],
  ['principal_type_in', '{"principal_type_in": ["service", "application"]}', 'Matches account principal type.'],
  ['enabled_status_in', '{"enabled_status_in": ["enabled"]}', 'Matches account status.'],
  ['interactive_shell_is_non_interactive', '{"interactive_shell_is_non_interactive": true}', 'Matches accounts with non-interactive shell status.'],
  ['is_dormant', '{"is_dormant": true}', 'Matches accounts with no login or login older than the dormancy threshold.'],
  ['all_of', '{"all_of": [{"principal_type_in": ["service"]}, {"enabled_status_in": ["enabled"]}]}', 'All nested predicates must match.'],
  ['any_of', '{"any_of": [{"uid_equals": 0}, {"entitlement_kind_name_in": {"kind": "unix_group", "names": ["wheel"]}}]}', 'At least one nested predicate must match.'],
  ['not', '{"not": {"interactive_shell_is_non_interactive": true}}', 'Negates another predicate.'],
]

const ruleSamples = [
  [
    'Unix root account',
    'Platform: RHEL/Linux. Classification: full_admin. Confidence: 100. Priority: 10.',
    '{"uid_equals": 0}',
    "Account '{account}' has UID 0 and should be treated as full administrator.",
  ],
  [
    'Linux sudo or wheel member',
    'Platform: Linux. Classification: admin_equivalent. Confidence: 95. Priority: 20.',
    '{"entitlement_kind_name_in": {"kind": "unix_group", "names": ["sudo", "wheel"]}}',
    "Account '{account}' is a member of privileged Unix/Linux group(s): {matched}.",
  ],
  [
    'Passwordless sudo',
    'Platform: Linux. Classification: full_admin. Confidence: 95. Priority: 15.',
    '{"entitlement_kind_attr_true": {"kind": "sudo_rule", "attr": "nopasswd"}}',
    "Account '{account}' has passwordless sudo evidence: {matched}.",
  ],
  [
    'Windows local administrator',
    'Platform: Windows. Classification: full_admin. Confidence: 98. Priority: 10.',
    '{"entitlement_kind_attr_true": {"kind": "windows_local_group", "attr": "is_administrators"}}',
    "Account '{account}' is in the Windows local Administrators group.",
  ],
  [
    'MSSQL sysadmin role',
    'Platform: MSSQL. Classification: full_admin. Confidence: 98. Priority: 10.',
    '{"entitlement_kind_name_in": {"kind": "mssql_server_role", "names": ["sysadmin"]}}',
    "SQL login '{account}' has MSSQL sysadmin role membership: {matched}.",
  ],
  [
    'MongoDB critical role',
    'Platform: MongoDB. Classification: admin_equivalent. Confidence: 95. Priority: 20.',
    '{"entitlement_kind_attr_true": {"kind": "mongo_role", "attr": "admin_critical"}}',
    "MongoDB account '{account}' has critical administrative role evidence: {matched}.",
  ],
  [
    'Enabled service account',
    'Platform: Any. Classification: privileged_service. Confidence: 75. Priority: 120.',
    '{"all_of": [{"principal_type_in": ["service", "application"]}, {"enabled_status_in": ["enabled"]}]}',
    "Account '{account}' is an enabled service/application account and should be reviewed for ownership.",
  ],
  [
    'Dormant privileged account',
    'Platform: Any. Classification: dormant_privileged. Confidence: 85. Priority: 80.',
    '{"all_of": [{"is_dormant": true}, {"any_of": [{"uid_equals": 0}, {"entitlement_kind_attr_true": {"kind": "windows_local_group", "attr": "high_impact"}}]}]}',
    "Account '{account}' appears dormant while still carrying privileged evidence.",
  ],
]

function Table({ headers, rows }: { headers: string[]; rows: Array<Array<string>> }) {
  return (
    <div className="overflow-x-auto border border-slate-200 rounded-lg">
      <table className="w-full text-sm">
        <thead className="bg-slate-50 border-b border-slate-200">
          <tr>
            {headers.map((h) => <th key={h} className="table-th whitespace-nowrap">{h}</th>)}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rows.map((row, i) => (
            <tr key={i} className="align-top">
              {row.map((cell, j) => (
                <td key={j} className={j === 0 ? 'table-td font-semibold text-slate-900' : 'table-td text-slate-600 whitespace-normal'}>
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function CodeTable({ headers, rows }: { headers: string[]; rows: Array<Array<string>> }) {
  return (
    <div className="overflow-x-auto border border-slate-200 rounded-lg">
      <table className="w-full text-sm">
        <thead className="bg-slate-50 border-b border-slate-200">
          <tr>
            {headers.map((h) => <th key={h} className="table-th whitespace-nowrap">{h}</th>)}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rows.map((row, i) => (
            <tr key={i} className="align-top">
              {row.map((cell, j) => (
                <td key={j} className={j === 0 ? 'table-td font-semibold text-slate-900' : 'table-td text-slate-600 whitespace-normal'}>
                  {j === 2 ? (
                    <pre className="max-w-xl overflow-x-auto rounded bg-slate-900 px-3 py-2 text-[11px] text-slate-50">{cell}</pre>
                  ) : (
                    cell
                  )}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function Help() {
  return (
    <div>
      <PageHeader
        title="Help"
        subtitle="User operations guide for Account Discovery Tool"
      />

      <div className="p-6 space-y-6 max-w-7xl">
        <section className="card p-5 space-y-3">
          <h2 className="text-lg font-semibold text-slate-900">Operating Flow</h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-sm">
            {operatingFlow.map((item, i) => (
              <a
                key={item.step}
                href={`#${item.target}`}
                className="block rounded-lg border border-slate-200 bg-slate-50 p-3 transition-colors hover:border-brand-300 hover:bg-brand-50 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:ring-offset-2"
              >
                <div className="text-xs font-semibold text-brand-700 mb-1">Step {i + 1}</div>
                <div className="font-medium text-slate-900">{item.step}</div>
                <div className="mt-1 text-xs leading-5 text-slate-500">{item.summary}</div>
              </a>
            ))}
          </div>
        </section>

        <section id="connectors-assets-guide" className="card p-5 space-y-3 scroll-mt-6">
          <h2 className="text-lg font-semibold text-slate-900">Step 1: Configure Connectors and Assets</h2>
          <Table
            headers={['Area', 'User operation', 'Use when']}
            rows={[
              ['Connectors', 'Create vault-backed credentials, create SSH/WinRM/database connectors, set ports/options, and test configuration.', 'Before scanning new platforms or updating credential paths.'],
              ['Assets', 'Add target hosts or databases, set platform and hostname/IP, assign connector, add tags, and enable discovery.', 'Onboarding targets, retiring systems, or narrowing scan scope.'],
              ['Tags', 'Create and assign business metadata such as application, environment, owner, compliance, or criticality.', 'Scoping scans and reporting by business context.'],
              ['Agent Connectors', 'Generate enrollment tokens, approve agents, and confirm heartbeat for segmented networks.', 'Remote sites, DMZs, cloud VPCs, or networks unreachable from the console.'],
            ]}
          />
        </section>

        <section id="scan-schedule-guide" className="card p-5 space-y-3 scroll-mt-6">
          <h2 className="text-lg font-semibold text-slate-900">Step 2: Launch or Schedule Scans</h2>
          <Table
            headers={['Operation', 'How to use it', 'Use when']}
            rows={[
              ['Launch Scan', 'Open Scans, choose a scan profile, optionally collect password policies, then launch for all enabled assets.', 'Immediate discovery, validation after changes, or incident response.'],
              ['Scheduled Scan', 'Open Scheduled Scans, add a schedule, select Daily, Weekly, Monthly, or Custom, set the GMT+8 run time, choose profile and scope, then save.', 'Recurring discovery coverage without typing raw cron.'],
              ['Retry failed', 'Select a failed or partially successful job, review target errors, fix credential/network/platform issues, then retry failed targets.', 'Recovering from temporary failures without rerunning successful targets.'],
              ['Scan Profiles', 'Use built-in profiles or create targeted profiles by platform and scan mode.', 'Narrowing scan scope to operating systems, databases, or specific technologies.'],
            ]}
          />
        </section>

        <section id="review-results-guide" className="card p-5 space-y-3 scroll-mt-6">
          <h2 className="text-lg font-semibold text-slate-900">Step 3: Review Accounts and Findings</h2>
          <Table
            headers={['Area', 'User operation', 'Use when']}
            rows={[
              ['Dashboard', 'Review discovery coverage, risk classes, privileged account totals, and latest scan time.', 'Daily operations and management review.'],
              ['Accounts', 'Filter identities by platform, privilege class, enabled state, or search text, then open Account Detail for evidence.', 'Finding access holders, dormant privileged accounts, or shared/service accounts.'],
              ['Findings', 'Review open findings, affected account/asset context, and remediation priority.', 'Weekly privileged access review and remediation tracking.'],
              ['Password Policy', 'Review policy summary, findings, exceptions, comparisons, and exports collected during scans.', 'Weak policy, password-never-expires, lockout, and policy-drift review.'],
            ]}
          />
        </section>

        <section id="rules-exceptions-guide" className="card p-5 space-y-3 scroll-mt-6">
          <h2 className="text-lg font-semibold text-slate-900">Step 4: Tune Rules and Document Exceptions</h2>
          <Table
            headers={['Area', 'User operation', 'Use when']}
            rows={[
              ['Rules', 'Review built-in rules, add or edit custom rules, and verify priority, privilege class, confidence, and risk score.', 'Tuning classification for enterprise-specific admin groups, DBA roles, or service naming.'],
              ['Exceptions', 'Create approved suppressions by account, asset, group, or global scope, with review state and expiry.', 'Documenting accepted risk without deleting evidence.'],
              ['Audit Log', 'Review who launched scans, changed credentials/connectors/rules/exceptions, approved agents, or exported reports.', 'Compliance review, incident investigation, and operational accountability.'],
            ]}
          />
        </section>

        <section className="card p-5 space-y-3">
          <h2 className="text-lg font-semibold text-slate-900">Rules Guide</h2>
          <p className="text-sm text-slate-600">
            Rules classify discovered accounts by matching account evidence and entitlements collected during scans. Use them to reflect your organization&apos;s privilege model, then rerun the relevant scan profile to refresh Accounts and Findings.
          </p>
          <Table
            headers={['Task', 'How to use it', 'When to use']}
            rows={ruleUsage}
          />
        </section>

        <section className="card p-5 space-y-3">
          <h2 className="text-lg font-semibold text-slate-900">Rule Predicate Operators</h2>
          <p className="text-sm text-slate-600">
            Predicate JSON is a safe, closed vocabulary. It is not executable code. Combine operators with all_of, any_of, and not for more specific matching.
          </p>
          <Table
            headers={['Operator', 'Example Predicate JSON', 'What it matches']}
            rows={predicateOperators}
          />
        </section>

        <section className="card p-5 space-y-3">
          <h2 className="text-lg font-semibold text-slate-900">Sample Custom Rules</h2>
          <CodeTable
            headers={['Sample', 'Suggested Settings', 'Predicate JSON', 'Explanation Template']}
            rows={ruleSamples}
          />
        </section>

        <section className="card p-5 space-y-3">
          <h2 className="text-lg font-semibold text-slate-900">Page-by-Page User Operations</h2>
          <Table
            headers={['Page', 'Purpose', 'User operations', 'Use when']}
            rows={pages.map((p) => [p.page, p.purpose, p.operations, p.useWhen])}
          />
        </section>

        <section className="card p-5 space-y-3">
          <h2 className="text-lg font-semibold text-slate-900">Scan Types and Scenarios</h2>
          <Table
            headers={['Scan profile', 'Purpose', 'Recommended scenario']}
            rows={scanProfiles}
          />
        </section>

        <section className="card p-5 space-y-3">
          <h2 className="text-lg font-semibold text-slate-900">Scan Modes and Job Types</h2>
          <Table
            headers={['Type', 'Purpose', 'When to use']}
            rows={scanModes}
          />
        </section>

        <section className="card p-5 space-y-3">
          <h2 className="text-lg font-semibold text-slate-900">Scheduled Scan Options</h2>
          <Table
            headers={['Option', 'Purpose', 'Recommended scenario']}
            rows={scheduleOptions}
          />
        </section>

        <section className="card p-5 space-y-3">
          <h2 className="text-lg font-semibold text-slate-900">Common Workflows</h2>
          <Table
            headers={['Scenario', 'Recommended operation']}
            rows={workflows}
          />
        </section>

        <section className="card p-5 space-y-3">
          <h2 className="text-lg font-semibold text-slate-900">Operational Notes</h2>
          <ul className="list-disc pl-5 text-sm text-slate-600 space-y-1.5">
            <li>Assets must be discovery-enabled before they are included in Launch All Enabled scans.</li>
            <li>Scan profiles with an empty platform list scan all platforms; profiles with platform values skip assets outside that scope.</li>
            <li>Password policy collection is opt-in because it adds extra target commands and some platforms provide partial evidence.</li>
            <li>Use Retry failed after fixing credentials, network reachability, WinRM/SSH settings, or database grants.</li>
            <li>Use Exceptions to document accepted risk; do not delete evidence to hide known approved accounts.</li>
            <li>Use Audit Log to prove who launched scans, changed rules, approved agents, or exported reports.</li>
          </ul>
        </section>
      </div>
    </div>
  )
}
