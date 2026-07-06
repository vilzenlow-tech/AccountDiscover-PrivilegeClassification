import { useMemo, useState } from 'react'
import { downloadServerFile } from '../../api/download'
import { useCan } from '../../app/rbac'
import { ActionButton, Badge, DataPanel, EmptyState, InlineAlert, PageFrame, UnavailableState, cx } from '../../components/ui'

type ReportCategory = 'Inventory' | 'Privilege' | 'Risk' | 'Policy'
type ReportFormat = 'CSV' | 'Excel'
type Report = {
  title: string
  category: ReportCategory
  format: ReportFormat
  detail: string
  scope: string
  evidence: string
  owner: string
  path: string
  filename: string
  perm: boolean
}

const categoryTone: Record<ReportCategory, string> = {
  Inventory: 'blue',
  Privilege: 'red',
  Risk: 'amber',
  Policy: 'purple',
}

export default function Reports() {
  const can = useCan()
  const allowed = can('export:run')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState<ReportCategory | 'All'>('All')

  const reports: Report[] = [
    {
      title: 'Account inventory',
      category: 'Inventory',
      format: 'CSV',
      detail: 'Complete account list with privilege, status, activity, and platform context.',
      scope: 'All discovered accounts',
      evidence: 'Account rows, entitlements, activity evidence',
      owner: 'IAM Operations',
      path: '/exports/accounts/csv',
      filename: 'accounts.csv',
      perm: allowed,
    },
    {
      title: 'Account inventory',
      category: 'Inventory',
      format: 'Excel',
      detail: 'Workbook version of the complete account inventory for reviewer handling.',
      scope: 'All discovered accounts',
      evidence: 'Account rows, entitlements, activity evidence',
      owner: 'IAM Operations',
      path: '/exports/accounts/excel',
      filename: 'accounts.xlsx',
      perm: allowed,
    },
    {
      title: 'Privileged accounts',
      category: 'Privilege',
      format: 'CSV',
      detail: 'Focused extract of admin, root, and high-impact identities for control review.',
      scope: 'Privileged accounts only',
      evidence: 'Classification rules, UID, roles, groups, grants',
      owner: 'Security Assurance',
      path: '/exports/accounts/csv?only_privileged=true',
      filename: 'accounts-privileged.csv',
      perm: allowed,
    },
    {
      title: 'Housekeeping risk',
      category: 'Risk',
      format: 'CSV',
      detail: 'Dormancy and privilege risk matrix used for cleanup and exception review.',
      scope: 'Dormant, stale, and risky accounts',
      evidence: 'Last login, status, privilege class, policy signals',
      owner: 'IT Operations',
      path: '/exports/housekeeping/csv',
      filename: 'housekeeping.csv',
      perm: allowed,
    },
    {
      title: 'Password policy',
      category: 'Policy',
      format: 'CSV',
      detail: 'Policy coverage and exception findings for enforcement tracking.',
      scope: 'Assets with collected password policy',
      evidence: 'Policy source, expected values, discovered values',
      owner: 'GRC',
      path: '/password-policy/export/csv',
      filename: 'password-policy.csv',
      perm: allowed,
    },
    {
      title: 'Password policy',
      category: 'Policy',
      format: 'Excel',
      detail: 'Workbook version of policy coverage and exception findings.',
      scope: 'Assets with collected password policy',
      evidence: 'Policy source, expected values, discovered values',
      owner: 'GRC',
      path: '/password-policy/export/excel',
      filename: 'password-policy.xlsx',
      perm: allowed,
    },
  ]

  const filteredReports = useMemo(() => {
    const needle = query.trim().toLowerCase()
    return reports.filter((report) => {
      const matchesCategory = category === 'All' || report.category === category
      const matchesQuery = !needle || [
        report.title,
        report.category,
        report.format,
        report.detail,
        report.scope,
        report.evidence,
        report.owner,
        report.filename,
      ].some((value) => value.toLowerCase().includes(needle))
      return matchesCategory && matchesQuery
    })
  }, [category, query, reports])

  async function run(report: Report) {
    setError(null)
    setBusy(report.path)
    try {
      await downloadServerFile(report.path, report.filename)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Export failed')
    } finally {
      setBusy(null)
    }
  }

  return (
    <PageFrame
      eyebrow="Assurance"
      title="Reports / Exports"
      subtitle="Evidence-backed exports for auditors, reviewers, and ITAC control owners. Generated server-side from live backend data."
      actions={<ActionButton disabled={!allowed || filteredReports.length === 0 || Boolean(busy)} onClick={() => filteredReports[0] && run(filteredReports[0])}>{busy ? 'Generating…' : 'Download first result'}</ActionButton>}
    >
      {!allowed && <InlineAlert tone="slate">Your role can view this catalog but cannot run exports.</InlineAlert>}
      {error && <InlineAlert tone="red">{error}</InlineAlert>}

      <div className="grid gap-3 md:grid-cols-3">
        <ReportMetric label="Export catalog" value={reports.length} detail="Server-backed report definitions" />
        <ReportMetric label="Evidence mode" value="Live" detail="Generated from backend data at download time" />
        <ReportMetric label="Access control" value={allowed ? 'Allowed' : 'View only'} detail="Controlled by export permissions" />
      </div>

      <DataPanel title="Report catalog" detail={`${filteredReports.length} of ${reports.length} report(s) visible`}>
        <div className="border-b border-slate-200 bg-slate-50/70 p-4">
          <div className="flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
            <div className="max-w-2xl">
              <div className="text-sm font-semibold text-slate-900">Find the right evidence package</div>
              <p className="mt-1 text-xs leading-5 text-slate-500">Search by report name, owner, evidence source, scope, or filename. Filters do not change backend data.</p>
            </div>
            <input
              className="h-10 w-full rounded-md border border-slate-300 bg-white px-3 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100 xl:max-w-sm"
              placeholder="Search reports, evidence, owner"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            {(['All', 'Inventory', 'Privilege', 'Risk', 'Policy'] as Array<ReportCategory | 'All'>).map((item) => (
              <button
                key={item}
                type="button"
                onClick={() => setCategory(item)}
                className={cx(
                  'rounded-md border px-3 py-1.5 text-xs font-semibold transition',
                  category === item ? 'border-blue-600 bg-blue-50 text-blue-700' : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50',
                )}
              >
                {item}
              </button>
            ))}
          </div>
        </div>

        {filteredReports.length === 0 ? (
          <EmptyState title="No matching reports." detail="Clear the search or choose another category." />
        ) : (
          <div className="divide-y divide-slate-100">
            {filteredReports.map((report) => (
              <article key={report.path} className="grid gap-4 p-4 xl:grid-cols-[minmax(0,1fr)_220px] xl:items-center">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <h3 className="text-sm font-semibold text-slate-950">{report.title}</h3>
                    <Badge tone={categoryTone[report.category]}>{report.category}</Badge>
                    <Badge tone="slate">{report.format}</Badge>
                  </div>
                  <p className="mt-2 text-sm leading-6 text-slate-600">{report.detail}</p>
                  <dl className="mt-3 grid gap-3 text-xs sm:grid-cols-3">
                    <ReportFact label="Scope" value={report.scope} />
                    <ReportFact label="Evidence" value={report.evidence} />
                    <ReportFact label="Owner" value={report.owner} />
                  </dl>
                </div>
                <div className="rounded-md border border-slate-200 bg-slate-50 p-3">
                  <div className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500">Output file</div>
                  <div className="mt-1 truncate text-sm font-medium text-slate-900">{report.filename}</div>
                  <div className="mt-3">
                    <ActionButton disabled={!report.perm || busy === report.path} onClick={() => run(report)}>
                      {busy === report.path ? 'Generating…' : `Download ${report.format}`}
                    </ActionButton>
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}
      </DataPanel>

      <DataPanel title="Scoped export roadmap" detail="Planned report controls that need backend query support.">
        <div className="p-4">
          <UnavailableState
            title="Tag, scan, and application scoped exports are not enabled yet"
            detail="The current endpoints support all-account, privileged-only, housekeeping, and password-policy exports. Platform, tag, application, and scan scoped exports need backend query parameters before they can be safely exposed."
          />
        </div>
      </DataPanel>
    </PageFrame>
  )
}

function ReportMetric({ label, value, detail }: { label: string; value: string | number; detail: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <div className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">{label}</div>
      <div className="mt-2 text-2xl font-semibold tracking-tight text-slate-950">{value}</div>
      <div className="mt-1 text-xs leading-5 text-slate-500">{detail}</div>
    </div>
  )
}

function ReportFact({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="font-semibold uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 leading-5 text-slate-700">{value}</dd>
    </div>
  )
}
