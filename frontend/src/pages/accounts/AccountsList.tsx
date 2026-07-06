import { useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useGetAccountsQuery } from '../../api/apiSlice'
import { downloadServerFile } from '../../api/download'
import type { Account } from '../../api/types'
import { useCan } from '../../app/rbac'
import {
  ActionButton, DataPanel, DataTable, ErrorState, Field, LoadingPanel, NativeSelect, PageFrame,
  StatusBadge, TextInput, apiErrorMessage, cx, type Column,
} from '../../components/ui'

const PLATFORMS = ['windows', 'rhel', 'centos', 'ubuntu', 'sles', 'solaris', 'aix', 'hpux', 'mysql', 'mssql', 'mongodb', 'oracle_db', 'postgresql', 'redis']
const CLASSES = ['full_admin', 'admin_equivalent', 'operator_high_impact', 'delegated_admin', 'privileged_service', 'sensitive_non_admin', 'dormant_privileged', 'non_privileged', 'unknown_review_required']
const ENABLED = ['enabled', 'disabled', 'locked', 'expired', 'unknown']
const INTERACTIVE = ['interactive', 'non_interactive', 'unknown']
const ACTIVITY = ['active', 'inactive', 'never_logged_in', 'no_evidence']
const opt = (vals: string[]) => vals.map((v) => ({ value: v, label: v.replace(/_/g, ' ') }))

type Filters = {
  search: string; platform: string; classification: string; enabled_status: string
  interactive_status: string; account_origin: string; activity_status: string
  only_privileged: boolean; only_shared: boolean
}
const empty: Filters = { search: '', platform: '', classification: '', enabled_status: '', interactive_status: '', account_origin: '', activity_status: '', only_privileged: false, only_shared: false }

function fmt(ts: string | null | undefined) { return ts ? new Date(ts).toLocaleDateString() : '—' }
function evidenceSummary(a: Account): string {
  const e = a.evidence_summary
  if (!e || typeof e !== 'object') return '—'
  const keys = Object.keys(e)
  return keys.length ? `${keys.length} field(s)` : '—'
}
function originLabel(a: Account) {
  if (a.account_origin === 'domain') return `Domain Account${a.account_domain ? ` · ${a.account_domain}` : ''}`
  if (a.account_origin === 'local') return `Local Account${a.account_domain ? ` · ${a.account_domain}` : ''}`
  if (a.account_origin === 'database') return 'Database native'
  if (a.account_origin === 'os_integrated') return 'OS integrated'
  return a.principal_source ?? a.auth_source ?? 'Unknown'
}

function originBadgeValue(a: Account) {
  if (a.account_origin === 'domain') return 'Domain Account'
  if (a.account_origin === 'local') return 'Local Account'
  if (a.account_origin === 'database') return 'Database Account'
  if (a.account_origin === 'os_integrated') return 'OS Integrated'
  return 'Unknown Origin'
}

export default function AccountsList() {
  const navigate = useNavigate()
  const can = useCan()
  const [params] = useSearchParams()
  const assetId = params.get('asset') ?? ''
  const [filters, setFilters] = useState<Filters>(empty)
  const set = (p: Partial<Filters>) => setFilters((f) => ({ ...f, ...p }))

  // Server-side filtering (true parity): build query params from active filters.
  const query = useMemo(() => {
    const q: Record<string, unknown> = { limit: 500 }
    if (assetId) q.asset_id = assetId
    if (filters.search) q.search = filters.search
    if (filters.platform) q.platform = filters.platform
    if (filters.classification) q.classification = filters.classification
    if (filters.enabled_status) q.enabled_status = filters.enabled_status
    if (filters.interactive_status) q.interactive_status = filters.interactive_status
    if (filters.account_origin) q.account_origin = filters.account_origin
    if (filters.activity_status) q.activity_status = filters.activity_status
    if (filters.only_privileged) q.only_privileged = true
    if (filters.only_shared) q.only_shared = true
    return q
  }, [assetId, filters])

  const { data, isLoading, isFetching, isError, error, refetch } = useGetAccountsQuery(query)
  const rows = data?.items ?? []

  const columns: Column<Account>[] = [
    { key: 'name', header: 'Account', render: (a) => <span className="font-medium text-slate-900">{a.account_name}</span> },
    { key: 'asset', header: 'Asset', render: (a) => a.asset_hostname ? <button className="text-blue-700 hover:underline" onClick={(e) => { e.stopPropagation(); navigate(`/assets/${a.asset_id}`) }}>{a.asset_hostname}</button> : '—' },
    { key: 'platform', header: 'Platform', render: (a) => a.platform },
    { key: 'schema', header: 'DB / Schema', render: (a) => a.schema_name ?? '—' },
    { key: 'source', header: 'Source', render: (a) => a.source_type },
    { key: 'origin', header: 'Account origin', render: (a) => <div><StatusBadge value={originBadgeValue(a)} /><div className="mt-1 text-xs text-slate-500">{originLabel(a)}</div></div> },
    { key: 'type', header: 'Type', render: (a) => a.principal_type },
    { key: 'enabled', header: 'Enabled', render: (a) => <StatusBadge value={a.enabled_status} /> },
    { key: 'interactive', header: 'Interactive', render: (a) => a.interactive_status },
    { key: 'priv', header: 'Privilege', render: (a) => <StatusBadge value={a.privilege_classification} /> },
    { key: 'reason', header: 'Reason', render: (a) => a.review_required_reason ? <span className="text-xs text-slate-500" title={a.review_required_reason}>{a.review_required_reason.slice(0, 40)}</span> : '—' },
    { key: 'last', header: 'Last login', render: (a) => fmt(a.last_login) },
    { key: 'evidence', header: 'Evidence', render: (a) => <span className="text-xs text-slate-500">{evidenceSummary(a)}</span> },
    { key: 'discovered', header: 'Discovered', render: (a) => fmt(a.discovered_at) },
  ]

  return (
    <PageFrame
      eyebrow="Account governance"
      title="Account Workbench"
      subtitle="Review discovered identities, privilege classification, activity, and evidence across every platform."
      actions={
        <div className="flex flex-wrap gap-2">
          <ActionButton onClick={() => refetch()}>{isFetching ? 'Refreshing…' : 'Refresh'}</ActionButton>
          {can('export:run') && <ActionButton onClick={() => downloadServerFile('/exports/accounts/csv', 'accounts.csv')}>Server CSV</ActionButton>}
          {can('export:run') && <ActionButton onClick={() => downloadServerFile('/exports/accounts/csv?only_privileged=true', 'accounts-privileged.csv')}>Privileged CSV</ActionButton>}
        </div>
      }
    >
      <DataPanel title="Filters" detail="Filters apply server-side. Exports are generated by backend endpoints only.">
        <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4">
          <Field label="Search"><TextInput value={filters.search} onChange={(e) => set({ search: e.target.value })} placeholder="account name…" /></Field>
          <Field label="Platform"><NativeSelect value={filters.platform} options={opt(PLATFORMS)} onChange={(v) => set({ platform: v })} placeholder="All platforms" /></Field>
          <Field label="Classification"><NativeSelect value={filters.classification} options={opt(CLASSES)} onChange={(v) => set({ classification: v })} placeholder="All classifications" /></Field>
          <Field label="Enabled status"><NativeSelect value={filters.enabled_status} options={opt(ENABLED)} onChange={(v) => set({ enabled_status: v })} placeholder="Any status" /></Field>
          <Field label="Interactive"><NativeSelect value={filters.interactive_status} options={opt(INTERACTIVE)} onChange={(v) => set({ interactive_status: v })} placeholder="Any" /></Field>
          <Field label="Origin"><NativeSelect value={filters.account_origin} options={opt(['local', 'domain', 'database', 'os_integrated', 'unknown'])} onChange={(v) => set({ account_origin: v })} placeholder="Local / domain" /></Field>
          <Field label="Activity"><NativeSelect value={filters.activity_status} options={opt(ACTIVITY)} onChange={(v) => set({ activity_status: v })} placeholder="Any activity" /></Field>
          <div className="flex items-end gap-4">
            <label className="flex items-center gap-2 text-sm text-slate-700"><input type="checkbox" checked={filters.only_privileged} onChange={(e) => set({ only_privileged: e.target.checked })} />Privileged</label>
            <label className="flex items-center gap-2 text-sm text-slate-700"><input type="checkbox" checked={filters.only_shared} onChange={(e) => set({ only_shared: e.target.checked })} />Shared</label>
          </div>
        </div>
        <div className="flex items-center justify-between border-t border-slate-200 px-4 py-2">
          {assetId ? <span className="text-xs font-medium text-blue-700">Scoped to one asset · <button className="underline" onClick={() => navigate('/accounts')}>clear</button></span> : <span className="text-xs text-slate-500">All assets</span>}
          <button className={cx('text-xs font-medium text-slate-500 hover:text-slate-800')} onClick={() => setFilters(empty)}>Reset filters</button>
        </div>
      </DataPanel>

      {isLoading ? <LoadingPanel label="Loading accounts…" /> : isError ? (
        <ErrorState detail={apiErrorMessage(error)} onRetry={refetch} />
      ) : (
        <DataPanel title="Accounts" detail={`${data?.total ?? 0} match · showing ${rows.length}`}>
          <DataTable columns={columns} rows={rows} getRowKey={(a) => a.id} onRowClick={(a) => navigate(`/accounts/${a.id}`)} empty="No accounts match these filters." minWidth={1380} />
        </DataPanel>
      )}
    </PageFrame>
  )
}
