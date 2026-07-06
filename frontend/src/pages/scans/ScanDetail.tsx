import { useMemo } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  useCancelScanMutation, useGetAccountsQuery, useGetScanQuery, useGetScanTargetsQuery,
  useRetryFailedTargetsMutation,
} from '../../api/apiSlice'
import type { Account, ScanTarget } from '../../api/types'
import { useCan } from '../../app/rbac'
import {
  ActionButton, DataPanel, DataTable, ErrorState, InlineAlert, LoadingPanel, MetricTile,
  PageFrame, StatusBadge, apiErrorMessage, type Column,
} from '../../components/ui'
import { SCAN_TYPE_OPTIONS } from './constants'
import { scanProgress } from './ScansList'

const ACTIVE = new Set(['pending', 'queued', 'running'])
const SCAN_TYPE_LABEL = Object.fromEntries(SCAN_TYPE_OPTIONS.map((o) => [o.value, o.label]))

function fmt(ts: string | null) { return ts ? new Date(ts).toLocaleString() : '—' }
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

export default function ScanDetail() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const can = useCan()

  const jobQ = useGetScanQuery(id, { pollingInterval: 4000 })
  const targetsQ = useGetScanTargetsQuery(id, { pollingInterval: jobQ.data && ACTIVE.has(jobQ.data.status) ? 4000 : 0 })
  const accountsQ = useGetAccountsQuery({ limit: 500 })
  const [retry, retryState] = useRetryFailedTargetsMutation()
  const [cancel, cancelState] = useCancelScanMutation()

  const job = jobQ.data
  const targets = targetsQ.data ?? []
  const targetAssetIds = useMemo(() => new Set(targets.map((t) => t.asset_id)), [targets])
  const discovered = useMemo(
    () => (accountsQ.data?.items ?? []).filter((a) => targetAssetIds.has(a.asset_id)),
    [accountsQ.data, targetAssetIds],
  )

  if (jobQ.isLoading) return <PageFrame eyebrow="Scan" title="Scan detail" subtitle="Loading…"><LoadingPanel /></PageFrame>
  if (jobQ.isError || !job) return <PageFrame eyebrow="Scan" title="Scan detail" subtitle="Could not load this scan."><ErrorState detail={apiErrorMessage(jobQ.error)} onRetry={jobQ.refetch} /></PageFrame>

  const t = job.totals ?? {}
  const failedCount = Number(t.failed ?? 0)

  const targetCols: Column<ScanTarget>[] = [
    { key: 'host', header: 'Host', render: (x) => <span className="font-medium text-slate-900">{x.hostname ?? x.asset_id.slice(0, 8)}</span> },
    { key: 'ip', header: 'IP', render: (x) => x.ip_address ?? '—' },
    { key: 'platform', header: 'Platform', render: (x) => x.platform },
    { key: 'status', header: 'Status', render: (x) => <StatusBadge value={x.status} /> },
    { key: 'attempt', header: 'Attempt', render: (x) => x.attempt },
    { key: 'duration', header: 'Duration', render: (x) => (x.duration_ms != null ? `${x.duration_ms} ms` : '—') },
    { key: 'reason', header: 'Failure / skip reason', render: (x) => x.error_bucket ? <span className="text-red-700" title={x.error_detail ?? ''}>{x.error_bucket}{x.error_detail ? ` — ${x.error_detail.slice(0, 60)}` : ''}</span> : '—' },
  ]

  const acctCols: Column<Account>[] = [
    { key: 'name', header: 'Account', render: (a) => <span className="font-medium text-slate-900">{a.account_name}</span> },
    { key: 'host', header: 'Asset', render: (a) => a.asset_hostname ?? '—' },
    { key: 'platform', header: 'Platform', render: (a) => a.platform },
    { key: 'origin', header: 'Account origin', render: (a) => <div><StatusBadge value={originBadgeValue(a)} /><div className="mt-1 text-xs text-slate-500">{originLabel(a)}</div></div> },
    { key: 'priv', header: 'Privilege', render: (a) => <StatusBadge value={a.privilege_classification} /> },
    { key: 'enabled', header: 'Enabled', render: (a) => a.enabled_status },
    { key: 'interactive', header: 'Interactive', render: (a) => a.interactive_status },
    { key: 'last', header: 'Last login', render: (a) => fmt(a.last_login) },
  ]

  return (
    <PageFrame
      eyebrow="Discovery operations"
      title={job.name || job.scope_description || `Scan ${job.id.slice(0, 8)}`}
      subtitle="Per-target results, discovered accounts, and evidence for this discovery job."
      actions={
        <div className="flex gap-2">
          <ActionButton onClick={() => navigate('/scans')}>Back to scans</ActionButton>
          {ACTIVE.has(job.status) && can('scan:manage') && (
            <ActionButton variant="destructive" disabled={cancelState.isLoading} onClick={() => cancel(job.id)}>Cancel</ActionButton>
          )}
          {failedCount > 0 && can('scan:manage') && (
            <ActionButton variant="primary" disabled={retryState.isLoading} onClick={() => retry(job.id)}>{retryState.isLoading ? 'Retrying…' : `Retry ${failedCount} failed`}</ActionButton>
          )}
        </div>
      }
    >
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile label="Status" value={job.status === 'success' ? 'completed' : job.status.replace(/_/g, ' ')} detail={`${scanProgress(job)}% complete`} tone="blue" />
        <MetricTile label="Targets" value={Number(t.total ?? targets.length)} detail="Assets in scope" tone="slate" />
        <MetricTile label="Succeeded" value={Number(t.success ?? 0)} detail="Targets collected" tone="green" />
        <MetricTile label="Failed" value={failedCount} detail="Targets with errors" tone={failedCount ? 'red' : 'slate'} />
      </div>

      <DataPanel title="Scan parameters">
        <dl className="grid grid-cols-2 gap-4 p-4 text-sm md:grid-cols-3 lg:grid-cols-4">
          <Item k="Scan type" v={job.scan_type ? SCAN_TYPE_LABEL[job.scan_type] ?? job.scan_type : '—'} />
          <Item k="Platforms" v={job.selected_platforms?.join(', ') || '—'} />
          <Item k="Credential mode" v={job.credential_mode ?? '—'} />
          <Item k="Password policy" v={job.collect_password_policy ? 'collected' : 'no'} />
          <Item k="Scope" v={job.scope_description} />
          <Item k="Triggered by" v={job.triggered_by ?? job.triggered_kind} />
          <Item k="Started" v={fmt(job.started_at)} />
          <Item k="Finished" v={fmt(job.finished_at)} />
        </dl>
      </DataPanel>

      <DataPanel title="Per-target results" detail={`${targets.length} target(s)`}>
        {targetsQ.isLoading ? <div className="p-5"><LoadingPanel /></div> : (
          <DataTable columns={targetCols} rows={targets} getRowKey={(x) => x.id} empty="No targets recorded for this scan." minWidth={900} />
        )}
      </DataPanel>

      <DataPanel
        title="Discovered accounts"
        detail={accountsQ.isLoading ? 'Loading…' : `${discovered.length} account(s) on scanned assets`}
      >
        {ACTIVE.has(job.status) ? <InlineAlert tone="blue"><span className="m-4 block">Scan in progress — accounts appear as targets complete.</span></InlineAlert> : null}
        <DataTable columns={acctCols} rows={discovered} getRowKey={(a) => a.id} empty="No accounts discovered on the scanned assets yet." minWidth={1100} />
      </DataPanel>
    </PageFrame>
  )
}

function Item({ k, v }: { k: string; v?: string | null }) {
  return <div><dt className="text-xs uppercase tracking-wide text-slate-500">{k}</dt><dd className="mt-0.5 font-medium text-slate-900">{v || '—'}</dd></div>
}
