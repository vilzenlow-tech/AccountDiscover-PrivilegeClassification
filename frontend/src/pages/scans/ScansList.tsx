import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useGetScansQuery } from '../../api/apiSlice'
import type { ScanJob } from '../../api/types'
import { useCan } from '../../app/rbac'
import {
  ActionButton, DataPanel, DataTable, ErrorState, LoadingPanel, MetricTile, NativeSelect,
  PageFrame, StatusBadge, TextInput, apiErrorMessage, type Column,
} from '../../components/ui'
import { SCAN_TYPE_OPTIONS } from './constants'

const SCAN_TYPE_LABEL = Object.fromEntries(SCAN_TYPE_OPTIONS.map((o) => [o.value, o.label]))

export function scanProgress(job: ScanJob): number {
  const t = job.totals ?? {}
  const total = Number(t.total ?? 0)
  if (!total) return job.status === 'success' || job.status === 'failed' ? 100 : 0
  const done = Number(t.success ?? 0) + Number(t.failed ?? 0) + Number(t.skipped ?? 0)
  return Math.min(100, Math.round((done / total) * 100))
}

function fmt(ts: string | null) {
  return ts ? new Date(ts).toLocaleString() : '—'
}

export default function ScansList() {
  const navigate = useNavigate()
  const can = useCan()
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('')
  const { data, isLoading, isError, error, refetch } = useGetScansQuery({ limit: 100 }, { pollingInterval: 5000 })
  const jobs = useMemo(() => {
    const term = query.trim().toLowerCase()
    return (data?.items ?? []).filter((job) => {
      const matchesStatus = !status || job.status === status
      const haystack = [job.name, job.scope_description, job.scan_type, job.selected_platforms?.join(' ')].join(' ').toLowerCase()
      return matchesStatus && (!term || haystack.includes(term))
    })
  }, [data?.items, query, status])
  const active = jobs.filter((job) => job.status === 'running' || job.status === 'queued' || job.status === 'pending').length
  const failed = jobs.filter((job) => job.status === 'failed' || job.status === 'partial_success').length
  const complete = jobs.filter((job) => job.status === 'success').length

  const columns: Column<ScanJob>[] = [
    { key: 'name', header: 'Scan', render: (j) => <div><div className="font-medium text-slate-900">{j.name || j.scope_description || j.id.slice(0, 8)}</div><div className="mt-0.5 text-xs text-slate-500">{j.scope_description}</div></div> },
    { key: 'type', header: 'Type', render: (j) => <div><div>{j.scan_type ? SCAN_TYPE_LABEL[j.scan_type] ?? j.scan_type : '-'}</div><div className="mt-0.5 text-xs text-slate-500">{j.selected_platforms?.length ? j.selected_platforms.join(', ') : '-'}</div></div> },
    { key: 'status', header: 'Status', render: (j) => <StatusBadge value={j.status} /> },
    {
      key: 'progress', header: 'Progress', render: (j) => {
        const p = scanProgress(j)
        return (
          <div className="flex items-center gap-2">
            <div className="h-1.5 w-20 overflow-hidden rounded-full bg-slate-200">
              <div className="h-full rounded-full bg-blue-600" style={{ width: `${p}%` }} />
            </div>
            <span className="text-xs text-slate-500">{p}%</span>
          </div>
        )
      },
    },
    { key: 'results', header: 'Results', render: (j) => {
      const t = j.totals ?? {}
      return <span className="tabular-nums text-xs"><span className="text-emerald-700">{Number(t.success ?? 0)} ok</span> <span className="text-red-700">{Number(t.failed ?? 0)} failed</span> <span className="text-amber-700">{Number(t.skipped ?? 0)} skipped</span></span>
    } },
    { key: 'created', header: 'Created', render: (j) => <div className="text-xs text-slate-500"><div className="whitespace-nowrap">{fmt(j.created_at)}</div><div>{j.triggered_by ?? j.triggered_kind}</div></div> },
  ]

  return (
    <PageFrame
      eyebrow="Discovery operations"
      title="Scans"
      subtitle="Launch, monitor, and review account discovery jobs across operating systems and databases."
      actions={can('scan:launch') ? <ActionButton variant="primary" onClick={() => navigate('/scans/new')}>New scan</ActionButton> : undefined}
    >
      {isLoading ? <LoadingPanel label="Loading scans…" /> : isError ? (
        <ErrorState detail={apiErrorMessage(error)} onRetry={refetch} />
      ) : (
        <div className="space-y-4">
          <div className="grid gap-3 md:grid-cols-3">
            <MetricTile label="Active" value={active} detail="Queued, pending, or running" tone={active ? 'blue' : 'slate'} />
            <MetricTile label="Completed" value={complete} detail="Successful jobs in current view" tone="green" />
            <MetricTile label="Needs attention" value={failed} detail="Failed or partial scans" tone={failed ? 'red' : 'slate'} />
          </div>
          <DataPanel title="Scan workbench" detail={`${jobs.length} visible of ${data?.total ?? 0} total. Live-updating every 5 seconds.`}>
            <div className="grid gap-3 border-b border-slate-200 p-4 md:grid-cols-[minmax(0,1fr)_220px]">
              <TextInput value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search scan name, scope, type, or platform..." />
              <NativeSelect value={status} onChange={setStatus} placeholder="All statuses" options={['queued', 'pending', 'running', 'success', 'partial_success', 'failed', 'cancelled'].map((value) => ({ value, label: value.replace(/_/g, ' ') }))} />
            </div>
          <DataTable
            columns={columns}
            rows={jobs}
            getRowKey={(j) => j.id}
            onRowClick={(j) => navigate(`/scans/${j.id}`)}
            empty="No scans have run yet. Launch a scan to begin discovery."
            minWidth={820}
          />
          </DataPanel>
        </div>
      )}
    </PageFrame>
  )
}
