import { useMemo, useState } from 'react'
import { useGetAuditLogQuery } from '../../api/apiSlice'
import type { AuditLogItem } from '../../api/types'
import { useCan } from '../../app/rbac'
import {
  DataPanel, DataTable, ErrorState, LoadingPanel, PageFrame, TextInput, UnavailableState,
  apiErrorMessage, type Column,
} from '../../components/ui'

function fmt(ts: string) { return new Date(ts).toLocaleString() }

export default function AuditLogs() {
  const can = useCan()
  const allowed = can('audit:view')
  const { data, isLoading, isError, error, refetch } = useGetAuditLogQuery({ limit: 300 }, { skip: !allowed })
  const [q, setQ] = useState('')

  const rows = useMemo(() => {
    const items = data?.items ?? []
    const needle = q.trim().toLowerCase()
    if (!needle) return items
    return items.filter((r) => `${r.action} ${r.actor_email ?? ''} ${r.subject_type ?? ''}`.toLowerCase().includes(needle))
  }, [data, q])

  const columns: Column<AuditLogItem>[] = [
    { key: 'time', header: 'Time', render: (r) => <span className="whitespace-nowrap text-xs text-slate-500">{fmt(r.occurred_at)}</span> },
    { key: 'actor', header: 'Actor', render: (r) => r.actor_email ?? <span className="text-slate-400">system</span> },
    { key: 'action', header: 'Action', render: (r) => <span className="font-medium text-slate-900">{r.action}</span> },
    { key: 'subject', header: 'Subject', render: (r) => [r.subject_type, r.subject_id ? r.subject_id.slice(0, 8) : null].filter(Boolean).join(' · ') || '—' },
    { key: 'ip', header: 'IP', render: (r) => r.ip ?? '—' },
    { key: 'context', header: 'Context', render: (r) => r.context ? <span className="text-xs text-slate-500" title={JSON.stringify(r.context)}>{Object.keys(r.context).slice(0, 3).join(', ')}</span> : '—' },
  ]

  return (
    <PageFrame
      eyebrow="Assurance"
      title="Audit Logs"
      subtitle="Timestamped record of sensitive actions — logins, scans, exports, and configuration changes."
    >
      {!allowed ? (
        <UnavailableState title="Audit access restricted" detail="Audit logs are visible to administrators and auditors only. Your role does not include audit:view." />
      ) : isLoading ? <LoadingPanel label="Loading audit trail…" /> : isError ? (
        <ErrorState detail={apiErrorMessage(error)} onRetry={refetch} />
      ) : (
        <DataPanel title="Audit trail" detail={`${data?.total ?? 0} event(s)`}>
          <div className="border-b border-slate-200 p-3">
            <TextInput value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter by action, actor, or subject…" className="max-w-sm" />
          </div>
          <DataTable columns={columns} rows={rows} getRowKey={(r) => r.id} empty="No audit events recorded yet." minWidth={900} />
        </DataPanel>
      )}
    </PageFrame>
  )
}
