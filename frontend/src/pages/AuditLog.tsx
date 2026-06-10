import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { getAuditLog } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PageSpinner } from '@/components/Spinner'
import { format } from 'date-fns'

export default function AuditLog() {
  const [page, setPage] = useState(0)
  const [action, setAction] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['audit', page, action],
    queryFn: () => getAuditLog({ limit: 50, offset: page * 50, action: action || undefined }).then((r) => r.data),
  })

  return (
    <div>
      <PageHeader title="Audit Log" subtitle="Append-only record of privileged actions" />
      <div className="px-6 py-3 border-b border-slate-200 bg-white flex gap-3">
        <input className="input w-64" placeholder="Filter by action…" value={action}
          onChange={(e) => { setAction(e.target.value); setPage(0) }} />
      </div>
      {isLoading ? <PageSpinner /> : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr>
                  <th className="table-th">Time</th>
                  <th className="table-th">Action</th>
                  <th className="table-th">Actor</th>
                  <th className="table-th">Subject</th>
                  <th className="table-th">IP</th>
                  <th className="table-th">Context</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {data?.items.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-50">
                    <td className="table-td text-slate-400 whitespace-nowrap">{format(new Date(a.occurred_at), 'dd MMM HH:mm:ss')}</td>
                    <td className="table-td font-mono text-xs font-semibold text-slate-700">{a.action}</td>
                    <td className="table-td text-slate-600 text-xs">{a.actor_email ?? a.actor_id ?? '—'}</td>
                    <td className="table-td text-slate-500 text-xs">{a.subject_type ? `${a.subject_type} / ${a.subject_id}` : '—'}</td>
                    <td className="table-td text-slate-400 text-xs">{a.ip ?? '—'}</td>
                    <td className="table-td text-slate-400 text-xs font-mono truncate max-w-[200px]">
                      {a.context ? JSON.stringify(a.context) : ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {data && data.total > 50 && (
            <div className="flex items-center gap-3 px-6 py-3 border-t border-slate-200 text-sm">
              <button className="btn-secondary" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}>← Prev</button>
              <span className="text-slate-500">Page {page + 1} of {Math.ceil(data.total / 50)}</span>
              <button className="btn-secondary" onClick={() => setPage((p) => p + 1)} disabled={(page + 1) * 50 >= data.total}>Next →</button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
