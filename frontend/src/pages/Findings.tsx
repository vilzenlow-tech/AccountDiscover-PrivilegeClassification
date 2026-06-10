import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { getFindings, setReviewState } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PrivilegeBadge } from '@/components/PrivilegeBadge'
import { PageSpinner } from '@/components/Spinner'
import toast from 'react-hot-toast'
import { format } from 'date-fns'

const REVIEW_OPTIONS = ['acknowledged', 'risk_accepted', 'remediated', 'false_positive']

export default function Findings() {
  const [params] = useSearchParams()
  const qc = useQueryClient()
  const [page, setPage] = useState(0)
  const [classification, setClassification] = useState('')
  const [winningOnly, setWinningOnly] = useState(params.get('winning') === 'true')

  const { data, isLoading } = useQuery({
    queryKey: ['findings', page, classification, winningOnly],
    queryFn: () =>
      getFindings({
        limit: 50, offset: page * 50,
        classification: classification || undefined,
        is_winning: winningOnly || undefined,
      }).then((r) => r.data),
  })

  const reviewMut = useMutation({
    mutationFn: ({ id, state, comment }: { id: string; state: string; comment?: string }) =>
      setReviewState(id, state, comment),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['findings'] }); toast.success('Review state saved') },
  })

  return (
    <div>
      <PageHeader
        title="Privilege Findings"
        subtitle={data ? `${data.total} ${winningOnly ? 'open alert' : 'finding'}${data.total !== 1 ? 's' : ''}` : ''}
      />

      <div className="px-6 py-3 border-b border-slate-200 bg-white flex gap-3">
        <select className="input w-52" value={classification} onChange={(e) => { setClassification(e.target.value); setPage(0) }}>
          <option value="">All classifications</option>
          <option value="full_admin">Full Admin</option>
          <option value="admin_equivalent">Admin Equivalent</option>
          <option value="operator_high_impact">Operator – High Impact</option>
          <option value="delegated_admin">Delegated Admin</option>
          <option value="dormant_privileged">Dormant Privileged</option>
        </select>
        <label className="flex items-center gap-2 text-sm cursor-pointer">
          <input type="checkbox" checked={winningOnly} onChange={(e) => setWinningOnly(e.target.checked)} />
          Winning rules only
        </label>
      </div>

      {isLoading ? <PageSpinner /> : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                <th className="table-th">Rule</th>
                <th className="table-th">Classification</th>
                <th className="table-th">Confidence</th>
                <th className="table-th">Direct</th>
                <th className="table-th">Explanation</th>
                <th className="table-th">Evaluated</th>
                <th className="table-th">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data?.items.map((f) => (
                <tr key={f.id} className="hover:bg-slate-50">
                  <td className="table-td font-mono text-xs text-slate-600">{f.rule_key}</td>
                  <td className="table-td"><PrivilegeBadge classification={f.classification} size="sm" /></td>
                  <td className="table-td text-slate-500">{f.confidence}%</td>
                  <td className="table-td">
                    {f.direct ? (
                      <span className="badge bg-slate-100 text-slate-500">direct</span>
                    ) : (
                      <span className="badge bg-blue-50 text-blue-600 border border-blue-200" title={f.inheritance_path ?? ''}>inherited</span>
                    )}
                  </td>
                  <td className="table-td text-xs text-slate-600 max-w-xs truncate" title={f.explanation}>{f.explanation}</td>
                  <td className="table-td text-slate-400 text-xs whitespace-nowrap">{format(new Date(f.evaluated_at), 'dd MMM HH:mm')}</td>
                  <td className="table-td">
                    <select
                      className="input text-xs py-0.5 w-36"
                      defaultValue=""
                      onChange={(e) => { if (e.target.value) reviewMut.mutate({ id: f.id, state: e.target.value }) }}
                    >
                      <option value="">Set review…</option>
                      {REVIEW_OPTIONS.map((o) => <option key={o} value={o}>{o.replace(/_/g, ' ')}</option>)}
                    </select>
                  </td>
                </tr>
              ))}
              {data?.items.length === 0 && (
                <tr><td colSpan={7} className="py-12 text-center text-slate-400">No findings. Run a scan first.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
