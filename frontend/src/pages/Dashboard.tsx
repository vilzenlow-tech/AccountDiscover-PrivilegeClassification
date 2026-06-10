import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { getDashboardMetrics } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { StatCard } from '@/components/StatCard'
import { PageSpinner } from '@/components/Spinner'
import { PrivilegeBadge } from '@/components/PrivilegeBadge'
import type { PrivilegeClass } from '@/api/endpoints'
import { PLATFORM_LABELS } from '@/lib/privilege'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import { format } from 'date-fns'

const CHART_COLORS = ['#ef4444', '#f97316', '#f59e0b', '#a855f7', '#8b5cf6', '#ec4899', '#94a3b8']

export default function Dashboard() {
  const nav = useNavigate()
  const { data, isLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => getDashboardMetrics().then((r) => r.data),
    refetchInterval: 60_000,
  })

  if (isLoading || !data) return <PageSpinner />

  const classChart = Object.entries(data.by_classification)
    .filter(([k]) => k !== 'non_privileged')
    .map(([k, v]) => ({ name: k, value: v }))
    .sort((a, b) => b.value - a.value)

  const platformChart = Object.entries(data.by_platform).map(([k, v]) => ({
    name: PLATFORM_LABELS[k] ?? k,
    value: v,
  }))

  return (
    <div>
      <PageHeader
        title="Dashboard"
        subtitle={data.last_scan_at ? `Last scan: ${format(new Date(data.last_scan_at), 'dd MMM yyyy HH:mm')}` : 'No scans yet'}
        actions={
          <button className="btn-primary" onClick={() => nav('/scans')}>
            + Launch Scan
          </button>
        }
      />
      <div className="p-6 space-y-6">
        {/* Summary cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-3">
          <StatCard label="Total Assets" value={data.total_assets} color="blue" onClick={() => nav('/assets')} />
          <StatCard label="Total Accounts" value={data.total_accounts} color="slate" onClick={() => nav('/accounts')} />
          <StatCard label="Privileged" value={data.privileged_accounts} color="orange" onClick={() => nav('/accounts?only_privileged=true')} />
          <StatCard label="New (7d)" value={data.newly_privileged_last_7d} color="amber" sub="newly privileged" />
          <StatCard label="Dormant Priv." value={data.dormant_privileged} color="pink" onClick={() => nav('/accounts?classification=dormant_privileged')} />
          <StatCard label="Shared Priv." value={data.shared_privileged} color="purple" onClick={() => nav('/accounts?only_shared=true')} />
          <StatCard label="Unknown / Review" value={data.unknown_review_required} color="red" onClick={() => nav('/accounts?classification=unknown_review_required')} />
          <StatCard label="Open Alerts" value={data.open_alerts} color={data.open_alerts > 0 ? 'red' : 'green'} onClick={() => nav('/findings?winning=true')} />
        </div>

        {/* Charts */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="card p-4">
            <h2 className="text-sm font-semibold text-slate-700 mb-3">Classification Breakdown</h2>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={classChart} layout="vertical" margin={{ left: 120, right: 16 }}>
                <XAxis type="number" tick={{ fontSize: 11 }} />
                <YAxis type="category" dataKey="name" tick={{ fontSize: 11 }} width={120}
                  tickFormatter={(v) => v.replace(/_/g, ' ')} />
                <Tooltip formatter={(v: number) => [`${v} accounts`, '']} />
                <Bar dataKey="value" radius={[0, 3, 3, 0]}>
                  {classChart.map((_, i) => <Cell key={i} fill={CHART_COLORS[i % CHART_COLORS.length]} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="card p-4">
            <h2 className="text-sm font-semibold text-slate-700 mb-3">Accounts by Platform</h2>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={platformChart} margin={{ left: 8, right: 16 }}>
                <XAxis dataKey="name" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="value" fill="#3b82f6" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Local admin sprawl */}
        {data.local_admin_sprawl.length > 0 && (
          <div className="card p-4">
            <h2 className="text-sm font-semibold text-slate-700 mb-3">Local Admin Sprawl</h2>
            <p className="text-xs text-slate-500 mb-3">Assets with more than 3 full-admin accounts.</p>
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-100">
                  <th className="table-th">Hostname</th>
                  <th className="table-th text-right">Admin Count</th>
                </tr>
              </thead>
              <tbody>
                {data.local_admin_sprawl.map((row) => (
                  <tr key={row.asset_id} className="border-b border-slate-50 hover:bg-slate-50 cursor-pointer"
                    onClick={() => nav(`/assets/${row.asset_id}`)}>
                    <td className="table-td font-medium">{row.hostname}</td>
                    <td className="table-td text-right">
                      <span className="badge bg-red-100 text-red-700">{row.count}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
