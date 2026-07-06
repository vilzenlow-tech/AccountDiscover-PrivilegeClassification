import { useNavigate } from 'react-router-dom'
import { useGetConnectorAgentsQuery, useGetConnectorsQuery, useGetDashboardMetricsQuery, useGetScansQuery } from '../api/apiSlice'
import type { Connector, ConnectorAgent, ScanJob } from '../api/types'
import {
  Badge, DataPanel, DataTable, ErrorState, LoadingPanel, MetricTile, PageFrame, StatusBadge,
  UnavailableState, apiErrorMessage, type Column,
} from '../components/ui'
import { scanProgress } from './scans/ScansList'

function fmt(ts: string | null) { return ts ? new Date(ts).toLocaleString() : '—' }
function labelize(value: string) { return value.replace(/_/g, ' ') }
function connectorHealthTone(status: string) {
  if (status === 'online' || status === 'active') return 'green'
  if (status === 'approved' || status === 'stale' || status === 'pending') return 'amber'
  if (status === 'offline' || status === 'disabled' || status === 'revoked' || status === 'error' || status === 'inactive') return 'red'
  return 'slate'
}

const CLASSIFICATION_META: Record<string, { tone: 'red' | 'amber' | 'blue' | 'green' | 'slate'; label: string; note: string; bar: string; bg: string }> = {
  full_admin: { tone: 'red', label: 'Critical control', note: 'Root, sysadmin, or unrestricted admin authority', bar: 'bg-red-600', bg: 'bg-red-50/80 border-red-200' },
  admin_equivalent: { tone: 'red', label: 'Critical control', note: 'Can become or act as administrator', bar: 'bg-red-600', bg: 'bg-red-50/80 border-red-200' },
  dormant_privileged: { tone: 'red', label: 'Critical control', note: 'Privileged identity with stale activity', bar: 'bg-red-600', bg: 'bg-red-50/80 border-red-200' },
  operator_high_impact: { tone: 'amber', label: 'Elevated review', note: 'Operational authority with material blast radius', bar: 'bg-amber-500', bg: 'bg-amber-50/80 border-amber-200' },
  delegated_admin: { tone: 'amber', label: 'Elevated review', note: 'Scoped administration or delegated control', bar: 'bg-amber-500', bg: 'bg-amber-50/80 border-amber-200' },
  privileged_service: { tone: 'amber', label: 'Elevated review', note: 'Service identity with privileged access', bar: 'bg-amber-500', bg: 'bg-amber-50/80 border-amber-200' },
  sensitive_non_admin: { tone: 'blue', label: 'Sensitive', note: 'Non-admin but business or data sensitive', bar: 'bg-blue-500', bg: 'bg-blue-50/80 border-blue-200' },
  unknown_review_required: { tone: 'amber', label: 'Needs evidence', note: 'Insufficient evidence to classify confidently', bar: 'bg-amber-500', bg: 'bg-amber-50/80 border-amber-200' },
  non_privileged: { tone: 'green', label: 'Standard', note: 'No elevated privilege detected', bar: 'bg-emerald-500', bg: 'bg-emerald-50/80 border-emerald-200' },
}

function classMeta(classification: string) {
  return CLASSIFICATION_META[classification] ?? { tone: 'slate' as const, label: 'Unmapped', note: 'Classification requires review', bar: 'bg-slate-400', bg: 'bg-slate-50 border-slate-200' }
}

export default function Dashboard() {
  const navigate = useNavigate()
  const { data, isLoading, isError, error, refetch } = useGetDashboardMetricsQuery()
  const scansQ = useGetScansQuery({ limit: 8 })
  const connectorsQ = useGetConnectorsQuery()
  const agentsQ = useGetConnectorAgentsQuery()

  if (isLoading) return <PageFrame eyebrow="Operations" title="Dashboard" subtitle="Identity control overview."><LoadingPanel label="Loading metrics…" /></PageFrame>
  if (isError || !data) return <PageFrame eyebrow="Operations" title="Dashboard" subtitle="Identity control overview."><ErrorState detail={apiErrorMessage(error)} onRetry={refetch} /></PageFrame>

  const platformRows = Object.entries(data.by_platform).map(([platform, count]) => ({ platform, count }))
  const classRows = Object.entries(data.by_classification)
    .map(([classification, count]) => ({ classification, count, meta: classMeta(classification) }))
    .sort((a, b) => {
      const rank = { red: 0, amber: 1, blue: 2, green: 3, slate: 4 }
      return rank[a.meta.tone] - rank[b.meta.tone] || b.count - a.count
    })
  const failedScans = (scansQ.data?.items ?? []).filter((s) => s.status === 'failed' || s.status === 'partial_success').length
  const connectors = connectorsQ.data?.items ?? []
  const agents = agentsQ.data?.items ?? []
  const activeConnectors = connectors.filter((connector) => connector.is_active).length
  const onlineAgents = agents.filter((agent) => agent.status === 'online').length
  const unhealthyAgents = agents.filter((agent) => ['offline', 'stale', 'error', 'disabled', 'revoked'].includes(agent.status)).length

  const scanCols: Column<ScanJob>[] = [
    { key: 'name', header: 'Scan', render: (s) => <span className="font-medium text-slate-900">{s.name || s.scope_description || s.id.slice(0, 8)}</span> },
    { key: 'status', header: 'Status', render: (s) => <StatusBadge value={s.status} /> },
    { key: 'progress', header: 'Progress', render: (s) => `${scanProgress(s)}%` },
    { key: 'created', header: 'Created', render: (s) => <span className="text-xs text-slate-500">{fmt(s.created_at)}</span> },
  ]
  const connectorCols: Column<Connector | ConnectorAgent>[] = [
    { key: 'name', header: 'Connector', render: (row) => <span className="font-medium text-slate-900">{row.name}</span> },
    { key: 'type', header: 'Type', render: (row) => 'kind' in row ? row.kind : row.os_platform ?? 'agent' },
    { key: 'status', header: 'Status', render: (row) => {
      const status = 'is_active' in row ? row.is_active ? 'active' : 'inactive' : row.status
      return <Badge tone={connectorHealthTone(status)}>{labelize(status)}</Badge>
    } },
    { key: 'heartbeat', header: 'Last heartbeat', render: (row) => 'last_heartbeat_at' in row ? <span className="text-xs text-slate-500">{fmt(row.last_heartbeat_at)}</span> : <span className="text-xs text-slate-400">direct connector</span> },
  ]
  const connectorRows: Array<Connector | ConnectorAgent> = [...agents, ...connectors].slice(0, 8)

  return (
    <PageFrame eyebrow="Operations command center" title="Identity Control Overview" subtitle="Real-time account, privilege, and discovery posture across all onboarded platforms.">
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile label="Total assets" value={data.total_assets} detail="Onboarded systems & databases" tone="blue" />
        <MetricTile label="Total accounts" value={data.total_accounts} detail="Discovered identities" tone="slate" />
        <MetricTile label="Privileged accounts" value={data.privileged_accounts} detail="Admin / root / high-impact" tone="red" />
        <MetricTile label="Dormant privileged" value={data.dormant_privileged} detail="Privileged & inactive" tone="amber" />
        <MetricTile label="Shared privileged" value={data.shared_privileged} detail="Shared admin identities" tone="amber" />
        <MetricTile label="Newly privileged (7d)" value={data.newly_privileged_last_7d} detail="Privilege escalations this week" tone="purple" />
        <MetricTile label="Needs review" value={data.unknown_review_required} detail="Insufficient evidence" tone="amber" />
        <MetricTile label="Failed / partial scans" value={failedScans} detail="In the last 8 scans" tone={failedScans ? 'red' : 'green'} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <DataPanel title="Coverage by platform">
          <DataTable columns={[{ key: 'platform', header: 'Platform', render: (r: { platform: string; count: number }) => r.platform }, { key: 'count', header: 'Accounts', render: (r) => r.count }]} rows={platformRows} getRowKey={(r) => r.platform} empty="No accounts discovered yet." minWidth={300} />
        </DataPanel>
        <DataPanel title="Privilege classification map" detail="Color bands show review urgency: red = critical, amber = elevated / evidence gap, blue = sensitive, green = standard.">
          {classRows.length === 0 ? (
            <div className="p-4"><UnavailableState title="No classifications yet" detail="Run a discovery scan to populate privilege classification." /></div>
          ) : (
            <div className="grid gap-3 p-4">
              {classRows.map((row) => (
                <div key={row.classification} className={`overflow-hidden rounded-xl border ${row.meta.bg}`}>
                  <div className="flex items-stretch">
                    <div className={`w-1.5 ${row.meta.bar}`} />
                    <div className="flex flex-1 flex-col gap-3 p-3 sm:flex-row sm:items-center sm:justify-between">
                      <div className="min-w-0">
                        <div className="flex flex-wrap items-center gap-2">
                          <StatusBadge value={row.classification} />
                          <Badge tone={row.meta.tone}>{row.meta.label}</Badge>
                        </div>
                        <div className="mt-1 text-xs text-slate-600">{row.meta.note}</div>
                      </div>
                      <div className="text-right">
                        <div className="text-2xl font-semibold tabular-nums text-slate-950">{row.count}</div>
                        <div className="text-[11px] uppercase tracking-wide text-slate-500">{labelize(row.classification)}</div>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </DataPanel>
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <DataPanel title="Recent scans" detail="Latest discovery activity">
          {scansQ.isLoading ? <div className="p-5"><LoadingPanel /></div> : (
            <DataTable columns={scanCols} rows={scansQ.data?.items ?? []} getRowKey={(s) => s.id} onRowClick={(s) => navigate(`/scans/${s.id}`)} empty="No scans yet." minWidth={420} />
          )}
        </DataPanel>
        <DataPanel title="Connector health" detail="Online / offline status">
          {connectorsQ.isLoading || agentsQ.isLoading ? <div className="p-5"><LoadingPanel label="Loading connector health…" /></div> : connectorsQ.isError || agentsQ.isError ? (
            <div className="p-4"><ErrorState detail={apiErrorMessage(connectorsQ.error ?? agentsQ.error)} onRetry={() => { connectorsQ.refetch(); agentsQ.refetch() }} /></div>
          ) : connectorRows.length === 0 ? (
            <div className="p-4"><UnavailableState title="No connectors configured" detail="Create direct connectors or enroll connector agents to show health here." /></div>
          ) : (
            <div>
              <div className="grid gap-3 border-b border-slate-200 p-4 sm:grid-cols-3">
                <MetricTile label="Direct connectors" value={`${activeConnectors}/${connectors.length}`} detail="Active / total configured" tone={activeConnectors === connectors.length ? 'green' : 'amber'} />
                <MetricTile label="Agents online" value={`${onlineAgents}/${agents.length}`} detail="Heartbeat-derived online status" tone={onlineAgents === agents.length ? 'green' : agents.length ? 'amber' : 'slate'} />
                <MetricTile label="Needs attention" value={unhealthyAgents} detail="Offline, stale, error, disabled, or revoked" tone={unhealthyAgents ? 'red' : 'green'} />
              </div>
              <DataTable columns={connectorCols} rows={connectorRows} getRowKey={(row) => row.id} onRowClick={(row) => navigate('kind' in row ? '/connectors' : `/connectors/agents/${row.id}`)} empty="No connectors configured." minWidth={620} />
            </div>
          )}
        </DataPanel>
      </div>
    </PageFrame>
  )
}
