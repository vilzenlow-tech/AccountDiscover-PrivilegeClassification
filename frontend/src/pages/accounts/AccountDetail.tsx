import { useNavigate, useParams } from 'react-router-dom'
import { useGetAccountQuery } from '../../api/apiSlice'
import type { Entitlement } from '../../api/types'
import {
  ActionButton, DataPanel, DataTable, ErrorState, LoadingPanel, MetricTile, PageFrame,
  apiErrorMessage, type Column,
} from '../../components/ui'

function fmt(ts: string | null | undefined) { return ts ? new Date(ts).toLocaleString() : '—' }
function yn(v: boolean | null | undefined) { return v == null ? '—' : v ? 'yes' : 'no' }
function originLabel(origin: string, domain: string | null | undefined) {
  if (origin === 'domain') return `Domain Account${domain ? ` · ${domain}` : ''}`
  if (origin === 'local') return `Local Account${domain ? ` · ${domain}` : ''}`
  if (origin === 'database') return 'Database native'
  if (origin === 'os_integrated') return 'OS integrated'
  return 'Unknown'
}

export default function AccountDetail() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const { data: a, isLoading, isError, error, refetch } = useGetAccountQuery(id)

  if (isLoading) return <PageFrame eyebrow="Account" title="Account detail" subtitle="Loading…"><LoadingPanel /></PageFrame>
  if (isError || !a) return <PageFrame eyebrow="Account" title="Account detail" subtitle="Could not load this account."><ErrorState detail={apiErrorMessage(error)} onRetry={refetch} /></PageFrame>

  const isWindows = a.platform === 'windows'
  const entCols: Column<Entitlement>[] = [
    { key: 'kind', header: 'Kind', render: (e) => e.kind },
    { key: 'name', header: 'Name', render: (e) => <span className="font-medium text-slate-900">{e.name}</span> },
    { key: 'scope', header: 'Scope', render: (e) => e.scope ?? '—' },
    { key: 'source', header: 'Source', render: (e) => e.source ?? '—' },
    { key: 'inherited', header: 'Inherited', render: (e) => e.inherited ? `via ${e.via ?? 'group'}` : 'direct' },
  ]

  return (
    <PageFrame
      eyebrow="Account governance"
      title={a.account_name}
      subtitle={`${a.platform} account on ${a.asset_hostname ?? a.asset_id.slice(0, 8)}`}
      actions={
        <div className="flex gap-2">
          <ActionButton onClick={() => navigate('/accounts')}>Back to accounts</ActionButton>
          <ActionButton onClick={() => navigate(`/assets/${a.asset_id}`)}>View asset</ActionButton>
        </div>
      }
    >
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile label="Privilege" value={a.privilege_classification.replace(/_/g, ' ')} detail={`confidence ${a.privilege_confidence}%`} tone="red" />
        <MetricTile label="Risk score" value={a.risk_score} detail="Composite risk" tone={a.risk_score >= 70 ? 'red' : a.risk_score >= 40 ? 'amber' : 'slate'} />
        <MetricTile label="Status" value={a.enabled_status} detail={`activity: ${a.activity_status}`} tone="blue" />
        <MetricTile label="Type" value={a.principal_type} detail={a.is_shared ? 'shared identity' : 'individual'} tone="slate" />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <DataPanel title="Identity & provenance">
          <dl className="grid grid-cols-2 gap-4 p-4 text-sm">
            <Item k="Account name" v={a.account_name} />
            <Item k="Source type" v={a.source_type} />
            <Item k="DB / schema" v={a.schema_name ?? '—'} />
            <Item k="Auth source" v={a.auth_source} />
            <Item k="Origin" v={originLabel(a.account_origin, a.account_domain)} />
            <Item k="Principal source" v={a.principal_source ?? '—'} />
            <Item k="Owner" v={a.owner ?? '—'} />
            <Item k="Interactive" v={a.interactive_status} />
            <Item k="Shared" v={yn(a.is_shared)} />
            <Item k="Review reason" v={a.review_required_reason ?? '—'} />
          </dl>
        </DataPanel>
        <DataPanel title="Activity & password">
          <dl className="grid grid-cols-2 gap-4 p-4 text-sm">
            <Item k="Last login" v={fmt(a.last_login)} />
            <Item k="Last login source" v={a.last_login_source ?? '—'} />
            <Item k="Never logged in" v={yn(a.never_logged_in)} />
            <Item k="Password never expires" v={yn(a.password_never_expires)} />
            <Item k="Password last changed" v={fmt(a.password_last_changed)} />
            <Item k="Password expires" v={fmt(a.password_expires_at)} />
            <Item k="Discovered" v={fmt(a.discovered_at)} />
            <Item k="Updated" v={fmt(a.updated_at)} />
          </dl>
        </DataPanel>
      </div>

      {isWindows && (
        <DataPanel title="Interactive logon classification" detail={`method: ${a.interactive_detection_method ?? 'n/a'} · confidence ${a.interactive_confidence ?? '—'}`}>
          <dl className="grid grid-cols-2 gap-4 p-4 text-sm md:grid-cols-5">
            <Item k="Local logon" v={yn(a.allows_local_logon)} />
            <Item k="Remote interactive" v={yn(a.allows_remote_interactive_logon)} />
            <Item k="Service logon" v={yn(a.allows_service_logon)} />
            <Item k="Batch logon" v={yn(a.allows_batch_logon)} />
            <Item k="Network logon" v={yn(a.allows_network_logon)} />
          </dl>
        </DataPanel>
      )}

      <DataPanel title="Entitlements" detail={`${a.entitlements.length} entitlement(s)`}>
        <DataTable columns={entCols} rows={a.entitlements} getRowKey={(e) => e.id} empty="No entitlements recorded for this account." minWidth={700} />
      </DataPanel>

      <DataPanel title="Evidence summary" detail="Raw collector evidence backing the classification.">
        <pre className="max-h-80 overflow-auto p-4 text-xs leading-5 text-slate-700">{JSON.stringify(a.evidence_summary ?? { note: 'No evidence summary recorded.' }, null, 2)}</pre>
      </DataPanel>
    </PageFrame>
  )
}

function Item({ k, v }: { k: string; v?: string | null }) {
  return <div><dt className="text-xs uppercase tracking-wide text-slate-500">{k}</dt><dd className="mt-0.5 font-medium text-slate-900">{v || '—'}</dd></div>
}
