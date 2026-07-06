import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  useAssignAssetTagsMutation, useGetAccountsQuery, useGetAssetQuery,
  useGetPoliciesQuery, useGetPolicyFindingsQuery, useGetTagsQuery,
  useRemoveAssetTagsMutation,
} from '../../api/apiSlice'
import type { Account, PasswordPolicyFinding } from '../../api/types'
import { useCan } from '../../app/rbac'
import {
  ActionButton, DataPanel, DataTable, ErrorState, InlineAlert, LoadingPanel, MetricTile, PageFrame,
  StatusBadge, UnavailableState, apiErrorMessage, cx, type Column,
} from '../../components/ui'

const PRIVILEGED = new Set(['full_admin', 'admin_equivalent', 'operator_high_impact', 'delegated_admin', 'privileged_service', 'dormant_privileged'])
function fmt(ts: string | null | undefined) { return ts ? new Date(ts).toLocaleString() : '—' }
const yn = (v: boolean | null | undefined) => (v == null ? '—' : v ? 'yes' : 'no')
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

export default function AssetDetail() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const assetQ = useGetAssetQuery(id)
  const accountsQ = useGetAccountsQuery({ asset_id: id, limit: 500 })

  if (assetQ.isLoading) return <PageFrame eyebrow="Asset" title="Asset detail" subtitle="Loading…"><LoadingPanel /></PageFrame>
  if (assetQ.isError || !assetQ.data) return <PageFrame eyebrow="Asset" title="Asset detail" subtitle="Could not load this asset."><ErrorState detail={apiErrorMessage(assetQ.error)} onRetry={assetQ.refetch} /></PageFrame>

  const a = assetQ.data
  const accounts = accountsQ.data?.items ?? []
  const privCount = accounts.filter((x) => PRIVILEGED.has(x.privilege_classification)).length

  const cols: Column<Account>[] = [
    { key: 'name', header: 'Account', render: (x) => <span className="font-medium text-slate-900">{x.account_name}</span> },
    { key: 'origin', header: 'Account origin', render: (x) => <div><StatusBadge value={originBadgeValue(x)} /><div className="mt-1 text-xs text-slate-500">{originLabel(x)}</div></div> },
    { key: 'type', header: 'Type', render: (x) => x.principal_type },
    { key: 'priv', header: 'Privilege', render: (x) => <StatusBadge value={x.privilege_classification} /> },
    { key: 'enabled', header: 'Enabled', render: (x) => <StatusBadge value={x.enabled_status} /> },
    { key: 'interactive', header: 'Interactive', render: (x) => x.interactive_status },
    { key: 'last', header: 'Last login', render: (x) => fmt(x.last_login) },
  ]

  return (
    <PageFrame
      eyebrow="Application onboarding"
      title={a.hostname}
      subtitle={`${a.platform} · ${a.environment ?? 'no environment'} · ${a.criticality ?? 'unrated'}`}
      actions={
        <div className="flex gap-2">
          <ActionButton onClick={() => navigate('/assets')}>Back to assets</ActionButton>
          <ActionButton onClick={() => navigate(`/accounts?asset=${a.id}`)}>View all accounts</ActionButton>
        </div>
      }
    >
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile label="Accounts" value={accountsQ.isLoading ? '…' : accounts.length} detail="Discovered on this asset" tone="blue" />
        <MetricTile label="Privileged" value={accountsQ.isLoading ? '…' : privCount} detail="Admin / high-impact" tone={privCount ? 'red' : 'slate'} />
        <MetricTile label="Discovery" value={a.discovery_enabled ? 'enabled' : 'disabled'} detail="Scan eligibility" tone={a.discovery_enabled ? 'green' : 'amber'} />
        <MetricTile label="Connector" value={a.connector_name ?? 'none'} detail="Collection path" tone="slate" />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <DataPanel title="Asset metadata">
          <dl className="grid grid-cols-2 gap-4 p-4 text-sm">
            <Item k="Hostname" v={a.hostname} />
            <Item k="IP address" v={a.ip_address ?? '—'} />
            <Item k="Platform" v={a.platform} />
            <Item k="Instance" v={a.instance ?? '—'} />
            <Item k="Port" v={a.port != null ? String(a.port) : '—'} />
            <Item k="Environment" v={a.environment ?? '—'} />
            <Item k="Owner" v={a.owner ?? '—'} />
            <Item k="Business unit" v={a.business_unit ?? '—'} />
            <Item k="Criticality" v={a.criticality ?? '—'} />
            <Item k="Connector" v={a.connector_name ?? '—'} />
          </dl>
        </DataPanel>
        <div className="space-y-4">
          <TagsPanel assetId={a.id} assigned={(a.tag_summaries ?? []).map((t) => ({ id: t.id, name: t.tag_name, category: t.category }))} />
          <DataPanel title="Scan history">
            <div className="p-4"><UnavailableState title="Per-asset scan history arrives with the Scans-by-asset view" detail="Backend exposes scans + per-target results; the asset-scoped history widget is wired in a later phase. Use Scans for now." /></div>
          </DataPanel>
        </div>
      </div>

      <PolicyPanel assetId={a.id} />

      <DataPanel title="Discovered accounts" detail={accountsQ.isLoading ? 'Loading…' : `${accounts.length} account(s)`}>
        {accountsQ.isError ? <div className="p-4"><ErrorState detail={apiErrorMessage(accountsQ.error)} onRetry={accountsQ.refetch} /></div> : (
          <DataTable columns={cols} rows={accounts} getRowKey={(x) => x.id} onRowClick={(x) => navigate(`/accounts/${x.id}`)} empty="No accounts discovered on this asset yet." minWidth={1000} />
        )}
      </DataPanel>
    </PageFrame>
  )
}

function Item({ k, v }: { k: string; v?: string | null }) {
  return <div><dt className="text-xs uppercase tracking-wide text-slate-500">{k}</dt><dd className="mt-0.5 font-medium text-slate-900">{v || '—'}</dd></div>
}

function Control({ label, value, weak }: { label: string; value: string; weak?: boolean | null }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className={cx('mt-0.5 font-semibold', weak ? 'text-red-700' : 'text-slate-900')}>{value}{weak ? ' ⚠' : ''}</dd>
    </div>
  )
}

function PolicyPanel({ assetId }: { assetId: string }) {
  const navigate = useNavigate()
  const can = useCan()
  const policiesQ = useGetPoliciesQuery({ asset_id: assetId, limit: 50 })
  const findingsQ = useGetPolicyFindingsQuery({ asset_id: assetId, limit: 50 })

  const policies = policiesQ.data?.items ?? []
  const findings = findingsQ.data?.items ?? []
  // Prefer the effective policy as the headline; fall back to the first snapshot.
  const headline = policies.find((p) => p.is_effective_policy) ?? policies[0] ?? null
  const openFindings = findings.filter((f) => f.review_state === 'open').length
  const critical = findings.filter((f) => f.severity === 'critical').length

  const findingCols: Column<PasswordPolicyFinding>[] = [
    { key: 'sev', header: 'Severity', render: (f) => <StatusBadge value={f.severity} /> },
    { key: 'title', header: 'Finding', render: (f) => <span className="font-medium text-slate-900">{f.title}</span> },
    { key: 'scope', header: 'Scope', render: (f) => f.affected_scope ?? '—' },
    { key: 'state', header: 'Review', render: (f) => <StatusBadge value={f.review_state} /> },
  ]

  const detail = headline
    ? `${policies.length} snapshot(s) · ${headline.policy_source}${headline.policy_scope ? ` / ${headline.policy_scope}` : ''}`
    : undefined

  return (
    <DataPanel
      title="Password policy"
      detail={detail}
    >
      {policiesQ.isLoading ? (
        <div className="p-4"><LoadingPanel /></div>
      ) : policiesQ.isError ? (
        <div className="p-4"><ErrorState detail={apiErrorMessage(policiesQ.error)} onRetry={policiesQ.refetch} /></div>
      ) : !headline ? (
        <div className="space-y-3 p-4">
          <UnavailableState title="No password policy collected for this asset" detail="Run a password-policy or credentialed discovery scan to capture the effective policy and surface weak-control findings." />
          {can('scan:launch') && <ActionButton variant="primary" onClick={() => navigate('/scans/new')}>Scan password policy</ActionButton>}
        </div>
      ) : (
        <div className="space-y-4 p-4">
          <dl className="grid grid-cols-2 gap-4 text-sm md:grid-cols-3 xl:grid-cols-6">
            <Control label="Min length" value={headline.min_password_length != null ? String(headline.min_password_length) : '—'} weak={headline.has_weak_length} />
            <Control label="Complexity" value={yn(headline.complexity_enabled)} weak={headline.has_no_complexity} />
            <Control label="Lockout threshold" value={headline.lockout_threshold != null ? String(headline.lockout_threshold) : '—'} weak={headline.has_no_lockout} />
            <Control label="Max age (days)" value={headline.max_password_age_days != null ? String(headline.max_password_age_days) : '—'} weak={headline.has_no_expiry} />
            <Control label="Reversible enc." value={yn(headline.reversible_encryption_enabled)} weak={headline.reversible_encryption_enabled === true} />
            <Item k="Policy name" v={headline.policy_name ?? '—'} />
          </dl>
          <div className="flex flex-wrap items-center gap-3">
            <MetricTile label="Findings" value={findingsQ.isLoading ? '…' : findings.length} detail={`${openFindings} open`} tone={findings.length ? 'amber' : 'green'} />
            <MetricTile label="Critical" value={findingsQ.isLoading ? '…' : critical} detail="Highest severity" tone={critical ? 'red' : 'slate'} />
            <div className="ml-auto flex gap-2">
              <ActionButton onClick={() => navigate('/password-policy')}>Open Password Policy</ActionButton>
            </div>
          </div>
          {findings.length > 0 && (
            <div className="rounded-md border border-slate-200">
              <DataTable columns={findingCols} rows={findings} getRowKey={(f) => f.id} empty="No policy findings for this asset." minWidth={600} />
            </div>
          )}
        </div>
      )}
    </DataPanel>
  )
}

type AssignedTag = { id: string; name: string; category: string }

function TagsPanel({ assetId, assigned }: { assetId: string; assigned: AssignedTag[] }) {
  const can = useCan()
  const manage = can('tag:manage')
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const tagsQ = useGetTagsQuery({ limit: 300 }, { skip: !editing })
  const [assign, assignState] = useAssignAssetTagsMutation()
  const [remove, removeState] = useRemoveAssetTagsMutation()
  const busy = assignState.isLoading || removeState.isLoading

  const assignedIds = assigned.map((t) => t.id)

  function startEdit() {
    setDraft(assignedIds)
    setError(null)
    setEditing(true)
  }

  async function save() {
    setError(null)
    const toAdd = draft.filter((id) => !assignedIds.includes(id))
    const toRemove = assignedIds.filter((id) => !draft.includes(id))
    try {
      if (toAdd.length) await assign({ assetId, tag_ids: toAdd }).unwrap()
      if (toRemove.length) await remove({ assetId, tag_ids: toRemove }).unwrap()
      setEditing(false)
    } catch (e) {
      setError(apiErrorMessage(e))
    }
  }

  return (
    <DataPanel title="Tags / applications" detail={`${assigned.length} tag(s)`}>
      {!editing ? (
        <>
          <div className="flex flex-wrap gap-2 p-4">
            {assigned.length ? assigned.map((t) => (
              <span key={t.id} className="rounded-md border border-slate-200 bg-slate-50 px-2.5 py-1 text-xs font-medium text-slate-700">{t.name}<span className="ml-1 text-slate-400">{t.category}</span></span>
            )) : <span className="text-sm text-slate-500">No tags assigned.</span>}
          </div>
          {manage && (
            <div className="border-t border-slate-200 px-4 py-3">
              <ActionButton onClick={startEdit}>Edit tags</ActionButton>
            </div>
          )}
        </>
      ) : (
        <div className="space-y-3 p-4">
          {tagsQ.isLoading ? <LoadingPanel label="Loading tags…" /> : tagsQ.isError ? <ErrorState detail={apiErrorMessage(tagsQ.error)} onRetry={tagsQ.refetch} /> : (
            <div className="max-h-64 overflow-y-auto rounded-md border border-slate-200">
              {(tagsQ.data?.items ?? []).map((t) => (
                <label key={t.id} className="flex items-center gap-2 border-b border-slate-100 px-3 py-2 text-sm last:border-0 hover:bg-slate-50">
                  <input type="checkbox" checked={draft.includes(t.id)} onChange={() => setDraft((s) => s.includes(t.id) ? s.filter((x) => x !== t.id) : [...s, t.id])} />
                  <span className="inline-flex items-center gap-2 font-medium text-slate-800"><span className="h-2.5 w-2.5 rounded-full" style={{ background: t.color }} />{t.tag_name}</span>
                  <span className="text-xs text-slate-500">{t.category}</span>
                </label>
              ))}
            </div>
          )}
          {error && <InlineAlert tone="red">{error}</InlineAlert>}
          <div className="flex items-center gap-2">
            <ActionButton variant="primary" disabled={busy} onClick={save}>{busy ? 'Saving…' : 'Save tags'}</ActionButton>
            <ActionButton variant="ghost" disabled={busy} onClick={() => setEditing(false)}>Cancel</ActionButton>
          </div>
        </div>
      )}
    </DataPanel>
  )
}
