import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  useComparePoliciesMutation, useCreatePolicyExceptionMutation, useGetAssetsQuery, useGetPoliciesQuery,
  useGetPolicyExceptionsQuery, useGetPolicyFindingsQuery, useGetPolicySummaryQuery, useReviewPolicyFindingMutation,
} from '../../api/apiSlice'
import { downloadServerFile } from '../../api/download'
import type { Asset, PasswordPolicy as PasswordPolicyRecord, PasswordPolicyFinding, PolicyException } from '../../api/types'
import { useCan } from '../../app/rbac'
import {
  ActionButton, DataPanel, DataTable, ErrorState, Field, InlineAlert, LoadingPanel, MetricTile,
  NativeSelect, PageFrame, StatusBadge, TextArea, TextInput, apiErrorMessage, cx, type Column,
} from '../../components/ui'

type Tab = 'summary' | 'policies' | 'findings' | 'exceptions' | 'compare' | 'coverage'
const PAGE_LIMIT = 200
const yn = (v: boolean | null | undefined) => (v == null ? '—' : v ? 'yes' : 'no')

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']
const REVIEW_STATES = ['open', 'acknowledged', 'risk_accepted', 'remediated', 'false_positive']
const PLATFORMS = ['windows', 'rhel', 'centos', 'ubuntu', 'sles', 'solaris', 'aix', 'mysql', 'mssql', 'mongodb', 'oracle_db', 'postgresql']
const EXCEPTION_TYPES = ['password_never_expires', 'password_not_required', 'check_policy_off', 'check_expiration_off', 'lockout_exempt', 'under_weaker_policy', 'privileged_account_weak_policy', 'under_external_policy', 'unknown_effective_policy', 'service_account_exception', 'fgpp_not_applied']
const REVIEW_ACTIONS: { state: string; label: string }[] = [
  { state: 'acknowledged', label: 'Acknowledge' },
  { state: 'risk_accepted', label: 'Accept risk' },
  { state: 'remediated', label: 'Remediated' },
  { state: 'false_positive', label: 'False positive' },
  { state: 'open', label: 'Reopen' },
]
const opt = (vals: string[]) => vals.map((v) => ({ value: v, label: v.replace(/_/g, ' ') }))
const cellText = (v: unknown) => (typeof v === 'boolean' ? (v ? 'yes' : 'no') : v == null || v === '' ? '—' : String(v))

export default function PasswordPolicy() {
  const can = useCan()
  const navigate = useNavigate()
  const canReview = can('policy:review')
  const canManage = can('policy:manage')
  const [tab, setTab] = useState<Tab>('summary')
  // finding filters
  const [fSeverity, setFSeverity] = useState('')
  const [fReview, setFReview] = useState('')
  const [fPlatform, setFPlatform] = useState('')
  const [fException, setFException] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [comment, setComment] = useState('')
  // policy filters
  const [pPlatform, setPPlatform] = useState('')
  const [pWeak, setPWeak] = useState(false)
  // compare + exception
  const [compareIds, setCompareIds] = useState<string[]>([])
  const [showException, setShowException] = useState(false)
  const [exForm, setExForm] = useState({ asset_id: '', exception_type: EXCEPTION_TYPES[0], description: '' })

  const findingParams = useMemo(() => {
    const q: Record<string, unknown> = { limit: PAGE_LIMIT }
    if (fSeverity) q.severity = fSeverity
    if (fReview) q.review_state = fReview
    if (fPlatform) q.platform = fPlatform
    if (fException) q.is_exception_finding = true
    return q
  }, [fSeverity, fReview, fPlatform, fException])
  const policyParams = useMemo(() => {
    const q: Record<string, unknown> = { limit: PAGE_LIMIT }
    if (pPlatform) q.platform = pPlatform
    if (pWeak) q.has_weak_length = true
    return q
  }, [pPlatform, pWeak])

  const summaryQ = useGetPolicySummaryQuery()
  const policiesQ = useGetPoliciesQuery(policyParams, { skip: tab !== 'policies' })
  const findingsQ = useGetPolicyFindingsQuery(findingParams, { skip: tab !== 'findings' })
  const exceptionsQ = useGetPolicyExceptionsQuery({ limit: PAGE_LIMIT }, { skip: tab !== 'exceptions' })
  const coveragePoliciesQ = useGetPoliciesQuery({ limit: 1000 }, { skip: tab !== 'coverage' })
  const assetsQ = useGetAssetsQuery({ limit: 1000 }, { skip: tab !== 'compare' && tab !== 'coverage' && tab !== 'exceptions' })
  const [review, reviewState] = useReviewPolicyFindingMutation()
  const [compare, compareState] = useComparePoliciesMutation()
  const [createException, exState] = useCreatePolicyExceptionMutation()

  const findings = findingsQ.data?.items ?? []
  const selected = findings.find((f) => f.id === selectedId) ?? null
  const assets = assetsQ.data?.items ?? []
  const noPolicyAssets = useMemo(() => {
    const withPolicy = new Set((coveragePoliciesQ.data?.items ?? []).map((p) => p.asset_id))
    return assets.filter((a) => !withPolicy.has(a.id))
  }, [assets, coveragePoliciesQ.data])

  function jumpToFindings(patch: { severity?: string; review_state?: string }) {
    setFSeverity(patch.severity ?? ''); setFReview(patch.review_state ?? '')
    setFPlatform(''); setFException(false); setSelectedId(null); setTab('findings')
  }
  async function applyReview(state: string) {
    if (!selected) return
    await review({ id: selected.id, state, comment: comment || undefined }).unwrap().catch(() => {})
    setComment('')
  }
  function toggleCompare(id: string) {
    setCompareIds((s) => s.includes(id) ? s.filter((x) => x !== id) : s.length < 20 ? [...s, id] : s)
  }
  async function submitException() {
    if (!exForm.asset_id) return
    await createException({ asset_id: exForm.asset_id, exception_type: exForm.exception_type, description: exForm.description || null, discovered_at: new Date().toISOString() }).unwrap().catch(() => {})
    setExForm({ asset_id: '', exception_type: EXCEPTION_TYPES[0], description: '' })
    setShowException(false)
  }

  const policyCols: Column<PasswordPolicyRecord>[] = [
    { key: 'host', header: 'Asset', render: (p) => <span className="font-medium text-slate-900">{p.hostname ?? p.asset_id.slice(0, 8)}</span> },
    { key: 'platform', header: 'Platform', render: (p) => p.platform },
    { key: 'source', header: 'Source', render: (p) => p.policy_source },
    { key: 'scope', header: 'Scope', render: (p) => p.policy_scope },
    { key: 'len', header: 'Min length', render: (p) => <span className={cx(p.has_weak_length && 'font-semibold text-red-700')}>{p.min_password_length ?? '—'}</span> },
    { key: 'complex', header: 'Complexity', render: (p) => <span className={cx(p.has_no_complexity && 'text-red-700')}>{yn(p.complexity_enabled)}</span> },
    { key: 'age', header: 'Max age (d)', render: (p) => (p.max_password_age_days ?? '—') },
    { key: 'lockout', header: 'Lockout', render: (p) => <span className={cx(p.has_no_lockout && 'text-red-700')}>{p.lockout_threshold ?? '—'}</span> },
    { key: 'findings', header: 'Findings', render: (p) => <span className={cx(p.critical_finding_count ? 'font-semibold text-red-700' : 'text-slate-600')}>{p.finding_count}{p.critical_finding_count ? ` (${p.critical_finding_count} crit)` : ''}</span> },
  ]
  const findingCols: Column<PasswordPolicyFinding>[] = [
    { key: 'sev', header: 'Severity', render: (f) => <StatusBadge value={f.severity} /> },
    { key: 'title', header: 'Finding', render: (f) => <span className="font-medium text-slate-900">{f.title}</span> },
    { key: 'host', header: 'Asset', render: (f) => f.hostname ?? f.asset_id.slice(0, 8) },
    { key: 'account', header: 'Account', render: (f) => f.account_name ?? (f.account_id ? f.account_id.slice(0, 8) : '—') },
    { key: 'state', header: 'Review', render: (f) => <StatusBadge value={f.review_state} /> },
    { key: 'exc', header: 'Exception', render: (f) => (f.is_exception_finding ? 'yes' : 'no') },
  ]
  const excCols: Column<PolicyException>[] = [
    { key: 'type', header: 'Exception type', render: (e) => <span className="font-medium text-slate-900">{e.exception_type}</span> },
    { key: 'account', header: 'Account', render: (e) => e.account_name ?? '—' },
    { key: 'host', header: 'Asset', render: (e) => e.asset_hostname ?? '—' },
    { key: 'desc', header: 'Description', render: (e) => <span className="text-xs text-slate-500">{e.description ?? '—'}</span> },
  ]
  const coverageCols: Column<Asset>[] = [
    { key: 'host', header: 'Asset', render: (a) => <span className="font-medium text-slate-900">{a.hostname}</span> },
    { key: 'platform', header: 'Platform', render: (a) => a.platform },
    { key: 'env', header: 'Environment', render: (a) => a.environment ?? '—' },
    { key: 'owner', header: 'Owner', render: (a) => a.owner ?? '—' },
  ]

  const TABS: Tab[] = ['summary', 'policies', 'findings', 'exceptions', 'compare', 'coverage']

  return (
    <PageFrame
      eyebrow="Policy governance"
      title="Password Policy"
      subtitle="Password, complexity, lockout, and dormancy policy coverage with findings, comparison, and approved exceptions."
      actions={can('export:run') ? (
        <div className="flex gap-2">
          <ActionButton onClick={() => downloadServerFile('/password-policy/export/csv', 'password-policy.csv')}>Export CSV</ActionButton>
          <ActionButton onClick={() => downloadServerFile('/password-policy/export/excel', 'password-policy.xlsx')}>Export Excel</ActionButton>
        </div>
      ) : undefined}
    >
      <div className="flex flex-wrap gap-2">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)} className={cx('rounded-md border px-3 py-1.5 text-sm font-semibold capitalize', tab === t ? 'border-blue-600 bg-blue-50 text-blue-700' : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50')}>{t}</button>
        ))}
      </div>

      {tab === 'summary' && (
        summaryQ.isLoading ? <LoadingPanel /> : summaryQ.isError ? <ErrorState detail={apiErrorMessage(summaryQ.error)} onRetry={summaryQ.refetch} /> : summaryQ.data ? (
          <>
            <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
              <button onClick={() => setTab('policies')} className="text-left"><MetricTile label="Assets with policy" value={summaryQ.data.total_assets_with_policy} detail={`${summaryQ.data.assets_with_no_policy} without policy →`} tone="blue" /></button>
              <button onClick={() => jumpToFindings({ review_state: 'open' })} className="text-left"><MetricTile label="Open findings" value={summaryQ.data.open_findings} detail="Awaiting review →" tone={summaryQ.data.open_findings ? 'amber' : 'green'} /></button>
              <button onClick={() => jumpToFindings({ severity: 'critical' })} className="text-left"><MetricTile label="Critical findings" value={summaryQ.data.critical_findings} detail={`${summaryQ.data.high_findings} high →`} tone={summaryQ.data.critical_findings ? 'red' : 'slate'} /></button>
              <button onClick={() => setTab('exceptions')} className="text-left"><MetricTile label="Exceptions" value={summaryQ.data.total_exceptions} detail={`${summaryQ.data.privileged_account_exceptions} on privileged →`} tone="purple" /></button>
            </div>
            <DataPanel title="Weak control coverage" detail="Assets whose effective policy fails a core control.">
              <div className="grid grid-cols-2 gap-4 p-4 text-sm md:grid-cols-4">
                <Item k="Weak min length" v={String(summaryQ.data.assets_with_weak_length ?? 0)} />
                <Item k="No complexity" v={String(summaryQ.data.assets_with_no_complexity ?? 0)} />
                <Item k="No lockout" v={String(summaryQ.data.assets_with_no_lockout ?? 0)} />
                <Item k="Reversible encryption" v={String(summaryQ.data.assets_with_reversible_encryption ?? 0)} />
              </div>
            </DataPanel>
            <div className="grid gap-4 lg:grid-cols-2">
              <DataPanel title="By platform"><Breakdown data={summaryQ.data.by_platform} /></DataPanel>
              <DataPanel title="By policy source"><Breakdown data={summaryQ.data.by_policy_source} /></DataPanel>
            </div>
          </>
        ) : null
      )}

      {tab === 'policies' && (
        <div className="space-y-4">
          <DataPanel title="Filters">
            <div className="grid gap-3 p-4 sm:grid-cols-3">
              <Field label="Platform"><NativeSelect value={pPlatform} options={opt(PLATFORMS)} onChange={setPPlatform} placeholder="All platforms" /></Field>
              <div className="flex items-end"><label className="flex items-center gap-2 text-sm text-slate-700"><input type="checkbox" checked={pWeak} onChange={(e) => setPWeak(e.target.checked)} />Weak min length only</label></div>
            </div>
          </DataPanel>
          {policiesQ.isLoading ? <LoadingPanel /> : policiesQ.isError ? <ErrorState detail={apiErrorMessage(policiesQ.error)} onRetry={policiesQ.refetch} /> : (
            <DataPanel title="Effective policies" detail={`${policiesQ.data?.total ?? 0} policy snapshot(s)`}>
              <DataTable columns={policyCols} rows={policiesQ.data?.items ?? []} getRowKey={(p) => p.id} onRowClick={(p) => navigate(`/assets/${p.asset_id}`)} empty="No policies match these filters." minWidth={900} />
            </DataPanel>
          )}
        </div>
      )}

      {tab === 'findings' && (
        <div className="space-y-4">
          <DataPanel title="Filters">
            <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4">
              <Field label="Severity"><NativeSelect value={fSeverity} options={opt(SEVERITIES)} onChange={setFSeverity} placeholder="All severities" /></Field>
              <Field label="Review state"><NativeSelect value={fReview} options={opt(REVIEW_STATES)} onChange={setFReview} placeholder="Any state" /></Field>
              <Field label="Platform"><NativeSelect value={fPlatform} options={opt(PLATFORMS)} onChange={setFPlatform} placeholder="All platforms" /></Field>
              <div className="flex items-end"><label className="flex items-center gap-2 text-sm text-slate-700"><input type="checkbox" checked={fException} onChange={(e) => setFException(e.target.checked)} />Account exceptions only</label></div>
            </div>
          </DataPanel>
          {findingsQ.isLoading ? <LoadingPanel /> : findingsQ.isError ? <ErrorState detail={apiErrorMessage(findingsQ.error)} onRetry={findingsQ.refetch} /> : (
            <DataPanel title="Policy findings" detail={`${findingsQ.data?.total ?? 0} finding(s)`}>
              <DataTable columns={findingCols} rows={findings} getRowKey={(f) => f.id} onRowClick={(f) => { setSelectedId(f.id); setComment('') }} empty="No policy findings match these filters." minWidth={900} />
            </DataPanel>
          )}
          {selected && (
            <DataPanel title="Finding detail" detail={`${selected.hostname ?? ''} · ${selected.rule_key}`}>
              <div className="space-y-4 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge value={selected.severity} /><StatusBadge value={selected.review_state} />
                  <span className="font-semibold text-slate-900">{selected.title}</span>
                </div>
                <div className="text-sm text-slate-700">{selected.description}</div>
                {selected.recommendation && <div className="rounded-md border border-blue-200 bg-blue-50 p-3 text-sm text-blue-900"><span className="font-semibold">Recommendation: </span>{selected.recommendation}</div>}
                <div className="grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
                  <Item k="Rule" v={selected.rule_key} /><Item k="Affected scope" v={selected.affected_scope ?? '—'} />
                  <Item k="Account" v={selected.account_name ?? '—'} /><Item k="Reviewed by" v={selected.reviewed_by ?? '—'} />
                </div>
                {canReview ? (
                  <div className="space-y-2 border-t border-slate-200 pt-4">
                    <Field label="Review comment (optional)"><TextInput value={comment} onChange={(e) => setComment(e.target.value)} /></Field>
                    <div className="flex flex-wrap gap-2">{REVIEW_ACTIONS.map((a) => <ActionButton key={a.state} disabled={reviewState.isLoading} onClick={() => applyReview(a.state)}>{a.label}</ActionButton>)}</div>
                    {reviewState.isSuccess && <InlineAlert tone="green">Review state recorded.</InlineAlert>}
                    {reviewState.isError && <InlineAlert tone="red">{apiErrorMessage(reviewState.error)}</InlineAlert>}
                  </div>
                ) : <InlineAlert tone="slate">Your role can view findings but not record review decisions.</InlineAlert>}
              </div>
            </DataPanel>
          )}
        </div>
      )}

      {tab === 'exceptions' && (
        <div className="space-y-4">
          {canManage && (
            <div className="flex justify-end"><ActionButton variant="primary" onClick={() => setShowException((s) => !s)}>{showException ? 'Close' : 'New exception'}</ActionButton></div>
          )}
          {showException && canManage && (
            <DataPanel title="Record policy exception" detail="Document an approved deviation from the expected password policy.">
              <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-3">
                <Field label="Asset" required><NativeSelect value={exForm.asset_id} options={assets.map((a) => ({ value: a.id, label: a.hostname }))} onChange={(v) => setExForm({ ...exForm, asset_id: v })} placeholder="Select asset…" /></Field>
                <Field label="Exception type" required><NativeSelect value={exForm.exception_type} options={opt(EXCEPTION_TYPES)} onChange={(v) => setExForm({ ...exForm, exception_type: v })} /></Field>
                <Field label="Description"><TextArea rows={1} value={exForm.description} onChange={(e) => setExForm({ ...exForm, description: e.target.value })} /></Field>
              </div>
              <div className="flex items-center gap-3 border-t border-slate-200 px-4 py-3">
                <ActionButton variant="primary" disabled={!exForm.asset_id || exState.isLoading} onClick={submitException}>{exState.isLoading ? 'Saving…' : 'Record exception'}</ActionButton>
                {exState.isError && <InlineAlert tone="red">{apiErrorMessage(exState.error)}</InlineAlert>}
              </div>
            </DataPanel>
          )}
          {exceptionsQ.isLoading ? <LoadingPanel /> : exceptionsQ.isError ? <ErrorState detail={apiErrorMessage(exceptionsQ.error)} onRetry={exceptionsQ.refetch} /> : (
            <DataPanel title="Account policy exceptions" detail={`${exceptionsQ.data?.total ?? 0} exception(s)`}>
              <DataTable columns={excCols} rows={exceptionsQ.data?.items ?? []} getRowKey={(e) => e.id} empty="No policy exceptions recorded." minWidth={800} />
            </DataPanel>
          )}
        </div>
      )}

      {tab === 'compare' && (
        <div className="space-y-4">
          <DataPanel title="Select assets to compare" detail="Pick 2–20 assets to compare effective password policy settings side by side.">
            {assetsQ.isLoading ? <div className="p-4"><LoadingPanel /></div> : (
              <div className="space-y-3 p-4">
                <div className="max-h-56 overflow-y-auto rounded-md border border-slate-200">
                  {assets.map((a) => (
                    <label key={a.id} className="flex items-center gap-2 border-b border-slate-100 px-3 py-2 text-sm last:border-0 hover:bg-slate-50">
                      <input type="checkbox" checked={compareIds.includes(a.id)} onChange={() => toggleCompare(a.id)} />
                      <span className="font-medium text-slate-800">{a.hostname}</span><span className="text-xs text-slate-500">{a.platform}</span>
                    </label>
                  ))}
                </div>
                <ActionButton variant="primary" disabled={compareIds.length < 2 || compareState.isLoading} onClick={() => compare(compareIds)}>{compareState.isLoading ? 'Comparing…' : `Compare ${compareIds.length} asset(s)`}</ActionButton>
                {compareState.isError && <InlineAlert tone="red">{apiErrorMessage(compareState.error)}</InlineAlert>}
              </div>
            )}
          </DataPanel>
          {compareState.data && (
            <DataPanel title="Policy comparison" detail={`${compareState.data.inconsistency_count} inconsistent setting(s)${compareState.data.worst_severity ? ` · worst: ${compareState.data.worst_severity}` : ''}`}>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm" style={{ minWidth: 700 }}>
                  <thead className="bg-slate-50 text-[11px] uppercase tracking-[0.08em] text-slate-500">
                    <tr>
                      <th className="border-b border-slate-200 px-4 py-3 font-semibold">Setting</th>
                      <th className="border-b border-slate-200 px-4 py-3 font-semibold">Baseline</th>
                      {compareState.data.assets.map((a) => <th key={a.id} className="border-b border-slate-200 px-4 py-3 font-semibold">{a.hostname}</th>)}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-100">
                    {compareState.data.rows.map((row) => (
                      <tr key={row.setting} className={cx(row.has_inconsistency && 'bg-amber-50/40')}>
                        <td className="px-4 py-2 font-medium text-slate-800">{row.label}{row.has_inconsistency ? <span className="ml-1 text-amber-600">⚠</span> : null}</td>
                        <td className="px-4 py-2 text-slate-500">{cellText(row.baseline)}</td>
                        {compareState.data!.assets.map((a) => {
                          const cell = row.values.find((c) => c.asset_id === a.id)
                          return <td key={a.id} className={cx('px-4 py-2', cell?.is_weak ? 'font-semibold text-red-700' : 'text-slate-700')}>{cell ? cellText(cell.value) : '—'}</td>
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </DataPanel>
          )}
        </div>
      )}

      {tab === 'coverage' && (
        coveragePoliciesQ.isLoading || assetsQ.isLoading ? <LoadingPanel /> : (
          <div className="space-y-4">
            <div className="grid gap-3 md:grid-cols-3">
              <MetricTile label="Assets without policy" value={noPolicyAssets.length} detail="No effective policy collected" tone={noPolicyAssets.length ? 'red' : 'green'} />
              <MetricTile label="Assets with policy" value={assets.length - noPolicyAssets.length} detail="Policy snapshot present" tone="green" />
              <MetricTile label="Total assets" value={assets.length} detail="In inventory" tone="slate" />
            </div>
            <DataPanel title="Assets with no collected password policy" detail="Run a password-policy scan to close these coverage gaps.">
              <div className="flex justify-end border-b border-slate-200 px-4 py-2">
                {can('scan:launch') && <ActionButton variant="primary" onClick={() => navigate('/scans/new')}>Scan password policy</ActionButton>}
              </div>
              <DataTable columns={coverageCols} rows={noPolicyAssets} getRowKey={(a) => a.id} onRowClick={(a) => navigate(`/assets/${a.id}`)} empty="Every asset has a collected password policy." minWidth={600} />
            </DataPanel>
          </div>
        )
      )}
    </PageFrame>
  )
}

function Item({ k, v }: { k: string; v?: string | null }) {
  return <div><dt className="text-xs uppercase tracking-wide text-slate-500">{k}</dt><dd className="mt-0.5 font-medium text-slate-900">{v || '—'}</dd></div>
}

function Breakdown({ data }: { data: Record<string, number> }) {
  const rows = Object.entries(data ?? {})
  if (rows.length === 0) return <div className="p-4 text-sm text-slate-500">No data.</div>
  return (
    <div className="divide-y divide-slate-100">
      {rows.map(([k, v]) => (
        <div key={k} className="flex items-center justify-between px-4 py-2 text-sm"><span className="text-slate-700">{k}</span><span className="font-semibold tabular-nums text-slate-900">{v}</span></div>
      ))}
    </div>
  )
}
