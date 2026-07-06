import { useMemo, useState } from 'react'
import type React from 'react'
import { downloadServerFile } from '../../api/download'
import { useGetFindingsQuery, useReviewFindingMutation } from '../../api/apiSlice'
import type { Finding, Platform, PrivilegeClass, ReviewState } from '../../api/types'
import { useCan } from '../../app/rbac'
import {
  ActionButton, Badge, DataPanel, EmptyState, ErrorState, Field, InlineAlert, LoadingPanel,
  NativeSelect, PageFrame, StatusBadge, TextInput, apiErrorMessage, cx,
} from '../../components/ui'

const CLASSES: PrivilegeClass[] = [
  'full_admin', 'admin_equivalent', 'operator_high_impact', 'delegated_admin',
  'privileged_service', 'sensitive_non_admin', 'dormant_privileged',
  'unknown_review_required',
]
const PLATFORMS: Platform[] = ['rhel', 'centos', 'ubuntu', 'sles', 'solaris', 'aix', 'hpux', 'windows', 'mysql', 'mssql', 'mongodb', 'oracle_db', 'postgresql', 'redis']
const REVIEW_STATES: { value: ReviewState; label: string }[] = [
  { value: 'acknowledged', label: 'Acknowledge' },
  { value: 'risk_accepted', label: 'Accept risk' },
  { value: 'remediated', label: 'Mark remediated' },
  { value: 'false_positive', label: 'False positive' },
]
type QuickFilter = 'critical' | 'high' | 'unmanaged' | 'dormant' | 'interactive' | 'service' | 'shared' | 'no_owner' | 'inherited' | 'unknown'
type SortKey = 'risk_score' | 'account' | 'asset' | 'platform' | 'classification' | 'last_login' | 'last_discovered'

const CLASS_HELP: Record<PrivilegeClass, string> = {
  full_admin: 'Unrestricted administrative control such as root, Domain Admin, SQL sysadmin, Oracle SYSDBA, or MongoDB root.',
  admin_equivalent: 'Admin-equivalent authority through local admin groups, powerful roles, or broad grants.',
  operator_high_impact: 'Operational role with high-impact privileges such as backup, restore, or security administration.',
  delegated_admin: 'Scoped or delegated admin authority that still requires reviewer validation.',
  privileged_service: 'Service or automation account with elevated rights.',
  sensitive_non_admin: 'Sensitive access that is not full admin but may expose high-value data or controls.',
  dormant_privileged: 'Privileged account with stale, missing, or never-login activity evidence.',
  unknown_review_required: 'Evidence is incomplete or ambiguous. Manual review is required.',
  non_privileged: 'Hidden from this page. No privileged evidence currently matched.',
}

function severity(f: Finding): 'critical' | 'high' | 'medium' | 'low' | 'review' {
  if (f.classification === 'unknown_review_required') return 'review'
  if (f.risk_score >= 90) return 'critical'
  if (f.risk_score >= 75) return 'high'
  if (f.risk_score >= 50) return 'medium'
  return 'low'
}

export default function FindingsList() {
  const can = useCan()
  const [search, setSearch] = useState('')
  const [classification, setClassification] = useState('')
  const [platform, setPlatform] = useState('')
  const [reviewStateFilter, setReviewStateFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [direct, setDirect] = useState('')
  const [pam, setPam] = useState('')
  const [enabled, setEnabled] = useState('')
  const [interactive, setInteractive] = useState('')
  const [owner, setOwner] = useState('')
  const [quick, setQuick] = useState<QuickFilter | ''>('')
  const [winningOnly, setWinningOnly] = useState(true)
  const [sort, setSort] = useState<SortKey>('risk_score')
  const [direction, setDirection] = useState<'asc' | 'desc'>('desc')
  const [limit, setLimit] = useState(25)
  const [offset, setOffset] = useState(0)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [comment, setComment] = useState('')
  const [exportError, setExportError] = useState<string | null>(null)

  const quickParams = useMemo(() => {
    if (quick === 'critical') return { severity: 'critical' }
    if (quick === 'high') return { severity: 'high' }
    if (quick === 'unmanaged') return { pam_managed: false }
    if (quick === 'dormant') return { dormant_privileged: true }
    if (quick === 'interactive') return { interactive_status: 'interactive' }
    if (quick === 'service') return { service_account: true }
    if (quick === 'shared') return { shared_account: true }
    if (quick === 'no_owner') return { no_owner: true }
    if (quick === 'inherited') return { direct: false }
    if (quick === 'unknown') return { classification: 'unknown_review_required' }
    return {}
  }, [quick])

  const params = useMemo(() => {
    const q: Record<string, unknown> = { limit, offset, sort, direction }
    q.real_only = true
    q.privileged_only = true
    if (search.trim()) q.search = search.trim()
    if (classification) q.classification = classification
    if (platform) q.platform = platform
    if (reviewStateFilter) q.review_state = reviewStateFilter
    if (severityFilter) q.severity = severityFilter
    if (direct) q.direct = direct === 'direct'
    if (pam) q.pam_managed = pam === 'managed'
    if (enabled) q.enabled_status = enabled
    if (interactive) q.interactive_status = interactive
    if (owner.trim()) q.owner = owner.trim()
    if (winningOnly) q.is_winning = true
    return { ...q, ...quickParams }
  }, [classification, direct, direction, enabled, interactive, limit, offset, owner, pam, platform, quickParams, reviewStateFilter, search, severityFilter, sort, winningOnly])

  const { data, isLoading, isError, error, refetch } = useGetFindingsQuery(params)
  const [review, reviewMutation] = useReviewFindingMutation()
  const findings = data?.items ?? []
  const selected = findings.find((f) => f.id === selectedId) ?? null
  const total = data?.total ?? 0
  const page = Math.floor(offset / limit) + 1
  const pages = Math.max(1, Math.ceil(total / limit))

  const summary = useMemo(() => {
    return findings.reduce((acc, f) => {
      acc.total += 1
      const sev = severity(f)
      if (sev === 'critical') acc.critical += 1
      if (sev === 'high') acc.high += 1
      if (f.pam_managed === false) acc.unmanaged += 1
      if (f.activity_status === 'inactive_90d' || f.activity_status === 'inactive_30d' || f.activity_status === 'never_logged_in') acc.dormant += 1
      if (String(f.interactive_status ?? '').includes('interactive')) acc.interactive += 1
      if (f.classification === 'unknown_review_required') acc.unknown += 1
      return acc
    }, { total: 0, critical: 0, high: 0, unmanaged: 0, dormant: 0, interactive: 0, unknown: 0 })
  }, [findings])

  function resetFilters() {
    setSearch('')
    setClassification('')
    setPlatform('')
    setReviewStateFilter('')
    setSeverityFilter('')
    setDirect('')
    setPam('')
    setEnabled('')
    setInteractive('')
    setOwner('')
    setQuick('')
    setWinningOnly(true)
    setOffset(0)
  }

  async function applyReview(state: ReviewState) {
    if (!selected) return
    await review({ finding_id: selected.id, state, comment: comment || undefined })
    setComment('')
  }

  async function exportFiltered() {
    setExportError(null)
    const exportParams = new URLSearchParams()
    for (const [key, value] of Object.entries(params)) {
      if (['limit', 'offset', 'sort', 'direction'].includes(key)) continue
      if (value !== undefined && value !== null && value !== '') exportParams.set(key, String(value))
    }
    try {
      await downloadServerFile(`/findings/export/csv?${exportParams.toString()}`, 'privilege-findings.csv')
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'Export failed')
    }
  }

  return (
    <PageFrame
      eyebrow="Privilege governance"
      title="Privileged Findings"
      subtitle="Evidence-backed privilege findings for IAM, PAM, audit, and remediation review."
      actions={<><ActionButton onClick={() => refetch()}>Refresh</ActionButton>{can('export:run') && <ActionButton onClick={exportFiltered}>Export filtered CSV</ActionButton>}</>}
    >
      {!can('findings:view') && <InlineAlert tone="red">Your role is not authorized to view privileged findings.</InlineAlert>}
      {exportError && <InlineAlert tone="red">{exportError}</InlineAlert>}

      <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Metric label="Visible findings" value={summary.total} tone="blue" />
        <Metric label="Critical" value={summary.critical} tone="red" />
        <Metric label="High" value={summary.high} tone="amber" />
        <Metric label="Unmanaged PAM" value={summary.unmanaged} tone="red" />
        <Metric label="Dormant" value={summary.dormant} tone="amber" />
        <Metric label="Review required" value={summary.unknown} tone="slate" />
      </div>

      <DataPanel title="Search and filters" detail="Filters run server-side and can be combined.">
        <div className="space-y-4 p-4">
          <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto]">
            <TextInput placeholder="Search account, asset, IP, platform, privilege path, owner, scan ID, evidence text" value={search} onChange={(e) => { setSearch(e.target.value); setOffset(0) }} />
            <div className="flex flex-wrap gap-2">
              <ActionButton onClick={() => refetch()}>Search</ActionButton>
              <ActionButton variant="ghost" onClick={resetFilters}>Reset</ActionButton>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Quick active={quick === 'critical'} onClick={() => { setQuick(quick === 'critical' ? '' : 'critical'); setOffset(0) }}>Critical findings</Quick>
            <Quick active={quick === 'high'} onClick={() => { setQuick(quick === 'high' ? '' : 'high'); setOffset(0) }}>High risk</Quick>
            <Quick active={quick === 'unmanaged'} onClick={() => { setQuick(quick === 'unmanaged' ? '' : 'unmanaged'); setOffset(0) }}>Unmanaged in PAM</Quick>
            <Quick active={quick === 'dormant'} onClick={() => { setQuick(quick === 'dormant' ? '' : 'dormant'); setOffset(0) }}>Dormant privileged</Quick>
            <Quick active={quick === 'interactive'} onClick={() => { setQuick(quick === 'interactive' ? '' : 'interactive'); setOffset(0) }}>Interactive privileged</Quick>
            <Quick active={quick === 'service'} onClick={() => { setQuick(quick === 'service' ? '' : 'service'); setOffset(0) }}>Service privileged</Quick>
            <Quick active={quick === 'shared'} onClick={() => { setQuick(quick === 'shared' ? '' : 'shared'); setOffset(0) }}>Shared privileged</Quick>
            <Quick active={quick === 'no_owner'} onClick={() => { setQuick(quick === 'no_owner' ? '' : 'no_owner'); setOffset(0) }}>No owner</Quick>
            <Quick active={quick === 'inherited'} onClick={() => { setQuick(quick === 'inherited' ? '' : 'inherited'); setOffset(0) }}>Inherited privilege</Quick>
            <Quick active={quick === 'unknown'} onClick={() => { setQuick(quick === 'unknown' ? '' : 'unknown'); setOffset(0) }}>Unknown review</Quick>
          </div>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <Field label="Severity"><NativeSelect value={severityFilter} options={['critical', 'high', 'medium', 'low', 'review_required'].map((v) => ({ value: v, label: labelize(v) }))} onChange={(v) => { setSeverityFilter(v); setOffset(0) }} placeholder="All severities" /></Field>
            <Field label="Platform"><NativeSelect value={platform} options={PLATFORMS.map((p) => ({ value: p, label: p }))} onChange={(v) => { setPlatform(v); setOffset(0) }} placeholder="All platforms" /></Field>
            <Field label="Classification"><NativeSelect value={classification} options={CLASSES.map((c) => ({ value: c, label: labelize(c) }))} onChange={(v) => { setClassification(v); setOffset(0) }} placeholder="All classifications" /></Field>
            <Field label="Review status"><NativeSelect value={reviewStateFilter} options={REVIEW_STATES.map((s) => ({ value: s.value, label: s.label }))} onChange={(v) => { setReviewStateFilter(v); setOffset(0) }} placeholder="Any status" /></Field>
            <Field label="Direct or inherited"><NativeSelect value={direct} options={[{ value: 'direct', label: 'Direct' }, { value: 'inherited', label: 'Inherited' }]} onChange={(v) => { setDirect(v); setOffset(0) }} placeholder="Any path" /></Field>
            <Field label="PAM status"><NativeSelect value={pam} options={[{ value: 'managed', label: 'Managed' }, { value: 'unmanaged', label: 'Unmanaged' }]} onChange={(v) => { setPam(v); setOffset(0) }} placeholder="Any PAM state" /></Field>
            <Field label="Enabled status"><NativeSelect value={enabled} options={['enabled', 'disabled', 'locked', 'expired', 'unknown'].map((v) => ({ value: v, label: labelize(v) }))} onChange={(v) => { setEnabled(v); setOffset(0) }} placeholder="Any status" /></Field>
            <Field label="Interactive status"><NativeSelect value={interactive} options={['interactive', 'non_interactive', 'interactive_capable', 'service_or_batch_only', 'unknown', 'unknown_review_required'].map((v) => ({ value: v, label: labelize(v) }))} onChange={(v) => { setInteractive(v); setOffset(0) }} placeholder="Any interactivity" /></Field>
          </div>
          <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_220px_180px_180px]">
            <Field label="Owner or custodian"><TextInput placeholder="Filter owner" value={owner} onChange={(e) => { setOwner(e.target.value); setOffset(0) }} /></Field>
            <Field label="Sort by"><NativeSelect value={sort} options={['risk_score', 'account', 'asset', 'platform', 'classification', 'last_login', 'last_discovered'].map((v) => ({ value: v, label: labelize(v) }))} onChange={(v) => setSort(v as SortKey)} /></Field>
            <Field label="Direction"><NativeSelect value={direction} options={[{ value: 'desc', label: 'Descending' }, { value: 'asc', label: 'Ascending' }]} onChange={(v) => setDirection(v as 'asc' | 'desc')} /></Field>
            <Field label="Page size"><NativeSelect value={String(limit)} options={['10', '25', '50', '100'].map((v) => ({ value: v, label: v }))} onChange={(v) => { setLimit(Number(v)); setOffset(0) }} /></Field>
          </div>
          <label className="flex items-center gap-2 text-sm text-slate-700"><input type="checkbox" checked={winningOnly} onChange={(e) => { setWinningOnly(e.target.checked); setOffset(0) }} />Winning findings only</label>
        </div>
      </DataPanel>

      {isLoading ? <LoadingPanel label="Loading findings…" /> : isError ? (
        <ErrorState detail={apiErrorMessage(error)} onRetry={refetch} />
      ) : (
        <DataPanel title="Findings table" detail={`${total} matching finding(s). Page ${page} of ${pages}.`}>
          {findings.length === 0 ? <EmptyState title="No findings match the current filters." detail="Clear filters or run a privileged discovery scan to generate evidence-backed findings." /> : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[1280px] text-left">
                <thead className="sticky top-14 z-10 bg-slate-50 text-[11px] uppercase tracking-[0.08em] text-slate-500">
                  <tr>
                    {['Severity', 'Account', 'Asset', 'Platform', 'Classification', 'Path', 'PAM', 'Owner', 'Interactive', 'Last login', 'Review', 'Last discovered'].map((h) => <th key={h} className="border-b border-slate-200 px-4 py-3 font-semibold">{h}</th>)}
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {findings.map((finding) => (
                    <tr key={finding.id} onClick={() => setSelectedId(finding.id)} className={cx('cursor-pointer bg-white text-sm hover:bg-blue-50/50', selectedId === finding.id && 'bg-blue-50')}>
                      <td className="px-4 py-3"><SeverityBadge value={severity(finding)} /></td>
                      <td className="px-4 py-3"><div className="font-semibold text-slate-900">{finding.account_name ?? finding.account_id.slice(0, 8)}</div><div className="text-xs text-slate-500">{finding.account_type ?? finding.account_source ?? 'unknown'}</div></td>
                      <td className="px-4 py-3"><div className="font-medium text-slate-800">{finding.asset_hostname ?? 'Unknown asset'}</div><div className="text-xs text-slate-500">{finding.asset_ip_address ?? finding.environment ?? 'No IP'}</div></td>
                      <td className="px-4 py-3"><Badge tone="slate">{finding.platform ?? 'unknown'}</Badge></td>
                      <td className="px-4 py-3"><StatusBadge value={finding.classification} /></td>
                      <td className="max-w-[220px] px-4 py-3"><div className="truncate text-slate-700">{finding.direct ? 'Direct' : finding.inheritance_path ?? 'Inherited'}</div><div className="text-xs text-slate-500">{finding.rule_key}</div></td>
                      <td className="px-4 py-3"><PamBadge value={finding.pam_managed} /></td>
                      <td className="px-4 py-3 text-slate-700">{finding.owner ?? <span className="text-red-600">No owner</span>}</td>
                      <td className="px-4 py-3"><StatusBadge value={finding.interactive_status ?? 'unknown'} /></td>
                      <td className="px-4 py-3 text-xs text-slate-600">{fmt(finding.last_login)}</td>
                      <td className="px-4 py-3"><StatusBadge value={finding.latest_review_state ?? 'unreviewed'} /></td>
                      <td className="px-4 py-3 text-xs text-slate-600">{fmt(finding.evaluated_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="flex flex-col gap-3 border-t border-slate-200 p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-sm text-slate-500">Showing {findings.length} of {total} matching findings.</div>
            <div className="flex gap-2">
              <ActionButton disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - limit))}>Previous</ActionButton>
              <ActionButton disabled={offset + limit >= total} onClick={() => setOffset(offset + limit)}>Next</ActionButton>
            </div>
          </div>
        </DataPanel>
      )}

      {selected && (
        <DataPanel title="Finding detail" detail={`${selected.account_name ?? selected.account_id} · ${selected.rule_key}`}>
          <div className="space-y-4 p-4">
            <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_280px]">
              <div className="rounded-md border border-slate-200 bg-slate-50 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge value={severity(selected)} />
                  <StatusBadge value={selected.classification} />
                  <Badge tone={selected.direct ? 'green' : 'amber'}>{selected.direct ? 'Direct privilege' : 'Inherited privilege'}</Badge>
                </div>
                <p className="mt-3 text-sm leading-6 text-slate-700">{selected.explanation}</p>
                <div className="mt-3 rounded-md border border-blue-100 bg-blue-50 px-3 py-2 text-xs leading-5 text-blue-800">{CLASS_HELP[selected.classification]}</div>
              </div>
              <div className="rounded-md border border-slate-200 bg-white p-4">
                <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Reviewer state</div>
                <div className="mt-2"><StatusBadge value={selected.latest_review_state ?? 'unreviewed'} /></div>
                <div className="mt-3 text-xs leading-5 text-slate-500">{selected.latest_review_comment ?? 'No reviewer note recorded.'}</div>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-4 text-sm md:grid-cols-4">
              <Item k="Account" v={selected.account_name} />
              <Item k="Asset" v={selected.asset_hostname} />
              <Item k="Platform" v={selected.platform} />
              <Item k="Environment" v={selected.environment} />
              <Item k="Owner" v={selected.owner} />
              <Item k="PAM status" v={selected.pam_managed === true ? 'Managed' : selected.pam_managed === false ? 'Unmanaged' : 'Unknown'} />
              <Item k="Confidence" v={`${selected.confidence}%`} />
              <Item k="Risk score" v={String(selected.risk_score)} />
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Privilege path</div>
              <div className="mt-1 rounded-md border border-slate-200 bg-white p-3 text-sm text-slate-700">{selected.direct ? 'Direct privilege from matched evidence.' : selected.inheritance_path ?? 'Inherited path was not resolved.'}</div>
            </div>
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Evidence summary</div>
              <pre className="mt-1 max-h-64 overflow-auto rounded-md bg-slate-950 p-3 text-xs leading-5 text-slate-100">{JSON.stringify(selected.matched_evidence ?? {}, null, 2)}</pre>
            </div>
            {can('findings:review') ? (
              <div className="space-y-2 border-t border-slate-200 pt-4">
                <Field label="Reviewer note"><TextInput value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Add rationale for the status change" /></Field>
                <div className="flex flex-wrap gap-2">
                  {REVIEW_STATES.map((state) => <ActionButton key={state.value} disabled={reviewMutation.isLoading} onClick={() => applyReview(state.value)}>{state.label}</ActionButton>)}
                </div>
                {reviewMutation.isSuccess && <InlineAlert tone="green">Review state recorded.</InlineAlert>}
                {reviewMutation.isError && <InlineAlert tone="red">{apiErrorMessage(reviewMutation.error)}</InlineAlert>}
              </div>
            ) : <InlineAlert tone="slate">Your role can view findings but cannot record review decisions.</InlineAlert>}
          </div>
        </DataPanel>
      )}
    </PageFrame>
  )
}

function Metric({ label, value, tone }: { label: string; value: number; tone: 'blue' | 'red' | 'amber' | 'slate' }) {
  const colors = { blue: 'text-blue-700', red: 'text-red-700', amber: 'text-amber-700', slate: 'text-slate-700' }[tone]
  return <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm"><div className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</div><div className={cx('mt-2 text-2xl font-semibold', colors)}>{value}</div></div>
}

function Quick({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return <button type="button" onClick={onClick} className={cx('rounded-md border px-3 py-1.5 text-xs font-semibold transition', active ? 'border-blue-600 bg-blue-50 text-blue-700' : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50')}>{children}</button>
}

function SeverityBadge({ value }: { value: ReturnType<typeof severity> }) {
  const tone = value === 'critical' ? 'red' : value === 'high' ? 'amber' : value === 'medium' ? 'blue' : value === 'review' ? 'purple' : 'slate'
  return <Badge tone={tone}>{labelize(value)}</Badge>
}

function PamBadge({ value }: { value?: boolean | null }) {
  if (value === true) return <Badge tone="green">Managed</Badge>
  if (value === false) return <Badge tone="red">Unmanaged</Badge>
  return <Badge tone="slate">Unknown</Badge>
}

function Item({ k, v }: { k: string; v?: string | null }) {
  return <div><dt className="text-xs uppercase tracking-wide text-slate-500">{k}</dt><dd className="mt-0.5 font-medium text-slate-900">{v || 'Not recorded'}</dd></div>
}

function fmt(value?: string | null) {
  return value ? new Date(value).toLocaleString() : 'Not recorded'
}

function labelize(value: string) {
  return value.replace(/_/g, ' ').replace(/^./, (letter) => letter.toUpperCase())
}
