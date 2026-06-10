import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import {
  getPasswordPolicies,
  getPasswordPolicySummary,
  getPolicyFindings,
  getPolicyExceptions,
  comparePolicies,
  reviewPolicyFinding,
  exportPolicyCsv,
  exportPolicyExcel,
  type PasswordPolicy,
  type PasswordPolicyFinding,
  type AccountPolicyException,
  type PolicyFindingSeverity,
  type PolicyFindingReviewState,
} from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { StatCard } from '@/components/StatCard'
import { PageSpinner } from '@/components/Spinner'
import { PLATFORM_LABELS } from '@/lib/privilege'
import toast from 'react-hot-toast'
import { format } from 'date-fns'

// ── Constants ──────────────────────────────────────────────────────────────────

const POLICY_SOURCE_LABELS: Record<string, string> = {
  local_policy: 'Local Policy', domain_policy: 'Domain Policy',
  fine_grained_ad: 'Fine-Grained AD (PSO)', pam_module: 'PAM Module',
  pam_tally: 'PAM Tally / Faillock', login_defs: '/etc/login.defs',
  database_native: 'DB Native', external_idp: 'External IdP', unknown: 'Unknown',
}

const SEV_COLORS: Record<PolicyFindingSeverity, string> = {
  critical: 'bg-red-100 text-red-800 border border-red-200',
  high: 'bg-orange-100 text-orange-800 border border-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 border border-yellow-200',
  low: 'bg-green-100 text-green-800 border border-green-200',
  info: 'bg-blue-100 text-blue-800 border border-blue-200',
}

const SEV_DOT: Record<PolicyFindingSeverity, string> = {
  critical: 'bg-red-500', high: 'bg-orange-500',
  medium: 'bg-yellow-500', low: 'bg-green-500', info: 'bg-blue-500',
}

const REVIEW_OPTIONS: PolicyFindingReviewState[] = [
  'acknowledged', 'risk_accepted', 'remediated', 'false_positive',
]

// ── Sub-components ─────────────────────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: PolicyFindingSeverity }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${SEV_COLORS[sev]}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${SEV_DOT[sev]}`} />
      {sev.charAt(0).toUpperCase() + sev.slice(1)}
    </span>
  )
}

function PolicyRiskIcons({ policy }: { policy: PasswordPolicy }) {
  const icons = []
  if (policy.has_weak_length) icons.push({ tip: 'Weak length', cls: 'text-red-600', icon: 'L' })
  if (policy.has_no_complexity) icons.push({ tip: 'No complexity', cls: 'text-orange-600', icon: 'C' })
  if (policy.has_no_lockout) icons.push({ tip: 'No lockout', cls: 'text-red-600', icon: 'K' })
  if (policy.has_no_expiry) icons.push({ tip: 'No expiry', cls: 'text-yellow-600', icon: 'E' })
  if (policy.external_policy_enforced) icons.push({ tip: 'External policy', cls: 'text-blue-600', icon: '↗' })
  if (!icons.length) return <span className="text-green-600 text-xs font-semibold">✓ Strong</span>
  return (
    <div className="flex gap-1">
      {icons.map((ic, i) => (
        <span key={i} title={ic.tip} className={`text-xs font-bold px-1 py-0.5 rounded bg-slate-100 ${ic.cls}`}>
          {ic.icon}
        </span>
      ))}
    </div>
  )
}

function NullableVal({ v, zero = '0', trueLabel = 'Yes', falseLabel = 'No' }: {
  v: unknown; zero?: string; trueLabel?: string; falseLabel?: string
}) {
  if (v === null || v === undefined) return <span className="text-slate-300 text-xs">—</span>
  if (typeof v === 'boolean') {
    return <span className={v ? 'text-green-700 text-xs font-semibold' : 'text-red-600 text-xs font-semibold'}>
      {v ? trueLabel : falseLabel}
    </span>
  }
  if (v === 0) return <span className="text-red-600 text-xs font-semibold">{zero}</span>
  return <span className="text-slate-700 text-xs">{String(v)}</span>
}

// ── Main Page ─────────────────────────────────────────────────────────────────

type Tab = 'policies' | 'findings' | 'exceptions'

export default function PasswordPolicies() {
  const nav = useNavigate()
  const qc = useQueryClient()
  const [tab, setTab] = useState<Tab>('policies')

  // ── Policy filters
  const [platFilter, setPlatFilter] = useState('')
  const [srcFilter, setSrcFilter] = useState('')
  const [weakOnly, setWeakOnly] = useState(false)
  const [effectiveOnly, setEffectiveOnly] = useState(false)
  const [policyPage, setPolicyPage] = useState(0)

  // ── Finding filters
  const [sevFilter, setSevFilter] = useState('')
  const [reviewFilter, setReviewFilter] = useState('')
  const [exFilter, setExFilter] = useState<boolean | undefined>(undefined)
  const [findPage, setFindPage] = useState(0)
  const [reviewState, setReviewState] = useState<Record<string, string>>({})
  const [reviewComment, setReviewComment] = useState<Record<string, string>>({})

  // ── Exception filters
  const [excTypeFilter, setExcTypeFilter] = useState('')
  const [excPage, setExcPage] = useState(0)

  // ── Compare
  const [compareMode, setCompareMode] = useState(false)
  const [compareIds, setCompareIds] = useState<Set<string>>(new Set())

  const { data: summary } = useQuery({
    queryKey: ['pwpol', 'summary'],
    queryFn: () => getPasswordPolicySummary().then(r => r.data),
  })

  const { data: policies, isLoading: loadingPolicies } = useQuery({
    queryKey: ['pwpol', 'list', platFilter, srcFilter, weakOnly, effectiveOnly, policyPage],
    queryFn: () => getPasswordPolicies({
      platform: platFilter || undefined,
      policy_source: srcFilter || undefined,
      has_weak_length: weakOnly || undefined,
      is_effective_policy: effectiveOnly || undefined,
      limit: 50, offset: policyPage * 50,
    }).then(r => r.data),
    enabled: tab === 'policies',
  })

  const { data: findings, isLoading: loadingFindings } = useQuery({
    queryKey: ['pwpol', 'findings', sevFilter, reviewFilter, exFilter, findPage],
    queryFn: () => getPolicyFindings({
      severity: sevFilter || undefined,
      review_state: reviewFilter || undefined,
      is_exception_finding: exFilter,
      limit: 50, offset: findPage * 50,
    }).then(r => r.data),
    enabled: tab === 'findings',
  })

  const { data: exceptions, isLoading: loadingExceptions } = useQuery({
    queryKey: ['pwpol', 'exceptions', excTypeFilter, excPage],
    queryFn: () => getPolicyExceptions({
      exception_type: excTypeFilter || undefined,
      limit: 50, offset: excPage * 50,
    }).then(r => r.data),
    enabled: tab === 'exceptions',
  })

  const { data: compareResult, isLoading: comparing } = useQuery({
    queryKey: ['pwpol', 'compare', [...compareIds].sort().join(',')],
    queryFn: () => comparePolicies([...compareIds]).then(r => r.data),
    enabled: compareMode && compareIds.size >= 2,
  })

  const reviewMut = useMutation({
    mutationFn: ({ id, state, comment }: { id: string; state: PolicyFindingReviewState; comment?: string }) =>
      reviewPolicyFinding(id, state, comment),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['pwpol', 'findings'] })
      qc.invalidateQueries({ queryKey: ['pwpol', 'summary'] })
      toast.success('Review state saved')
    },
    onError: () => toast.error('Failed to save review'),
  })

  const handleExportCsv = async () => {
    try {
      const r = await exportPolicyCsv()
      const url = URL.createObjectURL(r.data as Blob)
      const a = document.createElement('a')
      a.href = url; a.download = 'password_policies.csv'; a.click()
      URL.revokeObjectURL(url)
    } catch { toast.error('Export failed') }
  }

  const handleExportExcel = async () => {
    try {
      const r = await exportPolicyExcel()
      const url = URL.createObjectURL(r.data as Blob)
      const a = document.createElement('a')
      a.href = url; a.download = 'password_policies.xlsx'; a.click()
      URL.revokeObjectURL(url)
    } catch { toast.error('Export failed') }
  }

  const toggleCompare = (id: string) => {
    setCompareIds(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  return (
    <div>
      <PageHeader
        title="Password Policies"
        subtitle={summary ? `${summary.total_policies} policies · ${summary.open_findings} open findings` : ''}
        actions={
          <div className="flex gap-2">
            <button className="btn-secondary text-sm" onClick={handleExportCsv}>CSV</button>
            <button className="btn-secondary text-sm" onClick={handleExportExcel}>Excel</button>
            {compareMode && compareIds.size >= 2 && (
              <button className="btn-primary text-sm" onClick={() => {}}>
                Compare ({compareIds.size})
              </button>
            )}
            <button
              className={`btn-secondary text-sm ${compareMode ? 'ring-2 ring-brand-500' : ''}`}
              onClick={() => { setCompareMode(m => !m); setCompareIds(new Set()) }}
            >
              {compareMode ? 'Cancel Compare' : 'Compare'}
            </button>
          </div>
        }
      />

      {/* Summary cards */}
      {summary && (
        <div className="px-6 pt-4 grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
          <StatCard label="Assets with Policy" value={summary.total_assets_with_policy} />
          <StatCard label="Assets without Policy" value={summary.assets_with_no_policy}
            className={summary.assets_with_no_policy > 0 ? 'border-orange-200' : ''} />
          <StatCard label="Critical Findings" value={summary.critical_findings}
            className={summary.critical_findings > 0 ? 'border-red-300' : ''} />
          <StatCard label="High Findings" value={summary.high_findings}
            className={summary.high_findings > 0 ? 'border-orange-300' : ''} />
          <StatCard label="Account Exceptions" value={summary.total_exceptions} />
          <StatCard label="Priv. Exceptions" value={summary.privileged_account_exceptions}
            className={summary.privileged_account_exceptions > 0 ? 'border-red-200' : ''} />
        </div>
      )}

      {/* Weak-settings summary bar */}
      {summary && (
        <div className="px-6 pt-3 flex flex-wrap gap-3">
          {[
            { label: 'Weak Length', count: summary.assets_with_weak_length, color: 'text-red-700 bg-red-50' },
            { label: 'No Complexity', count: summary.assets_with_no_complexity, color: 'text-orange-700 bg-orange-50' },
            { label: 'No Lockout', count: summary.assets_with_no_lockout, color: 'text-red-700 bg-red-50' },
            { label: 'Reversible Enc.', count: summary.assets_with_reversible_encryption, color: 'text-red-900 bg-red-100 font-bold' },
          ].map(item => (
            <div key={item.label} className={`px-3 py-1 rounded text-xs ${item.color} ${item.count === 0 ? 'opacity-40' : ''}`}>
              {item.count} asset{item.count !== 1 ? 's' : ''} — {item.label}
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div className="px-6 pt-4 border-b border-slate-200 bg-white flex gap-1">
        {(['policies', 'findings', 'exceptions'] as Tab[]).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors -mb-px ${
              tab === t
                ? 'border-brand-600 text-brand-700'
                : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}
          >
            {t.charAt(0).toUpperCase() + t.slice(1)}
            {t === 'findings' && summary && summary.open_findings > 0 && (
              <span className="ml-1.5 px-1.5 py-0.5 text-[10px] rounded-full bg-red-500 text-white">
                {summary.open_findings}
              </span>
            )}
            {t === 'exceptions' && summary && summary.total_exceptions > 0 && (
              <span className="ml-1.5 px-1.5 py-0.5 text-[10px] rounded-full bg-orange-400 text-white">
                {summary.total_exceptions}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* ── POLICIES TAB ── */}
      {tab === 'policies' && (
        <>
          {/* Filters */}
          <div className="px-6 py-3 bg-white border-b border-slate-200 flex flex-wrap gap-3 items-center">
            <select className="input w-44 text-sm" value={platFilter} onChange={e => { setPlatFilter(e.target.value); setPolicyPage(0) }}>
              <option value="">All Platforms</option>
              {['windows', 'rhel', 'centos', 'ubuntu', 'sles', 'solaris', 'aix', 'hpux', 'mysql', 'mssql', 'mongodb', 'oracle_db', 'postgresql'].map(p => (
                <option key={p} value={p}>{PLATFORM_LABELS[p as keyof typeof PLATFORM_LABELS] ?? p}</option>
              ))}
            </select>
            <select className="input w-52 text-sm" value={srcFilter} onChange={e => { setSrcFilter(e.target.value); setPolicyPage(0) }}>
              <option value="">All Sources</option>
              {Object.entries(POLICY_SOURCE_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={weakOnly} onChange={e => { setWeakOnly(e.target.checked); setPolicyPage(0) }} />
              Weak settings only
            </label>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={effectiveOnly} onChange={e => { setEffectiveOnly(e.target.checked); setPolicyPage(0) }} />
              Effective policies only
            </label>
          </div>

          {compareMode && compareIds.size > 0 && (
            <div className="px-6 py-2 bg-brand-50 border-b border-brand-200 text-sm text-brand-800">
              {compareIds.size} asset{compareIds.size > 1 ? 's' : ''} selected for comparison.
              {compareIds.size >= 2 && (
                <span className="ml-2">
                  Scroll down or click Compare to view the side-by-side analysis.
                </span>
              )}
            </div>
          )}

          {loadingPolicies ? <PageSpinner /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200">
                    {compareMode && <th className="w-8 px-3 py-2" />}
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Asset</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Platform</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Source</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Policy Name</th>
                    <th className="px-3 py-2 text-center text-xs font-semibold text-slate-500 uppercase">Min Len</th>
                    <th className="px-3 py-2 text-center text-xs font-semibold text-slate-500 uppercase">Complex.</th>
                    <th className="px-3 py-2 text-center text-xs font-semibold text-slate-500 uppercase">History</th>
                    <th className="px-3 py-2 text-center text-xs font-semibold text-slate-500 uppercase">Max Age</th>
                    <th className="px-3 py-2 text-center text-xs font-semibold text-slate-500 uppercase">Lockout</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Risk</th>
                    <th className="px-3 py-2 text-center text-xs font-semibold text-slate-500 uppercase">Findings</th>
                    <th className="px-3 py-2 text-center text-xs font-semibold text-slate-500 uppercase">Conf.</th>
                  </tr>
                </thead>
                <tbody>
                  {policies?.items.map(pol => (
                    <tr
                      key={pol.id}
                      className={`border-b border-slate-100 hover:bg-slate-50 ${pol.is_effective_policy ? '' : 'opacity-70'}`}
                    >
                      {compareMode && (
                        <td className="px-3 py-2 text-center">
                          <input
                            type="checkbox"
                            checked={compareIds.has(pol.asset_id)}
                            onChange={() => toggleCompare(pol.asset_id)}
                          />
                        </td>
                      )}
                      <td className="px-4 py-2">
                        <button
                          className="text-brand-600 hover:underline font-medium text-left"
                          onClick={() => nav(`/assets/${pol.asset_id}`)}
                        >
                          {pol.hostname ?? pol.asset_id.slice(0, 8)}
                        </button>
                        {pol.is_effective_policy && (
                          <span className="ml-1.5 text-[10px] bg-green-100 text-green-700 px-1 py-0.5 rounded font-semibold">
                            EFFECTIVE
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-slate-600 text-xs">
                        {PLATFORM_LABELS[pol.platform] ?? pol.platform}
                      </td>
                      <td className="px-4 py-2 text-xs text-slate-600">
                        {POLICY_SOURCE_LABELS[pol.policy_source] ?? pol.policy_source}
                      </td>
                      <td className="px-4 py-2 text-xs text-slate-600 max-w-[200px] truncate" title={pol.policy_name ?? ''}>
                        {pol.policy_name ?? <span className="text-slate-300">—</span>}
                      </td>
                      <td className="px-3 py-2 text-center">
                        <NullableVal v={pol.min_password_length} />
                      </td>
                      <td className="px-3 py-2 text-center">
                        <NullableVal v={pol.complexity_enabled} trueLabel="Yes" falseLabel="No" />
                      </td>
                      <td className="px-3 py-2 text-center">
                        <NullableVal v={pol.password_history_count} zero="None" />
                      </td>
                      <td className="px-3 py-2 text-center">
                        {pol.max_password_age_days === 0
                          ? <span className="text-yellow-600 text-xs font-semibold">Never</span>
                          : <NullableVal v={pol.max_password_age_days} />}
                      </td>
                      <td className="px-3 py-2 text-center">
                        {pol.lockout_threshold === 0
                          ? <span className="text-red-600 text-xs font-semibold">None</span>
                          : <NullableVal v={pol.lockout_threshold} />}
                      </td>
                      <td className="px-4 py-2">
                        <PolicyRiskIcons policy={pol} />
                      </td>
                      <td className="px-3 py-2 text-center">
                        {pol.finding_count > 0 ? (
                          <button
                            className={`text-xs font-semibold px-2 py-0.5 rounded ${pol.critical_finding_count > 0 ? 'bg-red-100 text-red-700' : 'bg-orange-100 text-orange-700'}`}
                            onClick={() => { setTab('findings'); setSevFilter('') }}
                          >
                            {pol.finding_count}
                          </button>
                        ) : <span className="text-slate-300 text-xs">0</span>}
                      </td>
                      <td className="px-3 py-2 text-center">
                        <span className={`text-xs font-semibold ${pol.confidence_score >= 75 ? 'text-green-700' : pol.confidence_score >= 40 ? 'text-yellow-700' : 'text-red-600'}`}>
                          {pol.confidence_score}%
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {/* Pagination */}
              {policies && policies.total > 50 && (
                <div className="px-6 py-3 flex items-center gap-4 border-t border-slate-200">
                  <button className="btn-secondary text-xs" disabled={policyPage === 0} onClick={() => setPolicyPage(p => p - 1)}>← Prev</button>
                  <span className="text-xs text-slate-500">{policyPage * 50 + 1}–{Math.min((policyPage + 1) * 50, policies.total)} of {policies.total}</span>
                  <button className="btn-secondary text-xs" disabled={(policyPage + 1) * 50 >= policies.total} onClick={() => setPolicyPage(p => p + 1)}>Next →</button>
                </div>
              )}
            </div>
          )}

          {/* Compare result panel */}
          {compareMode && compareIds.size >= 2 && compareResult && (
            <div className="px-6 py-4 mt-2">
              <h3 className="text-sm font-semibold text-slate-700 mb-3">
                Policy Comparison
                {compareResult.worst_severity && (
                  <span className="ml-2"><SeverityBadge sev={compareResult.worst_severity as PolicyFindingSeverity} /></span>
                )}
                <span className="ml-2 text-slate-400 font-normal">{compareResult.inconsistency_count} inconsistencies</span>
              </h3>
              <div className="overflow-x-auto rounded-lg border border-slate-200">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="bg-slate-800 text-white">
                      <th className="px-4 py-2 text-left">Setting</th>
                      <th className="px-3 py-2 text-center">Baseline</th>
                      {compareResult.assets.map(a => (
                        <th key={a.id} className="px-3 py-2 text-center">{a.hostname}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {compareResult.rows.map(row => (
                      <tr key={row.setting} className={`border-t border-slate-100 ${row.has_inconsistency ? 'bg-yellow-50' : ''}`}>
                        <td className="px-4 py-2 font-medium text-slate-700">
                          {row.label}
                          {row.has_inconsistency && <span className="ml-1 text-yellow-600">⚠</span>}
                        </td>
                        <td className="px-3 py-2 text-center text-slate-400">
                          {row.baseline !== undefined && row.baseline !== null ? String(row.baseline) : '—'}
                        </td>
                        {row.values.map(cell => (
                          <td key={cell.asset_id} className={`px-3 py-2 text-center ${cell.is_weak ? 'text-red-700 font-semibold bg-red-50' : 'text-slate-700'}`}>
                            {cell.value === null || cell.value === undefined ? '—' : String(cell.value)}
                            {cell.is_effective && <span className="block text-[9px] text-green-600 font-normal">effective</span>}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {/* ── FINDINGS TAB ── */}
      {tab === 'findings' && (
        <>
          <div className="px-6 py-3 bg-white border-b border-slate-200 flex flex-wrap gap-3 items-center">
            <select className="input w-40 text-sm" value={sevFilter} onChange={e => { setSevFilter(e.target.value); setFindPage(0) }}>
              <option value="">All Severities</option>
              {['critical', 'high', 'medium', 'low', 'info'].map(s => (
                <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
              ))}
            </select>
            <select className="input w-44 text-sm" value={reviewFilter} onChange={e => { setReviewFilter(e.target.value); setFindPage(0) }}>
              <option value="">All Review States</option>
              {['open', 'acknowledged', 'risk_accepted', 'remediated', 'false_positive'].map(s => (
                <option key={s} value={s}>{s.replace(/_/g, ' ')}</option>
              ))}
            </select>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={exFilter === true} onChange={e => setExFilter(e.target.checked ? true : undefined)} />
              Exception findings only
            </label>
            <button className="btn-secondary text-xs ml-auto" onClick={handleExportExcel}>
              Export Excel
            </button>
          </div>

          {loadingFindings ? <PageSpinner /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200">
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Severity</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Rule</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Title</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Asset</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Scope</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">State</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Discovered</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {findings?.items.map(f => (
                    <tr key={f.id} className="border-b border-slate-100 hover:bg-slate-50">
                      <td className="px-4 py-2"><SeverityBadge sev={f.severity} /></td>
                      <td className="px-4 py-2">
                        <span className="font-mono text-xs bg-slate-100 px-1.5 py-0.5 rounded">{f.rule_key}</span>
                        {f.is_exception_finding && (
                          <span className="ml-1 text-[10px] bg-purple-100 text-purple-700 px-1 rounded">EXCEPTION</span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-slate-700 max-w-[280px]">
                        <div className="font-medium text-xs">{f.title}</div>
                        <div className="text-slate-400 text-[11px] mt-0.5 line-clamp-2">{f.description}</div>
                      </td>
                      <td className="px-4 py-2">
                        <button className="text-brand-600 text-xs hover:underline" onClick={() => nav(`/assets/${f.asset_id}`)}>
                          {f.hostname ?? f.asset_id.slice(0, 8)}
                        </button>
                        {f.account_name && <div className="text-slate-400 text-[11px]">{f.account_name}</div>}
                      </td>
                      <td className="px-4 py-2 text-xs text-slate-500">{f.affected_scope ?? '—'}</td>
                      <td className="px-4 py-2">
                        <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                          f.review_state === 'open' ? 'bg-red-100 text-red-700' :
                          f.review_state === 'remediated' ? 'bg-green-100 text-green-700' :
                          'bg-slate-100 text-slate-600'
                        }`}>
                          {f.review_state.replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-xs text-slate-400">
                        {format(new Date(f.discovered_at), 'dd MMM yyyy')}
                      </td>
                      <td className="px-4 py-2">
                        {f.review_state === 'open' && (
                          <div className="flex gap-1 items-center">
                            <select
                              className="input text-xs w-32 py-0.5"
                              value={reviewState[f.id] ?? ''}
                              onChange={e => setReviewState(p => ({ ...p, [f.id]: e.target.value }))}
                            >
                              <option value="">Mark as…</option>
                              {REVIEW_OPTIONS.map(o => (
                                <option key={o} value={o}>{o.replace(/_/g, ' ')}</option>
                              ))}
                            </select>
                            <button
                              className="btn-primary text-xs py-0.5 px-2"
                              disabled={!reviewState[f.id]}
                              onClick={() => reviewMut.mutate({
                                id: f.id,
                                state: reviewState[f.id] as PolicyFindingReviewState,
                                comment: reviewComment[f.id],
                              })}
                            >
                              Save
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {findings && findings.total > 50 && (
                <div className="px-6 py-3 flex items-center gap-4 border-t border-slate-200">
                  <button className="btn-secondary text-xs" disabled={findPage === 0} onClick={() => setFindPage(p => p - 1)}>← Prev</button>
                  <span className="text-xs text-slate-500">{findPage * 50 + 1}–{Math.min((findPage + 1) * 50, findings.total)} of {findings.total}</span>
                  <button className="btn-secondary text-xs" disabled={(findPage + 1) * 50 >= findings.total} onClick={() => setFindPage(p => p + 1)}>Next →</button>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* ── EXCEPTIONS TAB ── */}
      {tab === 'exceptions' && (
        <>
          <div className="px-6 py-3 bg-white border-b border-slate-200 flex flex-wrap gap-3 items-center">
            <select className="input w-56 text-sm" value={excTypeFilter} onChange={e => { setExcTypeFilter(e.target.value); setExcPage(0) }}>
              <option value="">All Exception Types</option>
              {[
                'password_never_expires', 'password_not_required', 'check_policy_off',
                'check_expiration_off', 'lockout_exempt', 'under_weaker_policy',
                'privileged_account_weak_policy', 'under_external_policy',
                'unknown_effective_policy', 'fgpp_not_applied',
              ].map(t => <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>)}
            </select>
          </div>

          {loadingExceptions ? <PageSpinner /> : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-200">
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Exception Type</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Asset</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Account</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Effective Policy</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Expected Policy</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Description</th>
                    <th className="px-4 py-2 text-left text-xs font-semibold text-slate-500 uppercase">Discovered</th>
                  </tr>
                </thead>
                <tbody>
                  {exceptions?.items.map(exc => (
                    <tr key={exc.id} className="border-b border-slate-100 hover:bg-slate-50">
                      <td className="px-4 py-2">
                        <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                          exc.exception_type.includes('not_required') || exc.exception_type === 'check_policy_off'
                            ? 'bg-red-100 text-red-700'
                            : exc.exception_type.includes('privileged')
                              ? 'bg-orange-100 text-orange-700'
                              : 'bg-slate-100 text-slate-600'
                        }`}>
                          {exc.exception_type.replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td className="px-4 py-2">
                        <button className="text-brand-600 text-xs hover:underline" onClick={() => nav(`/assets/${exc.asset_id}`)}>
                          {exc.asset_hostname ?? exc.asset_id.slice(0, 8)}
                        </button>
                      </td>
                      <td className="px-4 py-2 text-xs text-slate-600">
                        {exc.account_name ?? (exc.account_id ? exc.account_id.slice(0, 8) : '—')}
                      </td>
                      <td className="px-4 py-2 text-xs text-slate-500">{exc.effective_policy_source ?? '—'}</td>
                      <td className="px-4 py-2 text-xs text-slate-500">{exc.expected_policy_source ?? '—'}</td>
                      <td className="px-4 py-2 text-xs text-slate-500 max-w-[200px] truncate" title={exc.description ?? ''}>
                        {exc.description ?? '—'}
                      </td>
                      <td className="px-4 py-2 text-xs text-slate-400">
                        {format(new Date(exc.discovered_at), 'dd MMM yyyy')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {exceptions && exceptions.total > 50 && (
                <div className="px-6 py-3 flex items-center gap-4 border-t border-slate-200">
                  <button className="btn-secondary text-xs" disabled={excPage === 0} onClick={() => setExcPage(p => p - 1)}>← Prev</button>
                  <span className="text-xs text-slate-500">{excPage * 50 + 1}–{Math.min((excPage + 1) * 50, exceptions.total)} of {exceptions.total}</span>
                  <button className="btn-secondary text-xs" disabled={(excPage + 1) * 50 >= exceptions.total} onClick={() => setExcPage(p => p + 1)}>Next →</button>
                </div>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}
