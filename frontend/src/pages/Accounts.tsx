import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { getAccounts, exportCsv, exportExcel } from '@/api/endpoints'
import type { PrivilegeClass } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PrivilegeBadge } from '@/components/PrivilegeBadge'
import { PageSpinner } from '@/components/Spinner'
import { PLATFORM_LABELS } from '@/lib/privilege'
import { format } from 'date-fns'
import toast from 'react-hot-toast'

const PAGE_SIZE = 50

const PRIVILEGE_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'All classes' },
  { value: 'full_admin', label: 'Full Admin' },
  { value: 'admin_equivalent', label: 'Admin Equivalent' },
  { value: 'operator_high_impact', label: 'Operator – High Impact' },
  { value: 'delegated_admin', label: 'Delegated Admin' },
  { value: 'privileged_service', label: 'Privileged Service' },
  { value: 'dormant_privileged', label: 'Dormant Privileged' },
  { value: 'unknown_review_required', label: 'Unknown / Review' },
  { value: 'non_privileged', label: 'Non-Privileged' },
]

const INTERACTIVE_OPTIONS: { value: string; label: string }[] = [
  { value: '', label: 'All logon types' },
  { value: 'interactive_capable',    label: 'Interactive Capable' },
  { value: 'non_interactive_only',   label: 'Non-Interactive Only' },
  { value: 'service_or_batch_only',  label: 'Service / Batch Only' },
  { value: 'network_only',           label: 'Network Only' },
  { value: 'interactive',            label: 'Interactive (legacy)' },
  { value: 'non_interactive',        label: 'Non-Interactive (legacy)' },
  { value: 'unknown_review_required', label: 'Review Required' },
  { value: 'unknown',                label: 'Unknown' },
]

export default function Accounts() {
  const [params] = useSearchParams()
  const nav = useNavigate()
  const [page, setPage] = useState(0)
  const [search, setSearch] = useState('')
  const [classification, setClassification] = useState(params.get('classification') ?? '')
  const [platform, setPlatform] = useState('')
  const [interactiveStatus, setInteractiveStatus] = useState('')
  const [onlyPriv, setOnlyPriv] = useState(params.get('only_privileged') === 'true')
  const [onlyShared, setOnlyShared] = useState(params.get('only_shared') === 'true')

  const { data, isLoading } = useQuery({
    queryKey: ['accounts', page, search, classification, platform, interactiveStatus, onlyPriv, onlyShared],
    queryFn: () =>
      getAccounts({
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
        search: search || undefined,
        classification: classification || undefined,
        platform: platform || undefined,
        interactive_status: interactiveStatus || undefined,
        only_privileged: onlyPriv || undefined,
        only_shared: onlyShared || undefined,
      }).then((r) => r.data),
  })

  const handleExportCsv = async () => {
    try {
      const r = await exportCsv(onlyPriv)
      const url = URL.createObjectURL(new Blob([r.data]))
      const a = document.createElement('a')
      a.href = url; a.download = 'accounts.csv'; a.click()
      URL.revokeObjectURL(url)
    } catch { toast.error('Export failed') }
  }

  const handleExportExcel = async () => {
    try {
      const r = await exportExcel(onlyPriv)
      const url = URL.createObjectURL(new Blob([r.data]))
      const a = document.createElement('a')
      a.href = url; a.download = 'accounts.xlsx'; a.click()
      URL.revokeObjectURL(url)
    } catch { toast.error('Export failed') }
  }

  return (
    <div>
      <PageHeader
        title="Accounts"
        subtitle={data ? `${data.total} accounts` : ''}
        actions={
          <>
            <button className="btn-secondary" onClick={handleExportCsv}>CSV</button>
            <button className="btn-secondary" onClick={handleExportExcel}>Excel</button>
          </>
        }
      />

      {/* Filters */}
      <div className="px-6 py-3 border-b border-slate-200 bg-white flex flex-wrap gap-3">
        <input className="input w-56" placeholder="Search account name…" value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(0) }} />
        <select className="input w-52" value={classification} onChange={(e) => { setClassification(e.target.value); setPage(0) }}>
          {PRIVILEGE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <select className="input w-40" value={platform} onChange={(e) => { setPlatform(e.target.value); setPage(0) }}>
          <option value="">All platforms</option>
          {Object.entries(PLATFORM_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <select className="input w-48" value={interactiveStatus} onChange={(e) => { setInteractiveStatus(e.target.value); setPage(0) }}>
          {INTERACTIVE_OPTIONS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
        <label className="flex items-center gap-2 text-sm cursor-pointer">
          <input type="checkbox" checked={onlyPriv} onChange={(e) => { setOnlyPriv(e.target.checked); setPage(0) }} />
          Privileged only
        </label>
        <label className="flex items-center gap-2 text-sm cursor-pointer">
          <input type="checkbox" checked={onlyShared} onChange={(e) => { setOnlyShared(e.target.checked); setPage(0) }} />
          Shared only
        </label>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        {isLoading ? <PageSpinner /> : (
          <table className="w-full">
            <thead className="bg-slate-50 border-b border-slate-200 sticky top-0">
              <tr>
                <th className="table-th">Account</th>
                <th className="table-th">Platform</th>
                <th className="table-th">Asset</th>
                <th className="table-th">Classification</th>
                <th className="table-th">Risk</th>
                <th className="table-th">Type</th>
                <th className="table-th">Status / Logon</th>
                <th className="table-th">Last Login</th>
                <th className="table-th">Discovered</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data?.items.map((acc) => (
                <tr key={acc.id} className="hover:bg-slate-50 cursor-pointer transition-colors"
                  onClick={() => nav(`/accounts/${acc.id}`)}>
                  <td className="table-td">
                    <div className="flex items-center gap-2">
                      <div className="font-medium text-slate-900">{acc.account_name}</div>
                      {acc.is_shared && (
                        <span className="badge bg-purple-100 text-purple-700 text-xs font-medium">Shared</span>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <span className="text-[10px] text-slate-400">{acc.asset_hostname ?? acc.source_type}</span>
                      <AuthSourceBadge authSource={acc.auth_source} />
                    </div>
                  </td>
                  <td className="table-td">
                    <span className="badge bg-slate-100 text-slate-600">{PLATFORM_LABELS[acc.platform]}</span>
                  </td>
                  <td className="table-td text-slate-500">{acc.asset_hostname ?? '—'}</td>
                  <td className="table-td">
                    <PrivilegeBadge classification={acc.privilege_classification} size="sm" />
                  </td>
                  <td className="table-td">
                    <RiskBar value={acc.risk_score} />
                  </td>
                  <td className="table-td text-slate-500">{acc.principal_type}</td>
                  <td className="table-td">
                    <div className="flex flex-col gap-1">
                      <span className={`badge ${acc.enabled_status === 'enabled' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'}`}>
                        {acc.enabled_status}
                      </span>
                      <InteractiveStatusBadge status={acc.interactive_status} />
                    </div>
                  </td>
                  <td className="table-td text-slate-500">
                    {acc.last_login ? format(new Date(acc.last_login), 'dd MMM yy') : <span className="text-slate-300">—</span>}
                  </td>
                  <td className="table-td text-slate-400">
                    {format(new Date(acc.discovered_at), 'dd MMM yy')}
                  </td>
                </tr>
              ))}
              {data?.items.length === 0 && (
                <tr><td colSpan={9} className="py-12 text-center text-slate-400">No accounts found.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination */}
      {data && data.total > PAGE_SIZE && (
        <div className="flex items-center gap-3 px-6 py-3 border-t border-slate-200 bg-white text-sm">
          <button className="btn-secondary" onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}>← Prev</button>
          <span className="text-slate-500">Page {page + 1} of {Math.ceil(data.total / PAGE_SIZE)}</span>
          <button className="btn-secondary" onClick={() => setPage((p) => p + 1)} disabled={(page + 1) * PAGE_SIZE >= data.total}>Next →</button>
        </div>
      )}
    </div>
  )
}

const AUTH_SOURCE_LABELS: Record<string, { label: string; cls: string }> = {
  local:  { label: 'Local',  cls: 'bg-slate-100 text-slate-500' },
  ad:     { label: 'Domain', cls: 'bg-blue-100 text-blue-600' },
  ldap:   { label: 'LDAP',   cls: 'bg-indigo-100 text-indigo-600' },
  db:     { label: 'DB',     cls: 'bg-amber-100 text-amber-600' },
  system: { label: 'System', cls: 'bg-purple-100 text-purple-600' },
}

function AuthSourceBadge({ authSource }: { authSource: string }) {
  const meta = AUTH_SOURCE_LABELS[authSource]
  if (!meta) return null
  return <span className={`inline-flex items-center px-1.5 py-0 rounded text-[9px] font-semibold ${meta.cls}`}>{meta.label}</span>
}

const INTERACTIVE_STATUS_META: Record<string, { label: string; cls: string }> = {
  interactive:             { label: 'Interactive',      cls: 'bg-blue-100 text-blue-700' },
  interactive_capable:     { label: 'Interactive',      cls: 'bg-blue-100 text-blue-700' },
  non_interactive:         { label: 'Non-Interactive',  cls: 'bg-slate-100 text-slate-500' },
  non_interactive_only:    { label: 'Non-Interactive',  cls: 'bg-slate-100 text-slate-500' },
  service_or_batch_only:   { label: 'Svc/Batch',        cls: 'bg-purple-100 text-purple-600' },
  network_only:            { label: 'Network Only',     cls: 'bg-amber-100 text-amber-700' },
  unknown_review_required: { label: 'Review Reqd',      cls: 'bg-orange-100 text-orange-600' },
  unknown:                 { label: 'Unknown',           cls: 'bg-slate-50 text-slate-400' },
}

function InteractiveStatusBadge({ status }: { status: string }) {
  const meta = INTERACTIVE_STATUS_META[status]
  if (!meta || status === 'unknown') return null
  return <span className={`inline-flex items-center px-1.5 py-0 rounded text-[9px] font-semibold ${meta.cls}`}>{meta.label}</span>
}

function RiskBar({ value }: { value: number }) {
  const color = value >= 80 ? 'bg-red-500' : value >= 60 ? 'bg-orange-400' : value >= 40 ? 'bg-amber-400' : 'bg-green-400'
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-16 bg-slate-100 rounded-full h-1.5 overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${value}%` }} />
      </div>
      <span className="text-xs text-slate-500">{value}</span>
    </div>
  )
}
