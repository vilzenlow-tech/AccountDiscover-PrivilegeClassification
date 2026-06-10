import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { getAccount, getFindings } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PrivilegeBadge } from '@/components/PrivilegeBadge'
import { PageSpinner } from '@/components/Spinner'
import { PLATFORM_LABELS } from '@/lib/privilege'
import { format } from 'date-fns'

export default function AccountDetail() {
  const { id } = useParams<{ id: string }>()
  const nav = useNavigate()
  const [expandedEnt, setExpandedEnt] = useState<string | null>(null)

  const { data: acc, isLoading } = useQuery({
    queryKey: ['account', id],
    queryFn: () => getAccount(id!).then((r) => r.data),
    enabled: !!id,
  })

  const { data: findings } = useQuery({
    queryKey: ['findings', 'account', id],
    queryFn: () => getFindings({ account_id: id, limit: 20 }).then((r) => r.data),
    enabled: !!id,
  })

  if (isLoading) return <PageSpinner />
  if (!acc) return <div className="p-6 text-slate-400">Account not found.</div>

  const winningFinding = findings?.items.find((f) => f.is_winning)
  const connectorRuleMatch = acc.evidence_summary?.connector_agent_rule_match as {
    rule_key?: string
    classification?: string
    explanation?: string
  } | undefined
  const shownEvidence = compactEvidenceSummary(acc.evidence_summary)

  return (
    <div>
      <PageHeader
        title={acc.account_name}
        subtitle={`${PLATFORM_LABELS[acc.platform]} · ${acc.source_type}`}
        actions={
          <button className="btn-secondary" onClick={() => nav(-1)}>← Back</button>
        }
      />

      <div className="p-6 grid grid-cols-1 xl:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_minmax(22rem,0.95fr)] gap-4">
        {/* Classification card */}
        <div className="card p-4 space-y-3 min-w-0">
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Classification</h2>
          <div><PrivilegeBadge classification={acc.privilege_classification} /></div>
          <div className="text-xs text-slate-500">Confidence: <span className="font-semibold text-slate-700">{acc.privilege_confidence}%</span></div>
          <div className="text-xs text-slate-500">Risk Score: <span className="font-semibold text-slate-700">{acc.risk_score} / 100</span></div>
          {winningFinding && (
            <div className="mt-3 pt-3 border-t border-slate-100 text-xs">
              <div className="font-semibold text-slate-700 mb-1 break-words">Winning Rule: {winningFinding.rule_key}</div>
              <p className="text-slate-500 leading-relaxed">{winningFinding.explanation}</p>
              {!winningFinding.direct && winningFinding.inheritance_path && (
                <div className="mt-2 text-blue-600 font-mono text-[10px] bg-blue-50 px-2 py-1 rounded">
                  Inherited via: {winningFinding.inheritance_path}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Identity card */}
        <div className="card p-4 space-y-2 min-w-0">
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Identity</h2>
          {acc.asset_hostname && (
            <div className="flex items-start justify-between text-xs gap-2">
              <span className="text-slate-500 shrink-0">Asset</span>
              <button className="font-medium text-right text-brand-600 hover:underline" onClick={() => nav(`/assets/${acc.asset_id}`)}>
                {acc.asset_hostname}
              </button>
            </div>
          )}
          <Row label="Platform" value={PLATFORM_LABELS[acc.platform]} />
          <Row label="Principal Type" value={acc.principal_type} />
          <Row label="Auth Source" value={acc.auth_source} />
          <Row label="Enabled Status" value={acc.enabled_status} />
          <Row label="Interactive" value={acc.interactive_status} />
          <Row label="Shared Account" value={acc.is_shared ? 'Yes' : 'No'} alert={acc.is_shared} />
          <Row label="Password Never Expires" value={acc.password_never_expires ? 'Yes' : 'No'} alert={acc.password_never_expires} />
          <Row label="Owner" value={acc.owner ?? '—'} />
          {acc.last_login && (
            <Row label="Last Login" value={format(new Date(acc.last_login), 'dd MMM yyyy HH:mm')} />
          )}
          {!acc.last_login && <Row label="Last Login" value="Unknown / Never" alert />}
        </div>

        {/* Evidence summary */}
        <div className="card p-4 min-w-0">
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Evidence Summary</h2>
          <pre className="text-xs text-slate-600 bg-slate-50 rounded p-3 overflow-auto max-h-48 font-mono">
            {JSON.stringify(shownEvidence, null, 2)}
          </pre>
        </div>

        {/* Entitlements */}
        <div className="card p-4 xl:col-span-2 min-w-0 overflow-hidden">
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
            Entitlements ({acc.entitlements.length})
          </h2>
          <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] table-fixed">
            <colgroup>
              <col className="w-[18%]" />
              <col className="w-[32%]" />
              <col className="w-[16%]" />
              <col className="w-[24%]" />
              <col className="w-[10%]" />
            </colgroup>
            <thead>
              <tr className="border-b border-slate-100 text-left">
                <th className="table-th">Kind</th>
                <th className="table-th">Name</th>
                <th className="table-th">Scope</th>
                <th className="table-th">Source</th>
                <th className="table-th">Inherited</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-50">
              {acc.entitlements.map((e) => (
                <>
                  <tr key={e.id} className="hover:bg-slate-50 cursor-pointer"
                    onClick={() => setExpandedEnt(expandedEnt === e.id ? null : e.id)}>
                    <td className="table-td font-mono text-[11px] text-slate-500 truncate" title={e.kind}>{e.kind}</td>
                    <td className="table-td font-medium break-words" title={e.name}>{e.name}</td>
                    <td className="table-td text-slate-500 truncate" title={e.scope ?? '—'}>{e.scope ?? '—'}</td>
                    <td className="table-td text-slate-400 text-[11px] truncate" title={e.source ?? '—'}>{e.source ?? '—'}</td>
                    <td className="table-td whitespace-nowrap">
                      {e.inherited ? (
                        <span className="badge bg-blue-50 text-blue-600 border border-blue-200">via {e.via}</span>
                      ) : (
                        <span className="badge bg-slate-50 text-slate-500">direct</span>
                      )}
                    </td>
                  </tr>
                  {expandedEnt === e.id && e.attributes && Object.keys(e.attributes).length > 0 && (
                    <tr key={`${e.id}-attrs`}>
                      <td colSpan={5} className="px-3 pb-2">
                        <pre className="text-[10px] font-mono bg-slate-50 rounded p-2 text-slate-600 overflow-auto">
                          {JSON.stringify(e.attributes, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
          </div>
        </div>

        {/* All findings */}
        <div className="card p-4 min-w-0">
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">
            Rule Matches ({findings?.items.length ?? 0})
          </h2>
          <div className="space-y-3">
            {findings?.items.length === 0 && connectorRuleMatch && (
              <div className="rounded border border-sky-200 bg-sky-50 p-3 text-xs">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono font-semibold text-slate-700 break-all">{connectorRuleMatch.rule_key ?? 'connector_agent_rule'}</span>
                  <span className="badge bg-sky-100 text-sky-700 border border-sky-200">from connector</span>
                </div>
                <PrivilegeBadge classification={acc.privilege_classification} size="sm" />
                <p className="mt-1.5 text-slate-600 leading-relaxed">
                  {connectorRuleMatch.explanation ?? 'Classification was evaluated during connector-agent ingestion.'}
                </p>
                <div className="mt-1 text-slate-400">Confidence: {acc.privilege_confidence}% · Risk: {acc.risk_score}</div>
              </div>
            )}
            {findings?.items.map((f) => (
              <div key={f.id} className={`rounded border p-3 text-xs ${f.is_winning ? 'border-orange-300 bg-orange-50' : 'border-slate-200 bg-white'}`}>
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono font-semibold text-slate-700 break-all">{f.rule_key}</span>
                  {f.is_winning && <span className="badge bg-orange-100 text-orange-700 border border-orange-200">winning</span>}
                </div>
                <PrivilegeBadge classification={f.classification} size="sm" />
                <p className="mt-1.5 text-slate-600 leading-relaxed">{f.explanation}</p>
                {!f.direct && f.inheritance_path && (
                  <div className="mt-1 font-mono text-blue-600 text-[10px]">Inherited: {f.inheritance_path}</div>
                )}
                <div className="mt-1 text-slate-400">Confidence: {f.confidence}% · Risk: {f.risk_score}</div>
              </div>
            ))}
            {findings?.items.length === 0 && !connectorRuleMatch && (
              <p className="text-slate-400">
                {acc.privilege_classification === 'non_privileged'
                  ? 'No rule matches — account classified as non-privileged.'
                  : 'No persisted rule-match records for this account yet.'}
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function compactEvidenceSummary(evidence: Record<string, unknown> | null) {
  if (!evidence) return {}
  const copy: Record<string, unknown> = { ...evidence }
  const sid = extractSidValue(copy.sid)
  if (sid) copy.sid = sid
  delete copy.connector_agent_rule_match
  return copy
}

function extractSidValue(value: unknown): string | null {
  if (typeof value === 'string') return value
  if (!value || typeof value !== 'object') return null
  const record = value as Record<string, unknown>
  if (typeof record.Value === 'string') return record.Value
  if (typeof record.value === 'string') return record.value
  return null
}

function Row({ label, value, alert }: { label: string; value: string; alert?: boolean }) {
  return (
    <div className="flex items-start justify-between text-xs gap-2">
      <span className="text-slate-500 shrink-0">{label}</span>
      <span className={`font-medium text-right ${alert ? 'text-red-600' : 'text-slate-800'}`}>{value}</span>
    </div>
  )
}
