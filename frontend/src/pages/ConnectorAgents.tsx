import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  getConnectorAgents, createConnectorAgent, generateEnrollmentToken,
  approveConnectorAgent, revokeConnectorAgent, disableConnectorAgent, enableConnectorAgent,
} from '@/api/endpoints'
import type { ConnectorAgentOut, ConnectorAgentStatus } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PageSpinner } from '@/components/Spinner'
import { format, formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import clsx from 'clsx'

// ── Status badge ──────────────────────────────────────────────────────────────
const STATUS_STYLES: Record<ConnectorAgentStatus, string> = {
  online:   'bg-green-100 text-green-700',
  approved: 'bg-blue-100 text-blue-700',
  pending:  'bg-amber-100 text-amber-700',
  stale:    'bg-yellow-100 text-yellow-700',
  offline:  'bg-slate-100 text-slate-500',
  disabled: 'bg-slate-100 text-slate-400',
  revoked:  'bg-red-100 text-red-600',
  error:    'bg-red-100 text-red-700',
}
const STATUS_DOT: Record<ConnectorAgentStatus, string> = {
  online: 'bg-green-500 animate-pulse', approved: 'bg-blue-400',
  pending: 'bg-amber-400', stale: 'bg-yellow-400',
  offline: 'bg-slate-400', disabled: 'bg-slate-300',
  revoked: 'bg-red-500', error: 'bg-red-500',
}

export function AgentStatusBadge({ status }: { status: ConnectorAgentStatus }) {
  return (
    <span className={clsx('inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium', STATUS_STYLES[status])}>
      <span className={clsx('w-1.5 h-1.5 rounded-full', STATUS_DOT[status])} />
      {status}
    </span>
  )
}

// ── Enroll token modal ────────────────────────────────────────────────────────
function EnrollTokenModal({ onClose }: { onClose: () => void }) {
  const [form, setForm] = useState({ expected_hostname: '', expected_site: '', expected_environment: '', auto_approve: false, expires_in_seconds: 86400 })
  const [result, setResult] = useState<{ token: string; token_prefix: string; expires_at: string } | null>(null)
  const [copied, setCopied] = useState(false)

  const genMut = useMutation({
    mutationFn: () => generateEnrollmentToken({
      expected_hostname: form.expected_hostname || undefined,
      expected_site: form.expected_site || undefined,
      expected_environment: form.expected_environment || undefined,
      auto_approve: form.auto_approve,
      expires_in_seconds: form.expires_in_seconds,
    }),
    onSuccess: (r) => setResult(r.data),
    onError: () => toast.error('Failed to generate token'),
  })

  const copyToken = () => {
    if (result) { navigator.clipboard.writeText(result.token); setCopied(true); setTimeout(() => setCopied(false), 2000) }
  }

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-slate-900">Generate Enrollment Token</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
        </div>
        {!result ? (
          <div className="space-y-3">
            <p className="text-sm text-slate-500">Generate a one-time token to enroll a new connector agent. Share it securely with the operator deploying the agent.</p>
            <div><label className="label">Expected Hostname (optional)</label>
              <input className="input" placeholder="e.g. jump-srv-01.corp.internal" value={form.expected_hostname} onChange={e => setForm({...form, expected_hostname: e.target.value})} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div><label className="label">Site</label>
                <input className="input" placeholder="e.g. HQ" value={form.expected_site} onChange={e => setForm({...form, expected_site: e.target.value})} />
              </div>
              <div><label className="label">Environment</label>
                <input className="input" placeholder="e.g. production" value={form.expected_environment} onChange={e => setForm({...form, expected_environment: e.target.value})} />
              </div>
            </div>
            <div><label className="label">Token expiry</label>
              <select className="input" value={form.expires_in_seconds} onChange={e => setForm({...form, expires_in_seconds: Number(e.target.value)})}>
                <option value={3600}>1 hour</option>
                <option value={86400}>24 hours</option>
                <option value={604800}>7 days</option>
              </select>
            </div>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input type="checkbox" checked={form.auto_approve} onChange={e => setForm({...form, auto_approve: e.target.checked})} />
              <span>Auto-approve (agent starts immediately without manual approval)</span>
            </label>
            {form.auto_approve && (
              <div className="flex items-start gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-700">
                <span className="text-base">⚠</span>
                <span>Auto-approve skips the admin approval step. Only use in trusted environments.</span>
              </div>
            )}
            <div className="flex gap-2 pt-2">
              <button className="btn-primary" onClick={() => genMut.mutate()} disabled={genMut.isPending}>Generate Token</button>
              <button className="btn-secondary" onClick={onClose}>Cancel</button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center gap-2 p-3 bg-green-50 border border-green-200 rounded-lg text-sm text-green-700">
              <span className="text-base">✓</span>
              <span>Token generated successfully. Share it securely — it will not be shown again.</span>
            </div>
            <div>
              <label className="label">Enrollment Token</label>
              <div className="flex gap-2">
                <input className="input font-mono text-xs flex-1" readOnly value={result.token} />
                <button className={clsx('btn-secondary text-xs', copied && 'bg-green-100 text-green-700')} onClick={copyToken}>
                  {copied ? '✓ Copied' : 'Copy'}
                </button>
              </div>
              <p className="text-xs text-slate-400 mt-1">Expires: {format(new Date(result.expires_at), 'dd MMM yyyy HH:mm')}</p>
            </div>
            <div className="p-3 bg-slate-50 rounded-lg text-xs font-mono text-slate-600">
              <p className="font-semibold text-slate-700 mb-2 font-sans">Deploy agent with:</p>
              <p>CONSOLE_URL=https://your-console.internal</p>
              <p>REGISTRATION_TOKEN={result.token_prefix}…</p>
              <p>./adpct-agent --register</p>
            </div>
            <button className="btn-primary w-full" onClick={onClose}>Done</button>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Revoke modal ──────────────────────────────────────────────────────────────
function RevokeModal({ agent, onClose }: { agent: ConnectorAgentOut; onClose: () => void }) {
  const [reason, setReason] = useState('')
  const qc = useQueryClient()
  const revokeMut = useMutation({
    mutationFn: () => revokeConnectorAgent(agent.id, reason),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['connector-agents'] }); toast.success('Connector revoked'); onClose() },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Revocation failed'),
  })
  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-md p-6">
        <h2 className="font-semibold text-slate-900 mb-2">Revoke Connector</h2>
        <p className="text-sm text-slate-500 mb-4">Revoking <strong>{agent.name}</strong> is permanent. The connector's token will be immediately invalidated and all pending jobs cancelled.</p>
        <div className="mb-4">
          <label className="label">Reason <span className="text-red-500">*</span></label>
          <textarea className="input" rows={3} placeholder="e.g. Compromised host, decommissioned..." value={reason} onChange={e => setReason(e.target.value)} />
        </div>
        <div className="flex gap-2">
          <button className="btn text-xs py-1.5 px-4 bg-red-600 text-white rounded-lg hover:bg-red-700" onClick={() => revokeMut.mutate()} disabled={!reason.trim() || revokeMut.isPending}>Revoke</button>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  )
}

// ── Create modal ──────────────────────────────────────────────────────────────
function CreateAgentModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const [form, setForm] = useState({ name: '', description: '', site: '', location: '', environment: '' })
  const createMut = useMutation({
    mutationFn: () => createConnectorAgent({ name: form.name, description: form.description || undefined, site: form.site || undefined, location: form.location || undefined, environment: form.environment || undefined }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['connector-agents'] }); toast.success('Connector created'); onClose() },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Failed to create'),
  })
  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-md p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-slate-900">Register Connector Agent</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
        </div>
        <div className="space-y-3">
          <div><label className="label">Name <span className="text-red-500">*</span></label>
            <input className="input" placeholder="e.g. connector-prod-01" value={form.name} onChange={e => setForm({...form, name: e.target.value})} />
          </div>
          <div><label className="label">Description</label>
            <input className="input" placeholder="Optional" value={form.description} onChange={e => setForm({...form, description: e.target.value})} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div><label className="label">Site</label>
              <input className="input" placeholder="e.g. HQ" value={form.site} onChange={e => setForm({...form, site: e.target.value})} />
            </div>
            <div><label className="label">Environment</label>
              <input className="input" placeholder="e.g. production" value={form.environment} onChange={e => setForm({...form, environment: e.target.value})} />
            </div>
          </div>
          <div className="flex gap-2 pt-2">
            <button className="btn-primary" onClick={() => createMut.mutate()} disabled={!form.name.trim() || createMut.isPending}>Create</button>
            <button className="btn-secondary" onClick={onClose}>Cancel</button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function ConnectorAgents() {
  const nav = useNavigate()
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [showEnroll, setShowEnroll] = useState(false)
  const [showCreate, setShowCreate] = useState(false)
  const [revokeTarget, setRevokeTarget] = useState<ConnectorAgentOut | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['connector-agents', search],
    queryFn: () => getConnectorAgents({ search: search || undefined, limit: 100 }).then(r => r.data),
    refetchInterval: 15_000,
  })

  const approveMut = useMutation({
    mutationFn: (id: string) => approveConnectorAgent(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['connector-agents'] }); toast.success('Connector approved') },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Approval failed'),
  })
  const toggleMut = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      enabled ? enableConnectorAgent(id) : disableConnectorAgent(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['connector-agents'] }),
    onError: () => toast.error('Toggle failed'),
  })

  const pendingCount = data?.items.filter(a => a.status === 'pending').length ?? 0

  return (
    <div>
      <PageHeader
        title="Connector Agents"
        subtitle={data ? `${data.total} connector${data.total !== 1 ? 's' : ''}` : ''}
        actions={
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={() => setShowEnroll(true)}>⊞ Enrollment Token</button>
            <button className="btn-primary" onClick={() => setShowCreate(true)}>+ Register</button>
          </div>
        }
      />

      {pendingCount > 0 && (
        <div className="mx-6 mt-4 p-3 bg-amber-50 border border-amber-200 rounded-lg flex items-center gap-3 text-sm">
          <span className="text-amber-600 font-medium">⏳ {pendingCount} connector{pendingCount > 1 ? 's' : ''} awaiting approval</span>
          <span className="text-amber-500">—</span>
          <span className="text-amber-600">Review and approve below</span>
        </div>
      )}

      <div className="px-6 py-3 border-b border-slate-200 bg-white flex gap-3">
        <input className="input w-64" placeholder="Search connectors…" value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {isLoading ? <PageSpinner /> : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                <th className="table-th">Connector</th>
                <th className="table-th">Status</th>
                <th className="table-th">Platform</th>
                <th className="table-th">Site / Environment</th>
                <th className="table-th">Version</th>
                <th className="table-th">Last Seen</th>
                <th className="table-th">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data?.items.map((agent) => (
                <tr key={agent.id} className="hover:bg-slate-50 transition-colors">
                  <td className="table-td">
                    <div className="font-medium text-slate-900 cursor-pointer hover:text-brand-600" onClick={() => nav(`/connector-agents/${agent.id}`)}>
                      {agent.name}
                    </div>
                    {agent.hostname && <div className="text-xs text-slate-400 font-mono">{agent.hostname}</div>}
                    {agent.description && <div className="text-xs text-slate-400">{agent.description}</div>}
                  </td>
                  <td className="table-td"><AgentStatusBadge status={agent.status} /></td>
                  <td className="table-td text-slate-500 text-sm">{agent.os_platform ?? '—'}</td>
                  <td className="table-td text-slate-500 text-sm">
                    <div>{agent.site ?? '—'}</div>
                    {agent.environment && <div className="text-xs text-slate-400">{agent.environment}</div>}
                  </td>
                  <td className="table-td text-slate-500 text-xs font-mono">{agent.agent_version ?? '—'}</td>
                  <td className="table-td text-slate-500 text-xs">
                    {agent.last_seen_at
                      ? formatDistanceToNow(new Date(agent.last_seen_at), { addSuffix: true })
                      : <span className="text-slate-300">Never</span>}
                  </td>
                  <td className="table-td">
                    <div className="flex gap-1.5 flex-wrap">
                      <button className="btn-secondary text-xs py-1" onClick={() => nav(`/connector-agents/${agent.id}`)}>Details</button>
                      {agent.status === 'pending' && (
                        <button className="btn text-xs py-1 bg-green-600 text-white hover:bg-green-700 rounded-lg px-2" onClick={() => approveMut.mutate(agent.id)} disabled={approveMut.isPending}>Approve</button>
                      )}
                      {agent.status !== 'revoked' && (
                        <button
                          className="btn-secondary text-xs py-1"
                          onClick={() => toggleMut.mutate({ id: agent.id, enabled: !agent.is_enabled })}
                        >
                          {agent.is_enabled ? 'Disable' : 'Enable'}
                        </button>
                      )}
                      {agent.status !== 'revoked' && (
                        <button className="btn text-xs py-1 text-red-600 hover:bg-red-50 border border-red-200 rounded-lg px-2" onClick={() => setRevokeTarget(agent)}>Revoke</button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
              {data?.items.length === 0 && (
                <tr><td colSpan={7} className="py-16 text-center">
                  <div className="text-slate-400 text-sm">No connector agents registered yet.</div>
                  <div className="text-slate-400 text-xs mt-1">Click "Enrollment Token" to generate a token and deploy your first agent.</div>
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {showEnroll && <EnrollTokenModal onClose={() => setShowEnroll(false)} />}
      {showCreate && <CreateAgentModal onClose={() => setShowCreate(false)} />}
      {revokeTarget && <RevokeModal agent={revokeTarget} onClose={() => setRevokeTarget(null)} />}
    </div>
  )
}
