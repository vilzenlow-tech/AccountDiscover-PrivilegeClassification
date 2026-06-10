import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  getConnectorAgent, getConnectorAgentJobs, getConnectorHeartbeats, getConnectorLogs,
  getConnectorAgentSettings, updateConnectorAgentSettings,
  dispatchConnectorJob, cancelConnectorJob, rotateConnectorToken,
  approveConnectorAgent, disableConnectorAgent, enableConnectorAgent,
} from '@/api/endpoints'
import type { ConnectorAgentSettings } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PageSpinner } from '@/components/Spinner'
import { AgentStatusBadge } from './ConnectorAgents'
import { format, formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import clsx from 'clsx'

type Tab = 'overview' | 'jobs' | 'settings' | 'logs'

const JOB_STATUS_COLORS: Record<string, string> = {
  pending: 'bg-slate-100 text-slate-600',
  accepted: 'bg-blue-100 text-blue-700',
  running: 'bg-amber-100 text-amber-700',
  success: 'bg-green-100 text-green-700',
  partial_success: 'bg-yellow-100 text-yellow-700',
  failed: 'bg-red-100 text-red-700',
  cancelled: 'bg-slate-100 text-slate-400',
  timed_out: 'bg-orange-100 text-orange-700',
}

// ── DispatchJobModal ──────────────────────────────────────────────────────────
function DispatchJobModal({ agentId, onClose }: { agentId: string; onClose: () => void }) {
  const qc = useQueryClient()
  const [jobType, setJobType] = useState('on_demand')
  const [scanMode, setScanMode] = useState('safe')
  const [scanProfile, setScanProfile] = useState('standard')
  const [platform, setPlatform] = useState('windows')
  const [targets, setTargets] = useState('')   // comma-separated hostnames
  const [username, setUsername] = useState('')
  const [secret, setSecret] = useState('')
  const [winrmScheme, setWinrmScheme] = useState('http')
  const [winrmTransport, setWinrmTransport] = useState('ntlm')

  const dispatchMut = useMutation({
    mutationFn: () => dispatchConnectorJob(agentId, {
      job_type: jobType as any,
      payload: {
        scan_mode: scanMode,
        scan_profile: scanProfile,
        targets: targets.split(',').map(t => t.trim()).filter(Boolean).map(h => ({ hostname: h, platform })),
        ...(jobType === 'discovery_credentialed' && username && secret ? {
          credential: { username, secret, auth_method: 'password' },
        } : {}),
        ...(platform === 'windows' ? {
          options: {
            winrm_scheme: winrmScheme,
            winrm_transport: winrmTransport,
            winrm_cert_validation: 'ignore',
          },
        } : {}),
      },
      priority: 50,
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['connector-jobs', agentId] }); toast.success('Job dispatched'); onClose() },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Dispatch failed'),
  })

  return (
    <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-md p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-slate-900">Dispatch Scan Job</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
        </div>
        <div className="space-y-3">
          <div><label className="label">Job Type</label>
            <select className="input" value={jobType} onChange={e => setJobType(e.target.value)}>
              <option value="on_demand">On-Demand Discovery</option>
              <option value="discovery_basic">Basic Discovery (no creds)</option>
              <option value="discovery_credentialed">Credentialed Discovery</option>
              <option value="health_check">Health Check</option>
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div><label className="label">Scan Mode</label>
              <select className="input" value={scanMode} onChange={e => setScanMode(e.target.value)}>
                <option value="safe">Safe</option>
                <option value="deep">Deep</option>
              </select>
            </div>
            <div><label className="label">Scan Profile</label>
              <select className="input" value={scanProfile} onChange={e => setScanProfile(e.target.value)}>
                <option value="standard">Standard</option>
                <option value="fast">Fast</option>
                <option value="full">Full</option>
              </select>
            </div>
          </div>
          <div><label className="label">Platform</label>
            <select className="input" value={platform} onChange={e => setPlatform(e.target.value)}>
              <option value="windows">Windows</option>
              <option value="rhel">RHEL / Linux</option>
              <option value="ubuntu">Ubuntu</option>
              <option value="mssql">Microsoft SQL Server</option>
              <option value="mysql">MySQL</option>
              <option value="postgresql">PostgreSQL</option>
            </select>
          </div>
          {platform === 'windows' && (
            <div className="grid grid-cols-2 gap-3">
              <div><label className="label">WinRM Scheme</label>
                <select className="input" value={winrmScheme} onChange={e => setWinrmScheme(e.target.value)}>
                  <option value="http">HTTP :5985</option>
                  <option value="https">HTTPS :5986</option>
                </select>
              </div>
              <div><label className="label">WinRM Auth</label>
                <select className="input" value={winrmTransport} onChange={e => setWinrmTransport(e.target.value)}>
                  <option value="ntlm">NTLM</option>
                  <option value="basic">Basic</option>
                  <option value="kerberos">Kerberos</option>
                  <option value="credssp">CredSSP</option>
                </select>
              </div>
            </div>
          )}
          {jobType === 'discovery_credentialed' && (
            <div className="grid grid-cols-2 gap-3">
              <div><label className="label">Username</label>
                <input className="input font-mono text-xs" value={username} onChange={e => setUsername(e.target.value)}
                  placeholder="DOMAIN\\user or Administrator" />
              </div>
              <div><label className="label">Password</label>
                <input className="input font-mono text-xs" type="password" value={secret} onChange={e => setSecret(e.target.value)} />
              </div>
            </div>
          )}
          <div><label className="label">Target Hostnames (comma-separated)</label>
            <textarea className="input font-mono text-xs" rows={3}
              placeholder="server-01.corp, server-02.corp"
              value={targets} onChange={e => setTargets(e.target.value)} />
          </div>
          <div className="flex gap-2 pt-2">
            <button className="btn-primary" onClick={() => dispatchMut.mutate()} disabled={dispatchMut.isPending}>Dispatch</button>
            <button className="btn-secondary" onClick={onClose}>Cancel</button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── SettingsPanel ─────────────────────────────────────────────────────────────
function SettingsPanel({ agentId }: { agentId: string }) {
  const qc = useQueryClient()
  const { data: settings, isLoading } = useQuery({
    queryKey: ['connector-settings', agentId],
    queryFn: () => getConnectorAgentSettings(agentId).then(r => r.data),
  })
  const [form, setForm] = useState<Partial<ConnectorAgentSettings> | null>(null)

  const saveMut = useMutation({
    mutationFn: (d: Partial<ConnectorAgentSettings>) => updateConnectorAgentSettings(agentId, d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['connector-settings', agentId] }); setForm(null); toast.success('Settings saved') },
    onError: () => toast.error('Failed to save settings'),
  })

  if (isLoading) return <PageSpinner />
  if (!settings) return <div className="p-6 text-slate-400">No settings configured.</div>

  const s = form ?? settings

  const SF = ({ label, field, type = 'number', min, max }: { label: string; field: keyof ConnectorAgentSettings; type?: string; min?: number; max?: number }) => (
    <div>
      <label className="label">{label}</label>
      <input type={type} className="input" min={min} max={max}
        value={s[field] as any ?? ''}
        onChange={e => setForm({ ...s, [field]: type === 'number' ? Number(e.target.value) : e.target.value })} />
    </div>
  )

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-slate-700">Console-Managed Settings</h3>
        <div className="flex gap-2">
          {form && <button className="btn-primary text-xs py-1.5" onClick={() => saveMut.mutate(form)} disabled={saveMut.isPending}>Save</button>}
          {form && <button className="btn-secondary text-xs py-1.5" onClick={() => setForm(null)}>Discard</button>}
          {!form && <button className="btn-secondary text-xs py-1.5" onClick={() => setForm({ ...settings })}>Edit</button>}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Polling */}
        <div className="card p-4 space-y-3">
          <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Polling Intervals</h4>
          <SF label="Heartbeat Interval (s)" field="heartbeat_interval_seconds" min={5} max={300} />
          <SF label="Job Poll Interval (s)" field="job_poll_interval_seconds" min={5} max={300} />
          <SF label="Config Refresh (s)" field="config_refresh_interval_seconds" min={60} />
        </div>

        {/* Execution */}
        <div className="card p-4 space-y-3">
          <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Execution</h4>
          <SF label="Job Timeout (s)" field="job_timeout_seconds" min={60} max={86400} />
          <SF label="Max Concurrent Jobs" field="max_concurrent_jobs" min={1} max={20} />
          <SF label="Result Chunk Size (MB)" field="result_chunk_size_mb" min={1} max={500} />
        </div>

        {/* Retry */}
        <div className="card p-4 space-y-3">
          <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Retry</h4>
          <SF label="Max Retry Attempts" field="retry_max_attempts" min={1} max={20} />
          <SF label="Backoff Base (s)" field="retry_backoff_base_seconds" min={1} max={30} />
          <SF label="Backoff Max (s)" field="retry_backoff_max_seconds" min={30} max={3600} />
        </div>

        {/* Storage */}
        <div className="card p-4 space-y-3">
          <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Storage</h4>
          <SF label="Offline Queue Max (MB)" field="offline_queue_max_mb" min={50} max={10000} />
          <SF label="Result Retention (hrs)" field="result_retention_hours" min={1} max={720} />
          <SF label="Log Retention (days)" field="log_retention_days" min={1} max={365} />
        </div>

        {/* Security */}
        <div className="card p-4 space-y-3">
          <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Security</h4>
          <SF label="Token Rotation (days)" field="token_rotation_days" min={7} max={365} />
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={!!s.verify_console_certificate}
              onChange={e => setForm({ ...s, verify_console_certificate: e.target.checked })} />
            Verify TLS Certificate
          </label>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={!!s.sanitize_secrets_in_logs}
              onChange={e => setForm({ ...s, sanitize_secrets_in_logs: e.target.checked })} />
            Sanitize Secrets in Logs
          </label>
        </div>

        {/* Logging & Scope */}
        <div className="card p-4 space-y-3">
          <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Logging & Scope</h4>
          <div><label className="label">Log Level</label>
            <select className="input" value={s.log_level ?? 'info'} onChange={e => setForm({ ...s, log_level: e.target.value })}>
              {['debug', 'info', 'warning', 'error'].map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <SF label="Max Targets/Job" field="max_targets_per_job" min={1} max={10000} />
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={!!s.auto_upgrade}
              onChange={e => setForm({ ...s, auto_upgrade: e.target.checked })} />
            Auto Upgrade
          </label>
        </div>
      </div>
    </div>
  )
}

// ── Main Detail ───────────────────────────────────────────────────────────────
export default function ConnectorAgentDetail() {
  const { id } = useParams<{ id: string }>()
  const nav = useNavigate()
  const qc = useQueryClient()
  const [tab, setTab] = useState<Tab>('overview')
  const [showDispatch, setShowDispatch] = useState(false)
  const [newToken, setNewToken] = useState<string | null>(null)

  const { data: agent, isLoading } = useQuery({
    queryKey: ['connector-agent', id],
    queryFn: () => getConnectorAgent(id!).then(r => r.data),
    enabled: !!id,
    refetchInterval: 15_000,
  })

  const { data: jobsData } = useQuery({
    queryKey: ['connector-jobs', id],
    queryFn: () => getConnectorAgentJobs(id!, { limit: 50 }).then(r => r.data),
    enabled: !!id && tab === 'jobs',
    refetchInterval: 10_000,
  })

  const { data: heartbeats } = useQuery({
    queryKey: ['connector-heartbeats', id],
    queryFn: () => getConnectorHeartbeats(id!).then(r => r.data),
    enabled: !!id && tab === 'overview',
    refetchInterval: 15_000,
  })

  const { data: logs } = useQuery({
    queryKey: ['connector-logs', id],
    queryFn: () => getConnectorLogs(id!, { limit: 100 }).then(r => r.data),
    enabled: !!id && tab === 'logs',
  })

  const approveMut = useMutation({
    mutationFn: () => approveConnectorAgent(id!),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['connector-agent', id] }); toast.success('Approved') },
  })
  const toggleMut = useMutation({
    mutationFn: (enable: boolean) => enable ? enableConnectorAgent(id!) : disableConnectorAgent(id!),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['connector-agent', id] }),
    onError: () => toast.error('Toggle failed'),
  })
  const cancelJobMut = useMutation({
    mutationFn: (jobId: string) => cancelConnectorJob(id!, jobId),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['connector-jobs', id] }); toast.success('Job cancelled') },
  })
  const rotateMut = useMutation({
    mutationFn: () => rotateConnectorToken(id!),
    onSuccess: (r) => { setNewToken(r.data.token); toast.success('Token rotated') },
    onError: () => toast.error('Token rotation failed'),
  })

  if (isLoading) return <PageSpinner />
  if (!agent) return <div className="p-6 text-slate-400">Connector not found.</div>

  const TABS: { id: Tab; label: string }[] = [
    { id: 'overview', label: 'Overview & Health' },
    { id: 'jobs', label: 'Jobs' },
    { id: 'settings', label: 'Settings' },
    { id: 'logs', label: 'Logs' },
  ]

  return (
    <div>
      <PageHeader
        title={agent.name}
        subtitle={agent.hostname ?? 'Connector Agent'}
        actions={
          <div className="flex gap-2 flex-wrap">
            {agent.status === 'pending' && (
              <button className="btn text-xs py-1.5 px-3 bg-green-600 text-white rounded-lg hover:bg-green-700" onClick={() => approveMut.mutate()}>Approve</button>
            )}
            {agent.status !== 'revoked' && (
              <button className="btn-secondary text-xs py-1.5" onClick={() => toggleMut.mutate(!agent.is_enabled)}>
                {agent.is_enabled ? 'Disable' : 'Enable'}
              </button>
            )}
            <button className="btn-secondary text-xs py-1.5" onClick={() => setShowDispatch(true)}>+ Dispatch Job</button>
            <button className="btn-secondary text-xs py-1.5" onClick={() => { if (confirm('Rotate token?')) rotateMut.mutate() }}>Rotate Token</button>
            <button className="btn-secondary text-xs py-1.5" onClick={() => nav('/connector-agents')}>← Back</button>
          </div>
        }
      />

      {/* New token alert */}
      {newToken && (
        <div className="mx-6 mt-4 p-3 bg-green-50 border border-green-200 rounded-lg flex items-center gap-3 text-sm">
          <span className="text-green-700 font-medium">New token:</span>
          <code className="font-mono text-xs bg-green-100 px-2 py-0.5 rounded flex-1 select-all">{newToken}</code>
          <button className="text-xs text-green-600 hover:text-green-800" onClick={() => setNewToken(null)}>Dismiss</button>
        </div>
      )}

      {/* Tabs */}
      <div className="px-6 border-b border-slate-200 bg-white flex gap-0 mt-2">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={clsx('px-4 py-3 text-sm font-medium border-b-2 transition-colors',
              tab === t.id ? 'border-brand-600 text-brand-600' : 'border-transparent text-slate-500 hover:text-slate-700')}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Overview tab ─────────────────────────────────────────────────── */}
      {tab === 'overview' && (
        <div className="p-6 grid grid-cols-1 xl:grid-cols-3 gap-4">
          {/* Identity */}
          <div className="card p-4 space-y-3">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Identity</h3>
            <InfoRow label="Status"><AgentStatusBadge status={agent.status} /></InfoRow>
            <InfoRow label="Enabled">{agent.is_enabled ? '✓ Yes' : '✗ No'}</InfoRow>
            <InfoRow label="Connector ID"><code className="font-mono text-xs">{agent.id}</code></InfoRow>
            <InfoRow label="Token Prefix"><code className="font-mono text-xs">{agent.token_prefix ?? '—'}</code></InfoRow>
            <InfoRow label="Hostname">{agent.hostname ?? '—'}</InfoRow>
            <InfoRow label="IP Address">{agent.ip_address ?? '—'}</InfoRow>
            <InfoRow label="Platform">{agent.os_platform ?? '—'} {agent.os_version ? `(${agent.os_version})` : ''}</InfoRow>
            <InfoRow label="Agent Version"><code className="font-mono text-xs">{agent.agent_version ?? '—'}</code></InfoRow>
          </div>

          {/* Location & timestamps */}
          <div className="card p-4 space-y-3">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Location</h3>
            <InfoRow label="Site">{agent.site ?? '—'}</InfoRow>
            <InfoRow label="Location">{agent.location ?? '—'}</InfoRow>
            <InfoRow label="Environment">{agent.environment ?? '—'}</InfoRow>
            <div className="border-t border-slate-100 pt-3 mt-3 space-y-3">
              <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Activity</h3>
              <InfoRow label="Last Seen">
                {agent.last_seen_at ? formatDistanceToNow(new Date(agent.last_seen_at), { addSuffix: true }) : <span className="text-slate-300">Never</span>}
              </InfoRow>
              <InfoRow label="Last Heartbeat">
                {agent.last_heartbeat_at ? format(new Date(agent.last_heartbeat_at), 'dd MMM yyyy HH:mm:ss') : '—'}
              </InfoRow>
              <InfoRow label="Approved By">{agent.approved_by ?? '—'}</InfoRow>
              <InfoRow label="Approved At">
                {agent.approved_at ? format(new Date(agent.approved_at), 'dd MMM yyyy HH:mm') : '—'}
              </InfoRow>
            </div>
          </div>

          {/* Last heartbeats */}
          <div className="card p-4">
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-3">Recent Heartbeats</h3>
            {!heartbeats?.length ? (
              <p className="text-sm text-slate-400">No heartbeats received yet.</p>
            ) : (
              <div className="space-y-2">
                {heartbeats.slice(0, 8).map((hb: any) => (
                  <div key={hb.id} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className={clsx('w-2 h-2 rounded-full', hb.error_count > 0 ? 'bg-red-400' : 'bg-green-400')} />
                      <span className="text-slate-600">{format(new Date(hb.received_at), 'HH:mm:ss')}</span>
                    </div>
                    <div className="flex gap-3 text-slate-400">
                      {hb.active_jobs > 0 && <span>{hb.active_jobs} jobs</span>}
                      {hb.cpu_percent != null && <span>{hb.cpu_percent.toFixed(1)}% cpu</span>}
                      {hb.memory_mb != null && <span>{hb.memory_mb.toFixed(0)} MB</span>}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Jobs tab ─────────────────────────────────────────────────────── */}
      {tab === 'jobs' && (
        <div className="p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-slate-700">Jobs ({jobsData?.total ?? 0})</h3>
            <button className="btn-primary text-xs py-1.5" onClick={() => setShowDispatch(true)}>+ Dispatch Job</button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr>
                  <th className="table-th">Type</th>
                  <th className="table-th">Status</th>
                  <th className="table-th">Progress</th>
                  <th className="table-th">Targets</th>
                  <th className="table-th">Created</th>
                  <th className="table-th">Completed</th>
                  <th className="table-th">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {jobsData?.items.map((job: any) => (
                  <tr key={job.id} className="hover:bg-slate-50">
                    <td className="table-td text-xs font-mono text-slate-600">{job.job_type}</td>
                    <td className="table-td">
                      <span className={clsx('badge text-xs', JOB_STATUS_COLORS[job.status] ?? 'bg-slate-100 text-slate-600')}>
                        {job.status}
                      </span>
                    </td>
                    <td className="table-td">
                      <div className="flex items-center gap-2">
                        <div className="flex-1 bg-slate-200 rounded-full h-1.5 w-24">
                          <div className="bg-brand-500 h-1.5 rounded-full" style={{ width: `${job.progress_pct}%` }} />
                        </div>
                        <span className="text-xs text-slate-500">{job.progress_pct}%</span>
                      </div>
                    </td>
                    <td className="table-td text-xs text-slate-500">
                      {job.targets_total > 0 ? `${job.targets_done}/${job.targets_total}` : '—'}
                    </td>
                    <td className="table-td text-xs text-slate-400">
                      {format(new Date(job.created_at), 'dd MMM HH:mm')}
                    </td>
                    <td className="table-td text-xs text-slate-400">
                      {job.completed_at ? format(new Date(job.completed_at), 'dd MMM HH:mm') : '—'}
                    </td>
                    <td className="table-td">
                      {['pending', 'accepted', 'running'].includes(job.status) && (
                        <button className="btn-secondary text-xs py-0.5" onClick={() => cancelJobMut.mutate(job.id)}>Cancel</button>
                      )}
                    </td>
                  </tr>
                ))}
                {(!jobsData?.items.length) && (
                  <tr><td colSpan={7} className="py-10 text-center text-slate-400">No jobs yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── Settings tab ─────────────────────────────────────────────────── */}
      {tab === 'settings' && <SettingsPanel agentId={id!} />}

      {/* ── Logs tab ─────────────────────────────────────────────────────── */}
      {tab === 'logs' && (
        <div className="p-6">
          <h3 className="text-sm font-semibold text-slate-700 mb-4">Agent Logs</h3>
          <div className="bg-slate-900 rounded-lg p-4 font-mono text-xs overflow-auto max-h-[60vh] space-y-1">
            {!logs?.length ? (
              <span className="text-slate-500">No logs uploaded yet.</span>
            ) : (
              (logs as any[]).map((l, i) => (
                <div key={i} className={clsx('flex gap-3',
                  l.level === 'error' || l.level === 'critical' ? 'text-red-400' :
                  l.level === 'warning' ? 'text-yellow-400' :
                  l.level === 'debug' ? 'text-slate-500' : 'text-slate-300')}>
                  <span className="text-slate-600 shrink-0">
                    {l.agent_timestamp ? format(new Date(l.agent_timestamp), 'HH:mm:ss') : format(new Date(l.received_at), 'HH:mm:ss')}
                  </span>
                  <span className="text-slate-500 uppercase w-7 shrink-0">{l.level.slice(0,4)}</span>
                  <span>{l.message}</span>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {showDispatch && <DispatchJobModal agentId={id!} onClose={() => setShowDispatch(false)} />}
    </div>
  )
}

function InfoRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex justify-between items-start gap-2">
      <span className="text-xs text-slate-500 shrink-0">{label}</span>
      <span className="text-xs text-slate-800 text-right">{children}</span>
    </div>
  )
}
