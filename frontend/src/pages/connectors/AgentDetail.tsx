import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  useAgentActionMutation, useGetAgentHeartbeatsQuery, useGetAgentJobsQuery, useGetAgentLogsQuery,
  useGetAgentQuery, useGetAgentSettingsQuery, useRotateAgentTokenMutation, useUpdateAgentSettingsMutation,
} from '../../api/apiSlice'
import type {
  ConnectorAgentHeartbeat, ConnectorAgentJob, ConnectorAgentLog, ConnectorAgentSettings,
} from '../../api/types'
import { useCan } from '../../app/rbac'
import {
  ActionButton, DataPanel, DataTable, ErrorState, Field, InlineAlert, LoadingPanel, MetricTile,
  PageFrame, StatusBadge, TextInput, apiErrorMessage, cx, type Column,
} from '../../components/ui'

const EDITABLE_SETTINGS: { key: keyof ConnectorAgentSettings; label: string }[] = [
  { key: 'heartbeat_interval_seconds', label: 'Heartbeat (s)' },
  { key: 'job_poll_interval_seconds', label: 'Job poll (s)' },
  { key: 'job_timeout_seconds', label: 'Job timeout (s)' },
  { key: 'max_concurrent_jobs', label: 'Max concurrent jobs' },
  { key: 'offline_queue_max_mb', label: 'Offline queue (MB)' },
  { key: 'result_retention_hours', label: 'Result retention (h)' },
  { key: 'log_retention_days', label: 'Log retention (d)' },
  { key: 'token_rotation_days', label: 'Token rotation (d)' },
]

function fmt(ts: string | null | undefined) { return ts ? new Date(ts).toLocaleString() : '—' }
function ago(ts: string | null | undefined): string {
  if (!ts) return 'never'
  const m = Math.round((Date.now() - new Date(ts).getTime()) / 60000)
  return m < 1 ? 'just now' : m < 60 ? `${m}m ago` : m < 1440 ? `${Math.round(m / 60)}h ago` : `${Math.round(m / 1440)}d ago`
}

export default function AgentDetail() {
  const { id = '' } = useParams()
  const navigate = useNavigate()
  const can = useCan()
  const agentQ = useGetAgentQuery(id, { pollingInterval: 15000 })
  const settingsQ = useGetAgentSettingsQuery(id)
  const jobsQ = useGetAgentJobsQuery(id)
  const heartbeatsQ = useGetAgentHeartbeatsQuery(id)
  const logsQ = useGetAgentLogsQuery(id)
  const [agentAction, actionState] = useAgentActionMutation()
  const [updateSettings, settingsSave] = useUpdateAgentSettingsMutation()
  const [rotateToken, rotateState] = useRotateAgentTokenMutation()
  const [editSettings, setEditSettings] = useState<ConnectorAgentSettings | null>(null)
  const [nowMs] = useState(() => Date.now())

  if (agentQ.isLoading) return <PageFrame eyebrow="Agent" title="Agent detail" subtitle="Loading…"><LoadingPanel /></PageFrame>
  if (agentQ.isError || !agentQ.data) return <PageFrame eyebrow="Agent" title="Agent detail" subtitle="Could not load this agent."><ErrorState detail={apiErrorMessage(agentQ.error)} onRetry={agentQ.refetch} /></PageFrame>
  const a = agentQ.data
  const s = settingsQ.data
  const latestHb = heartbeatsQ.data?.[0]

  async function act(action: 'approve' | 'revoke' | 'enable' | 'disable') {
    if (action === 'revoke' && !confirm('Revoke this agent permanently? It will need to re-enroll.')) return
    await agentAction({ id, action }).unwrap().catch(() => {})
  }
  async function saveSettings() {
    if (!editSettings) return
    await updateSettings({ id, body: editSettings }).unwrap().catch(() => {})
    setEditSettings(null)
  }

  const jobCols: Column<ConnectorAgentJob>[] = [
    { key: 'type', header: 'Type', render: (j) => j.job_type },
    { key: 'status', header: 'Status', render: (j) => <StatusBadge value={j.status} /> },
    { key: 'progress', header: 'Progress', render: (j) => `${j.progress_pct}%${j.progress_message ? ` · ${j.progress_message}` : ''}` },
    { key: 'targets', header: 'Targets (done/fail/total)', render: (j) => `${j.targets_done} / ${j.targets_failed} / ${j.targets_total}` },
    { key: 'started', header: 'Started', render: (j) => <span className="whitespace-nowrap text-xs text-slate-500">{fmt(j.started_at)}</span> },
    { key: 'error', header: 'Error', render: (j) => j.error_message ? <span className="text-red-700">{j.error_message.slice(0, 50)}</span> : '—' },
  ]
  const hbCols: Column<ConnectorAgentHeartbeat>[] = [
    { key: 'time', header: 'Received', render: (h) => <span className="whitespace-nowrap text-xs text-slate-500">{fmt(h.received_at)}</span> },
    { key: 'status', header: 'Status', render: (h) => <StatusBadge value={h.status ?? '—'} /> },
    { key: 'jobs', header: 'Active jobs', render: (h) => h.active_jobs },
    { key: 'queued', header: 'Queued results', render: (h) => h.queued_results },
    { key: 'cpu', header: 'CPU %', render: (h) => (h.cpu_percent != null ? h.cpu_percent.toFixed(0) : '—') },
    { key: 'mem', header: 'Mem (MB)', render: (h) => (h.memory_mb != null ? h.memory_mb.toFixed(0) : '—') },
    { key: 'err', header: 'Errors', render: (h) => h.error_count },
  ]
  const logCols: Column<ConnectorAgentLog>[] = [
    { key: 'time', header: 'Time', render: (l) => <span className="whitespace-nowrap text-xs text-slate-500">{fmt(l.received_at)}</span> },
    { key: 'level', header: 'Level', render: (l) => <StatusBadge value={l.level} /> },
    { key: 'message', header: 'Message', render: (l) => <span className="text-sm">{l.message}</span> },
  ]

  return (
    <PageFrame
      eyebrow="Collection infrastructure"
      title={a.name}
      subtitle={`Remote agent · ${a.hostname ?? 'unknown host'} · ${[a.site, a.location].filter(Boolean).join(' / ') || 'no site'}`}
      actions={
        <div className="flex flex-wrap gap-2">
          <ActionButton onClick={() => navigate('/connectors')}>Back</ActionButton>
          {a.status === 'pending' && can('connector:admin') && <ActionButton variant="primary" disabled={actionState.isLoading} onClick={() => act('approve')}>Approve</ActionButton>}
          {a.status !== 'revoked' && can('connector:manage') && <ActionButton disabled={actionState.isLoading} onClick={() => act(a.is_enabled ? 'disable' : 'enable')}>{a.is_enabled ? 'Disable' : 'Enable'}</ActionButton>}
          {can('connector:admin') && <ActionButton disabled={rotateState.isLoading} onClick={() => rotateToken(id)}>{rotateState.isLoading ? 'Rotating…' : 'Rotate token'}</ActionButton>}
          {a.status !== 'revoked' && can('connector:admin') && <ActionButton variant="destructive" disabled={actionState.isLoading} onClick={() => act('revoke')}>Revoke</ActionButton>}
        </div>
      }
    >
      {rotateState.data && (
        <InlineAlert tone="green">
          New enrollment token (shown once): <code className="break-all">{rotateState.data.token}</code> — expires {new Date(rotateState.data.expires_at).toLocaleString()}.
        </InlineAlert>
      )}
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
        <MetricTile label="Status" value={a.status} detail={a.is_enabled ? 'enabled' : 'disabled'} tone={a.status === 'online' ? 'green' : a.status === 'pending' ? 'amber' : a.status === 'revoked' || a.status === 'error' ? 'red' : 'slate'} />
        <MetricTile label="Last heartbeat" value={ago(a.last_heartbeat_at)} detail={fmt(a.last_heartbeat_at)} tone="blue" />
        <MetricTile label="Version" value={a.agent_version ?? '—'} detail="Agent build" tone="slate" />
        <MetricTile label="Active jobs" value={latestHb?.active_jobs ?? 0} detail={`${latestHb?.queued_results ?? 0} queued results`} tone="purple" />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <DataPanel title="Configuration">
          {settingsQ.isLoading ? <div className="p-4"><LoadingPanel /></div> : settingsQ.isError ? <div className="p-4"><ErrorState detail={apiErrorMessage(settingsQ.error)} onRetry={settingsQ.refetch} /></div> : editSettings ? (
            <div className="space-y-3 p-4">
              <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
                {EDITABLE_SETTINGS.map(({ key, label }) => (
                  <Field key={key} label={label}>
                    <TextInput type="number" value={String(editSettings[key] ?? '')} onChange={(e) => setEditSettings({ ...editSettings, [key]: Number(e.target.value) })} />
                  </Field>
                ))}
              </div>
              <label className="flex items-center gap-2 text-sm text-slate-700"><input type="checkbox" checked={editSettings.verify_console_certificate} onChange={(e) => setEditSettings({ ...editSettings, verify_console_certificate: e.target.checked })} />Verify console certificate</label>
              {settingsSave.isError && <InlineAlert tone="red">{apiErrorMessage(settingsSave.error)}</InlineAlert>}
              <div className="flex gap-2">
                <ActionButton variant="primary" disabled={settingsSave.isLoading} onClick={saveSettings}>{settingsSave.isLoading ? 'Saving…' : 'Save settings'}</ActionButton>
                <ActionButton variant="ghost" onClick={() => setEditSettings(null)}>Cancel</ActionButton>
              </div>
            </div>
          ) : s ? (
            <>
              <dl className="grid grid-cols-2 gap-4 p-4 text-sm md:grid-cols-3">
                <Item k="Heartbeat" v={`${s.heartbeat_interval_seconds}s`} />
                <Item k="Job poll" v={`${s.job_poll_interval_seconds}s`} />
                <Item k="Job timeout" v={`${s.job_timeout_seconds}s`} />
                <Item k="Max concurrent jobs" v={String(s.max_concurrent_jobs)} />
                <Item k="Offline queue" v={`${s.offline_queue_max_mb} MB`} />
                <Item k="Result retention" v={`${s.result_retention_hours}h`} />
                <Item k="Log retention" v={`${s.log_retention_days}d`} />
                <Item k="Verify console cert" v={s.verify_console_certificate ? 'yes' : 'no'} />
                <Item k="Token rotation" v={`${s.token_rotation_days}d`} />
              </dl>
              {can('connector:manage') && (
                <div className="border-t border-slate-200 px-4 py-3">
                  <ActionButton onClick={() => setEditSettings(s)}>Edit settings</ActionButton>
                </div>
              )}
            </>
          ) : null}
        </DataPanel>
        <DataPanel title="Identity & security">
          <dl className="grid grid-cols-2 gap-4 p-4 text-sm">
            <Item k="Hostname" v={a.hostname} />
            <Item k="IP address" v={a.ip_address} />
            <Item k="OS" v={a.os_platform} />
            <Item k="Environment" v={a.environment} />
            <Item k="Token prefix" v={a.token_prefix} />
            <Item k="Approved by" v={a.approved_by} />
            <Item k="Cert fingerprint" v={a.cert_fingerprint ? `${a.cert_fingerprint.slice(0, 20)}…` : '—'} />
            <Item k="Cert expires" v={fmt(a.cert_expires_at)} tone={a.cert_expires_at && new Date(a.cert_expires_at).getTime() < nowMs ? 'red' : undefined} />
          </dl>
        </DataPanel>
      </div>

      <DataPanel title="Assigned jobs" detail={`${jobsQ.data?.total ?? 0} job(s)`}>
        {jobsQ.isLoading ? <div className="p-4"><LoadingPanel /></div> : jobsQ.isError ? <div className="p-4"><ErrorState detail={apiErrorMessage(jobsQ.error)} onRetry={jobsQ.refetch} /></div> : (
          <DataTable columns={jobCols} rows={jobsQ.data?.items ?? []} getRowKey={(j) => j.id} empty="No jobs dispatched to this agent yet." minWidth={900} />
        )}
      </DataPanel>

      <DataPanel title="Heartbeat history" detail={`${heartbeatsQ.data?.length ?? 0} recent`}>
        {heartbeatsQ.isLoading ? <div className="p-4"><LoadingPanel /></div> : heartbeatsQ.isError ? <div className="p-4"><ErrorState detail={apiErrorMessage(heartbeatsQ.error)} onRetry={heartbeatsQ.refetch} /></div> : (
          <DataTable columns={hbCols} rows={heartbeatsQ.data ?? []} getRowKey={(h) => h.id} empty="No heartbeats received yet." minWidth={800} />
        )}
      </DataPanel>

      <DataPanel title="Agent logs" detail={`${logsQ.data?.length ?? 0} recent`}>
        {logsQ.isLoading ? <div className="p-4"><LoadingPanel /></div> : logsQ.isError ? <div className="p-4"><ErrorState detail={apiErrorMessage(logsQ.error)} onRetry={logsQ.refetch} /></div> : (
          <DataTable columns={logCols} rows={logsQ.data ?? []} getRowKey={(l) => l.id} empty="No logs reported by this agent." minWidth={700} />
        )}
      </DataPanel>
    </PageFrame>
  )
}

function Item({ k, v, tone }: { k: string; v?: string | null; tone?: 'red' }) {
  return <div><dt className="text-xs uppercase tracking-wide text-slate-500">{k}</dt><dd className={cx('mt-0.5 font-medium', tone === 'red' ? 'text-red-700' : 'text-slate-900')}>{v || '—'}</dd></div>
}
