import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  useAgentActionMutation, useCreateConnectorAgentMutation, useCreateConnectorMutation, useCreateCredentialMutation, useCreateEnrollmentTokenMutation,
  useDeleteConnectorMutation, useGetAssetsQuery, useGetConnectorAgentsQuery, useGetConnectorsQuery,
  useGetCredentialsQuery, useTestConnectionMutation, useUpdateConnectorMutation, useUpdateCredentialMutation,
} from '../../api/apiSlice'
import type { Connector, ConnectorAgent, Credential } from '../../api/types'
import { useCan } from '../../app/rbac'
import {
  ActionButton, DataPanel, DataTable, ErrorState, Field, InlineAlert, LoadingPanel,
  MetricTile, NativeSelect, PageFrame, StatusBadge, TextInput, apiErrorMessage, cx, type Column,
} from '../../components/ui'

const CONNECTOR_KINDS = ['ssh', 'winrm', 'wmi', 'mysql', 'mssql', 'mongodb', 'oracle', 'postgresql', 'redis']
const AUTH_METHODS = ['password', 'key', 'token', 'cert']

type Tab = 'connectors' | 'agents' | 'credentials'
type CredForm = { id?: string; name: string; description: string; vault_backend: string; vault_ref: string; username: string; auth_method: string; rotation_policy_days: string; is_active: boolean; secret_material: string }
const emptyCred: CredForm = { name: '', description: '', vault_backend: 'local', vault_ref: 'local/', username: '', auth_method: 'password', rotation_policy_days: '', is_active: true, secret_material: '' }
function fmt(ts: string | null) { return ts ? new Date(ts).toLocaleString() : '—' }
function ago(ts: string | null): string {
  if (!ts) return 'never'
  const mins = Math.round((Date.now() - new Date(ts).getTime()) / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`
  return `${Math.round(mins / 1440)}d ago`
}

export default function ConnectorsAgents() {
  const can = useCan()
  const navigate = useNavigate()
  const manage = can('connector:manage')
  const admin = can('connector:admin')
  const [tab, setTab] = useState<Tab>('connectors')
  const [restoreId, setRestoreId] = useState<string | null>(null)
  const [secret, setSecret] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [linkId, setLinkId] = useState<string | null>(null)
  const [linkCredId, setLinkCredId] = useState('')
  const [credentialSearch, setCredentialSearch] = useState('')
  const [testId, setTestId] = useState<string | null>(null)
  const [testAssetId, setTestAssetId] = useState('')
  const [assetSearch, setAssetSearch] = useState('')
  const [connectorSearch, setConnectorSearch] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const [newConn, setNewConn] = useState({ name: '', kind: 'ssh', default_port: '', credential_id: '' })
  const [credForm, setCredForm] = useState<CredForm | null>(null)
  const [agentForm, setAgentForm] = useState({ name: '', description: '', site: '', location: '', environment: '' })
  const [showEnroll, setShowEnroll] = useState(false)
  const [enroll, setEnroll] = useState({ expected_hostname: '', expected_site: '', expected_environment: '', auto_approve: false })

  const connectorsQ = useGetConnectorsQuery()
  const agentsQ = useGetConnectorAgentsQuery(undefined, { skip: tab !== 'agents', pollingInterval: tab === 'agents' ? 10000 : 0 })
  const credentialsQ = useGetCredentialsQuery()
  const assetsQ = useGetAssetsQuery({ limit: 1000 }, { skip: tab !== 'connectors' })
  const [updateCredential, updateState] = useUpdateCredentialMutation()
  const [updateConnector, connUpdateState] = useUpdateConnectorMutation()
  const [testConnection, testState] = useTestConnectionMutation()
  const [agentAction, agentActionState] = useAgentActionMutation()
  const [createConnector, createState] = useCreateConnectorMutation()
  const [createCredential, createCredState] = useCreateCredentialMutation()
  const [createAgent, createAgentState] = useCreateConnectorAgentMutation()
  const [deleteConnector] = useDeleteConnectorMutation()
  const [createEnrollmentToken, enrollState] = useCreateEnrollmentTokenMutation()

  async function submitCreateConnector() {
    if (!newConn.name.trim()) return
    setActionError(null)
    try {
      await createConnector({
        name: newConn.name.trim(), kind: newConn.kind,
        default_port: newConn.default_port ? Number(newConn.default_port) : null,
        credential_id: newConn.credential_id || null, is_active: true,
      }).unwrap()
      setNewConn({ name: '', kind: 'ssh', default_port: '', credential_id: '' })
      setShowCreate(false)
      setMessage('Connector created.')
    } catch (err) {
      setActionError(apiErrorMessage(err))
    }
  }
  async function removeConnector(c: Connector) {
    if (!confirm(`Delete connector "${c.name}"? Assets using it will fall back to kind-based resolution.`)) return
    setActionError(null)
    try {
      await deleteConnector(c.id).unwrap()
      setMessage(`Connector "${c.name}" deleted.`)
    } catch (err) {
      setActionError(apiErrorMessage(err))
    }
  }
  async function submitEnroll() {
    setActionError(null)
    try {
      await createEnrollmentToken({
        expected_hostname: enroll.expected_hostname || null,
        expected_site: enroll.expected_site || null,
        expected_environment: enroll.expected_environment || null,
        auto_approve: enroll.auto_approve,
      }).unwrap()
    } catch (err) {
      setActionError(apiErrorMessage(err))
    }
  }
  async function submitAgent() {
    if (!agentForm.name.trim()) return
    setActionError(null)
    try {
      await createAgent({
        name: agentForm.name.trim(),
        description: agentForm.description.trim() || null,
        site: agentForm.site.trim() || null,
        location: agentForm.location.trim() || null,
        environment: agentForm.environment.trim() || null,
      }).unwrap()
      setAgentForm({ name: '', description: '', site: '', location: '', environment: '' })
      setMessage('Agent record created. Generate an enrollment token when ready to install the collector.')
    } catch (err) {
      setActionError(apiErrorMessage(err))
    }
  }

  const credentials = credentialsQ.data?.items ?? []
  const credName = (id: string | null) => credentials.find((c) => c.id === id)?.name ?? null
  const credentialMatches = useMemo(() => {
    const term = credentialSearch.trim().toLowerCase()
    if (!term) return credentials
    return credentials.filter((c) => [c.name, c.username, c.vault_ref, c.auth_method].some((v) => String(v ?? '').toLowerCase().includes(term)))
  }, [credentialSearch, credentials])

  // ── Connector actions ──
  function connectorBody(c: Connector, patch: Partial<Connector>) {
    return {
      name: c.name, kind: c.kind, default_port: c.default_port, options: c.options,
      credential_id: c.credential_id, proxy_host: c.proxy_host ?? null, proxy_port: c.proxy_port ?? null,
      is_active: c.is_active, ...patch,
    }
  }
  async function saveLink(c: Connector) {
    setActionError(null)
    try {
      await updateConnector({ id: c.id, body: connectorBody(c, { credential_id: linkCredId || null }) }).unwrap()
      setLinkId(null); setLinkCredId('')
      setMessage(`Credential ${linkCredId ? `linked to ${c.name}` : `cleared from ${c.name}`}.`)
    } catch (err) {
      setActionError(apiErrorMessage(err))
    }
  }
  async function toggleConnector(c: Connector) {
    setActionError(null)
    try {
      await updateConnector({ id: c.id, body: connectorBody(c, { is_active: !c.is_active }) }).unwrap()
      setMessage(`Connector "${c.name}" ${c.is_active ? 'disabled' : 'enabled'}.`)
    } catch (err) {
      setActionError(apiErrorMessage(err))
    }
  }
  async function runTest() {
    if (!testId || !testAssetId) return
    setMessage(null); setActionError(null)
    try {
      await testConnection({ asset_id: testAssetId, connector_id: testId }).unwrap()
    } catch (err) {
      setActionError(apiErrorMessage(err))
    }
  }

  const connectorCols: Column<Connector>[] = [
    { key: 'name', header: 'Connector', render: (c) => <span className="font-medium text-slate-900">{c.name}</span> },
    { key: 'kind', header: 'Kind', render: (c) => c.kind },
    { key: 'port', header: 'Default port', render: (c) => (c.default_port ?? '—') },
    { key: 'cred', header: 'Credential', render: (c) => c.credential_id ? <span className="text-xs text-slate-700">{credName(c.credential_id) ?? <StatusBadge value="linked" />}</span> : <span className="text-amber-700">none</span> },
    { key: 'active', header: 'Status', render: (c) => <StatusBadge value={c.is_active ? 'active' : 'inactive'} /> },
    ...(manage ? [{
      key: 'actions', header: 'Actions', render: (c: Connector) => (
        <div className="flex flex-wrap gap-2" onClick={(e) => e.stopPropagation()}>
          <button className="text-xs font-medium text-blue-700 hover:underline" onClick={() => { setTestId(c.id); setTestAssetId(''); setAssetSearch(''); setMessage(null) }}>Test</button>
          <button className="text-xs font-medium text-slate-700 hover:underline" onClick={() => { setLinkId(c.id); setLinkCredId(c.credential_id ?? ''); setCredentialSearch(''); setMessage(null) }}>Link credential</button>
          <button className="text-xs font-medium text-slate-600 hover:underline" disabled={connUpdateState.isLoading} onClick={() => toggleConnector(c)}>{c.is_active ? 'Disable' : 'Enable'}</button>
          {admin && <button className="text-xs font-medium text-red-600 hover:underline" onClick={() => removeConnector(c)}>Delete</button>}
        </div>
      ),
    } as Column<Connector>] : []),
  ]

  const linkConnector = connectorsQ.data?.items.find((c) => c.id === linkId) ?? null
  const testConnector = connectorsQ.data?.items.find((c) => c.id === testId) ?? null
  const testAssets = (assetsQ.data?.items ?? []).filter((a) => a.connector_id === testId)
  const availableTestAssets = testAssets.length ? testAssets : (assetsQ.data?.items ?? [])
  const assetMatches = useMemo(() => {
    const term = assetSearch.trim().toLowerCase()
    if (!term) return availableTestAssets
    return availableTestAssets.filter((a) => [a.hostname, a.ip_address, a.platform, a.environment, a.owner].some((v) => String(v ?? '').toLowerCase().includes(term)))
  }, [assetSearch, availableTestAssets])
  const connectorRows = useMemo(() => {
    const rows = connectorsQ.data?.items ?? []
    const term = connectorSearch.trim().toLowerCase()
    if (!term) return rows
    return rows.filter((c) => [c.name, c.kind, c.default_port, credName(c.credential_id)].some((v) => String(v ?? '').toLowerCase().includes(term)))
  }, [connectorSearch, connectorsQ.data?.items, credentials])

  // ── Agent actions ──
  async function doAgent(id: string, action: 'approve' | 'revoke' | 'enable' | 'disable') {
    if ((action === 'revoke') && !confirm('Revoke this agent permanently? It will need to re-enroll.')) return
    setMessage(null); setActionError(null)
    try {
      await agentAction({ id, action }).unwrap()
      setMessage(`Agent ${action}d.`)
    } catch (err) {
      setActionError(apiErrorMessage(err))
    }
  }
  const agentCols: Column<ConnectorAgent>[] = [
    { key: 'name', header: 'Agent', render: (a) => <span className="font-medium text-slate-900">{a.name}</span> },
    { key: 'status', header: 'Status', render: (a) => <StatusBadge value={a.status} /> },
    { key: 'site', header: 'Site / location', render: (a) => [a.site, a.location].filter(Boolean).join(' · ') || '—' },
    { key: 'os', header: 'OS', render: (a) => a.os_platform ?? '—' },
    { key: 'version', header: 'Version', render: (a) => a.agent_version ?? '—' },
    { key: 'heartbeat', header: 'Last heartbeat', render: (a) => <span className={cx('whitespace-nowrap text-xs', a.status === 'stale' || a.status === 'offline' ? 'font-medium text-red-700' : 'text-slate-500')} title={fmt(a.last_heartbeat_at)}>{ago(a.last_heartbeat_at)}</span> },
    { key: 'enabled', header: 'Enabled', render: (a) => <StatusBadge value={a.is_enabled ? 'enabled' : 'disabled'} /> },
    ...((manage || admin) ? [{
      key: 'actions', header: 'Actions', render: (a: ConnectorAgent) => {
        const busy = agentActionState.isLoading
        return (
          <div className="flex flex-wrap gap-2" onClick={(e) => e.stopPropagation()}>
            {a.status === 'pending' && admin && <button className="text-xs font-medium text-emerald-700 hover:underline" disabled={busy} onClick={() => doAgent(a.id, 'approve')}>Approve</button>}
            {a.status !== 'revoked' && manage && (a.is_enabled
              ? <button className="text-xs font-medium text-amber-700 hover:underline" disabled={busy} onClick={() => doAgent(a.id, 'disable')}>Disable</button>
              : <button className="text-xs font-medium text-emerald-700 hover:underline" disabled={busy} onClick={() => doAgent(a.id, 'enable')}>Enable</button>)}
            {a.status !== 'revoked' && admin && <button className="text-xs font-medium text-red-600 hover:underline" disabled={busy} onClick={() => doAgent(a.id, 'revoke')}>Revoke</button>}
            {a.status === 'revoked' && <span className="text-xs text-slate-400">revoked</span>}
          </div>
        )
      },
    } as Column<ConnectorAgent>] : []),
  ]

  const credentialCols: Column<Credential>[] = [
    { key: 'name', header: 'Credential', render: (c) => <span className="font-medium text-slate-900">{c.name}</span> },
    { key: 'username', header: 'Username', render: (c) => c.username || '—' },
    { key: 'vault', header: 'Vault reference', render: (c) => <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs text-slate-700">{c.vault_ref}</code> },
    { key: 'rotated', header: 'Last restored', render: (c) => <span className="text-xs text-slate-500">{fmt(c.last_rotated_at)}</span> },
    { key: 'status', header: 'Status', render: (c) => <StatusBadge value={c.is_active ? (c.rotation_overdue ? 'expired' : 'active') : 'disabled'} /> },
    ...(can('credential:manage') ? [{
      key: 'actions', header: 'Actions', render: (c: Credential) => (
        <div className="flex flex-wrap gap-2" onClick={(e) => e.stopPropagation()}>
          <ActionButton variant="secondary" onClick={() => editCredential(c)}>Edit</ActionButton>
          <ActionButton variant="secondary" onClick={() => { setRestoreId(c.id); setSecret(''); setMessage(null) }}>Restore secret</ActionButton>
        </div>
      ),
    } as Column<Credential>] : []),
  ]

  const agents = agentsQ.data?.items ?? []
  const online = agents.filter((a) => a.status === 'online').length
  const pending = agents.filter((a) => a.status === 'pending').length
  const degraded = agents.filter((a) => a.status === 'offline' || a.status === 'stale' || a.status === 'error').length
  const selectedCredential = credentialsQ.data?.items.find((c) => c.id === restoreId) ?? null

  function editCredential(c: Credential) {
    setCredForm({
      id: c.id,
      name: c.name,
      description: c.description ?? '',
      vault_backend: c.vault_backend,
      vault_ref: c.vault_ref,
      username: c.username,
      auth_method: c.auth_method,
      rotation_policy_days: c.rotation_policy_days != null ? String(c.rotation_policy_days) : '',
      is_active: c.is_active,
      secret_material: '',
    })
    setMessage(null)
  }
  function credBody(form: CredForm) {
    return {
      name: form.name.trim(),
      description: form.description.trim() || null,
      vault_backend: form.vault_backend,
      vault_ref: form.vault_ref.trim(),
      username: form.username.trim(),
      auth_method: form.auth_method,
      rotation_policy_days: form.rotation_policy_days ? Number(form.rotation_policy_days) : null,
      is_active: form.is_active,
      secret_material: form.secret_material || null,
    }
  }
  async function saveCredential() {
    if (!credForm?.name.trim() || !credForm.vault_ref.trim()) return
    setActionError(null)
    try {
      if (credForm.id) await updateCredential({ id: credForm.id, body: credBody(credForm) }).unwrap()
      else await createCredential(credBody(credForm)).unwrap()
      setCredForm(null)
      setMessage(`Credential ${credForm.id ? 'updated' : 'created'}.`)
    } catch (err) {
      setActionError(apiErrorMessage(err))
    }
  }

  async function restoreSecret() {
    if (!selectedCredential || !secret) return
    await updateCredential({
      id: selectedCredential.id,
      body: {
        name: selectedCredential.name,
        description: selectedCredential.description,
        vault_backend: selectedCredential.vault_backend,
        vault_ref: selectedCredential.vault_ref,
        username: selectedCredential.username,
        auth_method: selectedCredential.auth_method,
        rotation_policy_days: selectedCredential.rotation_policy_days,
        is_active: selectedCredential.is_active,
        secret_material: secret,
      },
    }).unwrap()
    setSecret('')
    setRestoreId(null)
    setMessage(`${selectedCredential.name} secret restored. Retry the scan when all required credentials are restored.`)
  }

  return (
    <PageFrame
      eyebrow="Collection infrastructure"
      title="Connectors / Agents"
      subtitle="Collection paths and remote agents used to reach segmented estates. Status is backend-driven."
    >
      <div className="flex flex-wrap gap-2">
        {(['connectors', 'agents', 'credentials'] as Tab[]).map((t) => (
          <button key={t} onClick={() => setTab(t)} className={cx('rounded-md border px-3 py-1.5 text-sm font-semibold capitalize', tab === t ? 'border-blue-600 bg-blue-50 text-blue-700' : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50')}>{t}</button>
        ))}
      </div>
      {message ? <InlineAlert tone="green">{message}</InlineAlert> : null}
      {actionError ? <InlineAlert tone="red">{actionError}</InlineAlert> : null}
      {!manage && <InlineAlert tone="slate">You can view collection infrastructure but not manage it. Management requires the security analyst or admin role.</InlineAlert>}

      {tab === 'connectors' && (
        connectorsQ.isLoading ? <LoadingPanel /> : connectorsQ.isError ? <ErrorState detail={apiErrorMessage(connectorsQ.error)} onRetry={connectorsQ.refetch} /> : (
          <div className="space-y-4">
            {manage && (
              <div className="flex justify-end">
                <ActionButton variant="primary" onClick={() => setShowCreate((s) => !s)}>{showCreate ? 'Close' : 'New connector'}</ActionButton>
              </div>
            )}
            {showCreate && manage && (
              <DataPanel title="Create connector">
                <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4">
                  <Field label="Name" required><TextInput value={newConn.name} onChange={(e) => setNewConn({ ...newConn, name: e.target.value })} placeholder="RHEL SSH" /></Field>
                  <Field label="Kind"><NativeSelect value={newConn.kind} options={CONNECTOR_KINDS.map((k) => ({ value: k, label: k }))} onChange={(v) => setNewConn({ ...newConn, kind: v })} /></Field>
                  <Field label="Default port"><TextInput type="number" value={newConn.default_port} onChange={(e) => setNewConn({ ...newConn, default_port: e.target.value })} placeholder="22" /></Field>
                  <Field label="Credential"><NativeSelect value={newConn.credential_id} options={credentials.map((c) => ({ value: c.id, label: c.name }))} onChange={(v) => setNewConn({ ...newConn, credential_id: v })} placeholder="None" /></Field>
                </div>
                <div className="flex items-center gap-3 border-t border-slate-200 px-4 py-3">
                  <ActionButton variant="primary" disabled={!newConn.name.trim() || createState.isLoading} onClick={submitCreateConnector}>{createState.isLoading ? 'Creating…' : 'Create connector'}</ActionButton>
                  {createState.isError && <InlineAlert tone="red">{apiErrorMessage(createState.error)}</InlineAlert>}
                </div>
              </DataPanel>
            )}
            <DataPanel title="Connectors" detail={`${connectorsQ.data?.total ?? 0} connector(s)`}>
              <div className="border-b border-slate-200 bg-slate-50/70 p-3">
                <TextInput value={connectorSearch} onChange={(e) => setConnectorSearch(e.target.value)} placeholder="Search connectors by name, kind, port, or credential…" />
                <div className="mt-2 text-xs text-slate-500">{connectorRows.length} visible · actions open in a fixed side drawer</div>
              </div>
              <DataTable columns={connectorCols} rows={connectorRows} getRowKey={(c) => c.id} empty="No connectors match this search." minWidth={820} />
            </DataPanel>
          </div>
        )
      )}

      {linkConnector && (
        <SideDrawer title="Link credential" subtitle={linkConnector.name} onClose={() => setLinkId(null)}>
          <Field label="Search credentials" hint="Search by name, username, vault reference, or auth method.">
            <TextInput value={credentialSearch} onChange={(e) => setCredentialSearch(e.target.value)} placeholder="Find credential…" autoFocus />
          </Field>
          <div className="mt-4 max-h-[42vh] overflow-y-auto rounded-lg border border-slate-200">
            <button type="button" onClick={() => setLinkCredId('')} className={cx('flex w-full items-center justify-between border-b border-slate-100 px-3 py-2 text-left text-sm', !linkCredId && 'bg-blue-50 text-blue-700')}>
              <span>No credential</span><span className="text-xs text-slate-400">clear link</span>
            </button>
            {credentialMatches.map((c) => (
              <button key={c.id} type="button" onClick={() => setLinkCredId(c.id)} className={cx('flex w-full items-center justify-between gap-3 border-b border-slate-100 px-3 py-2 text-left text-sm last:border-b-0 hover:bg-slate-50', linkCredId === c.id && 'bg-blue-50 text-blue-700')}>
                <span><span className="font-medium">{c.name}</span><span className="ml-2 text-xs text-slate-500">{c.username || 'no user'}</span></span>
                <span className="truncate text-xs text-slate-400">{c.vault_ref}</span>
              </button>
            ))}
          </div>
          <DrawerActions>
            <ActionButton variant="primary" disabled={connUpdateState.isLoading} onClick={() => saveLink(linkConnector)}>{connUpdateState.isLoading ? 'Saving…' : 'Save link'}</ActionButton>
            <ActionButton variant="ghost" onClick={() => setLinkId(null)}>Cancel</ActionButton>
          </DrawerActions>
          {connUpdateState.isError && <InlineAlert tone="red">{apiErrorMessage(connUpdateState.error)}</InlineAlert>}
        </SideDrawer>
      )}

      {testConnector && (
        <SideDrawer title="Test connection" subtitle={testConnector.name} onClose={() => { setTestId(null); testState.reset() }}>
          <Field label="Search target assets" hint={testAssets.length ? 'Showing assets linked to this connector.' : 'No assets are linked to this connector, so all assets are available.'}>
            <TextInput value={assetSearch} onChange={(e) => setAssetSearch(e.target.value)} placeholder="Find asset by host, IP, platform, owner…" autoFocus />
          </Field>
          <div className="mt-4 max-h-[42vh] overflow-y-auto rounded-lg border border-slate-200">
            {assetMatches.map((a) => (
              <button key={a.id} type="button" onClick={() => setTestAssetId(a.id)} className={cx('flex w-full items-center justify-between gap-3 border-b border-slate-100 px-3 py-2 text-left text-sm last:border-b-0 hover:bg-slate-50', testAssetId === a.id && 'bg-blue-50 text-blue-700')}>
                <span><span className="font-medium">{a.hostname}</span><span className="ml-2 text-xs text-slate-500">{a.platform}</span></span>
                <span className="text-xs text-slate-400">{a.ip_address ?? 'no IP'}</span>
              </button>
            ))}
            {assetMatches.length === 0 && <div className="p-4 text-sm text-slate-500">No assets match this search.</div>}
          </div>
          <DrawerActions>
            <ActionButton variant="primary" disabled={!testAssetId || testState.isLoading} onClick={runTest}>{testState.isLoading ? 'Testing…' : 'Run test'}</ActionButton>
            <ActionButton variant="ghost" onClick={() => { setTestId(null); testState.reset() }}>Cancel</ActionButton>
          </DrawerActions>
          {testState.data && <InlineAlert tone={testState.data.success ? 'green' : 'red'}>{testState.data.success ? '✓ ' : '✕ '}{testState.data.message} {testState.data.latency_ms ? `(${testState.data.latency_ms} ms)` : ''}</InlineAlert>}
          {testState.isError && <InlineAlert tone="red">{apiErrorMessage(testState.error)}</InlineAlert>}
        </SideDrawer>
      )}

      {tab === 'agents' && (
        agentsQ.isLoading ? <LoadingPanel /> : agentsQ.isError ? <ErrorState detail={apiErrorMessage(agentsQ.error)} onRetry={agentsQ.refetch} /> : (
          <div className="space-y-4">
            {admin && (
              <div className="flex flex-wrap justify-end gap-2">
                <ActionButton onClick={() => setAgentForm((f) => f.name ? { name: '', description: '', site: '', location: '', environment: '' } : { ...f, name: 'new-agent' })}>{agentForm.name ? 'Close agent form' : 'Add agent record'}</ActionButton>
                <ActionButton variant="primary" onClick={() => { setShowEnroll((s) => !s); enrollState.reset() }}>{showEnroll ? 'Close' : 'Enroll agent'}</ActionButton>
              </div>
            )}
            {admin && agentForm.name && (
              <DataPanel title="Add agent record" detail="Pre-create a pending collector record before installing the remote agent.">
                <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-5">
                  <Field label="Name" required><TextInput value={agentForm.name} onChange={(e) => setAgentForm({ ...agentForm, name: e.target.value })} /></Field>
                  <Field label="Site"><TextInput value={agentForm.site} onChange={(e) => setAgentForm({ ...agentForm, site: e.target.value })} /></Field>
                  <Field label="Location"><TextInput value={agentForm.location} onChange={(e) => setAgentForm({ ...agentForm, location: e.target.value })} /></Field>
                  <Field label="Environment"><TextInput value={agentForm.environment} onChange={(e) => setAgentForm({ ...agentForm, environment: e.target.value })} /></Field>
                  <Field label="Description"><TextInput value={agentForm.description} onChange={(e) => setAgentForm({ ...agentForm, description: e.target.value })} /></Field>
                </div>
                <div className="flex items-center gap-3 border-t border-slate-200 px-4 py-3">
                  <ActionButton variant="primary" disabled={!agentForm.name.trim() || createAgentState.isLoading} onClick={submitAgent}>{createAgentState.isLoading ? 'Creating…' : 'Create pending agent'}</ActionButton>
                </div>
              </DataPanel>
            )}
            {showEnroll && admin && (
              <DataPanel title="Enroll new agent" detail="Generates a one-time enrollment token to register a remote collector.">
                {enrollState.data ? (
                  <div className="space-y-3 p-4">
                    <InlineAlert tone="green">Token generated — copy it now. It is shown only once and expires {new Date(enrollState.data.expires_at).toLocaleString()}.</InlineAlert>
                    <code className="block break-all rounded-md bg-slate-900 p-3 text-xs text-emerald-200">{enrollState.data.token}</code>
                    <div className="flex gap-2">
                      <ActionButton onClick={() => navigator.clipboard?.writeText(enrollState.data!.token)}>Copy token</ActionButton>
                      <ActionButton variant="ghost" onClick={() => { setShowEnroll(false); enrollState.reset() }}>Done</ActionButton>
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4">
                      <Field label="Expected hostname" hint="Optional"><TextInput value={enroll.expected_hostname} onChange={(e) => setEnroll({ ...enroll, expected_hostname: e.target.value })} /></Field>
                      <Field label="Site" hint="Optional"><TextInput value={enroll.expected_site} onChange={(e) => setEnroll({ ...enroll, expected_site: e.target.value })} /></Field>
                      <Field label="Environment" hint="Optional"><TextInput value={enroll.expected_environment} onChange={(e) => setEnroll({ ...enroll, expected_environment: e.target.value })} /></Field>
                      <Field label="Auto-approve"><label className="flex h-9 items-center gap-2 text-sm text-slate-700"><input type="checkbox" checked={enroll.auto_approve} onChange={(e) => setEnroll({ ...enroll, auto_approve: e.target.checked })} />Approve on enroll</label></Field>
                    </div>
                    <div className="flex items-center gap-3 border-t border-slate-200 px-4 py-3">
                      <ActionButton variant="primary" disabled={enrollState.isLoading} onClick={submitEnroll}>{enrollState.isLoading ? 'Generating…' : 'Generate token'}</ActionButton>
                      {enrollState.isError && <InlineAlert tone="red">{apiErrorMessage(enrollState.error)}</InlineAlert>}
                    </div>
                  </>
                )}
              </DataPanel>
            )}
            <div className="grid gap-3 md:grid-cols-4">
              <MetricTile label="Agents" value={agents.length} detail="Enrolled remote collectors" tone="blue" />
              <MetricTile label="Online" value={online} detail="Heartbeat within threshold" tone={online ? 'green' : 'slate'} />
              <MetricTile label="Pending approval" value={pending} detail="Awaiting admin approval" tone={pending ? 'amber' : 'slate'} />
              <MetricTile label="Offline / stale" value={degraded} detail="Missed heartbeats or error" tone={degraded ? 'red' : 'slate'} />
            </div>
            <DataPanel title="Remote agents" detail={`${agentsQ.data?.total ?? 0} agent(s) · live-updating · click a row for detail`}>
              <DataTable columns={agentCols} rows={agents} getRowKey={(a) => a.id} onRowClick={(a) => navigate(`/connectors/agents/${a.id}`)} empty="No remote agents enrolled. Enroll an agent to collect from segmented networks." minWidth={1000} />
            </DataPanel>
          </div>
        )
      )}

      {tab === 'credentials' && (
        credentialsQ.isLoading ? <LoadingPanel /> : credentialsQ.isError ? <ErrorState detail={apiErrorMessage(credentialsQ.error)} onRetry={credentialsQ.refetch} /> : (
          <div className="space-y-4">
            <InlineAlert tone="amber">
              Scan failures showing “Secret for credential … not found” mean the credential metadata exists but the encrypted vault secret is missing. Restore the secret here, then retry the scan.
            </InlineAlert>
            {can('credential:manage') && (
              <div className="flex justify-end">
                <ActionButton variant="primary" onClick={() => setCredForm({ ...emptyCred })}>New credential</ActionButton>
              </div>
            )}
            {credForm && (
              <DataPanel title={credForm.id ? `Edit credential · ${credForm.name}` : 'Create credential'} detail="Credential metadata plus optional write-only secret material.">
                <div className="grid gap-3 p-4 md:grid-cols-2 xl:grid-cols-4">
                  <Field label="Name" required><TextInput value={credForm.name} onChange={(e) => setCredForm({ ...credForm, name: e.target.value })} placeholder="Windows Domain" /></Field>
                  <Field label="Username"><TextInput value={credForm.username} onChange={(e) => setCredForm({ ...credForm, username: e.target.value })} placeholder="DEMO\\scanner" /></Field>
                  <Field label="Vault ref" required><TextInput value={credForm.vault_ref} onChange={(e) => setCredForm({ ...credForm, vault_ref: e.target.value })} placeholder="local/windows-domain" /></Field>
                  <Field label="Auth method"><NativeSelect value={credForm.auth_method} options={AUTH_METHODS.map((m) => ({ value: m, label: m }))} onChange={(v) => setCredForm({ ...credForm, auth_method: v })} /></Field>
                  <Field label="Rotation days"><TextInput type="number" value={credForm.rotation_policy_days} onChange={(e) => setCredForm({ ...credForm, rotation_policy_days: e.target.value })} placeholder="90" /></Field>
                  <Field label="Description"><TextInput value={credForm.description} onChange={(e) => setCredForm({ ...credForm, description: e.target.value })} /></Field>
                  <Field label="Secret material" hint={credForm.id ? 'Leave blank to keep existing secret.' : 'Optional, but needed before credentialed scans.'}><TextInput type="password" value={credForm.secret_material} onChange={(e) => setCredForm({ ...credForm, secret_material: e.target.value })} autoComplete="new-password" /></Field>
                  <Field label="Status"><label className="flex h-10 items-center gap-2 text-sm text-slate-700"><input type="checkbox" checked={credForm.is_active} onChange={(e) => setCredForm({ ...credForm, is_active: e.target.checked })} />Active</label></Field>
                </div>
                <div className="flex flex-wrap items-center gap-3 border-t border-slate-200 px-4 py-3">
                  <ActionButton variant="primary" disabled={!credForm.name.trim() || !credForm.vault_ref.trim() || createCredState.isLoading || updateState.isLoading} onClick={saveCredential}>{credForm.id ? 'Save credential' : 'Create credential'}</ActionButton>
                  <ActionButton variant="ghost" onClick={() => setCredForm(null)}>Cancel</ActionButton>
                </div>
              </DataPanel>
            )}
            <DataPanel title="Credentials" detail={`${credentialsQ.data?.total ?? 0} credential(s) · secret values are write-only and never displayed`}>
              <DataTable columns={credentialCols} rows={credentialsQ.data?.items ?? []} getRowKey={(c) => c.id} empty="No credentials configured." minWidth={980} />
            </DataPanel>
            {selectedCredential ? (
              <DataPanel title={`Restore secret · ${selectedCredential.name}`} detail={`Stores new secret material at ${selectedCredential.vault_ref}`}>
                <div className="grid gap-4 p-4 md:grid-cols-[1fr_auto] md:items-end">
                  <Field label="Secret material" required hint="Value is sent once to the backend vault and is never displayed again.">
                    <TextInput
                      type="password"
                      value={secret}
                      autoComplete="new-password"
                      onChange={(e) => setSecret(e.target.value)}
                      placeholder="Enter password / token / key"
                    />
                  </Field>
                  <div className="flex gap-2">
                    <ActionButton variant="primary" disabled={!secret || updateState.isLoading} onClick={restoreSecret}>
                      {updateState.isLoading ? 'Saving…' : 'Save secret'}
                    </ActionButton>
                    <ActionButton variant="ghost" onClick={() => { setRestoreId(null); setSecret('') }}>Cancel</ActionButton>
                  </div>
                </div>
                {updateState.isError ? <div className="px-4 pb-4"><ErrorState title="Could not restore secret" detail={apiErrorMessage(updateState.error)} /></div> : null}
              </DataPanel>
            ) : null}
          </div>
        )
      )}
    </PageFrame>
  )
}

function SideDrawer({ title, subtitle, onClose, children }: { title: string; subtitle: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-slate-950/30 backdrop-blur-[1px]">
      <aside className="flex h-full w-full max-w-xl flex-col border-l border-slate-200 bg-white shadow-2xl">
        <div className="border-b border-slate-200 px-5 py-4">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="text-xs font-semibold uppercase tracking-wide text-blue-700">{title}</div>
              <h2 className="mt-1 text-lg font-semibold text-slate-950">{subtitle}</h2>
            </div>
            <button className="rounded-md px-2 py-1 text-sm font-semibold text-slate-500 hover:bg-slate-100 hover:text-slate-900" onClick={onClose}>Close</button>
          </div>
        </div>
        <div className="flex-1 overflow-y-auto p-5">{children}</div>
      </aside>
    </div>
  )
}

function DrawerActions({ children }: { children: React.ReactNode }) {
  return <div className="sticky bottom-0 mt-4 flex gap-2 border-t border-slate-200 bg-white/95 py-4 backdrop-blur">{children}</div>
}
