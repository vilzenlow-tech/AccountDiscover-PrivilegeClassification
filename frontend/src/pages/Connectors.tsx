import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  createConnector,
  createCredential,
  deleteConnector,
  deleteCredential,
  getConnectors,
  getCredentials,
  updateConnector,
  updateCredential,
} from '@/api/endpoints'
import type { Connector, Credential } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PageSpinner } from '@/components/Spinner'
import toast from 'react-hot-toast'
import { format } from 'date-fns'
import type { AxiosError } from 'axios'

const CONNECTOR_KINDS = ['ssh', 'winrm', 'mysql', 'mssql', 'mongodb', 'oracle', 'postgresql', 'redis']
const VAULT_BACKENDS = ['local', 'cyberark', 'hashicorp', 'azure', 'aws']

export default function Connectors() {
  const qc = useQueryClient()
  const [connectorModal, setConnectorModal] = useState(false)
  const [credentialModal, setCredentialModal] = useState(false)
  const [editingConnector, setEditingConnector] = useState<Connector | null>(null)
  const [editingCredential, setEditingCredential] = useState<Credential | null>(null)
  const [connectorForm, setConnectorForm] = useState<Record<string, any>>({ kind: 'ssh', is_active: true })
  const [credentialForm, setCredentialForm] = useState<Record<string, any>>({ vault_backend: 'local', auth_method: 'password', is_active: true })

  const { data: connectors, isLoading: connectorsLoading } = useQuery({
    queryKey: ['connectors'],
    queryFn: () => getConnectors({ limit: 100 }).then((r) => r.data),
  })

  const { data: credentials, isLoading: credentialsLoading } = useQuery({
    queryKey: ['credentials'],
    queryFn: () => getCredentials({ limit: 100 }).then((r) => r.data),
  })

  const connectorCreateMut = useMutation({
    mutationFn: (data: Record<string, unknown>) => createConnector(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['connectors'] })
      setConnectorModal(false)
      setConnectorForm({ kind: 'ssh', is_active: true })
      toast.success('Connector created')
    },
    onError: () => toast.error('Failed to create connector'),
  })

  const connectorUpdateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) => updateConnector(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['connectors'] })
      setEditingConnector(null)
      toast.success('Connector updated')
    },
    onError: () => toast.error('Failed to update connector'),
  })

  const connectorDeleteMut = useMutation({
    mutationFn: (id: string) => deleteConnector(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['connectors'] })
      toast.success('Connector deleted')
    },
    onError: () => toast.error('Failed to delete connector'),
  })

  const credentialCreateMut = useMutation({
    mutationFn: (data: Record<string, unknown>) => createCredential(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['credentials'] })
      setCredentialModal(false)
      setCredentialForm({ vault_backend: 'local', auth_method: 'password', is_active: true })
      toast.success('Credential created')
    },
    onError: (error: AxiosError<{ detail?: string }>) => {
      toast.error(getApiErrorMessage(error, 'Failed to create credential'))
    },
  })

  const credentialUpdateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) => updateCredential(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['credentials'] })
      qc.invalidateQueries({ queryKey: ['connectors'] })
      setEditingCredential(null)
      toast.success('Credential updated')
    },
    onError: (error: AxiosError<{ detail?: string }>) => {
      toast.error(getApiErrorMessage(error, 'Failed to update credential'))
    },
  })

  const credentialDeleteMut = useMutation({
    mutationFn: (id: string) => deleteCredential(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['credentials'] })
      qc.invalidateQueries({ queryKey: ['connectors'] })
      toast.success('Credential deleted')
    },
    onError: () => toast.error('Failed to delete credential'),
  })

  const isLoading = connectorsLoading || credentialsLoading

  return (
    <div>
      <PageHeader
        title="Connectors & Credentials"
        subtitle="Discovery connector configuration and secret references"
        actions={
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={() => setCredentialModal(true)}>+ Credential</button>
            <button className="btn-primary" onClick={() => setConnectorModal(true)}>+ Connector</button>
          </div>
        }
      />

      {isLoading ? <PageSpinner /> : (
        <div className="p-6 grid grid-cols-1 xl:grid-cols-2 gap-4">
          <div className="card overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-100 text-sm font-semibold text-slate-700">Credentials</div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-slate-50 border-b border-slate-200">
                  <tr>
                    <th className="table-th">Name</th>
                    <th className="table-th">Backend</th>
                    <th className="table-th">Username</th>
                    <th className="table-th">Reference</th>
                    <th className="table-th">Active</th>
                    <th className="table-th">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {credentials?.items.map((c) => (
                    <tr key={c.id} className="hover:bg-slate-50">
                      <td className="table-td font-medium">
                        <div className="flex items-center gap-1.5">
                          {c.name}
                          {c.rotation_overdue && (
                            <span
                              className="badge bg-amber-100 text-amber-700 border border-amber-300 text-[10px]"
                              title={`Rotation overdue — last rotated: ${c.last_rotated_at ? new Date(c.last_rotated_at).toLocaleDateString() : 'never'} (policy: ${c.rotation_policy_days}d)`}
                            >
                              ⚠ Rotate
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="table-td text-slate-500">{c.vault_backend}</td>
                      <td className="table-td text-slate-500">{c.username}</td>
                      <td className="table-td text-xs text-slate-400">{c.vault_ref}</td>
                      <td className="table-td">
                        <span className={`badge ${c.is_active ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-400'}`}>
                          {c.is_active ? 'active' : 'inactive'}
                        </span>
                      </td>
                      <td className="table-td">
                        <div className="flex gap-1.5">
                          <button className="btn-secondary text-xs py-1" onClick={() => setEditingCredential(c)}>Edit</button>
                          <button className="btn text-xs py-1 text-red-600 hover:bg-red-50 border border-red-200" onClick={() => {
                            if (confirm(`Delete credential ${c.name}?`)) credentialDeleteMut.mutate(c.id)
                          }}>Del</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {credentials?.items.length === 0 && <tr><td colSpan={6} className="py-12 text-center text-slate-400">No credentials configured.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-100 text-sm font-semibold text-slate-700">Connectors</div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-slate-50 border-b border-slate-200">
                  <tr>
                    <th className="table-th">Name</th>
                    <th className="table-th">Kind</th>
                    <th className="table-th">Port</th>
                    <th className="table-th">Credential</th>
                    <th className="table-th">Active</th>
                    <th className="table-th">Created</th>
                    <th className="table-th">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {connectors?.items.map((c) => (
                    <tr key={c.id} className="hover:bg-slate-50">
                      <td className="table-td font-medium">{c.name}</td>
                      <td className="table-td"><span className="badge bg-slate-100 text-slate-600">{c.kind}</span></td>
                      <td className="table-td text-slate-500">{c.default_port ?? '—'}</td>
                      <td className="table-td text-slate-400 text-xs">{credentials?.items.find((cred) => cred.id === c.credential_id)?.name ?? '—'}</td>
                      <td className="table-td">
                        <span className={`badge ${c.is_active ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-400'}`}>
                          {c.is_active ? 'active' : 'inactive'}
                        </span>
                      </td>
                      <td className="table-td text-slate-400 text-xs">{format(new Date(c.created_at), 'dd MMM yyyy')}</td>
                      <td className="table-td">
                        <div className="flex gap-1.5">
                          <button className="btn-secondary text-xs py-1" onClick={() => setEditingConnector(c)}>Edit</button>
                          <button className="btn text-xs py-1 text-red-600 hover:bg-red-50 border border-red-200" onClick={() => {
                            if (confirm(`Delete connector ${c.name}?`)) connectorDeleteMut.mutate(c.id)
                          }}>Del</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {connectors?.items.length === 0 && <tr><td colSpan={7} className="py-12 text-center text-slate-400">No connectors configured.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {credentialModal && (
        <Modal title="Add Credential" onClose={() => setCredentialModal(false)}>
          <CredentialForm form={credentialForm} setForm={setCredentialForm} />
          <div className="flex gap-2 pt-4">
            <button className="btn-primary" disabled={credentialCreateMut.isPending}
              onClick={() => {
                const payload = { ...credentialForm }
                if (!payload.vault_ref) payload.vault_ref = `local/${payload.name ?? 'cred'}`
                credentialCreateMut.mutate(payload)
              }}>
              {credentialCreateMut.isPending ? 'Saving…' : 'Save'}
            </button>
            <button className="btn-secondary" onClick={() => setCredentialModal(false)}>Cancel</button>
          </div>
        </Modal>
      )}

      {editingCredential && (
        <Modal title={`Edit ${editingCredential.name}`} onClose={() => setEditingCredential(null)}>
          <CredentialForm form={{ ...editingCredential }} setForm={(next) => setEditingCredential({ ...editingCredential, ...next })} />
          <div className="flex gap-2 pt-4">
            <button className="btn-primary" onClick={() => credentialUpdateMut.mutate({ id: editingCredential.id, data: { ...editingCredential } })} disabled={credentialUpdateMut.isPending}>Save</button>
            <button className="btn-secondary" onClick={() => setEditingCredential(null)}>Cancel</button>
          </div>
        </Modal>
      )}

      {connectorModal && (
        <Modal title="Add Connector" onClose={() => setConnectorModal(false)}>
          <ConnectorForm form={connectorForm} setForm={setConnectorForm} credentials={credentials?.items ?? []} />
          <div className="flex gap-2 pt-4">
            <button className="btn-primary" onClick={() => connectorCreateMut.mutate(connectorForm)} disabled={connectorCreateMut.isPending}>Save</button>
            <button className="btn-secondary" onClick={() => setConnectorModal(false)}>Cancel</button>
          </div>
        </Modal>
      )}

      {editingConnector && (
        <Modal title={`Edit ${editingConnector.name}`} onClose={() => setEditingConnector(null)}>
          <ConnectorForm form={{ ...editingConnector }} setForm={(next) => setEditingConnector({ ...editingConnector, ...next })} credentials={credentials?.items ?? []} />
          <div className="flex gap-2 pt-4">
            <button className="btn-primary" onClick={() => connectorUpdateMut.mutate({ id: editingConnector.id, data: { ...editingConnector } })} disabled={connectorUpdateMut.isPending}>Save</button>
            <button className="btn-secondary" onClick={() => setEditingConnector(null)}>Cancel</button>
          </div>
        </Modal>
      )}
    </div>
  )
}

const AUTH_METHODS = ['password', 'key', 'token', 'cert']

function CredentialForm({ form, setForm }: { form: Record<string, any>; setForm: (next: any) => void }) {
  const [showSecret, setShowSecret] = useState(false)
  const update = (patch: Record<string, any>) => setForm({ ...form, ...patch })
  const isKey = form.auth_method === 'key'
  return (
    <div className="space-y-3">
      <Field label="Name *">
        <input className="input" value={form.name ?? ''} onChange={(e) => update({ name: e.target.value })} placeholder="e.g. prod-linux-ssh" />
      </Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Username *">
          <input className="input" value={form.username ?? ''} onChange={(e) => update({ username: e.target.value })} placeholder="e.g. svc_discovery" />
        </Field>
        <Field label="Auth Method *">
          <select className="input" value={form.auth_method ?? 'password'} onChange={(e) => update({ auth_method: e.target.value })}>
            {AUTH_METHODS.map(m => <option key={m} value={m}>{m}</option>)}
          </select>
        </Field>
      </div>
      <Field label={isKey ? 'Private Key *' : 'Password *'}>
        {isKey ? (
          <textarea
            className="input font-mono text-xs"
            rows={5}
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----&#10;..."
            value={form.secret_material ?? ''}
            onChange={(e) => update({ secret_material: e.target.value })}
          />
        ) : (
          <div className="relative">
            <input
              className="input pr-16"
              type={showSecret ? 'text' : 'password'}
              placeholder="Enter password"
              value={form.secret_material ?? ''}
              onChange={(e) => update({ secret_material: e.target.value })}
            />
            <button
              type="button"
              className="absolute right-2 top-1/2 -translate-y-1/2 text-xs text-slate-400 hover:text-slate-600"
              onClick={() => setShowSecret(s => !s)}
            >
              {showSecret ? 'Hide' : 'Show'}
            </button>
          </div>
        )}
      </Field>
      <div className="border-t border-slate-100 pt-3">
        <p className="text-xs text-slate-400 mb-2">Vault settings — leave as-is for local storage</p>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Vault Backend">
            <select className="input" value={form.vault_backend ?? 'local'} onChange={(e) => update({ vault_backend: e.target.value })}>
              {VAULT_BACKENDS.map(b => <option key={b} value={b}>{b}</option>)}
            </select>
          </Field>
          <Field label="Vault Ref">
            <input className="input font-mono text-xs" value={form.vault_ref ?? ''} onChange={(e) => update({ vault_ref: e.target.value })} placeholder="auto-generated if blank" />
          </Field>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Rotation Policy (days)">
          <input
            className="input"
            type="number"
            min="1"
            placeholder="e.g. 90"
            value={form.rotation_policy_days ?? ''}
            onChange={(e) => update({ rotation_policy_days: e.target.value ? Number(e.target.value) : null })}
          />
        </Field>
        <Field label="Description">
          <input className="input" value={form.description ?? ''} onChange={(e) => update({ description: e.target.value })} />
        </Field>
      </div>
    </div>
  )
}

function ConnectorForm({
  form,
  setForm,
  credentials,
}: {
  form: Record<string, any>
  setForm: (next: any) => void
  credentials: Credential[]
}) {
  const update = (patch: Record<string, any>) => setForm({ ...form, ...patch })
  return (
    <div className="space-y-3">
      <Field label="Name"><input className="input" value={form.name ?? ''} onChange={(e) => update({ name: e.target.value })} /></Field>
      <Field label="Kind">
        <select className="input" value={form.kind} onChange={(e) => update({ kind: e.target.value })}>
          {CONNECTOR_KINDS.map((kind) => <option key={kind} value={kind}>{kind}</option>)}
        </select>
      </Field>
      <Field label="Default Port">
        <input className="input" type="number" value={form.default_port ?? ''} onChange={(e) => update({ default_port: e.target.value ? Number(e.target.value) : null })} />
      </Field>
      <Field label="Credential">
        <select className="input" value={form.credential_id ?? ''} onChange={(e) => update({ credential_id: e.target.value || null })}>
          <option value="">None</option>
          {credentials.map((cred) => <option key={cred.id} value={cred.id}>{cred.name}</option>)}
        </select>
      </Field>
      <Field label="Proxy Host"><input className="input" value={form.proxy_host ?? ''} onChange={(e) => update({ proxy_host: e.target.value })} /></Field>
      <Field label="Proxy Port"><input className="input" type="number" value={form.proxy_port ?? ''} onChange={(e) => update({ proxy_port: e.target.value ? Number(e.target.value) : null })} /></Field>
      <label className="flex items-center gap-2 text-sm cursor-pointer">
        <input type="checkbox" checked={!!form.is_active} onChange={(e) => update({ is_active: e.target.checked })} />
        Connector active
      </label>
    </div>
  )
}

function Modal({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/30 flex items-start justify-center z-50 p-4 overflow-y-auto">
      <div className="card w-full max-w-lg p-6 my-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-slate-900">{title}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
        </div>
        {children}
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><label className="label">{label}</label>{children}</div>
}

function getApiErrorMessage(error: AxiosError<any>, fallback: string): string {
  const detail = error.response?.data?.detail
  if (typeof detail === 'string' && detail.trim()) return detail
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0]
    if (typeof first === 'string' && first.trim()) return first
    if (first && typeof first === 'object' && typeof first.msg === 'string') return first.msg
  }
  if (detail && typeof detail === 'object' && typeof detail.msg === 'string') return detail.msg
  return fallback
}
