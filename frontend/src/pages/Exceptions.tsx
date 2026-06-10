import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createException, deleteException, getExceptions, updateException } from '@/api/endpoints'
import type { ExceptionRule, PrivilegeClass } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PageSpinner } from '@/components/Spinner'
import { PrivilegeBadge } from '@/components/PrivilegeBadge'
import { format } from 'date-fns'
import toast from 'react-hot-toast'

const SCOPES = ['global', 'account', 'asset', 'group', 'rule']
const CLASSES: Array<PrivilegeClass | ''> = ['', 'full_admin', 'admin_equivalent', 'operator_high_impact', 'delegated_admin', 'privileged_service', 'sensitive_non_admin', 'dormant_privileged', 'non_privileged', 'unknown_review_required']

export default function Exceptions() {
  const qc = useQueryClient()
  const [showCreate, setShowCreate] = useState(false)
  const [editing, setEditing] = useState<ExceptionRule | null>(null)
  const [form, setForm] = useState<Record<string, any>>(blankException())

  const { data, isLoading } = useQuery({
    queryKey: ['exceptions'],
    queryFn: () => getExceptions({ limit: 100 }).then((r) => r.data),
  })

  const createMut = useMutation({
    mutationFn: (data: Record<string, unknown>) => createException(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['exceptions'] })
      setShowCreate(false)
      setForm(blankException())
      toast.success('Exception created')
    },
    onError: () => toast.error('Failed to create exception'),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) => updateException(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['exceptions'] })
      setEditing(null)
      toast.success('Exception updated')
    },
    onError: () => toast.error('Failed to update exception'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteException(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['exceptions'] })
      toast.success('Exception deleted')
    },
    onError: () => toast.error('Failed to delete exception'),
  })

  return (
    <div>
      <PageHeader
        title="Privilege Exceptions"
        subtitle="Approved suppression rules and risk acceptances"
        actions={<button className="btn-primary" onClick={() => setShowCreate(true)}>+ Add Exception</button>}
      />
      {isLoading ? <PageSpinner /> : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                <th className="table-th">Name</th>
                <th className="table-th">Scope</th>
                <th className="table-th">Downgrade To</th>
                <th className="table-th">Approved By</th>
                <th className="table-th">Expires</th>
                <th className="table-th">Active</th>
                <th className="table-th">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data?.items.map((e) => (
                <tr key={e.id} className="hover:bg-slate-50">
                  <td className="table-td font-medium">{e.name}</td>
                  <td className="table-td"><span className="badge bg-slate-100 text-slate-600">{e.scope}</span></td>
                  <td className="table-td">
                    {e.downgrade_to ? <PrivilegeBadge classification={e.downgrade_to as PrivilegeClass} size="sm" /> : <span className="text-slate-400 text-xs">suppress</span>}
                  </td>
                  <td className="table-td text-slate-500 text-xs">{e.approved_by}</td>
                  <td className="table-td text-slate-400 text-xs">
                    {e.expires_at ? format(new Date(e.expires_at), 'dd MMM yyyy') : 'Never'}
                  </td>
                  <td className="table-td">
                    <span className={`badge ${e.active ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-400'}`}>
                      {e.active ? 'active' : 'inactive'}
                    </span>
                  </td>
                  <td className="table-td">
                    <div className="flex gap-1.5">
                      <button className="btn-secondary text-xs py-1" onClick={() => setEditing(e)}>Edit</button>
                      <button className="btn text-xs py-1 text-red-600 hover:bg-red-50 border border-red-200" onClick={() => {
                        if (confirm(`Delete exception ${e.name}?`)) deleteMut.mutate(e.id)
                      }}>Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
              {data?.items.length === 0 && (
                <tr><td colSpan={7} className="py-12 text-center text-slate-400">No exceptions defined.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <ExceptionModal
          title="Add Exception"
          form={form}
          onClose={() => setShowCreate(false)}
          onChange={setForm}
          onSave={() => createMut.mutate(toExceptionPayload(form))}
          saving={createMut.isPending}
        />
      )}

      {editing && (
        <ExceptionModal
          title={`Edit ${editing.name}`}
          form={editing}
          onClose={() => setEditing(null)}
          onChange={(next) => setEditing({ ...editing, ...next })}
          onSave={() => updateMut.mutate({ id: editing.id, data: toExceptionPayload(editing) })}
          saving={updateMut.isPending}
        />
      )}
    </div>
  )
}

function ExceptionModal({
  title,
  form,
  onClose,
  onChange,
  onSave,
  saving,
}: {
  title: string
  form: Record<string, any>
  onClose: () => void
  onChange: (next: any) => void
  onSave: () => void
  saving: boolean
}) {
  const update = (patch: Record<string, any>) => onChange({ ...form, ...patch })

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-2xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-slate-900">{title}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Field label="Name"><input className="input" value={form.name ?? ''} onChange={(e) => update({ name: e.target.value })} /></Field>
          <Field label="Scope">
            <select className="input" value={form.scope ?? 'account'} onChange={(e) => update({ scope: e.target.value })}>
              {SCOPES.map((scope) => <option key={scope} value={scope}>{scope}</option>)}
            </select>
          </Field>
          <Field label="Approved By"><input className="input" value={form.approved_by ?? ''} onChange={(e) => update({ approved_by: e.target.value })} /></Field>
          <Field label="Approved At"><input className="input" type="datetime-local" value={toInputDate(form.approved_at)} onChange={(e) => update({ approved_at: e.target.value })} /></Field>
          <div className="md:col-span-2">
            <Field label="Description"><input className="input" value={form.description ?? ''} onChange={(e) => update({ description: e.target.value })} /></Field>
          </div>
          <div className="md:col-span-2">
            <Field label="Target JSON"><textarea className="input min-h-28 font-mono text-xs" value={typeof form.target === 'string' ? form.target : JSON.stringify(form.target ?? {}, null, 2)} onChange={(e) => update({ target: e.target.value })} /></Field>
          </div>
          <div className="md:col-span-2">
            <Field label="Rule Keys (comma separated)"><input className="input" value={Array.isArray(form.rule_keys) ? form.rule_keys.join(', ') : form.rule_keys ?? ''} onChange={(e) => update({ rule_keys: e.target.value })} /></Field>
          </div>
          <Field label="Downgrade To">
            <select className="input" value={form.downgrade_to ?? ''} onChange={(e) => update({ downgrade_to: e.target.value || null })}>
              {CLASSES.map((value) => <option key={value || 'blank'} value={value}>{value || 'Suppress only'}</option>)}
            </select>
          </Field>
          <Field label="Expires At"><input className="input" type="datetime-local" value={toInputDate(form.expires_at)} onChange={(e) => update({ expires_at: e.target.value || null })} /></Field>
          <label className="flex items-center gap-2 text-sm cursor-pointer mt-7">
            <input type="checkbox" checked={!!form.active} onChange={(e) => update({ active: e.target.checked })} />
            Exception active
          </label>
        </div>
        <div className="flex gap-2 pt-4">
          <button className="btn-primary" onClick={onSave} disabled={saving}>Save</button>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><label className="label">{label}</label>{children}</div>
}

function blankException() {
  return {
    name: '',
    description: '',
    scope: 'account',
    target: '{}',
    rule_keys: '',
    downgrade_to: null,
    approved_by: '',
    approved_at: new Date().toISOString().slice(0, 16),
    expires_at: '',
    active: true,
  }
}

function toExceptionPayload(form: Record<string, any>) {
  try {
    return {
      ...form,
      target: typeof form.target === 'string' ? JSON.parse(form.target || '{}') : form.target,
      rule_keys: Array.isArray(form.rule_keys) ? form.rule_keys : String(form.rule_keys ?? '').split(',').map((s) => s.trim()).filter(Boolean),
      approved_at: form.approved_at ? new Date(form.approved_at).toISOString() : new Date().toISOString(),
      expires_at: form.expires_at ? new Date(form.expires_at).toISOString() : null,
    }
  } catch {
    toast.error('Target must be valid JSON')
    throw new Error('Invalid exception target JSON')
  }
}

function toInputDate(value: string | null | undefined) {
  if (!value) return ''
  return value.slice(0, 16)
}
