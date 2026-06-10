import { useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { createRule, deleteRule, getRules, updateRule } from '@/api/endpoints'
import type { PrivilegeClass, Rule } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PrivilegeBadge } from '@/components/PrivilegeBadge'
import { PageSpinner } from '@/components/Spinner'
import { PLATFORM_LABELS } from '@/lib/privilege'
import toast from 'react-hot-toast'

const CLASSES: PrivilegeClass[] = [
  'full_admin',
  'admin_equivalent',
  'operator_high_impact',
  'delegated_admin',
  'privileged_service',
  'sensitive_non_admin',
  'dormant_privileged',
  'non_privileged',
  'unknown_review_required',
]

export default function Rules() {
  const qc = useQueryClient()
  const [platform, setPlatform] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)
  const [editing, setEditing] = useState<Rule | null>(null)
  const [form, setForm] = useState<Record<string, any>>(blankRule())

  const { data, isLoading } = useQuery({
    queryKey: ['rules', platform],
    queryFn: () => getRules({ platform: platform || undefined, limit: 100 }).then((r) => r.data),
  })

  const createMut = useMutation({
    mutationFn: (data: Record<string, unknown>) => createRule(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] })
      setShowCreate(false)
      setForm(blankRule())
      toast.success('Rule created')
    },
    onError: () => toast.error('Failed to create rule'),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) => updateRule(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] })
      setEditing(null)
      toast.success('Rule updated')
    },
    onError: () => toast.error('Failed to update rule'),
  })

  const delMut = useMutation({
    mutationFn: (id: string) => deleteRule(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['rules'] }); toast.success('Rule deleted') },
    onError: () => toast.error('Failed to delete rule'),
  })

  return (
    <div>
      <PageHeader
        title="Classification Rules"
        subtitle={data ? `${data.total} rules` : ''}
        actions={<button className="btn-primary" onClick={() => setShowCreate(true)}>+ Add Rule</button>}
      />

      <div className="px-6 py-3 border-b border-slate-200 bg-white flex gap-3">
        <select className="input w-40" value={platform} onChange={(e) => setPlatform(e.target.value)}>
          <option value="">All platforms</option>
          {Object.entries(PLATFORM_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
      </div>

      {isLoading ? <PageSpinner /> : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                <th className="table-th">Key</th>
                <th className="table-th">Platform</th>
                <th className="table-th">Classifies As</th>
                <th className="table-th">Confidence</th>
                <th className="table-th">Priority</th>
                <th className="table-th">Enabled</th>
                <th className="table-th">v</th>
                <th className="table-th">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data?.items.map((r) => (
                <>
                  <tr key={r.id} className="hover:bg-slate-50 cursor-pointer" onClick={() => setExpanded(expanded === r.id ? null : r.id)}>
                    <td className="table-td font-mono text-xs text-slate-700 font-semibold">{r.rule_key}</td>
                    <td className="table-td">
                      {r.platform ? <span className="badge bg-slate-100 text-slate-600">{PLATFORM_LABELS[r.platform]}</span> : <span className="text-slate-400 text-xs">any</span>}
                    </td>
                    <td className="table-td"><PrivilegeBadge classification={r.classify_as} size="sm" /></td>
                    <td className="table-td text-slate-500">{r.confidence}%</td>
                    <td className="table-td text-slate-500">{r.priority}</td>
                    <td className="table-td">
                      <span className={`badge ${r.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-400'}`}>
                        {r.enabled ? 'on' : 'off'}
                      </span>
                    </td>
                    <td className="table-td text-slate-400 text-xs">{r.version}</td>
                    <td className="table-td">
                      <div className="flex gap-1.5">
                        <button className="btn-secondary text-xs py-1" onClick={(e) => { e.stopPropagation(); setEditing(r) }}>Edit</button>
                        <button className="btn text-xs py-1 text-red-600 hover:bg-red-50 border border-red-200" onClick={(e) => { e.stopPropagation(); if (confirm(`Delete rule ${r.rule_key}?`)) delMut.mutate(r.id) }}>Delete</button>
                      </div>
                    </td>
                  </tr>
                  {expanded === r.id && (
                    <tr key={`${r.id}-exp`}>
                      <td colSpan={8} className="px-6 pb-4 bg-slate-50">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2">
                          <div>
                            <div className="text-xs font-semibold text-slate-500 mb-1">Description</div>
                            <p className="text-xs text-slate-600">{r.description ?? '—'}</p>
                            <div className="text-xs font-semibold text-slate-500 mt-3 mb-1">Explanation Template</div>
                            <p className="text-xs text-slate-600 italic">{r.explanation_template}</p>
                          </div>
                          <div>
                            <div className="text-xs font-semibold text-slate-500 mb-1">Predicate</div>
                            <pre className="text-[11px] font-mono bg-white border border-slate-200 rounded p-2 overflow-auto max-h-32">
                              {JSON.stringify(r.predicate, null, 2)}
                            </pre>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
              {data?.items.length === 0 && (
                <tr><td colSpan={8} className="py-12 text-center text-slate-400">No rules found.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {showCreate && (
        <RuleModal
          title="Add Rule"
          form={form}
          onClose={() => setShowCreate(false)}
          onChange={setForm}
          onSave={() => createMut.mutate(toRulePayload(form))}
          saving={createMut.isPending}
        />
      )}

      {editing && (
        <RuleModal
          title={`Edit ${editing.rule_key}`}
          form={editing}
          onClose={() => setEditing(null)}
          onChange={(next) => setEditing({ ...editing, ...next })}
          onSave={() => updateMut.mutate({ id: editing.id, data: toRulePayload(editing) })}
          saving={updateMut.isPending}
        />
      )}
    </div>
  )
}

function RuleModal({
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
          <Field label="Rule Key"><input className="input" value={form.rule_key ?? ''} onChange={(e) => update({ rule_key: e.target.value })} /></Field>
          <Field label="Name"><input className="input" value={form.name ?? ''} onChange={(e) => update({ name: e.target.value })} /></Field>
          <Field label="Platform">
            <select className="input" value={form.platform ?? ''} onChange={(e) => update({ platform: e.target.value || null })}>
              <option value="">Any</option>
              {Object.entries(PLATFORM_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </Field>
          <Field label="Classification">
            <select className="input" value={form.classify_as} onChange={(e) => update({ classify_as: e.target.value })}>
              {CLASSES.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          </Field>
          <Field label="Confidence"><input className="input" type="number" value={form.confidence ?? 90} onChange={(e) => update({ confidence: Number(e.target.value) })} /></Field>
          <Field label="Priority"><input className="input" type="number" value={form.priority ?? 100} onChange={(e) => update({ priority: Number(e.target.value) })} /></Field>
          <Field label="Risk Modifier"><input className="input" type="number" value={form.risk_modifier ?? 0} onChange={(e) => update({ risk_modifier: Number(e.target.value) })} /></Field>
          <label className="flex items-center gap-2 text-sm cursor-pointer mt-7">
            <input type="checkbox" checked={!!form.enabled} onChange={(e) => update({ enabled: e.target.checked })} />
            Rule enabled
          </label>
          <div className="md:col-span-2">
            <Field label="Description"><input className="input" value={form.description ?? ''} onChange={(e) => update({ description: e.target.value })} /></Field>
          </div>
          <div className="md:col-span-2">
            <Field label="Explanation Template"><textarea className="input min-h-20" value={form.explanation_template ?? ''} onChange={(e) => update({ explanation_template: e.target.value })} /></Field>
          </div>
          <div className="md:col-span-2">
            <Field label="Predicate JSON"><textarea className="input min-h-40 font-mono text-xs" value={typeof form.predicate === 'string' ? form.predicate : JSON.stringify(form.predicate ?? {}, null, 2)} onChange={(e) => update({ predicate: e.target.value })} /></Field>
          </div>
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

function blankRule() {
  return {
    rule_key: '',
    name: '',
    description: '',
    platform: '',
    predicate: '{}',
    classify_as: 'unknown_review_required',
    confidence: 90,
    risk_modifier: 0,
    explanation_template: '',
    priority: 100,
    enabled: true,
  }
}

function toRulePayload(form: Record<string, any>) {
  try {
    return { ...form, predicate: typeof form.predicate === 'string' ? JSON.parse(form.predicate || '{}') : form.predicate }
  } catch {
    toast.error('Predicate must be valid JSON')
    throw new Error('Invalid predicate JSON')
  }
}
