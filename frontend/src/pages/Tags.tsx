import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getTags, createTag, updateTag, patchTagStatus, deleteTag } from '@/api/endpoints'
import type { Tag, TagCategory, TagStatus } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PageSpinner } from '@/components/Spinner'
import { TagBadge } from '@/components/TagBadge'
import toast from 'react-hot-toast'
import { format } from 'date-fns'

// ── Constants ─────────────────────────────────────────────────────────────────

const CATEGORIES: { value: TagCategory; label: string }[] = [
  { value: 'application',   label: 'Application' },
  { value: 'environment',   label: 'Environment' },
  { value: 'business_unit', label: 'Business Unit' },
  { value: 'criticality',   label: 'Criticality' },
  { value: 'compliance',    label: 'Compliance' },
  { value: 'ownership',     label: 'Ownership' },
  { value: 'technology',    label: 'Technology' },
  { value: 'custom',        label: 'Custom' },
]

const CATEGORY_LABELS: Record<TagCategory, string> = Object.fromEntries(
  CATEGORIES.map((c) => [c.value, c.label])
) as Record<TagCategory, string>

const COLOR_PRESETS = [
  '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
  '#f97316', '#06b6d4', '#64748b', '#6366f1', '#ec4899',
]

const EMPTY_FORM = {
  tag_name: '',
  tag_code: '',
  description: '',
  category: 'custom' as TagCategory,
  color: '#6366f1',
  status: 'active' as TagStatus,
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function Tags() {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [filterCat, setFilterCat] = useState('')
  const [filterStatus, setFilterStatus] = useState('active')
  const [showModal, setShowModal] = useState(false)
  const [editing, setEditing] = useState<Tag | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['tags', search, filterCat, filterStatus],
    queryFn: () =>
      getTags({
        search: search || undefined,
        category: filterCat || undefined,
        status: filterStatus || undefined,
        limit: 200,
      }).then((r) => r.data),
  })

  const createMut = useMutation({
    mutationFn: (d: Partial<Tag>) => createTag(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tags'] })
      setShowModal(false)
      toast.success('Tag created')
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Failed to create tag'),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Tag> }) => updateTag(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tags'] })
      setEditing(null)
      toast.success('Tag updated')
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Failed to update tag'),
  })

  const statusMut = useMutation({
    mutationFn: ({ id, status }: { id: string; status: TagStatus }) =>
      patchTagStatus(id, status),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tags'] })
      toast.success('Tag status updated')
    },
    onError: () => toast.error('Failed to update status'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteTag(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tags'] })
      toast.success('Tag deleted')
    },
    onError: (e: any) =>
      toast.error(e?.response?.data?.detail ?? 'Cannot delete tag'),
  })

  const handleDelete = (tag: Tag) => {
    if (tag.usage_count > 0) {
      toast.error(`Cannot delete — tag is assigned to ${tag.usage_count} asset(s). Deactivate it instead.`)
      return
    }
    if (!confirm(`Delete tag "${tag.tag_name}"? This cannot be undone.`)) return
    deleteMut.mutate(tag.id)
  }

  return (
    <div>
      <PageHeader
        title="Tag Management"
        subtitle={data ? `${data.total} tag${data.total !== 1 ? 's' : ''}` : ''}
        actions={
          <button className="btn-primary" onClick={() => { setEditing(null); setShowModal(true) }}>
            + New Tag
          </button>
        }
      />

      {/* Filters */}
      <div className="px-6 py-3 border-b border-slate-200 bg-white flex flex-wrap gap-3">
        <input
          className="input w-56"
          placeholder="Search name or code…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select className="input w-44" value={filterCat} onChange={(e) => setFilterCat(e.target.value)}>
          <option value="">All categories</option>
          {CATEGORIES.map((c) => (
            <option key={c.value} value={c.value}>{c.label}</option>
          ))}
        </select>
        <select className="input w-36" value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}>
          <option value="">All statuses</option>
          <option value="active">Active</option>
          <option value="inactive">Inactive</option>
        </select>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        {isLoading ? <PageSpinner /> : (
          <table className="w-full">
            <thead className="bg-slate-50 border-b border-slate-200 sticky top-0">
              <tr>
                <th className="table-th">Tag</th>
                <th className="table-th">Code</th>
                <th className="table-th">Category</th>
                <th className="table-th">Color</th>
                <th className="table-th">Description</th>
                <th className="table-th">Status</th>
                <th className="table-th text-center">Assets</th>
                <th className="table-th">Created</th>
                <th className="table-th">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data?.items.map((tag) => (
                <tr key={tag.id} className="hover:bg-slate-50">
                  <td className="table-td">
                    <TagBadge tag={tag} />
                  </td>
                  <td className="table-td font-mono text-xs text-slate-500">
                    {tag.tag_code ?? <span className="text-slate-300">—</span>}
                  </td>
                  <td className="table-td">
                    <span className="badge bg-slate-100 text-slate-600 text-xs">
                      {CATEGORY_LABELS[tag.category]}
                    </span>
                  </td>
                  <td className="table-td">
                    <div className="flex items-center gap-2">
                      <span
                        className="inline-block w-5 h-5 rounded border border-slate-200 flex-shrink-0"
                        style={{ backgroundColor: tag.color }}
                      />
                      <span className="font-mono text-xs text-slate-500">{tag.color}</span>
                    </div>
                  </td>
                  <td className="table-td text-xs text-slate-500 max-w-xs truncate" title={tag.description ?? ''}>
                    {tag.description ?? <span className="text-slate-300">—</span>}
                  </td>
                  <td className="table-td">
                    <span className={`badge text-xs ${tag.status === 'active' ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-500'}`}>
                      {tag.status}
                    </span>
                  </td>
                  <td className="table-td text-center">
                    <span className={`text-sm font-medium ${tag.usage_count > 0 ? 'text-brand-600' : 'text-slate-300'}`}>
                      {tag.usage_count}
                    </span>
                  </td>
                  <td className="table-td text-xs text-slate-400">
                    {format(new Date(tag.created_at), 'dd MMM yy')}
                    {tag.created_by && <div className="text-slate-300">{tag.created_by}</div>}
                  </td>
                  <td className="table-td">
                    <div className="flex items-center gap-2">
                      <button
                        className="text-xs text-brand-600 hover:text-brand-700 font-medium"
                        onClick={() => { setEditing(tag); setShowModal(true) }}
                      >
                        Edit
                      </button>
                      <button
                        className="text-xs text-slate-500 hover:text-slate-700"
                        onClick={() =>
                          statusMut.mutate({
                            id: tag.id,
                            status: tag.status === 'active' ? 'inactive' : 'active',
                          })
                        }
                      >
                        {tag.status === 'active' ? 'Deactivate' : 'Activate'}
                      </button>
                      <button
                        className="text-xs text-red-500 hover:text-red-700 disabled:opacity-30"
                        disabled={tag.usage_count > 0}
                        onClick={() => handleDelete(tag)}
                        title={tag.usage_count > 0 ? `Assigned to ${tag.usage_count} asset(s) — deactivate instead` : 'Delete tag'}
                      >
                        Delete
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {data?.items.length === 0 && (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-slate-400">
                    No tags found.{' '}
                    <button className="text-brand-600 hover:underline" onClick={() => { setEditing(null); setShowModal(true) }}>
                      Create the first one
                    </button>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* Create / Edit Modal */}
      {showModal && (
        <TagModal
          initial={editing}
          onClose={() => { setShowModal(false); setEditing(null) }}
          onSave={(form) => {
            if (editing) {
              updateMut.mutate({ id: editing.id, data: form })
            } else {
              createMut.mutate(form)
            }
          }}
          saving={createMut.isPending || updateMut.isPending}
        />
      )}
    </div>
  )
}

// ── Tag Create / Edit Modal ────────────────────────────────────────────────────

function TagModal({
  initial,
  onClose,
  onSave,
  saving,
}: {
  initial: Tag | null
  onClose: () => void
  onSave: (form: Partial<Tag>) => void
  saving: boolean
}) {
  const [form, setForm] = useState<typeof EMPTY_FORM>(() =>
    initial
      ? {
          tag_name: initial.tag_name,
          tag_code: initial.tag_code ?? '',
          description: initial.description ?? '',
          category: initial.category,
          color: initial.color,
          status: initial.status,
        }
      : { ...EMPTY_FORM }
  )

  const update = (patch: Partial<typeof EMPTY_FORM>) => setForm((f) => ({ ...f, ...patch }))

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSave({
      ...form,
      tag_code: form.tag_code || null,
      description: form.description || null,
    })
  }

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-lg p-6">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-base font-semibold text-slate-900">
            {initial ? 'Edit Tag' : 'New Tag'}
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Tag name */}
          <div>
            <label className="label">Tag Name *</label>
            <input
              className="input"
              required
              value={form.tag_name}
              onChange={(e) => update({ tag_name: e.target.value })}
              placeholder="e.g. SAP, CoreBanking, PCI"
            />
          </div>

          {/* Tag code */}
          <div>
            <label className="label">Short Code <span className="text-slate-400">(optional)</span></label>
            <input
              className="input font-mono"
              value={form.tag_code}
              onChange={(e) => update({ tag_code: e.target.value })}
              placeholder="e.g. sap, core-banking, pci"
            />
          </div>

          {/* Category */}
          <div>
            <label className="label">Category *</label>
            <select
              className="input"
              value={form.category}
              onChange={(e) => update({ category: e.target.value as TagCategory })}
            >
              {CATEGORIES.map((c) => (
                <option key={c.value} value={c.value}>{c.label}</option>
              ))}
            </select>
          </div>

          {/* Color */}
          <div>
            <label className="label">Color</label>
            <div className="flex items-center gap-3">
              <input
                type="color"
                className="w-10 h-10 rounded border border-slate-200 cursor-pointer p-0.5"
                value={form.color}
                onChange={(e) => update({ color: e.target.value })}
              />
              <div className="flex flex-wrap gap-1.5">
                {COLOR_PRESETS.map((c) => (
                  <button
                    key={c}
                    type="button"
                    className={`w-6 h-6 rounded-full border-2 transition-transform hover:scale-110 ${form.color === c ? 'border-slate-900 scale-110' : 'border-transparent'}`}
                    style={{ backgroundColor: c }}
                    onClick={() => update({ color: c })}
                    aria-label={`Set color ${c}`}
                  />
                ))}
              </div>
            </div>
            {/* Preview */}
            <div className="mt-2">
              <TagBadge tag={{ tag_name: form.tag_name || 'Preview', color: form.color }} />
            </div>
          </div>

          {/* Description */}
          <div>
            <label className="label">Description <span className="text-slate-400">(optional)</span></label>
            <textarea
              className="input resize-none"
              rows={2}
              value={form.description}
              onChange={(e) => update({ description: e.target.value })}
              placeholder="Brief description of what this tag represents…"
            />
          </div>

          {/* Status (edit only) */}
          {initial && (
            <div>
              <label className="label">Status</label>
              <select
                className="input w-40"
                value={form.status}
                onChange={(e) => update({ status: e.target.value as TagStatus })}
              >
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
              </select>
            </div>
          )}

          <div className="flex gap-2 pt-2">
            <button type="submit" className="btn-primary" disabled={saving || !form.tag_name}>
              {saving ? 'Saving…' : initial ? 'Save Changes' : 'Create Tag'}
            </button>
            <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
          </div>
        </form>
      </div>
    </div>
  )
}
