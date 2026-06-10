import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getAssets, createAsset, updateAsset, deleteAsset, toggleAsset,
  importAssetsCsv, getConnectors, getTags, bulkAssignTags, bulkRemoveTags,
  getAssetGroups, createAssetGroup, updateAssetGroup, deleteAssetGroup,
} from '@/api/endpoints'
import type { Asset, AssetGroup, Connector, BulkImportResult, Tag } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PageSpinner } from '@/components/Spinner'
import { TagBadge } from '@/components/TagBadge'
import { PLATFORM_LABELS } from '@/lib/privilege'
import toast from 'react-hot-toast'
import clsx from 'clsx'

const PLATFORMS = Object.keys(PLATFORM_LABELS)

const PLATFORM_CONNECTOR_KIND: Record<string, string> = {
  // Unix / Linux → SSH
  rhel: 'ssh', centos: 'ssh', ubuntu: 'ssh', sles: 'ssh',
  solaris: 'ssh', aix: 'ssh', hpux: 'ssh',
  // Windows
  windows: 'winrm',
  // Databases
  mysql: 'mysql', mssql: 'mssql', mongodb: 'mongodb',
  oracle_db: 'oracle', postgresql: 'postgresql', redis: 'redis',
}

const CSV_TEMPLATE = `hostname,ip_address,platform,port,environment,owner,business_unit,criticality,connector_name
webserver01,192.168.1.10,rhel,22,production,ops-team,IT,high,SSH Default
ubuntu-srv01,192.168.1.11,ubuntu,22,production,ops-team,IT,medium,SSH Default
dbserver01,192.168.1.20,mysql,3306,production,db-team,IT,critical,MySQL Default
pgserver01,192.168.1.21,postgresql,5432,production,db-team,IT,high,PostgreSQL Default
ora01,192.168.1.22,oracle_db,1521,production,db-team,IT,critical,Oracle Default
redis01,192.168.1.23,redis,6379,production,db-team,IT,medium,Redis Default`

export default function Assets() {
  const qc = useQueryClient()
  const [search, setSearch] = useState('')
  const [platform, setPlatform] = useState('')
  const [groupId, setGroupId] = useState('')
  const [filterTagIds, setFilterTagIds] = useState<string[]>([])
  const [activeTab, setActiveTab] = useState<'assets' | 'groups'>('assets')
  const [showAdd, setShowAdd] = useState(false)
  const [editing, setEditing] = useState<Asset | null>(null)
  const [showGroupModal, setShowGroupModal] = useState(false)
  const [editingGroup, setEditingGroup] = useState<AssetGroup | null>(null)
  const [groupForm, setGroupForm] = useState<{ name: string; description: string; asset_ids: string[] }>({ name: '', description: '', asset_ids: [] })
  const [showImport, setShowImport] = useState(false)
  const [form, setForm] = useState<Partial<Asset>>({ platform: 'rhel', discovery_enabled: true, connector_id: null })
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [showBulkTag, setShowBulkTag] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['assets', search, platform, groupId, filterTagIds],
    queryFn: () => getAssets({
      search: search || undefined,
      platform: platform || undefined,
      group_id: groupId || undefined,
      tag_ids: filterTagIds.length ? filterTagIds : undefined,
      limit: 100,
    }).then((r) => r.data),
  })

  const { data: groups = [] } = useQuery({
    queryKey: ['asset-groups'],
    queryFn: () => getAssetGroups().then((r) => r.data),
  })

  const { data: allAssetsData } = useQuery({
    queryKey: ['assets', 'group-picker'],
    queryFn: () => getAssets({ limit: 500 }).then((r) => r.data),
  })
  const groupPickerAssets = allAssetsData?.items ?? []

  const { data: allTagsData } = useQuery({
    queryKey: ['tags', 'active'],
    queryFn: () => getTags({ status: 'active', limit: 200 }).then((r) => r.data),
  })
  const allTags = allTagsData?.items ?? []

  const { data: connectorsData } = useQuery({
    queryKey: ['connectors'],
    queryFn: () => getConnectors({ limit: 200 }).then((r) => r.data),
  })
  const connectors = connectorsData?.items ?? []

  const createMut = useMutation({
    mutationFn: (d: Partial<Asset>) => createAsset(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['assets'] })
      setShowAdd(false)
      setForm({ platform: 'rhel', discovery_enabled: true, connector_id: null })
      toast.success('Asset created')
    },
    onError: () => toast.error('Failed to create asset'),
  })

  const updateMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Asset> }) => updateAsset(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['assets'] })
      setEditing(null)
      toast.success('Asset updated')
    },
    onError: () => toast.error('Failed to update asset'),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteAsset(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['assets'] }); toast.success('Asset deleted') },
  })

  const toggleMut = useMutation({
    mutationFn: (id: string) => toggleAsset(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['assets'] }),
    onError: () => toast.error('Failed to toggle asset'),
  })

  const bulkAssignMut = useMutation({
    mutationFn: ({ assetIds, tagIds }: { assetIds: string[]; tagIds: string[] }) =>
      bulkAssignTags(assetIds, tagIds),
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ['assets'] })
      setSelected(new Set())
      setShowBulkTag(false)
      toast.success(`Assigned tags to ${d.data.assets_affected} asset(s)`)
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Bulk assign failed'),
  })

  const bulkRemoveMut = useMutation({
    mutationFn: ({ assetIds, tagIds }: { assetIds: string[]; tagIds: string[] }) =>
      bulkRemoveTags(assetIds, tagIds),
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ['assets'] })
      setSelected(new Set())
      setShowBulkTag(false)
      toast.success(`Removed tags from ${d.data.assets_affected} asset(s)`)
    },
    onError: () => toast.error('Bulk remove failed'),
  })

  const createGroupMut = useMutation({
    mutationFn: (d: { name: string; description?: string | null; asset_ids: string[] }) => createAssetGroup(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['asset-groups'] })
      qc.invalidateQueries({ queryKey: ['assets'] })
      setShowGroupModal(false)
      setGroupForm({ name: '', description: '', asset_ids: [] })
      setSelected(new Set())
      toast.success('Asset group created')
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Failed to create group'),
  })

  const updateGroupMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: { name: string; description?: string | null; asset_ids: string[] } }) => updateAssetGroup(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['asset-groups'] })
      qc.invalidateQueries({ queryKey: ['assets'] })
      setEditingGroup(null)
      toast.success('Asset group updated')
    },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Failed to update group'),
  })

  const deleteGroupMut = useMutation({
    mutationFn: (id: string) => deleteAssetGroup(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['asset-groups'] })
      qc.invalidateQueries({ queryKey: ['assets'] })
      if (groupId) setGroupId('')
      toast.success('Asset group deleted')
    },
    onError: () => toast.error('Failed to delete group'),
  })

  const toggleSelect = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })

  const toggleSelectAll = () => {
    if (selected.size === (data?.items.length ?? 0)) {
      setSelected(new Set())
    } else {
      setSelected(new Set(data?.items.map((a) => a.id) ?? []))
    }
  }

  function downloadTemplate() {
    const blob = new Blob([CSV_TEMPLATE], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'assets_template.csv'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div>
      <PageHeader
        title="Assets"
        subtitle={data ? `${data.total} assets` : ''}
        actions={
          <div className="flex gap-2">
            <button
              className="btn-secondary"
              onClick={() => {
                setGroupForm({ name: '', description: '', asset_ids: [...selected] })
                setShowGroupModal(true)
              }}
              disabled={selected.size === 0}
            >
              + Group Selected
            </button>
            <button className="btn-secondary" onClick={() => setShowImport(true)}>Import CSV</button>
            <button className="btn-primary" onClick={() => setShowAdd(true)}>+ Add Asset</button>
          </div>
        }
      />

      <div className="px-6 pt-5">
        <div className="inline-flex rounded-lg border border-slate-200 bg-white p-1 shadow-sm">
          {[
            { id: 'assets', label: 'Assets' },
            { id: 'groups', label: 'Groups' },
          ].map((tab) => (
            <button
              key={tab.id}
              className={clsx(
                'px-3 py-1.5 text-sm font-medium rounded-md transition-colors',
                activeTab === tab.id ? 'bg-brand-600 text-white shadow-sm' : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900',
              )}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === 'assets' && (
      <>
      {/* Filters */}
      <div className="px-6 py-3 border-b border-slate-200 bg-white flex flex-wrap gap-3 items-center">
        <input className="input w-56" placeholder="Search hostname…" value={search} onChange={(e) => setSearch(e.target.value)} />
        <select className="input w-40" value={platform} onChange={(e) => setPlatform(e.target.value)}>
          <option value="">All platforms</option>
          {PLATFORMS.map((p) => <option key={p} value={p}>{PLATFORM_LABELS[p]}</option>)}
        </select>
        <select className="input w-48" value={groupId} onChange={(e) => setGroupId(e.target.value)}>
          <option value="">All groups</option>
          {groups.map((g) => <option key={g.id} value={g.id}>{g.name} ({g.asset_count})</option>)}
        </select>
        {/* Tag filter multi-select */}
        <TagFilterDropdown
          tags={allTags}
          selected={filterTagIds}
          onChange={setFilterTagIds}
        />
        {filterTagIds.length > 0 && (
          <button className="text-xs text-slate-400 hover:text-slate-600" onClick={() => setFilterTagIds([])}>
            Clear tags
          </button>
        )}
      </div>

      {/* Bulk action bar */}
      {selected.size > 0 && (
        <div className="px-6 py-2 bg-brand-50 border-b border-brand-100 flex items-center gap-3 text-sm">
          <span className="font-medium text-brand-700">{selected.size} asset{selected.size !== 1 ? 's' : ''} selected</span>
          <button className="btn-secondary text-xs py-1" onClick={() => setShowBulkTag(true)}>
            Manage Tags
          </button>
          <button
            className="btn-secondary text-xs py-1"
            onClick={() => {
              setGroupForm({ name: '', description: '', asset_ids: [...selected] })
              setShowGroupModal(true)
            }}
          >
            Create Group
          </button>
          <button className="text-xs text-slate-500 hover:text-slate-700" onClick={() => setSelected(new Set())}>
            Deselect all
          </button>
        </div>
      )}

      {isLoading ? <PageSpinner /> : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                <th className="table-th w-10">
                  <input
                    type="checkbox"
                    checked={selected.size > 0 && selected.size === data?.items.length}
                    ref={(el) => { if (el) el.indeterminate = selected.size > 0 && selected.size < (data?.items.length ?? 0) }}
                    onChange={toggleSelectAll}
                  />
                </th>
                <th className="table-th">Hostname</th>
                <th className="table-th">IP</th>
                <th className="table-th">Platform</th>
                <th className="table-th">Environment</th>
                <th className="table-th">Groups</th>
                <th className="table-th">Tags</th>
                <th className="table-th">Connector</th>
                <th className="table-th">Enabled</th>
                <th className="table-th">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {data?.items.map((a) => (
                <tr key={a.id} className={clsx('hover:bg-slate-50 transition-colors', selected.has(a.id) && 'bg-brand-50')}>
                  <td className="table-td">
                    <input type="checkbox" checked={selected.has(a.id)} onChange={() => toggleSelect(a.id)} onClick={(e) => e.stopPropagation()} />
                  </td>
                  <td className="table-td">
                    <div className="font-medium text-slate-900">{a.hostname}</div>
                    {a.instance && <div className="text-[10px] text-slate-400">{a.instance}</div>}
                  </td>
                  <td className="table-td text-slate-500 text-xs">{a.ip_address ?? '—'}</td>
                  <td className="table-td">
                    <span className="badge bg-slate-100 text-slate-600">{PLATFORM_LABELS[a.platform]}</span>
                  </td>
                  <td className="table-td text-slate-500">{a.environment ?? '—'}</td>
                  <td className="table-td">
                    <div className="flex flex-wrap gap-1">
                      {(a.group_summaries ?? []).map((group) => (
                        <span key={group.id} className="badge bg-blue-100 text-blue-700 text-[11px]">{group.name}</span>
                      ))}
                    </div>
                  </td>
                  <td className="table-td">
                    <div className="flex flex-wrap gap-1">
                      {(a.tag_summaries ?? []).map((tag) => (
                        <TagBadge key={tag.id} tag={tag} size="xs" />
                      ))}
                    </div>
                  </td>
                  <td className="table-td text-xs text-slate-500">{a.connector_name ?? '—'}</td>
                  <td className="table-td">
                    <button
                      type="button"
                      title={a.discovery_enabled ? 'Disable' : 'Enable'}
                      onClick={() => toggleMut.mutate(a.id)}
                      className={clsx(
                        'relative inline-flex h-5 w-9 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none',
                        a.discovery_enabled ? 'bg-brand-600' : 'bg-slate-300',
                      )}
                    >
                      <span
                        className={clsx(
                          'pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow ring-0 transition duration-200',
                          a.discovery_enabled ? 'translate-x-4' : 'translate-x-0',
                        )}
                      />
                    </button>
                  </td>
                  <td className="table-td">
                    <div className="flex gap-1.5">
                      <button className="btn-secondary text-xs py-1" onClick={() => setEditing(a)}>Edit</button>
                      <button
                        className="btn text-xs py-1 text-red-600 hover:bg-red-50 border border-red-200"
                        onClick={() => { if (confirm(`Delete ${a.hostname}?`)) deleteMut.mutate(a.id) }}
                      >
                        Del
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
              {data?.items.length === 0 && (
                <tr><td colSpan={10} className="py-12 text-center text-slate-400">No assets found.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      </>
      )}

      {activeTab === 'groups' && (
        <div className="p-6">
          <div className="card overflow-hidden">
            <div className="px-4 py-3 border-b border-slate-100 text-sm font-semibold text-slate-700 flex items-center justify-between">
              <span>Asset Groups</span>
              <button
                className="btn-secondary text-xs py-1"
                onClick={() => {
                  setGroupForm({ name: '', description: '', asset_ids: [] })
                  setShowGroupModal(true)
                }}
              >
                + Create Group
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-slate-50 border-b border-slate-200">
                  <tr>
                    <th className="table-th">Name</th>
                    <th className="table-th">Description</th>
                    <th className="table-th">Assets</th>
                    <th className="table-th">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {groups.map((group) => (
                    <tr key={group.id} className="hover:bg-slate-50">
                      <td className="table-td font-medium text-slate-900">{group.name}</td>
                      <td className="table-td text-slate-500">{group.description ?? '—'}</td>
                      <td className="table-td">
                        <button
                          className="badge bg-blue-100 text-blue-700"
                          onClick={() => { setGroupId(group.id); setActiveTab('assets') }}
                        >
                          {group.asset_count} asset{group.asset_count !== 1 ? 's' : ''}
                        </button>
                      </td>
                      <td className="table-td">
                        <div className="flex gap-1.5">
                          <button
                            className="btn-secondary text-xs py-1"
                            onClick={() => {
                              setEditingGroup(group)
                              setGroupForm({ name: group.name, description: group.description ?? '', asset_ids: group.asset_ids })
                            }}
                          >
                            Edit
                          </button>
                          <button
                            className="btn text-xs py-1 text-red-600 hover:bg-red-50 border border-red-200"
                            onClick={() => { if (confirm(`Delete group "${group.name}"?`)) deleteGroupMut.mutate(group.id) }}
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                  {groups.length === 0 && (
                    <tr><td colSpan={4} className="py-12 text-center text-slate-400">No asset groups yet.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Bulk tag modal */}
      {showBulkTag && (
        <BulkTagModal
          assetIds={[...selected]}
          tags={allTags}
          onAssign={(tagIds) => bulkAssignMut.mutate({ assetIds: [...selected], tagIds })}
          onRemove={(tagIds) => bulkRemoveMut.mutate({ assetIds: [...selected], tagIds })}
          saving={bulkAssignMut.isPending || bulkRemoveMut.isPending}
          onClose={() => setShowBulkTag(false)}
        />
      )}

      {/* Add asset modal */}
      {showAdd && (
        <Modal title="Add Asset" onClose={() => { setShowAdd(false); setForm({ platform: 'rhel', discovery_enabled: true, connector_id: null }) }}>
          <div className="space-y-3">
            <AssetForm form={form} setForm={setForm} connectors={connectors} />
            <div className="flex gap-2 pt-2">
              <button className="btn-primary" onClick={() => createMut.mutate(form)} disabled={createMut.isPending}>
                {createMut.isPending ? 'Saving...' : 'Save'}
              </button>
              <button className="btn-secondary" onClick={() => setShowAdd(false)}>Cancel</button>
            </div>
          </div>
        </Modal>
      )}

      {/* Edit asset modal */}
      {editing && (
        <Modal title={`Edit ${editing.hostname}`} onClose={() => setEditing(null)}>
          <div className="space-y-3">
            <AssetForm
              form={editing}
              setForm={(next) => setEditing((curr) => ({ ...(curr as Asset), ...next }))}
              connectors={connectors}
            />
            <div className="flex gap-2 pt-2">
              <button
                className="btn-primary"
                onClick={() => updateMut.mutate({ id: editing.id, data: editing })}
                disabled={updateMut.isPending}
              >
                {updateMut.isPending ? 'Saving...' : 'Save'}
              </button>
              <button className="btn-secondary" onClick={() => setEditing(null)}>Cancel</button>
            </div>
          </div>
        </Modal>
      )}

      {/* Import CSV modal */}
      {showImport && (
        <ImportCsvModal
          onClose={() => setShowImport(false)}
          onDownloadTemplate={downloadTemplate}
          onSuccess={() => qc.invalidateQueries({ queryKey: ['assets'] })}
        />
      )}

      {(showGroupModal || editingGroup) && (
        <AssetGroupModal
          title={editingGroup ? `Edit ${editingGroup.name}` : 'Create Asset Group'}
          form={groupForm}
          assets={groupPickerAssets}
          onChange={setGroupForm}
          onClose={() => { setShowGroupModal(false); setEditingGroup(null); setGroupForm({ name: '', description: '', asset_ids: [] }) }}
          onSave={() => {
            const payload = {
              name: groupForm.name,
              description: groupForm.description || null,
              asset_ids: groupForm.asset_ids,
            }
            if (editingGroup) {
              updateGroupMut.mutate({ id: editingGroup.id, data: payload })
            } else {
              createGroupMut.mutate(payload)
            }
          }}
          saving={createGroupMut.isPending || updateGroupMut.isPending}
        />
      )}
    </div>
  )
}

function Modal({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-lg p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-slate-900">{title}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
        </div>
        {children}
      </div>
    </div>
  )
}

// ── Tag filter dropdown ───────────────────────────────────────────────────────

function TagFilterDropdown({
  tags,
  selected,
  onChange,
}: {
  tags: Tag[]
  selected: string[]
  onChange: (ids: string[]) => void
}) {
  const [open, setOpen] = useState(false)

  const toggle = (id: string) => {
    onChange(selected.includes(id) ? selected.filter((s) => s !== id) : [...selected, id])
  }

  return (
    <div className="relative">
      <button
        type="button"
        className={clsx('input w-40 text-left flex items-center justify-between gap-1 text-sm',
          selected.length > 0 ? 'border-brand-500 text-brand-700' : 'text-slate-500')}
        onClick={() => setOpen((v) => !v)}
      >
        <span>{selected.length > 0 ? `${selected.length} tag${selected.length !== 1 ? 's' : ''}` : 'Filter by tag'}</span>
        <span className="text-slate-400">▾</span>
      </button>
      {open && (
        <div className="absolute left-0 top-full mt-1 z-20 bg-white border border-slate-200 rounded-lg shadow-lg w-56 max-h-64 overflow-y-auto py-1">
          {tags.length === 0 && (
            <p className="px-3 py-2 text-xs text-slate-400">No tags available</p>
          )}
          {tags.map((t) => (
            <label key={t.id} className="flex items-center gap-2 px-3 py-1.5 hover:bg-slate-50 cursor-pointer">
              <input
                type="checkbox"
                checked={selected.includes(t.id)}
                onChange={() => toggle(t.id)}
                className="flex-shrink-0"
              />
              <span className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: t.color }} />
              <span className="text-sm text-slate-700">{t.tag_name}</span>
            </label>
          ))}
          {selected.length > 0 && (
            <button
              className="w-full text-left px-3 py-1.5 text-xs text-slate-400 hover:text-slate-600 border-t border-slate-100 mt-1"
              onClick={() => { onChange([]); setOpen(false) }}
            >
              Clear selection
            </button>
          )}
        </div>
      )}
      {open && <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />}
    </div>
  )
}

// ── Bulk tag modal ─────────────────────────────────────────────────────────────

function BulkTagModal({
  assetIds,
  tags,
  onAssign,
  onRemove,
  saving,
  onClose,
}: {
  assetIds: string[]
  tags: Tag[]
  onAssign: (tagIds: string[]) => void
  onRemove: (tagIds: string[]) => void
  saving: boolean
  onClose: () => void
}) {
  const [mode, setMode] = useState<'assign' | 'remove'>('assign')
  const [chosen, setChosen] = useState<string[]>([])

  const toggle = (id: string) =>
    setChosen((prev) => prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id])

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-md p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-slate-900">
            Manage Tags — {assetIds.length} asset{assetIds.length !== 1 ? 's' : ''}
          </h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
        </div>

        <div className="flex gap-2 mb-4">
          <button
            className={clsx('flex-1 py-2 rounded-lg text-sm font-medium border transition-colors',
              mode === 'assign' ? 'bg-brand-600 text-white border-brand-600' : 'bg-white text-slate-600 border-slate-200')}
            onClick={() => { setMode('assign'); setChosen([]) }}
          >
            Assign Tags
          </button>
          <button
            className={clsx('flex-1 py-2 rounded-lg text-sm font-medium border transition-colors',
              mode === 'remove' ? 'bg-red-600 text-white border-red-600' : 'bg-white text-slate-600 border-slate-200')}
            onClick={() => { setMode('remove'); setChosen([]) }}
          >
            Remove Tags
          </button>
        </div>

        <div className="space-y-1 max-h-52 overflow-y-auto mb-4">
          {tags.map((t) => (
            <label key={t.id} className="flex items-center gap-3 px-2 py-1.5 rounded hover:bg-slate-50 cursor-pointer">
              <input type="checkbox" checked={chosen.includes(t.id)} onChange={() => toggle(t.id)} />
              <TagBadge tag={t} size="sm" />
              <span className="text-xs text-slate-400">{t.usage_count} asset{t.usage_count !== 1 ? 's' : ''}</span>
            </label>
          ))}
        </div>

        <div className="flex gap-2">
          <button
            className={clsx('btn-primary flex-1', mode === 'remove' && 'bg-red-600 hover:bg-red-700 border-red-600')}
            disabled={chosen.length === 0 || saving}
            onClick={() => mode === 'assign' ? onAssign(chosen) : onRemove(chosen)}
          >
            {saving ? 'Saving…' : mode === 'assign' ? `Assign ${chosen.length} tag${chosen.length !== 1 ? 's' : ''}` : `Remove ${chosen.length} tag${chosen.length !== 1 ? 's' : ''}`}
          </button>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  )
}

function AssetGroupModal({
  title,
  form,
  assets,
  onChange,
  onClose,
  onSave,
  saving,
}: {
  title: string
  form: { name: string; description: string; asset_ids: string[] }
  assets: Asset[]
  onChange: (next: { name: string; description: string; asset_ids: string[] }) => void
  onClose: () => void
  onSave: () => void
  saving: boolean
}) {
  const update = (patch: Partial<typeof form>) => onChange({ ...form, ...patch })
  const toggleAsset = (id: string) => {
    update({
      asset_ids: form.asset_ids.includes(id)
        ? form.asset_ids.filter((assetId) => assetId !== id)
        : [...form.asset_ids, id],
    })
  }

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-slate-900">{title}</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
        </div>

        <div className="space-y-3">
          <Field label="Group Name *">
            <input className="input" value={form.name} onChange={(e) => update({ name: e.target.value })} />
          </Field>
          <Field label="Description">
            <textarea className="input min-h-20" value={form.description} onChange={(e) => update({ description: e.target.value })} />
          </Field>
          <Field label={`Assets (${form.asset_ids.length} selected)`}>
            <div className="border border-slate-200 rounded-lg max-h-72 overflow-y-auto divide-y divide-slate-100">
              {assets.map((asset) => (
                <label key={asset.id} className="flex items-center gap-3 px-3 py-2 hover:bg-slate-50 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.asset_ids.includes(asset.id)}
                    onChange={() => toggleAsset(asset.id)}
                  />
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-slate-900 truncate">{asset.hostname}</div>
                    <div className="text-xs text-slate-400">
                      {PLATFORM_LABELS[asset.platform]} · {asset.environment ?? 'no environment'}{asset.ip_address ? ` · ${asset.ip_address}` : ''}
                    </div>
                  </div>
                </label>
              ))}
              {assets.length === 0 && (
                <div className="px-3 py-8 text-center text-sm text-slate-400">No assets available.</div>
              )}
            </div>
          </Field>
          <div className="flex gap-2 pt-2">
            <button className="btn-primary" onClick={onSave} disabled={saving || !form.name.trim()}>
              {saving ? 'Saving…' : 'Save Group'}
            </button>
            <button className="btn-secondary" onClick={onClose}>Cancel</button>
          </div>
        </div>
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><label className="label">{label}</label>{children}</div>
}

function AssetForm({
  form,
  setForm,
  connectors,
}: {
  form: Partial<Asset>
  setForm: (next: Partial<Asset>) => void
  connectors: Connector[]
}) {
  const update = (patch: Partial<Asset>) => setForm({ ...form, ...patch })
  const currentPlatform = form.platform ?? 'rhel'
  const expectedKind = PLATFORM_CONNECTOR_KIND[currentPlatform]
  const filteredConnectors = connectors.filter((c) => c.kind === expectedKind && c.is_active)

  return (
    <>
      <Field label="Hostname *">
        <input className="input" value={form.hostname ?? ''} onChange={(e) => update({ hostname: e.target.value })} />
      </Field>
      <Field label="IP Address">
        <input className="input" value={form.ip_address ?? ''} onChange={(e) => update({ ip_address: e.target.value || null })} />
      </Field>
      <Field label="Platform *">
        <select className="input" value={form.platform} onChange={(e) => update({ platform: e.target.value as any, connector_id: null })}>
          {PLATFORMS.map((p) => <option key={p} value={p}>{PLATFORM_LABELS[p]}</option>)}
        </select>
      </Field>
      <Field label="Connector">
        <select
          className="input"
          value={form.connector_id ?? ''}
          onChange={(e) => update({ connector_id: e.target.value || null })}
        >
          <option value="">— None (use default for platform) —</option>
          {filteredConnectors.map((c) => (
            <option key={c.id} value={c.id}>{c.name}</option>
          ))}
          {filteredConnectors.length === 0 && (
            <option disabled>No {expectedKind} connectors available</option>
          )}
        </select>
        <p className="text-[11px] text-slate-400 mt-0.5">Filtered to {expectedKind} connectors for this platform.</p>
      </Field>
      <Field label="Port">
        <input className="input" type="number" value={form.port ?? ''} onChange={(e) => update({ port: e.target.value ? Number(e.target.value) : null })} />
      </Field>
      <Field label="Environment">
        <input className="input" value={form.environment ?? ''} onChange={(e) => update({ environment: e.target.value || null })} />
      </Field>
      <Field label="Owner">
        <input className="input" value={form.owner ?? ''} onChange={(e) => update({ owner: e.target.value || null })} />
      </Field>
      <Field label="Business Unit">
        <input className="input" value={form.business_unit ?? ''} onChange={(e) => update({ business_unit: e.target.value || null })} />
      </Field>
      <Field label="Criticality">
        <select className="input" value={form.criticality ?? ''} onChange={(e) => update({ criticality: e.target.value || null })}>
          <option value="">— None —</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </Field>
      <Field label="Instance">
        <input className="input" value={form.instance ?? ''} onChange={(e) => update({ instance: e.target.value || null })} />
      </Field>
      <label className="flex items-center gap-2 text-sm cursor-pointer">
        <input type="checkbox" checked={!!form.discovery_enabled} onChange={(e) => update({ discovery_enabled: e.target.checked })} />
        Discovery enabled
      </label>
    </>
  )
}

function ImportCsvModal({
  onClose,
  onDownloadTemplate,
  onSuccess,
}: {
  onClose: () => void
  onDownloadTemplate: () => void
  onSuccess: () => void
}) {
  const [file, setFile] = useState<File | null>(null)
  const [result, setResult] = useState<BulkImportResult | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  const importMut = useMutation({
    mutationFn: (f: File) => importAssetsCsv(f).then((r) => r.data),
    onSuccess: (data) => {
      setResult(data)
      onSuccess()
      toast.success(`Imported ${data.imported_rows} asset(s)`)
    },
    onError: () => toast.error('Import failed'),
  })

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold text-slate-900">Import Assets from CSV</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 text-xl leading-none">×</button>
        </div>

        {!result ? (
          <div className="space-y-4">
            <p className="text-sm text-slate-600">
              Upload a CSV file with columns: <code className="text-xs bg-slate-100 px-1 rounded">hostname</code>,{' '}
              <code className="text-xs bg-slate-100 px-1 rounded">platform</code>,{' '}
              <code className="text-xs bg-slate-100 px-1 rounded">ip_address</code>,{' '}
              <code className="text-xs bg-slate-100 px-1 rounded">port</code>,{' '}
              <code className="text-xs bg-slate-100 px-1 rounded">environment</code>,{' '}
              <code className="text-xs bg-slate-100 px-1 rounded">owner</code>,{' '}
              <code className="text-xs bg-slate-100 px-1 rounded">business_unit</code>,{' '}
              <code className="text-xs bg-slate-100 px-1 rounded">criticality</code>,{' '}
              <code className="text-xs bg-slate-100 px-1 rounded">connector_name</code>
            </p>
            <button className="btn-secondary text-sm" onClick={onDownloadTemplate}>
              Download Template
            </button>
            <div
              className="border-2 border-dashed border-slate-300 rounded-lg p-8 text-center cursor-pointer hover:border-brand-400 transition-colors"
              onClick={() => inputRef.current?.click()}
            >
              {file ? (
                <div className="text-sm text-slate-700">
                  <div className="font-medium">{file.name}</div>
                  <div className="text-slate-400 text-xs mt-1">{(file.size / 1024).toFixed(1)} KB</div>
                </div>
              ) : (
                <div className="text-slate-400 text-sm">Click to select a CSV file</div>
              )}
              <input
                ref={inputRef}
                type="file"
                accept=".csv,text/csv"
                className="hidden"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </div>
            <div className="flex gap-2 pt-2">
              <button
                className="btn-primary"
                disabled={!file || importMut.isPending}
                onClick={() => file && importMut.mutate(file)}
              >
                {importMut.isPending ? 'Importing...' : 'Import'}
              </button>
              <button className="btn-secondary" onClick={onClose}>Cancel</button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <div className="bg-slate-50 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-slate-900">{result.total_rows}</div>
                <div className="text-xs text-slate-500">Total rows</div>
              </div>
              <div className="bg-green-50 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-green-700">{result.imported_rows}</div>
                <div className="text-xs text-green-600">Imported</div>
              </div>
              <div className="bg-yellow-50 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-yellow-700">{result.duplicate_rows}</div>
                <div className="text-xs text-yellow-600">Updated (duplicates)</div>
              </div>
              <div className="bg-red-50 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-red-700">{result.invalid_rows}</div>
                <div className="text-xs text-red-600">Invalid</div>
              </div>
            </div>
            {result.errors.length > 0 && (
              <div>
                <div className="text-xs font-semibold text-slate-700 mb-1">Errors / Warnings</div>
                <div className="max-h-48 overflow-y-auto border border-slate-200 rounded divide-y divide-slate-100">
                  {result.errors.map((e, i) => (
                    <div key={i} className="px-3 py-2 text-xs">
                      <span className="text-slate-400 mr-2">Row {e.row}</span>
                      <span className="text-red-600">{e.error}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div className="flex gap-2 pt-2">
              <button className="btn-secondary" onClick={() => { setResult(null); setFile(null) }}>Import Another</button>
              <button className="btn-primary" onClick={onClose}>Done</button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
