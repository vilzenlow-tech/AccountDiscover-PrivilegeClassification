import { useMemo, useState } from 'react'
import {
  useBulkAssignTagsMutation, useCreateTagMutation, useDeleteTagMutation, useGetAssetsQuery,
  useGetTagsQuery, usePatchTagStatusMutation,
} from '../../api/apiSlice'
import type { Asset, Tag, TagCategory } from '../../api/types'
import { useCan } from '../../app/rbac'
import {
  ActionButton, DataPanel, DataTable, ErrorState, Field, InlineAlert, LoadingPanel, NativeSelect,
  PageFrame, StatusBadge, TextArea, TextInput, apiErrorMessage, cx, type Column,
} from '../../components/ui'

const CATEGORIES: TagCategory[] = ['application', 'environment', 'business_unit', 'criticality', 'compliance', 'ownership', 'technology', 'custom']
type TagTab = 'registry' | 'assignment' | 'coverage'

const TABS: Array<{ key: TagTab; label: string; detail: string }> = [
  { key: 'registry', label: 'Tag registry', detail: 'Create, status, usage' },
  { key: 'assignment', label: 'Bulk assignment', detail: 'Apply tags to assets' },
  { key: 'coverage', label: 'Asset coverage', detail: 'Tagged vs untagged' },
]

export default function TagsAdmin() {
  const can = useCan()
  const manage = can('tag:manage')
  const { data, isLoading, isError, error, refetch } = useGetTagsQuery({ limit: 300 })
  const assetsQ = useGetAssetsQuery({ limit: 500 })
  const [createTag, createState] = useCreateTagMutation()
  const [patchStatus] = usePatchTagStatusMutation()
  const [deleteTag] = useDeleteTagMutation()
  const [bulkAssign, bulkState] = useBulkAssignTagsMutation()

  const [showCreate, setShowCreate] = useState(false)
  const [activeTab, setActiveTab] = useState<TagTab>('registry')
  const [form, setForm] = useState({ tag_name: '', tag_code: '', category: 'application' as TagCategory, description: '' })
  const [assignTagId, setAssignTagId] = useState('')
  const [assignAssetIds, setAssignAssetIds] = useState<string[]>([])
  const [bulkAssetSearch, setBulkAssetSearch] = useState('')
  const [assetSearch, setAssetSearch] = useState('')
  const [assetTagFilter, setAssetTagFilter] = useState('all')

  const tags = data?.items ?? []
  const assets = useMemo(() => assetsQ.data?.items ?? [], [assetsQ.data?.items])
  const taggedCount = assets.filter((a) => a.tag_summaries?.length).length
  const untaggedCount = assets.length - taggedCount
  const activeTags = tags.filter((tag) => tag.status === 'active').length
  const bulkAssets = useMemo(() => filterAssets(assets, bulkAssetSearch), [assets, bulkAssetSearch])
  const filteredAssets = useMemo(() => {
    const term = assetSearch.trim().toLowerCase()
    return assets.filter((asset) => {
      const tagIds = asset.tag_summaries?.map((tag) => tag.id) ?? []
      const matchesTag = assetTagFilter === 'all' || (assetTagFilter === 'untagged' ? tagIds.length === 0 : tagIds.includes(assetTagFilter))
      const haystack = [asset.hostname, asset.ip_address, asset.platform, asset.owner, asset.business_unit, asset.tag_summaries?.map((tag) => tag.tag_name).join(' ')].join(' ').toLowerCase()
      return matchesTag && (!term || haystack.includes(term))
    })
  }, [assetSearch, assetTagFilter, assets])

  const columns: Column<Tag>[] = [
    { key: 'name', header: 'Tag', render: (t) => <span className="inline-flex items-center gap-2 font-medium text-slate-900"><span className="h-3 w-3 rounded-full" style={{ background: t.color }} />{t.tag_name}</span> },
    { key: 'code', header: 'Code', render: (t) => t.tag_code ?? '—' },
    { key: 'category', header: 'Category', render: (t) => t.category },
    { key: 'status', header: 'Status', render: (t) => <StatusBadge value={t.status} /> },
    { key: 'usage', header: 'Usage', render: (t) => <span className="tabular-nums">{t.usage_count}</span> },
    { key: 'desc', header: 'Description', render: (t) => <span className="text-xs text-slate-500">{t.description ?? '—'}</span> },
    {
      key: 'actions', header: 'Actions', render: (t) => manage ? (
        <div className="flex gap-2" onClick={(e) => e.stopPropagation()}>
          <button className="text-xs font-medium text-slate-600 hover:text-slate-900" onClick={() => patchStatus({ id: t.id, status: t.status === 'active' ? 'inactive' : 'active' })}>{t.status === 'active' ? 'Deactivate' : 'Activate'}</button>
          <button className="text-xs font-medium text-red-600 hover:text-red-800" onClick={() => { if (confirm(`Delete tag "${t.tag_name}"?`)) deleteTag(t.id) }}>Delete</button>
        </div>
      ) : <span className="text-xs text-slate-400">read-only</span>,
    },
  ]
  const assetColumns: Column<Asset>[] = [
    { key: 'asset', header: 'Asset', render: (a) => <span className="font-medium text-slate-900">{a.hostname}</span> },
    { key: 'ip', header: 'IP', render: (a) => a.ip_address ?? '—' },
    { key: 'platform', header: 'Platform', render: (a) => a.platform },
    { key: 'owner', header: 'Owner / BU', render: (a) => <span className="text-xs text-slate-600">{[a.owner, a.business_unit].filter(Boolean).join(' · ') || '—'}</span> },
    { key: 'tags', header: 'Applied tags', render: (a) => <TagPills asset={a} /> },
  ]

  async function submitCreate() {
    if (!form.tag_name.trim()) return
    await createTag({ tag_name: form.tag_name.trim(), tag_code: form.tag_code.trim() || null, category: form.category, description: form.description.trim() || null }).unwrap().catch(() => {})
    setForm({ tag_name: '', tag_code: '', category: 'application', description: '' })
    setShowCreate(false)
  }

  async function submitAssign() {
    if (!assignTagId || assignAssetIds.length === 0) return
    await bulkAssign({ tag_ids: [assignTagId], asset_ids: assignAssetIds }).unwrap().catch(() => {})
    setAssignAssetIds([])
  }
  const selectVisibleBulkAssets = () => setAssignAssetIds((selected) => Array.from(new Set([...selected, ...bulkAssets.map((asset) => asset.id)])))
  const clearVisibleBulkAssets = () => setAssignAssetIds((selected) => selected.filter((id) => !bulkAssets.some((asset) => asset.id === id)))

  return (
    <PageFrame
      eyebrow="Governance metadata"
      title="Tags / Applications"
      subtitle="Application, environment, and ownership tags used for scoping scans, filtering, and reporting."
      actions={manage ? <ActionButton variant="primary" onClick={() => { setActiveTab('registry'); setShowCreate((s) => !s) }}>{showCreate && activeTab === 'registry' ? 'Close' : 'New tag'}</ActionButton> : undefined}
    >
      {!manage && <InlineAlert tone="slate">Your role can view tags but not manage them.</InlineAlert>}

      <div className="grid gap-3 md:grid-cols-3">
        <SummaryCard label="Active tags" value={activeTags} detail={`${tags.length} total defined`} tone="blue" />
        <SummaryCard label="Tagged assets" value={taggedCount} detail={`${untaggedCount} still untagged`} tone="emerald" />
        <SummaryCard label="Selected for bulk" value={assignAssetIds.length} detail={assignTagId ? 'Ready to assign' : 'Choose a tag first'} tone="slate" />
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-200 bg-slate-50/70 p-2">
          <div className="grid gap-2 lg:grid-cols-3">
            {TABS.map((tab) => (
              <button
                key={tab.key}
                type="button"
                onClick={() => setActiveTab(tab.key)}
                className={cx(
                  'rounded-lg border px-4 py-3 text-left transition',
                  activeTab === tab.key ? 'border-blue-600 bg-white shadow-sm ring-1 ring-blue-100' : 'border-transparent hover:border-slate-200 hover:bg-white',
                )}
              >
                <span className={cx('block text-sm font-semibold', activeTab === tab.key ? 'text-blue-700' : 'text-slate-800')}>{tab.label}</span>
                <span className="mt-0.5 block text-xs text-slate-500">{tab.detail}</span>
              </button>
            ))}
          </div>
        </div>

        <div className="p-4">
          {activeTab === 'registry' && (
            <div className="space-y-4">
              {showCreate && manage && (
                <DataPanel title="Create tag" detail="Add a reusable metadata label for applications, ownership, environments, or compliance scopes.">
                  <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-4">
                    <Field label="Tag name" required><TextInput value={form.tag_name} onChange={(e) => setForm({ ...form, tag_name: e.target.value })} placeholder="CoreBanking" /></Field>
                    <Field label="Tag code"><TextInput value={form.tag_code} onChange={(e) => setForm({ ...form, tag_code: e.target.value })} placeholder="CB" /></Field>
                    <Field label="Category"><NativeSelect value={form.category} options={CATEGORIES.map((c) => ({ value: c, label: c.replace(/_/g, ' ') }))} onChange={(v) => setForm({ ...form, category: v as TagCategory })} /></Field>
                    <Field label="Description"><TextArea rows={1} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
                  </div>
                  <div className="flex items-center gap-3 border-t border-slate-200 px-4 py-3">
                    <ActionButton variant="primary" disabled={!form.tag_name.trim() || createState.isLoading} onClick={submitCreate}>{createState.isLoading ? 'Creating…' : 'Create tag'}</ActionButton>
                    {createState.isError && <InlineAlert tone="red">{apiErrorMessage(createState.error)}</InlineAlert>}
                  </div>
                </DataPanel>
              )}

              {isLoading ? <LoadingPanel label="Loading tags…" /> : isError ? (
                <ErrorState detail={apiErrorMessage(error)} onRetry={refetch} />
              ) : (
                <DataPanel title="Tag registry" detail={`${data?.total ?? 0} tag(s) · ${activeTags} active`}>
                  <DataTable columns={columns} rows={tags} getRowKey={(t) => t.id} empty="No tags defined yet." minWidth={900} />
                </DataPanel>
              )}
            </div>
          )}

          {activeTab === 'assignment' && (
            manage ? (
              isLoading || assetsQ.isLoading ? <LoadingPanel label="Loading assignment workspace…" /> : isError ? (
                <ErrorState detail={apiErrorMessage(error)} onRetry={refetch} />
              ) : assetsQ.isError ? (
                <ErrorState detail={apiErrorMessage(assetsQ.error)} onRetry={assetsQ.refetch} />
              ) : (
                <DataPanel title="Bulk assign tag to assets" detail="Search, select visible results, then apply one tag to many assets.">
                  <div className="grid gap-4 p-4 xl:grid-cols-[320px_minmax(0,1fr)]">
                    <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
                      <Field label="Tag to assign" hint="Pick the metadata label first.">
                        <NativeSelect value={assignTagId} options={tags.map((t) => ({ value: t.id, label: t.tag_name }))} onChange={setAssignTagId} placeholder="Select tag…" />
                      </Field>
                      <div className="mt-4 rounded-md bg-white p-3 text-xs text-slate-500">
                        <span className="font-semibold text-slate-700">{assignAssetIds.length}</span> asset(s) selected from {assets.length} available.
                      </div>
                    </div>
                    <Field label="Assets" hint="Search narrows the selectable list without losing current selections.">
                      <div className="mb-3 grid gap-2 md:grid-cols-[minmax(0,1fr)_auto_auto]">
                        <TextInput value={bulkAssetSearch} onChange={(e) => setBulkAssetSearch(e.target.value)} placeholder="Search hostname, IP, platform, owner, or existing tag…" />
                        <ActionButton variant="secondary" disabled={!bulkAssets.length} onClick={selectVisibleBulkAssets}>Select visible</ActionButton>
                        <ActionButton variant="ghost" disabled={!assignAssetIds.length} onClick={clearVisibleBulkAssets}>Clear visible</ActionButton>
                      </div>
                      <p className="mb-2 text-xs font-medium text-slate-500">{bulkAssets.length} of {assets.length} asset(s) visible</p>
                      <div className="max-h-[28rem] overflow-y-auto rounded-lg border border-slate-200 bg-white">
                        {bulkAssets.length ? bulkAssets.map((a) => (
                          <label key={a.id} className="grid grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-3 border-b border-slate-100 px-3 py-3 text-sm last:border-0 hover:bg-slate-50">
                            <input type="checkbox" checked={assignAssetIds.includes(a.id)} onChange={() => setAssignAssetIds((s) => s.includes(a.id) ? s.filter((x) => x !== a.id) : [...s, a.id])} />
                            <span className="min-w-0">
                              <span className="block truncate font-medium text-slate-800">{a.hostname}</span>
                              <span className="text-xs text-slate-500">{[a.ip_address, a.platform, a.owner].filter(Boolean).join(' · ') || 'No asset metadata'}</span>
                            </span>
                            <span className="max-w-64 truncate text-xs text-slate-500">{a.tag_summaries?.map((t) => t.tag_name).join(', ') || 'untagged'}</span>
                          </label>
                        )) : <div className="px-3 py-8 text-center text-sm text-slate-500">No assets match this search.</div>}
                      </div>
                    </Field>
                  </div>
                  <div className="flex items-center gap-3 border-t border-slate-200 px-4 py-3">
                    <ActionButton variant="primary" disabled={!assignTagId || assignAssetIds.length === 0 || bulkState.isLoading} onClick={submitAssign}>{bulkState.isLoading ? 'Assigning…' : `Assign to ${assignAssetIds.length} asset(s)`}</ActionButton>
                    {bulkState.isSuccess && <InlineAlert tone="green">Tag assigned.</InlineAlert>}
                    {bulkState.isError && <InlineAlert tone="red">{apiErrorMessage(bulkState.error)}</InlineAlert>}
                  </div>
                </DataPanel>
              )
            ) : <InlineAlert tone="slate">Your role can view tag coverage but cannot bulk assign tags.</InlineAlert>
          )}

          {activeTab === 'coverage' && (
            assetsQ.isLoading ? <LoadingPanel label="Loading asset tag coverage…" /> : assetsQ.isError ? (
              <ErrorState detail={apiErrorMessage(assetsQ.error)} onRetry={assetsQ.refetch} />
            ) : (
              <DataPanel title="Asset tag coverage" detail={`${filteredAssets.length} visible · ${taggedCount} tagged · ${untaggedCount} untagged`}>
                <div className="grid gap-3 border-b border-slate-200 p-4 lg:grid-cols-[minmax(0,1fr)_280px]">
                  <Field label="Search assets or tags"><TextInput value={assetSearch} onChange={(e) => setAssetSearch(e.target.value)} placeholder="hostname, IP, owner, platform, tag…" /></Field>
                  <Field label="Filter by tag">
                    <NativeSelect
                      value={assetTagFilter}
                      onChange={setAssetTagFilter}
                      options={[{ value: 'all', label: 'All assets' }, { value: 'untagged', label: 'Untagged assets' }, ...tags.map((tag) => ({ value: tag.id, label: tag.tag_name }))]}
                    />
                  </Field>
                </div>
                <DataTable columns={assetColumns} rows={filteredAssets} getRowKey={(a) => a.id} empty="No assets match this tag filter." minWidth={980} />
              </DataPanel>
            )
          )}
        </div>
      </div>
    </PageFrame>
  )
}

function SummaryCard({ label, value, detail, tone }: { label: string; value: number; detail: string; tone: 'blue' | 'emerald' | 'slate' }) {
  const accents = {
    blue: 'border-blue-200 bg-blue-50 text-blue-700',
    emerald: 'border-emerald-200 bg-emerald-50 text-emerald-700',
    slate: 'border-slate-200 bg-slate-50 text-slate-700',
  }
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-center justify-between gap-3">
        <span className="text-xs font-semibold uppercase tracking-[0.12em] text-slate-500">{label}</span>
        <span className={cx('rounded-full border px-2 py-0.5 text-xs font-semibold', accents[tone])}>{detail}</span>
      </div>
      <div className="mt-3 text-3xl font-semibold tabular-nums text-slate-950">{value}</div>
    </div>
  )
}

function filterAssets(assets: Asset[], search: string) {
  const term = search.trim().toLowerCase()
  if (!term) return assets
  return assets.filter((asset) => [asset.hostname, asset.ip_address, asset.platform, asset.owner, asset.business_unit, asset.tag_summaries?.map((tag) => tag.tag_name).join(' ')].join(' ').toLowerCase().includes(term))
}

function TagPills({ asset }: { asset: Asset }) {
  if (!asset.tag_summaries?.length) return <span className="text-xs text-slate-400">No tags applied</span>
  return (
    <div className="flex flex-wrap gap-1.5">
      {asset.tag_summaries.map((tag) => (
        <span key={tag.id} className="inline-flex items-center gap-1 rounded-full border border-slate-200 bg-white px-2 py-0.5 text-xs font-medium text-slate-700">
          <span className="h-2 w-2 rounded-full" style={{ background: tag.color }} />
          {tag.tag_name}
        </span>
      ))}
    </div>
  )
}
