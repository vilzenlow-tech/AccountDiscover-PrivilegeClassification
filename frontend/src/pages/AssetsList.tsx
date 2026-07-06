import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  useCreateAssetGroupMutation, useCreateAssetMutation, useDeleteAssetGroupMutation, useGetAssetGroupsQuery,
  useGetAssetsQuery, useImportAssetsCsvMutation, useUpdateAssetGroupMutation,
  useGetConnectorsQuery,
} from '../api/apiSlice'
import { downloadServerFile } from '../api/download'
import type { Asset, AssetGroup, AssetRequest, Platform } from '../api/types'
import { useCan } from '../app/rbac'
import {
  ActionButton, Badge, DataPanel, DataTable, ErrorState, Field, InlineAlert, LoadingPanel,
  NativeSelect, PageFrame, StatusBadge, TextArea, TextInput, apiErrorMessage, cx, type Column,
} from '../components/ui'

type GroupForm = { id?: string; name: string; description: string; asset_ids: string[] }
type AssetForm = {
  hostname: string
  ip_address: string
  instance: string
  port: string
  environment: string
  platform: Platform
  owner: string
  business_unit: string
  criticality: string
  connector_id: string
  discovery_enabled: boolean
}
type AssetTab = 'inventory' | 'groups' | 'import'
const emptyGroup: GroupForm = { name: '', description: '', asset_ids: [] }
const emptyAsset: AssetForm = {
  hostname: '', ip_address: '', instance: '', port: '', environment: 'production',
  platform: 'windows', owner: '', business_unit: '', criticality: 'medium',
  connector_id: '', discovery_enabled: true,
}
const PLATFORMS: Platform[] = ['rhel', 'centos', 'ubuntu', 'sles', 'solaris', 'aix', 'hpux', 'windows', 'mysql', 'mssql', 'mongodb', 'oracle_db', 'postgresql', 'redis']

const ASSET_TABS: Array<{ key: AssetTab; label: string; detail: string }> = [
  { key: 'inventory', label: 'Inventory', detail: 'Search and open assets' },
  { key: 'groups', label: 'Groups', detail: 'Reusable scan scopes' },
  { key: 'import', label: 'Bulk import', detail: 'Template and CSV upload' },
]

export default function AssetsList() {
  const navigate = useNavigate()
  const can = useCan()
  const manage = can('scan:manage')
  const [activeTab, setActiveTab] = useState<AssetTab>('inventory')
  const [search, setSearch] = useState('')
  const [groupId, setGroupId] = useState('')
  const [groupForm, setGroupForm] = useState<GroupForm | null>(null)
  const [assetForm, setAssetForm] = useState<AssetForm | null>(null)
  const [assetError, setAssetError] = useState<string | null>(null)
  const [assetPickSearch, setAssetPickSearch] = useState('')
  const query = useMemo(() => {
    const value = search.trim()
    return { limit: 500, ...(value ? { search: value } : {}), ...(groupId ? { group_id: groupId } : {}) }
  }, [search, groupId])
  const { data, isLoading, isError, error, refetch } = useGetAssetsQuery(query)
  const allAssetsQ = useGetAssetsQuery({ limit: 1000 })
  const connectorsQ = useGetConnectorsQuery()
  const groupsQ = useGetAssetGroupsQuery()
  const [createAsset, createAssetState] = useCreateAssetMutation()
  const [importCsv, importState] = useImportAssetsCsvMutation()
  const [createGroup, createGroupState] = useCreateAssetGroupMutation()
  const [updateGroup, updateGroupState] = useUpdateAssetGroupMutation()
  const [deleteGroup] = useDeleteAssetGroupMutation()
  const assets = useMemo(() => data?.items ?? [], [data?.items])
  const allAssets = useMemo(() => allAssetsQ.data?.items ?? assets, [allAssetsQ.data?.items, assets])
  const groups = groupsQ.data ?? []
  const groupBusy = createGroupState.isLoading || updateGroupState.isLoading
  const enabledAssets = assets.filter((asset) => asset.discovery_enabled).length
  const groupedAssets = allAssets.filter((asset) => asset.group_summaries?.length).length
  const pickableAssets = useMemo(() => {
    const term = assetPickSearch.trim().toLowerCase()
    if (!term) return allAssets
    return allAssets.filter((a) => [a.hostname, a.ip_address, a.platform, a.environment, a.owner, a.business_unit].some((v) => String(v ?? '').toLowerCase().includes(term)))
  }, [assetPickSearch, allAssets])

  const columns: Column<Asset>[] = [
    { key: 'hostname', header: 'Hostname', render: (a) => <span className="font-medium text-slate-900">{a.hostname}</span> },
    { key: 'ip', header: 'IP', render: (a) => a.ip_address ?? '—' },
    { key: 'platform', header: 'Platform', render: (a) => a.platform },
    { key: 'env', header: 'Environment', render: (a) => a.environment ?? '—' },
    { key: 'owner', header: 'Owner', render: (a) => a.owner ?? '—' },
    { key: 'connector', header: 'Connector', render: (a) => a.connector_name ?? '—' },
    { key: 'discovery', header: 'Discovery', render: (a) => <StatusBadge value={a.discovery_enabled ? 'enabled' : 'disabled'} /> },
    { key: 'tags', header: 'Tags', render: (a) => a.tag_summaries?.length ? a.tag_summaries.map((t) => t.tag_name).join(', ') : '—' },
    { key: 'groups', header: 'Groups', render: (a) => a.group_summaries?.length ? a.group_summaries.map((g) => g.name).join(', ') : '—' },
  ]
  const groupCols: Column<AssetGroup>[] = [
    { key: 'name', header: 'Group', render: (g) => <span className="font-medium text-slate-900">{g.name}</span> },
    { key: 'count', header: 'Assets', render: (g) => g.asset_count },
    { key: 'desc', header: 'Description', render: (g) => <span className="text-xs text-slate-500">{g.description ?? '—'}</span> },
    { key: 'actions', header: 'Actions', render: (g) => manage ? <div className="flex gap-2" onClick={(e) => e.stopPropagation()}><button className="text-xs font-medium text-blue-700 hover:underline" onClick={() => setGroupForm({ id: g.id, name: g.name, description: g.description ?? '', asset_ids: g.asset_ids })}>Edit</button><button className="text-xs font-medium text-red-600 hover:underline" onClick={() => removeGroup(g)}>Delete</button></div> : '—' },
  ]

  async function uploadCsv(file: File | null) {
    if (!file) return
    await importCsv(file).unwrap().catch(() => {})
  }
  async function saveGroup() {
    if (!groupForm?.name.trim()) return
    const body = { name: groupForm.name.trim(), description: groupForm.description.trim() || null, asset_ids: groupForm.asset_ids }
    if (groupForm.id) await updateGroup({ id: groupForm.id, body }).unwrap().then(() => setGroupForm(null)).catch(() => {})
    else await createGroup(body).unwrap().then(() => setGroupForm(null)).catch(() => {})
  }
  async function removeGroup(group: AssetGroup) {
    if (!confirm(`Delete asset group "${group.name}"?`)) return
    await deleteGroup(group.id).unwrap().catch(() => {})
  }
  function assetBody(form: AssetForm): AssetRequest {
    return {
      hostname: form.hostname.trim(),
      ip_address: form.ip_address.trim() || null,
      instance: form.instance.trim() || null,
      port: form.port ? Number(form.port) : null,
      environment: form.environment.trim() || null,
      platform: form.platform,
      owner: form.owner.trim() || null,
      business_unit: form.business_unit.trim() || null,
      criticality: form.criticality.trim() || null,
      connection_type: null,
      discovery_enabled: form.discovery_enabled,
      jump_host_id: null,
      tags: null,
      connector_id: form.connector_id || null,
    }
  }
  async function saveAsset() {
    if (!assetForm?.hostname.trim()) return
    setAssetError(null)
    try {
      const created = await createAsset(assetBody(assetForm)).unwrap()
      setAssetForm(null)
      refetch()
      navigate(`/assets/${created.id}`)
    } catch (err) {
      setAssetError(apiErrorMessage(err))
    }
  }
  const toggleGroupAsset = (id: string) => groupForm && setGroupForm({ ...groupForm, asset_ids: groupForm.asset_ids.includes(id) ? groupForm.asset_ids.filter((x) => x !== id) : [...groupForm.asset_ids, id] })

  return (
    <PageFrame
      eyebrow="Application onboarding"
      title="Assets"
      subtitle="Systems and database instances available for discovery, scoping, and review."
      actions={<div className="flex flex-wrap gap-2">{manage && <ActionButton onClick={() => setAssetForm({ ...emptyAsset })}>Add asset</ActionButton>}<ActionButton variant="primary" onClick={() => navigate('/scans/new')}>Discover via scan</ActionButton></div>}
    >
      <div className="grid gap-3 md:grid-cols-3">
        <AssetSummary label="Visible assets" value={data?.total ?? assets.length} detail={search.trim() ? 'Filtered result' : 'Current inventory'} tone="blue" />
        <AssetSummary label="Discovery enabled" value={enabledAssets} detail="Credentialed scan ready" tone="emerald" />
        <AssetSummary label="Grouped assets" value={groupedAssets} detail={`${groups.length} group(s)`} tone="slate" />
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <div className="border-b border-slate-200 bg-slate-50/70 p-2">
          <div className="grid gap-2 lg:grid-cols-3">
            {ASSET_TABS.map((tab) => (
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

        <div className="space-y-4 p-4">
          {activeTab === 'inventory' && (
            <>
              {assetForm && manage && (
                <DataPanel title="Add asset" detail="Manually onboard a server or database instance before scanning.">
                  <div className="grid gap-3 p-4 md:grid-cols-2 xl:grid-cols-4">
                    <Field label="Hostname" required><TextInput value={assetForm.hostname} onChange={(e) => setAssetForm({ ...assetForm, hostname: e.target.value })} placeholder="192.168.101.115 or win-dc01" /></Field>
                    <Field label="Platform" required><NativeSelect value={assetForm.platform} options={PLATFORMS.map((p) => ({ value: p, label: p }))} onChange={(v) => setAssetForm({ ...assetForm, platform: v as Platform })} /></Field>
                    <Field label="IP address"><TextInput value={assetForm.ip_address} onChange={(e) => setAssetForm({ ...assetForm, ip_address: e.target.value })} placeholder="192.168.101.115" /></Field>
                    <Field label="Port"><TextInput type="number" value={assetForm.port} onChange={(e) => setAssetForm({ ...assetForm, port: e.target.value })} placeholder="22 / 5985 / 27017" /></Field>
                    <Field label="Instance"><TextInput value={assetForm.instance} onChange={(e) => setAssetForm({ ...assetForm, instance: e.target.value })} placeholder="optional DB/service instance" /></Field>
                    <Field label="Environment"><TextInput value={assetForm.environment} onChange={(e) => setAssetForm({ ...assetForm, environment: e.target.value })} placeholder="production" /></Field>
                    <Field label="Owner"><TextInput value={assetForm.owner} onChange={(e) => setAssetForm({ ...assetForm, owner: e.target.value })} placeholder="IAM Operations" /></Field>
                    <Field label="Business unit"><TextInput value={assetForm.business_unit} onChange={(e) => setAssetForm({ ...assetForm, business_unit: e.target.value })} placeholder="Security" /></Field>
                    <Field label="Criticality"><NativeSelect value={assetForm.criticality} options={['critical', 'high', 'medium', 'low'].map((v) => ({ value: v, label: v }))} onChange={(v) => setAssetForm({ ...assetForm, criticality: v })} /></Field>
                    <Field label="Connector"><NativeSelect value={assetForm.connector_id} placeholder="Auto by platform" options={(connectorsQ.data?.items ?? []).map((c) => ({ value: c.id, label: `${c.name} (${c.kind})` }))} onChange={(v) => setAssetForm({ ...assetForm, connector_id: v })} /></Field>
                    <Field label="Discovery"><label className="flex h-10 items-center gap-2 text-sm text-slate-700"><input type="checkbox" checked={assetForm.discovery_enabled} onChange={(e) => setAssetForm({ ...assetForm, discovery_enabled: e.target.checked })} />Enable for scans</label></Field>
                  </div>
                  <div className="flex flex-wrap items-center gap-3 border-t border-slate-200 px-4 py-3">
                    <ActionButton variant="primary" disabled={!assetForm.hostname.trim() || createAssetState.isLoading} onClick={saveAsset}>{createAssetState.isLoading ? 'Creating…' : 'Create asset'}</ActionButton>
                    <ActionButton variant="ghost" onClick={() => setAssetForm(null)}>Cancel</ActionButton>
                    {assetError && <InlineAlert tone="red">{assetError}</InlineAlert>}
                  </div>
                </DataPanel>
              )}
              <DataPanel title="Asset command search" detail="Search across hostname, IP, instance, owner, business unit, environment, and criticality.">
                <div className="space-y-3 bg-gradient-to-br from-white via-slate-50 to-blue-50/40 p-4">
                  <div className="flex flex-col gap-3 lg:flex-row lg:items-end">
                    <div className="relative flex-1">
                      <span className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-400">
                        <svg aria-hidden="true" viewBox="0 0 20 20" className="h-4 w-4 fill-current">
                          <path fillRule="evenodd" d="M8.5 3a5.5 5.5 0 1 0 3.39 9.83l3.14 3.14a.75.75 0 1 0 1.06-1.06l-3.14-3.14A5.5 5.5 0 0 0 8.5 3ZM4.5 8.5a4 4 0 1 1 8 0 4 4 0 0 1-8 0Z" clipRule="evenodd" />
                        </svg>
                      </span>
                      <TextInput
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        placeholder="Search assets — hostname, IP, owner, environment…"
                        aria-label="Search assets"
                        className="h-11 rounded-xl border-slate-300 bg-white pl-10 pr-28 shadow-sm focus:border-blue-600 focus:ring-blue-100"
                      />
                      <span className="pointer-events-none absolute right-3 top-1/2 hidden -translate-y-1/2 rounded-md border border-slate-200 bg-slate-50 px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400 sm:inline-flex">
                        Live filter
                      </span>
                    </div>
                    <div className="min-w-60">
                      <Field label="Group">
                        <NativeSelect value={groupId} onChange={setGroupId} placeholder="All groups" options={groups.map((g) => ({ value: g.id, label: `${g.name} (${g.asset_count})` }))} />
                      </Field>
                    </div>
                    <ActionButton variant="ghost" disabled={!search && !groupId} onClick={() => { setSearch(''); setGroupId('') }}>Clear</ActionButton>
                  </div>
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    <span className="font-semibold uppercase tracking-wide text-slate-400">Try</span>
                    {['192.168', 'mongodb', 'production', 'IAM'].map((sample) => (
                      <button key={sample} type="button" onClick={() => setSearch(sample)} className="rounded-full border border-slate-200 bg-white px-2.5 py-1 font-medium text-slate-600 shadow-sm transition hover:border-blue-300 hover:text-blue-700">
                        {sample}
                      </button>
                    ))}
                    {search.trim() ? <Badge tone="blue">{data?.total ?? 0} match</Badge> : null}
                  </div>
                </div>
              </DataPanel>
              {isLoading ? <LoadingPanel label="Loading assets…" /> : isError ? (
                <ErrorState detail={apiErrorMessage(error)} onRetry={refetch} />
              ) : (
                <DataPanel title="Asset inventory" detail={`${data?.total ?? 0} asset(s)${search.trim() ? ` matching “${search.trim()}”` : ''}${groupId ? ' in selected group' : ''}`}>
                  <DataTable columns={columns} rows={data?.items ?? []} getRowKey={(a) => a.id} onRowClick={(a) => navigate(`/assets/${a.id}`)} empty={search.trim() ? 'No assets match this search.' : 'No assets onboarded yet.'} minWidth={980} />
                </DataPanel>
              )}
            </>
          )}

          {activeTab === 'groups' && (
            <DataPanel title="Asset groups" detail="Reusable scopes for scans, ownership, and review queues.">
              {manage && <div className="flex gap-3 border-b border-slate-200 p-4"><ActionButton variant="primary" onClick={() => { setGroupForm(emptyGroup); setAssetPickSearch('') }}>New group</ActionButton></div>}
              {groupForm && (
                <div className="space-y-4 border-b border-slate-200 bg-slate-50/70 p-4">
                  <div className="grid gap-3 md:grid-cols-2">
                    <Field label="Group name" required><TextInput value={groupForm.name} onChange={(e) => setGroupForm({ ...groupForm, name: e.target.value })} placeholder="Production databases" /></Field>
                    <Field label="Description"><TextArea rows={1} value={groupForm.description} onChange={(e) => setGroupForm({ ...groupForm, description: e.target.value })} /></Field>
                  </div>
                  <Field label={`Assets (${groupForm.asset_ids.length} selected)`}>
                    <TextInput value={assetPickSearch} onChange={(e) => setAssetPickSearch(e.target.value)} placeholder="Search assets to add…" />
                    <div className="mt-2 max-h-80 overflow-y-auto rounded-md border border-slate-200 bg-white">
                      {pickableAssets.map((a) => (
                        <label key={a.id} className="flex items-center gap-2 border-b border-slate-100 px-3 py-2 text-sm last:border-0 hover:bg-slate-50">
                          <input type="checkbox" checked={groupForm.asset_ids.includes(a.id)} onChange={() => toggleGroupAsset(a.id)} />
                          <span className="font-medium text-slate-800">{a.hostname}</span><span className="text-xs text-slate-500">{a.platform} · {a.environment ?? 'no env'}</span>
                        </label>
                      ))}
                      {!pickableAssets.length && <div className="p-4 text-sm text-slate-500">No assets match this search.</div>}
                    </div>
                  </Field>
                  <div className="flex flex-wrap items-center gap-3">
                    <ActionButton variant="primary" disabled={!groupForm.name.trim() || groupBusy} onClick={saveGroup}>{groupBusy ? 'Saving…' : 'Save group'}</ActionButton>
                    <ActionButton variant="ghost" onClick={() => setGroupForm(null)}>Cancel</ActionButton>
                    {(createGroupState.isError || updateGroupState.isError) && <InlineAlert tone="red">{apiErrorMessage(createGroupState.error ?? updateGroupState.error)}</InlineAlert>}
                  </div>
                </div>
              )}
              {groupsQ.isLoading ? <div className="p-4"><LoadingPanel label="Loading groups…" /></div> : groupsQ.isError ? <ErrorState detail={apiErrorMessage(groupsQ.error)} onRetry={groupsQ.refetch} /> : (
                <DataTable columns={groupCols} rows={groups} getRowKey={(g) => g.id} empty="No asset groups configured yet." minWidth={720} />
              )}
            </DataPanel>
          )}

          {activeTab === 'import' && (
            manage ? (
              <DataPanel title="Bulk import assets" detail="Download the Excel template, complete the Assets sheet, then save it as CSV for upload.">
                <div className="grid gap-4 p-4 lg:grid-cols-[minmax(0,1fr)_320px]">
                  <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-5">
                    <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg border border-blue-100 bg-blue-50 p-3">
                      <div>
                        <div className="text-sm font-semibold text-blue-950">Need the correct format?</div>
                        <div className="mt-0.5 text-xs text-blue-800">Use the sample workbook with required columns, examples, and platform dropdowns.</div>
                      </div>
                      <ActionButton onClick={() => downloadServerFile('/assets/import/template/excel', 'asset_bulk_import_template.xlsx')}>Download Excel template</ActionButton>
                    </div>
                    <Field label="CSV inventory file" hint="Use this for onboarding known systems before discovery scans.">
                      <input type="file" accept=".csv,text/csv" onChange={(e) => uploadCsv(e.target.files?.[0] ?? null)} className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm" />
                    </Field>
                    <div className="mt-4 space-y-2">
                      {importState.isLoading && <InlineAlert tone="slate">Importing assets…</InlineAlert>}
                      {importState.isSuccess && importState.data && <InlineAlert tone="green">Imported {importState.data.imported_rows}; updated {importState.data.duplicate_rows}; invalid {importState.data.invalid_rows}.</InlineAlert>}
                      {importState.isError && <InlineAlert tone="red">{apiErrorMessage(importState.error)}</InlineAlert>}
                    </div>
                  </div>
                  <div className="rounded-lg border border-slate-200 bg-white p-4 text-sm text-slate-600">
                    <div className="font-semibold text-slate-900">Expected columns</div>
                    <p className="mt-2 text-xs leading-5 text-slate-500">Columns marked in the template are accepted by the existing bulk import. Only hostname and platform are required.</p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      {['hostname', 'platform', 'ip_address', 'port', 'environment', 'owner', 'business_unit', 'criticality', 'connector_name'].map((column) => <Badge key={column} tone="slate">{column}</Badge>)}
                    </div>
                  </div>
                </div>
                {importState.data?.errors?.length ? (
                  <div className="border-t border-slate-200 p-4 text-xs text-amber-800">
                    <div className="font-semibold">Import warnings</div>
                    <ul className="mt-2 list-disc space-y-1 pl-5">{importState.data.errors.slice(0, 5).map((err, i) => <li key={i}>Row {String(err.row ?? '—')}: {String(err.error ?? 'Unknown error')}</li>)}</ul>
                  </div>
                ) : null}
              </DataPanel>
            ) : <InlineAlert tone="slate">Your role can view assets but cannot bulk import inventory.</InlineAlert>
          )}
        </div>
      </div>
    </PageFrame>
  )
}

function AssetSummary({ label, value, detail, tone }: { label: string; value: number; detail: string; tone: 'blue' | 'emerald' | 'slate' }) {
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
