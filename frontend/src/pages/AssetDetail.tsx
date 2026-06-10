import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getAccounts, getAsset, testConnection, updateAsset, getTags, assignAssetTags, removeAssetTags, getAssetPasswordPolicies, getPolicyExceptions, type PasswordPolicy } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PageSpinner } from '@/components/Spinner'
import { TagBadge } from '@/components/TagBadge'
import { PLATFORM_LABELS } from '@/lib/privilege'
import toast from 'react-hot-toast'

// ── Password Policy helpers ───────────────────────────────────────────────────

const SOURCE_LABELS: Record<string, string> = {
  local_policy: 'Local Policy', domain_policy: 'Domain Policy',
  fine_grained_ad: 'FGPP (PSO)', pam_module: 'PAM Module',
  login_defs: '/etc/login.defs', database_native: 'DB Native',
  external_idp: 'External IdP', unknown: 'Unknown',
}

function PolicyVal({ v, zero = 'None', na = '—' }: { v: unknown; zero?: string; na?: string }) {
  if (v === null || v === undefined) return <span className="text-slate-300 text-xs">{na}</span>
  if (typeof v === 'boolean') return <span className={`text-xs font-semibold ${v ? 'text-green-700' : 'text-red-600'}`}>{v ? 'Yes' : 'No'}</span>
  if (v === 0) return <span className="text-red-600 text-xs font-semibold">{zero}</span>
  return <span className="text-slate-700 text-xs">{String(v)}</span>
}

function PasswordPolicyTab({ assetId }: { assetId: string }) {
  const { data: policiesPage, isLoading } = useQuery({
    queryKey: ['pwpol', 'asset', assetId],
    queryFn: () => getAssetPasswordPolicies(assetId).then(r => r.data),
  })
  const { data: excPage } = useQuery({
    queryKey: ['pwpol', 'exceptions', 'asset', assetId],
    queryFn: () => getPolicyExceptions({ asset_id: assetId, limit: 50 }).then(r => r.data),
  })

  if (isLoading) return <div className="py-6 text-center text-slate-400 text-sm">Loading…</div>
  if (!policiesPage?.items.length) return (
    <div className="py-8 text-center text-slate-400 text-sm">
      No password policy data collected for this asset yet.
    </div>
  )

  const policies = policiesPage.items

  return (
    <div className="space-y-4">
      {policies.map((pol: PasswordPolicy) => (
        <div key={pol.id} className={`rounded-lg border ${pol.is_effective_policy ? 'border-brand-300 bg-brand-50/30' : 'border-slate-200'} p-4`}>
          <div className="flex items-start justify-between mb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="font-semibold text-sm text-slate-800">{pol.policy_name ?? SOURCE_LABELS[pol.policy_source] ?? pol.policy_source}</span>
                {pol.is_effective_policy && (
                  <span className="text-[10px] bg-green-100 text-green-700 px-1.5 py-0.5 rounded font-semibold">EFFECTIVE</span>
                )}
                {pol.external_policy_enforced && (
                  <span className="text-[10px] bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded">EXTERNAL</span>
                )}
              </div>
              <div className="text-xs text-slate-400 mt-0.5">
                {SOURCE_LABELS[pol.policy_source] ?? pol.policy_source}
                {pol.applies_to?.name ? ` · ${pol.applies_to.name}` : ''}
                {pol.precedence != null ? ` · Precedence: ${pol.precedence}` : ''}
              </div>
            </div>
            <div className="text-right">
              <div className={`text-xs font-semibold ${pol.confidence_score >= 75 ? 'text-green-700' : pol.confidence_score >= 40 ? 'text-yellow-700' : 'text-red-600'}`}>
                Confidence: {pol.confidence_score}%
              </div>
              {pol.finding_count > 0 && (
                <div className={`text-xs mt-0.5 font-semibold ${pol.critical_finding_count > 0 ? 'text-red-700' : 'text-orange-600'}`}>
                  {pol.finding_count} finding{pol.finding_count !== 1 ? 's' : ''}
                  {pol.critical_finding_count > 0 ? ` (${pol.critical_finding_count} critical)` : ''}
                </div>
              )}
            </div>
          </div>

          {pol.collection_error && (
            <div className="mb-3 text-xs text-orange-700 bg-orange-50 border border-orange-200 rounded px-3 py-2">
              ⚠ {pol.collection_error}
            </div>
          )}

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
            {[
              { label: 'Min Length', v: pol.min_password_length, zero: 'Not set' },
              { label: 'Complexity', v: pol.complexity_enabled },
              { label: 'History', v: pol.password_history_count, zero: 'None' },
              { label: 'Max Age (days)', v: pol.max_password_age_days === 0 ? null : pol.max_password_age_days, zero: 'Never' },
              { label: 'Lockout Threshold', v: pol.lockout_threshold, zero: 'None' },
              { label: 'Lockout Duration (m)', v: pol.lockout_duration_minutes === -1 ? 'Admin only' : pol.lockout_duration_minutes },
              { label: 'Reversible Enc.', v: pol.reversible_encryption_enabled },
              { label: 'Dict. Check', v: pol.dictionary_check_enabled },
            ].map(({ label, v, zero }) => (
              <div key={label} className="bg-white rounded border border-slate-100 px-3 py-2">
                <div className="text-[10px] text-slate-400 uppercase tracking-wide mb-0.5">{label}</div>
                <PolicyVal v={v} zero={zero ?? 'None'} />
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Account exceptions */}
      {excPage && excPage.total > 0 && (
        <div className="mt-4">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wide mb-2">
            Account-Level Exceptions ({excPage.total})
          </h3>
          <div className="space-y-1.5">
            {excPage.items.map(exc => (
              <div key={exc.id} className="flex items-start gap-3 bg-orange-50 border border-orange-200 rounded px-3 py-2 text-xs">
                <span className="font-semibold text-orange-800 shrink-0">{exc.exception_type.replace(/_/g, ' ')}</span>
                <span className="text-orange-700">{exc.description ?? ''}</span>
                {exc.account_name && <span className="ml-auto text-slate-500 shrink-0">Account: {exc.account_name}</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default function AssetDetail() {
  const { id } = useParams<{ id: string }>()
  const nav = useNavigate()
  const qc = useQueryClient()
  const [editing, setEditing] = useState(false)
  const [form, setForm] = useState<Record<string, any> | null>(null)

  const { data: asset, isLoading } = useQuery({
    queryKey: ['asset', id],
    queryFn: () => getAsset(id!).then((r) => r.data),
    enabled: !!id,
  })

  const { data: accounts } = useQuery({
    queryKey: ['accounts', 'asset', id],
    queryFn: () => getAccounts({ asset_id: id, limit: 100 }).then((r) => r.data),
    enabled: !!id,
  })

  const updateMut = useMutation({
    mutationFn: (data: Record<string, unknown>) => updateAsset(id!, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['asset', id] })
      qc.invalidateQueries({ queryKey: ['assets'] })
      setEditing(false)
      toast.success('Asset updated')
    },
    onError: () => toast.error('Failed to update asset'),
  })

  const testMut = useMutation({
    mutationFn: () => testConnection(id!).then((r) => r.data),
    onSuccess: (d) => toast[d.success ? 'success' : 'error'](`${d.message} (${d.latency_ms}ms)`),
    onError: () => toast.error('Connection test failed'),
  })

  const { data: allTags } = useQuery({
    queryKey: ['tags', 'active'],
    queryFn: () => getTags({ status: 'active', limit: 200 }).then((r) => r.data),
  })

  const [showTagPicker, setShowTagPicker] = useState(false)
  const [tagSearch, setTagSearch] = useState('')
  const [detailTab, setDetailTab] = useState<'accounts' | 'password-policy'>('accounts')

  const assignMut = useMutation({
    mutationFn: (tagId: string) => assignAssetTags(id!, [tagId]),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['asset', id] }); toast.success('Tag assigned') },
    onError: (e: any) => toast.error(e?.response?.data?.detail ?? 'Failed to assign tag'),
  })

  const removeMut = useMutation({
    mutationFn: (tagId: string) => removeAssetTags(id!, [tagId]),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['asset', id] }); toast.success('Tag removed') },
    onError: () => toast.error('Failed to remove tag'),
  })

  if (isLoading) return <PageSpinner />
  if (!asset) return <div className="p-6 text-slate-400">Asset not found.</div>

  const model = form ?? asset

  return (
    <div>
      <PageHeader
        title={asset.hostname}
        subtitle={`${PLATFORM_LABELS[asset.platform]}${asset.instance ? ` · ${asset.instance}` : ''}`}
        actions={
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={() => testMut.mutate()}>Test</button>
            <button
              className="btn-secondary"
              onClick={() => {
                if (editing) {
                  setEditing(false)
                  setForm(null)
                } else {
                  setEditing(true)
                  setForm(asset)
                }
              }}
            >
              {editing ? 'Discard' : 'Edit'}
            </button>
            <button className="btn-secondary" onClick={() => nav('/assets')}>← Back</button>
          </div>
        }
      />

      <div className="p-6 grid grid-cols-1 xl:grid-cols-3 gap-4">
        <div className="card p-4 xl:col-span-1 space-y-3">
          <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Asset Details</h2>
          <Field label="Hostname">
            <input className="input" disabled={!editing} value={model.hostname ?? ''} onChange={(e) => setForm({ ...model, hostname: e.target.value })} />
          </Field>
          <Field label="IP Address">
            <input className="input" disabled={!editing} value={model.ip_address ?? ''} onChange={(e) => setForm({ ...model, ip_address: e.target.value })} />
          </Field>
          <Field label="Environment">
            <input className="input" disabled={!editing} value={model.environment ?? ''} onChange={(e) => setForm({ ...model, environment: e.target.value })} />
          </Field>
          <Field label="Owner">
            <input className="input" disabled={!editing} value={model.owner ?? ''} onChange={(e) => setForm({ ...model, owner: e.target.value })} />
          </Field>
          <Field label="Business Unit">
            <input className="input" disabled={!editing} value={model.business_unit ?? ''} onChange={(e) => setForm({ ...model, business_unit: e.target.value })} />
          </Field>
          <Field label="Criticality">
            <input className="input" disabled={!editing} value={model.criticality ?? ''} onChange={(e) => setForm({ ...model, criticality: e.target.value })} />
          </Field>

          {/* ── Tags section ────────────────────────────────── */}
          <div>
            <label className="label">Tags</label>
            <div className="flex flex-wrap gap-1.5 min-h-[28px]">
              {(asset.tag_summaries ?? []).map((tag) => (
                <TagBadge
                  key={tag.id}
                  tag={tag}
                  onRemove={() => removeMut.mutate(tag.id)}
                />
              ))}
              {(asset.tag_summaries ?? []).length === 0 && (
                <span className="text-xs text-slate-400">No tags assigned</span>
              )}
            </div>
            <div className="mt-2 relative">
              {!showTagPicker ? (
                <button
                  type="button"
                  className="text-xs text-brand-600 hover:text-brand-700 font-medium"
                  onClick={() => setShowTagPicker(true)}
                >
                  + Add tag
                </button>
              ) : (
                <div className="border border-slate-200 rounded-lg bg-white shadow-lg p-2 w-64 z-10">
                  <input
                    className="input text-sm mb-2"
                    placeholder="Search tags…"
                    autoFocus
                    value={tagSearch}
                    onChange={(e) => setTagSearch(e.target.value)}
                  />
                  <div className="max-h-40 overflow-y-auto space-y-0.5">
                    {(allTags?.items ?? [])
                      .filter((t) =>
                        !asset.tag_summaries?.some((at) => at.id === t.id) &&
                        t.tag_name.toLowerCase().includes(tagSearch.toLowerCase())
                      )
                      .map((t) => (
                        <button
                          key={t.id}
                          type="button"
                          className="w-full text-left px-2 py-1.5 text-sm rounded hover:bg-slate-50 flex items-center gap-2"
                          onClick={() => {
                            assignMut.mutate(t.id)
                            setShowTagPicker(false)
                            setTagSearch('')
                          }}
                        >
                          <span
                            className="w-3 h-3 rounded-full flex-shrink-0"
                            style={{ backgroundColor: t.color }}
                          />
                          {t.tag_name}
                          {t.tag_code && (
                            <span className="text-slate-400 text-xs font-mono">{t.tag_code}</span>
                          )}
                        </button>
                      ))}
                    {(allTags?.items ?? []).filter(
                      (t) => !asset.tag_summaries?.some((at) => at.id === t.id) &&
                        t.tag_name.toLowerCase().includes(tagSearch.toLowerCase())
                    ).length === 0 && (
                      <p className="text-xs text-slate-400 px-2 py-1">No more tags available</p>
                    )}
                  </div>
                  <button
                    type="button"
                    className="mt-1 text-xs text-slate-400 hover:text-slate-600 px-2"
                    onClick={() => { setShowTagPicker(false); setTagSearch('') }}
                  >
                    Cancel
                  </button>
                </div>
              )}
            </div>
          </div>

          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input
              type="checkbox"
              disabled={!editing}
              checked={!!model.discovery_enabled}
              onChange={(e) => setForm({ ...model, discovery_enabled: e.target.checked })}
            />
            Discovery enabled
          </label>
          {editing && (
            <button className="btn-primary w-full" onClick={() => updateMut.mutate({ ...model })} disabled={updateMut.isPending}>
              Save Changes
            </button>
          )}
        </div>

        <div className="card p-4 xl:col-span-2">
          {/* Tabs */}
          <div className="flex gap-1 border-b border-slate-200 mb-4 -mt-1">
            {(['accounts', 'password-policy'] as const).map(t => (
              <button
                key={t}
                onClick={() => setDetailTab(t)}
                className={`px-3 py-1.5 text-xs font-medium border-b-2 transition-colors -mb-px ${
                  detailTab === t
                    ? 'border-brand-600 text-brand-700'
                    : 'border-transparent text-slate-400 hover:text-slate-700'
                }`}
              >
                {t === 'accounts' ? `Accounts (${accounts?.total ?? 0})` : 'Password Policy'}
              </button>
            ))}
          </div>

          {detailTab === 'accounts' && (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead className="bg-slate-50 border-b border-slate-100">
                  <tr>
                    <th className="table-th">Account</th>
                    <th className="table-th">Classification</th>
                    <th className="table-th">Type</th>
                    <th className="table-th">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {accounts?.items.map((acc) => (
                    <tr key={acc.id} className="hover:bg-slate-50 cursor-pointer" onClick={() => nav(`/accounts/${acc.id}`)}>
                      <td className="table-td font-medium">{acc.account_name}</td>
                      <td className="table-td text-slate-600">{acc.privilege_classification}</td>
                      <td className="table-td text-slate-500">{acc.principal_type}</td>
                      <td className="table-td text-slate-500">{acc.enabled_status}</td>
                    </tr>
                  ))}
                  {accounts?.items.length === 0 && (
                    <tr><td colSpan={4} className="py-10 text-center text-slate-400">No discovered accounts for this asset yet.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}

          {detailTab === 'password-policy' && id && (
            <PasswordPolicyTab assetId={id} />
          )}
        </div>
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return <div><label className="label">{label}</label>{children}</div>
}
