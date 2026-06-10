import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getScans, launchScan, cancelScan, retryFailed, getScanTargets, getScanProfiles,
  createScanProfile, updateScanProfile, deleteScanProfile, seedScanProfiles,
  createSchedule, deleteSchedule, getSchedules, updateSchedule, getAssets, getAssetGroups,
} from '@/api/endpoints'
import type { AssetGroup, ScanProfile } from '@/api/endpoints'
import { PageHeader } from '@/components/PageHeader'
import { PageSpinner } from '@/components/Spinner'
import { JOB_STATUS_COLORS, PLATFORM_LABELS } from '@/lib/privilege'
import toast from 'react-hot-toast'
import { format } from 'date-fns'
import clsx from 'clsx'

type ScheduleFrequency = 'daily' | 'weekly' | 'monthly' | 'custom'

type SchedulePickerState = {
  frequency: ScheduleFrequency
  hour: string
  minute: string
  weekdays: string[]
  monthDay: string
  customCron: string
}

const GMT8_LABEL = 'GMT+8'
const GMT8_TIME_ZONE = 'Asia/Kuala_Lumpur'
const DEFAULT_SCHEDULE: SchedulePickerState = {
  frequency: 'daily',
  hour: '02',
  minute: '00',
  weekdays: ['1'],
  monthDay: '1',
  customCron: '0 2 * * *',
}
const WEEKDAYS = [
  { value: '1', label: 'Mon' },
  { value: '2', label: 'Tue' },
  { value: '3', label: 'Wed' },
  { value: '4', label: 'Thu' },
  { value: '5', label: 'Fri' },
  { value: '6', label: 'Sat' },
  { value: '0', label: 'Sun' },
]

function newScheduleForm() {
  const _schedule = { ...DEFAULT_SCHEDULE }
  return { name: '', description: '', cron: cronFromSchedule(_schedule), profile_id: '', scope: { all_enabled: true }, enabled: true, requires_approval: false, _schedule }
}

function padTime(value: string | number) {
  return String(value).padStart(2, '0')
}

function cronFromSchedule(schedule: SchedulePickerState) {
  const minute = Number(schedule.minute)
  const hour = Number(schedule.hour)
  if (schedule.frequency === 'weekly') {
    const weekdays = schedule.weekdays.length ? schedule.weekdays.join(',') : '1'
    return `${minute} ${hour} * * ${weekdays}`
  }
  if (schedule.frequency === 'monthly') {
    return `${minute} ${hour} ${Number(schedule.monthDay)} * *`
  }
  if (schedule.frequency === 'custom') return schedule.customCron || DEFAULT_SCHEDULE.customCron
  return `${minute} ${hour} * * *`
}

function scheduleFromCron(cron: string): SchedulePickerState {
  const [minute = '0', hour = '2', day = '*', month = '*', weekday = '*'] = (cron || '').trim().split(/\s+/)
  const base = { ...DEFAULT_SCHEDULE, hour: padTime(hour), minute: padTime(minute), customCron: cron || DEFAULT_SCHEDULE.customCron }
  if (month === '*' && day === '*' && weekday === '*') return { ...base, frequency: 'daily' }
  if (month === '*' && day === '*' && weekday !== '*') return { ...base, frequency: 'weekly', weekdays: weekday.split(',').filter(Boolean) }
  if (month === '*' && weekday === '*' && day !== '*') return { ...base, frequency: 'monthly', monthDay: day }
  return { ...base, frequency: 'custom' }
}

function describeCron(cron: string) {
  const schedule = scheduleFromCron(cron)
  const time = `${schedule.hour}:${schedule.minute} ${GMT8_LABEL}`
  if (schedule.frequency === 'daily') return `Daily at ${time}`
  if (schedule.frequency === 'weekly') {
    const dayLabels = schedule.weekdays
      .map((day) => WEEKDAYS.find((weekday) => weekday.value === day)?.label ?? day)
      .join(', ')
    return `Weekly on ${dayLabels || 'Mon'} at ${time}`
  }
  if (schedule.frequency === 'monthly') return `Monthly on day ${schedule.monthDay} at ${time}`
  return `Custom: ${cron} (${GMT8_LABEL})`
}

function scheduleSentence(cron: string) {
  const description = describeCron(cron)
  return `${description.charAt(0).toLowerCase()}${description.slice(1)}`
}

function formatInGmt8(value: string) {
  return `${new Intl.DateTimeFormat('en-GB', {
    timeZone: GMT8_TIME_ZONE,
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(new Date(value)).replace(',', '')} ${GMT8_LABEL}`
}

function schedulePayload(form: any) {
  return {
    name: form.name,
    description: form.description || null,
    cron: form.cron,
    profile_id: form.profile_id,
    scope: form.scope,
    enabled: !!form.enabled,
    requires_approval: !!form.requires_approval,
  }
}

function defaultTargetScope() {
  return { all_enabled: true, use_group_scope: false, use_asset_scope: false, group_ids: [], asset_ids: [] }
}

function profileTargetScope(profile?: Partial<ScanProfile> | null) {
  return profile?.target_scope ?? defaultTargetScope()
}

function launchScopeForProfile(profile?: ScanProfile) {
  if (!profile) return { all_enabled: true }
  const scope = profileTargetScope(profile)
  if (scope.use_group_scope || scope.use_asset_scope) {
    return {
      all_enabled: false,
      group_ids: scope.use_group_scope ? (scope.group_ids ?? []) : [],
      asset_ids: scope.use_asset_scope ? (scope.asset_ids ?? []) : [],
    }
  }
  const groupIds = scope.group_ids ?? []
  const assetIds = scope.asset_ids ?? []
  if (groupIds.length || assetIds.length) return { group_ids: groupIds, asset_ids: assetIds }
  return { all_enabled: true }
}

function describeTargetScope(scope: { all_enabled?: boolean; use_group_scope?: boolean; use_asset_scope?: boolean; group_ids?: string[]; asset_ids?: string[] }, groups: AssetGroup[] = [], assets: Array<{ id: string; hostname: string }> = []) {
  const groupIds = scope.use_group_scope === false ? [] : (scope.group_ids ?? [])
  const assetIds = scope.use_asset_scope === false ? [] : (scope.asset_ids ?? [])
  if (groupIds.length || assetIds.length) {
    const parts = []
    if (groupIds.length) {
      const names = groupIds.map((id) => groups.find((group) => group.id === id)?.name ?? 'group').join(', ')
      parts.push(`${groupIds.length} group${groupIds.length === 1 ? '' : 's'}${names ? `: ${names}` : ''}`)
    }
    if (assetIds.length) {
      const names = assetIds.map((id) => assets.find((asset) => asset.id === id)?.hostname ?? 'asset').join(', ')
      parts.push(`${assetIds.length} asset${assetIds.length === 1 ? '' : 's'}${names ? `: ${names}` : ''}`)
    }
    return parts.join(' + ')
  }
  if (scope.use_group_scope || scope.use_asset_scope) return 'No targets selected'
  return 'All enabled assets'
}

export default function Scans() {
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<'jobs' | 'schedules' | 'profiles'>('jobs')
  const [showLaunch, setShowLaunch] = useState(false)
  const [launchCollectPolicy, setLaunchCollectPolicy] = useState(false)
  const [selectedJob, setSelectedJob] = useState<string | null>(null)
  const [showSchedule, setShowSchedule] = useState(false)
  const [editingSchedule, setEditingSchedule] = useState<any | null>(null)
  const [scheduleForm, setScheduleForm] = useState<any>(newScheduleForm())
  const [showProfileModal, setShowProfileModal] = useState(false)
  const [editingProfile, setEditingProfile] = useState<ScanProfile | null>(null)
  const [profileForm, setProfileForm] = useState<Partial<ScanProfile>>({ name: '', description: '', platforms: [], mode: 'safe', target_scope: defaultTargetScope() })
  const [selectedLaunchProfile, setSelectedLaunchProfile] = useState('')

  const { data, isLoading } = useQuery({
    queryKey: ['scans'],
    queryFn: () => getScans({ limit: 50 }).then((r) => r.data),
    refetchInterval: 8_000,
  })

  const { data: profiles } = useQuery({
    queryKey: ['scan-profiles'],
    queryFn: () => getScanProfiles().then((r) => r.data),
  })

  const { data: schedules } = useQuery({
    queryKey: ['schedules'],
    queryFn: () => getSchedules({ limit: 100 }).then((r) => r.data),
  })

  const { data: assets } = useQuery({
    queryKey: ['assets', 'schedule-picker'],
    queryFn: () => getAssets({ limit: 200 }).then((r) => r.data),
  })

  const { data: assetGroups } = useQuery({
    queryKey: ['asset-groups', 'scan-profile-picker'],
    queryFn: () => getAssetGroups().then((r) => r.data),
  })

  const { data: targets } = useQuery({
    queryKey: ['scan-targets', selectedJob],
    queryFn: () => getScanTargets(selectedJob!).then((r) => r.data),
    enabled: !!selectedJob,
    refetchInterval: 4_000,
  })

  const launchMut = useMutation({
    mutationFn: (d: { all_enabled?: boolean; asset_ids?: string[]; group_ids?: string[]; profile_id?: string; collect_password_policy?: boolean }) =>
      launchScan(d).then((r) => r.data),
    onSuccess: (j) => {
      qc.invalidateQueries({ queryKey: ['scans'] })
      setShowLaunch(false)
      setLaunchCollectPolicy(false)
      toast.success(`Scan ${j.id.slice(0, 8)} launched`)
      setSelectedJob(j.id)
    },
    onError: () => toast.error('Launch failed'),
  })

  const cancelMut = useMutation({
    mutationFn: (id: string) => cancelScan(id).then((r) => r.data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scans'] }); toast.success('Scan cancelled') },
  })

  const retryMut = useMutation({
    mutationFn: (id: string) => retryFailed(id).then((r) => r.data),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scans'] }); toast.success('Retrying failed targets') },
  })

  const createScheduleMut = useMutation({
    mutationFn: (data: Record<string, unknown>) => createSchedule(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['schedules'] })
      setShowSchedule(false)
      setScheduleForm(newScheduleForm())
      toast.success('Schedule created')
    },
    onError: () => toast.error('Failed to create schedule'),
  })

  const updateScheduleMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Record<string, unknown> }) => updateSchedule(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['schedules'] })
      setEditingSchedule(null)
      toast.success('Schedule updated')
    },
    onError: () => toast.error('Failed to update schedule'),
  })

  const deleteScheduleMut = useMutation({
    mutationFn: (id: string) => deleteSchedule(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['schedules'] })
      toast.success('Schedule deleted')
    },
    onError: () => toast.error('Failed to delete schedule'),
  })

  const createProfileMut = useMutation({
    mutationFn: (data: Partial<ScanProfile>) => createScanProfile(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-profiles'] })
      setShowProfileModal(false)
      setProfileForm({ name: '', description: '', platforms: [], mode: 'safe', target_scope: defaultTargetScope() })
      toast.success('Profile created')
    },
    onError: () => toast.error('Failed to create profile'),
  })

  const updateProfileMut = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<ScanProfile> }) => updateScanProfile(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-profiles'] })
      setEditingProfile(null)
      toast.success('Profile updated')
    },
    onError: () => toast.error('Failed to update profile'),
  })

  const deleteProfileMut = useMutation({
    mutationFn: (id: string) => deleteScanProfile(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scan-profiles'] })
      toast.success('Profile deleted')
    },
    onError: () => toast.error('Failed to delete profile'),
  })

  const seedProfilesMut = useMutation({
    mutationFn: () => seedScanProfiles(),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['scan-profiles'] })
      toast.success(r.data.message)
    },
    onError: () => toast.error('Failed to seed profiles'),
  })

  return (
    <div>
      <PageHeader
        title="Scans"
        subtitle="Discovery job history and live status"
        actions={
          <button className="btn-primary" onClick={() => setShowLaunch(true)}>+ Launch Scan</button>
        }
      />

      <div className="px-6 pt-5">
        <div className="inline-flex rounded-lg border border-slate-200 bg-white p-1 shadow-sm">
          {[
            { id: 'jobs', label: 'Jobs' },
            { id: 'schedules', label: 'Scheduled Scans' },
            { id: 'profiles', label: 'Scan Profiles' },
          ].map((tab) => (
            <button
              key={tab.id}
              className={clsx(
                'px-3 py-1.5 text-sm font-medium rounded-md transition-colors',
                activeTab === tab.id
                  ? 'bg-brand-600 text-white shadow-sm'
                  : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900',
              )}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
            >
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {activeTab === 'jobs' && (
      <div className="p-6 grid grid-cols-1 xl:grid-cols-2 gap-4">
        {/* Job list */}
        <div className="card overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-100 text-sm font-semibold text-slate-700">Recent Jobs</div>
          {isLoading ? <PageSpinner /> : (
            <div className="divide-y divide-slate-100">
              {data?.items.map((j) => (
                <div
                  key={j.id}
                  className={clsx('px-4 py-3 cursor-pointer hover:bg-slate-50 transition-colors', selectedJob === j.id && 'bg-brand-50')}
                  onClick={() => setSelectedJob(j.id)}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div>
                      <div className="font-medium text-slate-900 text-sm">{j.scope_description}</div>
                      <div className="text-[11px] text-slate-400 mt-0.5">
                        {format(new Date(j.created_at), 'dd MMM yyyy HH:mm')} · {j.triggered_kind} · {j.triggered_by ?? 'system'}
                      </div>
                    </div>
                    <span className={clsx('badge text-[11px]', JOB_STATUS_COLORS[j.status])}>{j.status}</span>
                  </div>
                  {j.totals && (
                    <div className="flex gap-3 mt-1 text-[11px] text-slate-500">
                      <span>✓ {j.totals.success ?? 0}</span>
                      <span>✗ {j.totals.failed ?? 0}</span>
                      <span>Total {j.totals.total ?? 0}</span>
                    </div>
                  )}
                  {['running', 'queued', 'pending'].includes(j.status) && (
                    <button className="mt-1 text-[11px] text-red-500 hover:text-red-700"
                      onClick={(e) => { e.stopPropagation(); cancelMut.mutate(j.id) }}>Cancel</button>
                  )}
                  {j.status === 'partial_success' || j.status === 'failed' ? (
                    <button className="mt-1 text-[11px] text-brand-500 hover:text-brand-700 ml-2"
                      onClick={(e) => { e.stopPropagation(); retryMut.mutate(j.id) }}>Retry failed</button>
                  ) : null}
                </div>
              ))}
              {data?.items.length === 0 && <div className="p-8 text-center text-slate-400">No scans yet. Launch one to get started.</div>}
            </div>
          )}
        </div>

        {/* Target details */}
        <div className="card overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-100 text-sm font-semibold text-slate-700">
            {selectedJob ? (
              <>Targets — <span className="font-mono text-slate-500">{selectedJob.slice(0, 8)}…</span></>
            ) : 'Select a job to view targets'}
          </div>
          {targets ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="bg-slate-50 border-b border-slate-100">
                    <th className="table-th">Asset</th>
                    <th className="table-th">Platform</th>
                    <th className="table-th">Status</th>
                    <th className="table-th">Duration</th>
                    <th className="table-th">Accounts</th>
                    <th className="table-th">Error</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-50">
                  {targets.map((t) => (
                    <tr key={t.id} className="hover:bg-slate-50">
                      <td className="table-td">
                        <div className="font-medium text-slate-800 text-sm">{t.hostname ?? t.ip_address ?? t.asset_id.slice(0, 8)}</div>
                        {t.hostname && t.ip_address && <div className="text-[10px] text-slate-400">{t.ip_address}</div>}
                      </td>
                      <td className="table-td"><span className="badge bg-slate-100 text-slate-600">{PLATFORM_LABELS[t.platform]}</span></td>
                      <td className="table-td"><span className={clsx('badge', JOB_STATUS_COLORS[t.status])}>{t.status}</span></td>
                      <td className="table-td text-slate-500">{t.duration_ms ? `${(t.duration_ms / 1000).toFixed(1)}s` : '—'}</td>
                      <td className="table-td text-slate-500">{t.stats?.accounts ?? '—'}</td>
                      <td className="table-td text-xs text-red-600 max-w-[200px]">
                        {t.error_bucket && <div className="font-semibold">{t.error_bucket}</div>}
                        {t.error_detail && <div className="text-slate-500 break-words whitespace-normal">{t.error_detail}</div>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="p-8 text-center text-slate-400 text-sm">Select a job on the left.</div>
          )}
        </div>
      </div>
      )}

      {activeTab === 'schedules' && (
      <div className="px-6 pb-6">
        <div className="card overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-100 text-sm font-semibold text-slate-700 flex items-center justify-between">
            <span>Scheduled Scans</span>
            <button className="btn-secondary text-xs py-1" onClick={() => setShowSchedule(true)}>+ Add Schedule</button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr>
                  <th className="table-th">Name</th>
                    <th className="table-th">Schedule</th>
                  <th className="table-th">Profile</th>
                  <th className="table-th">Enabled</th>
                  <th className="table-th">Last Run</th>
                  <th className="table-th">Next Run</th>
                  <th className="table-th">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {schedules?.items.map((schedule) => (
                  <tr key={schedule.id} className="hover:bg-slate-50">
                    <td className="table-td font-medium">{schedule.name}</td>
                    <td className="table-td text-slate-500 text-xs">{describeCron(schedule.cron)}</td>
                    <td className="table-td text-slate-500 text-xs">{profiles?.items.find((p) => p.id === schedule.profile_id)?.name ?? schedule.profile_id}</td>
                    <td className="table-td">
                      <span className={`badge ${schedule.enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-400'}`}>{schedule.enabled ? 'enabled' : 'disabled'}</span>
                    </td>
                    <td className="table-td text-slate-400 text-xs">{schedule.last_run_at ? formatInGmt8(schedule.last_run_at) : 'Never'}</td>
                    <td className="table-td text-slate-400 text-xs">{schedule.next_run_at ? formatInGmt8(schedule.next_run_at) : '—'}</td>
                    <td className="table-td">
                      <div className="flex gap-1.5">
                        <button className="btn-secondary text-xs py-1" onClick={() => setEditingSchedule(schedule)}>Edit</button>
                        <button className="btn text-xs py-1 text-red-600 hover:bg-red-50 border border-red-200" onClick={() => {
                          if (confirm(`Delete schedule ${schedule.name}?`)) deleteScheduleMut.mutate(schedule.id)
                        }}>Delete</button>
                      </div>
                    </td>
                  </tr>
                ))}
                {schedules?.items.length === 0 && (
                  <tr><td colSpan={7} className="py-12 text-center text-slate-400">No scheduled scans configured.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      )}

      {/* Launch modal */}
      {showLaunch && (
        <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 p-4">
          <div className="card w-full max-w-sm p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-semibold">Launch Scan</h2>
              <button className="text-slate-400 hover:text-slate-600 text-xl" onClick={() => setShowLaunch(false)}>×</button>
            </div>
            <div className="space-y-3">
              <div>
                <label className="label">Scan Profile</label>
                <select
                  className="input"
                  value={selectedLaunchProfile}
                  onChange={(e) => setSelectedLaunchProfile(e.target.value)}
                >
                  <option value="">Default (all platforms)</option>
                  {profiles?.items.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
                </select>
              </div>
              {(() => {
                const profile = profiles?.items.find((p) => p.id === selectedLaunchProfile)
                if (!profile) return <p className="text-xs text-slate-500">All platforms will be scanned.</p>
                return (
                  <div className="bg-slate-50 rounded-lg p-3 space-y-1.5">
                    {profile.description && (
                      <p className="text-xs text-slate-600">{profile.description}</p>
                    )}
                    <div className="flex flex-wrap gap-1">
                      {profile.platforms.length === 0 ? (
                        <span className="badge bg-blue-100 text-blue-700 text-[11px]">All platforms</span>
                      ) : (
                        profile.platforms.map((plat) => (
                          <span key={plat} className="badge bg-brand-100 text-brand-700 text-[11px]">
                            {PLATFORM_LABELS[plat] ?? plat}
                          </span>
                        ))
                      )}
                    </div>
                    {profile.platforms.length > 0 && (
                      <p className="text-[11px] text-slate-400">Assets outside this scope will be skipped.</p>
                    )}
                    <p className="text-[11px] text-slate-500">
                      Target scope: {describeTargetScope(profileTargetScope(profile), assetGroups ?? [], assets?.items ?? [])}
                    </p>
                    {profile.collect_password_policy && (
                      <p className="text-[11px] text-amber-600 font-medium">
                        🔑 Password policy collection enabled by profile
                      </p>
                    )}
                  </div>
                )
              })()}
              <label className="flex items-center gap-2 text-sm cursor-pointer pt-1">
                <input
                  type="checkbox"
                  checked={launchCollectPolicy || !!(profiles?.items.find((p) => p.id === selectedLaunchProfile)?.collect_password_policy)}
                  onChange={(e) => setLaunchCollectPolicy(e.target.checked)}
                />
                <span>
                  Collect password policies
                  <span className="ml-1 text-[11px] text-slate-400">(adds extra commands per target)</span>
                </span>
              </label>
              <div className="flex gap-2 pt-2">
                <button
                  className="btn-primary"
                  onClick={() => {
                    const profile = profiles?.items.find((p) => p.id === selectedLaunchProfile)
                    launchMut.mutate({
                      ...launchScopeForProfile(profile),
                      profile_id: selectedLaunchProfile || undefined,
                      collect_password_policy: launchCollectPolicy || !!profile?.collect_password_policy,
                    })
                  }}
                  disabled={launchMut.isPending}
                >
                  {launchMut.isPending ? 'Launching...' : 'Launch Scan'}
                </button>
                <button className="btn-secondary" onClick={() => setShowLaunch(false)}>Cancel</button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Scan Profiles section */}
      {activeTab === 'profiles' && (
      <div className="px-6 pb-6">
        <div className="card overflow-hidden">
          <div className="px-4 py-3 border-b border-slate-100 text-sm font-semibold text-slate-700 flex items-center justify-between">
            <span>Scan Profiles</span>
            <div className="flex gap-2">
              <button
                className="btn-secondary text-xs py-1"
                onClick={() => seedProfilesMut.mutate()}
                disabled={seedProfilesMut.isPending}
              >
                Seed Defaults
              </button>
              <button
                className="btn-secondary text-xs py-1"
                onClick={() => {
                  setProfileForm({ name: '', description: '', platforms: [], mode: 'safe', target_scope: defaultTargetScope() })
                  setShowProfileModal(true)
                }}
              >
                + Create Profile
              </button>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr>
                  <th className="table-th">Name</th>
                  <th className="table-th">Platform Scope</th>
                  <th className="table-th">Target Scope</th>
                  <th className="table-th">Description</th>
                  <th className="table-th">Mode</th>
                  <th className="table-th">Pwd Policy</th>
                  <th className="table-th">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {profiles?.items.map((profile) => (
                  <tr key={profile.id} className="hover:bg-slate-50">
                    <td className="table-td font-medium">{profile.name}</td>
                    <td className="table-td">
                      <div className="flex flex-wrap gap-1">
                        {profile.platforms.length === 0 ? (
                          <span className="badge bg-blue-100 text-blue-700">All platforms</span>
                        ) : (
                          profile.platforms.map((plat) => (
                            <span key={plat} className="badge bg-slate-100 text-slate-600 text-[11px]">
                              {PLATFORM_LABELS[plat] ?? plat}
                            </span>
                          ))
                        )}
                      </div>
                    </td>
                    <td className="table-td text-slate-500 text-xs">
                      {describeTargetScope(profileTargetScope(profile), assetGroups ?? [], assets?.items ?? [])}
                    </td>
                    <td className="table-td text-slate-500 text-sm">{profile.description ?? '—'}</td>
                    <td className="table-td">
                      <span className="badge bg-slate-100 text-slate-600">{profile.mode}</span>
                    </td>
                    <td className="table-td text-center">
                      {profile.collect_password_policy
                        ? <span className="text-amber-500 text-sm" title="Password policy collection enabled">🔑</span>
                        : <span className="text-slate-300 text-xs">—</span>
                      }
                    </td>
                    <td className="table-td">
                      <div className="flex gap-1.5">
                        <button
                          className="btn-secondary text-xs py-1"
                          onClick={() => {
                            setEditingProfile(profile)
                            setProfileForm({ ...profile })
                          }}
                        >
                          Edit
                        </button>
                        <button
                          className="btn text-xs py-1 text-red-600 hover:bg-red-50 border border-red-200"
                          onClick={() => { if (confirm(`Delete profile "${profile.name}"?`)) deleteProfileMut.mutate(profile.id) }}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
                {profiles?.items.length === 0 && (
                  <tr><td colSpan={7} className="py-12 text-center text-slate-400">No scan profiles. Click "Seed Defaults" to create standard profiles.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
      )}

      {/* Profile create/edit modal */}
      {(showProfileModal || editingProfile) && (
        <ScanProfileModal
          title={editingProfile ? `Edit "${editingProfile.name}"` : 'Create Scan Profile'}
          form={profileForm}
          assets={assets?.items ?? []}
          assetGroups={assetGroups ?? []}
          onChange={setProfileForm}
          onClose={() => { setShowProfileModal(false); setEditingProfile(null) }}
          onSave={() => {
            if (editingProfile) {
              updateProfileMut.mutate({ id: editingProfile.id, data: profileForm })
            } else {
              createProfileMut.mutate(profileForm)
            }
          }}
          saving={createProfileMut.isPending || updateProfileMut.isPending}
        />
      )}

      {showSchedule && (
        <ScheduleModal
          title="Add Scheduled Scan"
          form={scheduleForm}
          assets={assets?.items ?? []}
          profiles={profiles?.items ?? []}
          onChange={setScheduleForm}
          onClose={() => setShowSchedule(false)}
          onSave={() => createScheduleMut.mutate(schedulePayload(scheduleForm))}
          saving={createScheduleMut.isPending}
        />
      )}

      {editingSchedule && (
        <ScheduleModal
          title={`Edit ${editingSchedule.name}`}
          form={editingSchedule}
          assets={assets?.items ?? []}
          profiles={profiles?.items ?? []}
          onChange={(next) => setEditingSchedule({ ...editingSchedule, ...next })}
          onClose={() => setEditingSchedule(null)}
          onSave={() => updateScheduleMut.mutate({ id: editingSchedule.id, data: schedulePayload(editingSchedule) })}
          saving={updateScheduleMut.isPending}
        />
      )}
    </div>
  )
}

const ALL_PLATFORMS = [
  // Unix / Linux
  'rhel', 'centos', 'ubuntu', 'sles', 'solaris', 'aix', 'hpux',
  // Windows
  'windows',
  // Databases
  'mysql', 'mssql', 'mongodb', 'oracle_db', 'postgresql', 'redis',
] as const

function ScanProfileModal({
  title,
  form,
  assets,
  assetGroups,
  onChange,
  onClose,
  onSave,
  saving,
}: {
  title: string
  form: Partial<ScanProfile>
  assets: Array<{ id: string; hostname: string }>
  assetGroups: AssetGroup[]
  onChange: (next: Partial<ScanProfile>) => void
  onClose: () => void
  onSave: () => void
  saving: boolean
}) {
  const update = (patch: Partial<ScanProfile>) => onChange({ ...form, ...patch })
  const selectedPlatforms: string[] = form.platforms ?? []
  const targetScope = profileTargetScope(form)
  const useAssetGroups = !!targetScope.use_group_scope || (targetScope.group_ids ?? []).length > 0
  const useSpecificAssets = !!targetScope.use_asset_scope || (targetScope.asset_ids ?? []).length > 0
  const updateTargetScope = (patch: Partial<{ all_enabled: boolean; use_group_scope: boolean; use_asset_scope: boolean; group_ids: string[]; asset_ids: string[] }>) => {
    const nextGroupIds = patch.group_ids ?? targetScope.group_ids ?? []
    const nextAssetIds = patch.asset_ids ?? targetScope.asset_ids ?? []
    const nextUseGroups = patch.use_group_scope ?? useAssetGroups
    const nextUseAssets = patch.use_asset_scope ?? useSpecificAssets
    const next = {
      all_enabled: !nextUseGroups && !nextUseAssets,
      use_group_scope: nextUseGroups,
      use_asset_scope: nextUseAssets,
      group_ids: nextGroupIds,
      asset_ids: nextAssetIds,
      ...patch,
    }
    update({ target_scope: next } as Partial<ScanProfile>)
  }

  function togglePlatform(plat: string) {
    if (selectedPlatforms.includes(plat)) {
      update({ platforms: selectedPlatforms.filter((p) => p !== plat) as any })
    } else {
      update({ platforms: [...selectedPlatforms, plat] as any })
    }
  }

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-2xl p-6 max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold">{title}</h2>
          <button className="text-slate-400 hover:text-slate-600 text-xl" onClick={onClose}>×</button>
        </div>
        <div className="space-y-3">
          <Field label="Name">
            <input className="input" value={form.name ?? ''} onChange={(e) => update({ name: e.target.value })} />
          </Field>
          <Field label="Description">
            <input className="input" value={form.description ?? ''} onChange={(e) => update({ description: e.target.value || undefined })} />
          </Field>
          <Field label="Mode">
            <select className="input" value={form.mode ?? 'safe'} onChange={(e) => update({ mode: e.target.value as any })}>
              <option value="safe">Safe</option>
              <option value="deep">Deep</option>
            </select>
          </Field>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={!!form.collect_password_policy}
              onChange={(e) => update({ collect_password_policy: e.target.checked } as any)}
            />
            <span>
              Collect password policies
              <span className="block text-[11px] text-slate-400 font-normal">
                Runs extra commands on each target to collect and evaluate password policy settings.
                Supported: Windows, RHEL/Linux, MSSQL, MySQL, MongoDB.
              </span>
            </span>
          </label>
          <div>
            <label className="label">Platform Scope</label>
            <p className="text-[11px] text-slate-400 mb-2">Check platforms to restrict. Leave all unchecked for "all platforms".</p>
            <div className="grid grid-cols-2 gap-1.5">
              {ALL_PLATFORMS.map((plat) => (
                <label key={plat} className="flex items-center gap-2 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={selectedPlatforms.includes(plat)}
                    onChange={() => togglePlatform(plat)}
                  />
                  {PLATFORM_LABELS[plat] ?? plat}
                </label>
              ))}
            </div>
            {selectedPlatforms.length === 0 && (
              <p className="text-[11px] text-blue-600 mt-1">All platforms (no restriction)</p>
            )}
          </div>
          <div className="border-t border-slate-100 pt-3 space-y-3">
            <div>
              <label className="label">Target Scope</label>
              <p className="text-[11px] text-slate-400">Leave both options unchecked to run this profile against all enabled assets.</p>
            </div>
            <label className="flex items-start gap-2 text-sm cursor-pointer">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={useAssetGroups}
                onChange={(e) => updateTargetScope({ use_group_scope: e.target.checked, group_ids: e.target.checked ? (targetScope.group_ids ?? []) : [] })}
              />
              <span>
                Include asset groups
                <span className="block text-[11px] text-slate-400 font-normal">Enable this before selecting one or more saved asset groups.</span>
              </span>
            </label>
            {useAssetGroups && (
              <Field label="Asset Groups">
                <select
                  className="input min-h-24"
                  multiple
                  value={targetScope.group_ids ?? []}
                  onChange={(e) => updateTargetScope({ group_ids: Array.from(e.target.selectedOptions).map((opt) => opt.value) })}
                >
                  {assetGroups.map((group) => (
                    <option key={group.id} value={group.id}>{group.name} ({group.asset_count})</option>
                  ))}
                </select>
                {assetGroups.length === 0 && <p className="text-[11px] text-slate-400 mt-1">No asset groups available.</p>}
              </Field>
            )}
            <label className="flex items-start gap-2 text-sm cursor-pointer">
              <input
                type="checkbox"
                className="mt-0.5"
                checked={useSpecificAssets}
                onChange={(e) => updateTargetScope({ use_asset_scope: e.target.checked, asset_ids: e.target.checked ? (targetScope.asset_ids ?? []) : [] })}
              />
              <span>
                Pick specific assets
                <span className="block text-[11px] text-slate-400 font-normal">Use this when asset groups are not suitable for this profile.</span>
              </span>
            </label>
            {useSpecificAssets && (
              <Field label="Specific Assets">
                <select
                  className="input min-h-32"
                  multiple
                  value={targetScope.asset_ids ?? []}
                  onChange={(e) => updateTargetScope({ asset_ids: Array.from(e.target.selectedOptions).map((opt) => opt.value) })}
                >
                  {assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.hostname}</option>)}
                </select>
                {assets.length === 0 && <p className="text-[11px] text-slate-400 mt-1">No assets available.</p>}
              </Field>
            )}
            <p className="text-xs text-slate-500">
              Current target scope: {describeTargetScope(targetScope, assetGroups, assets)}.
            </p>
          </div>
          <div className="flex gap-2 pt-2">
            <button className="btn-primary" onClick={onSave} disabled={saving}>
              {saving ? 'Saving...' : 'Save'}
            </button>
            <button className="btn-secondary" onClick={onClose}>Cancel</button>
          </div>
        </div>
      </div>
    </div>
  )
}

function ScheduleModal({
  title,
  form,
  assets,
  profiles,
  onChange,
  onClose,
  onSave,
  saving,
}: {
  title: string
  form: any
  assets: Array<{ id: string; hostname: string }>
  profiles: Array<{ id: string; name: string }>
  onChange: (next: any) => void
  onClose: () => void
  onSave: () => void
  saving: boolean
}) {
  const scopeMode = form.scope?.asset_ids?.length ? 'assets' : 'all'
  const scheduleState: SchedulePickerState = form._schedule ?? scheduleFromCron(form.cron)
  const update = (patch: Record<string, unknown>) => onChange({ ...form, ...patch })
  const updateSchedule = (patch: Partial<SchedulePickerState>) => {
    const next = { ...scheduleState, ...patch }
    const cron = cronFromSchedule(next)
    onChange({ ...form, _schedule: next, cron })
  }
  const toggleWeekday = (day: string) => {
    const weekdays = scheduleState.weekdays.includes(day)
      ? scheduleState.weekdays.filter((selected) => selected !== day)
      : [...scheduleState.weekdays, day]
    if (weekdays.length === 0) return
    updateSchedule({ weekdays })
  }

  return (
    <div className="fixed inset-0 bg-black/30 flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-xl p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="font-semibold">{title}</h2>
          <button className="text-slate-400 hover:text-slate-600 text-xl" onClick={onClose}>×</button>
        </div>
        <div className="space-y-3">
          <Field label="Name"><input className="input" value={form.name ?? ''} onChange={(e) => update({ name: e.target.value })} /></Field>
          <Field label="Description"><input className="input" value={form.description ?? ''} onChange={(e) => update({ description: e.target.value })} /></Field>
          <div>
            <div className="flex items-center justify-between gap-3 mb-2">
              <label className="label mb-0">Schedule</label>
              <span className="text-[11px] font-medium text-slate-500">{GMT8_LABEL}</span>
            </div>
            <div className="grid grid-cols-4 gap-1.5">
              {[
                { id: 'daily', label: 'Daily' },
                { id: 'weekly', label: 'Weekly' },
                { id: 'monthly', label: 'Monthly' },
                { id: 'custom', label: 'Custom' },
              ].map((option) => (
                <button
                  key={option.id}
                  type="button"
                  className={clsx(
                    'rounded-md border px-2 py-2 text-xs font-medium transition-colors',
                    scheduleState.frequency === option.id
                      ? 'border-brand-600 bg-brand-50 text-brand-700'
                      : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50',
                  )}
                  onClick={() => updateSchedule({ frequency: option.id as ScheduleFrequency })}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>
          {scheduleState.frequency !== 'custom' && (
            <div className="grid grid-cols-2 gap-3">
              <Field label="Time">
                <input
                  className="input"
                  type="time"
                  value={`${scheduleState.hour}:${scheduleState.minute}`}
                  onChange={(e) => {
                    const [hour, minute] = e.target.value.split(':')
                    updateSchedule({ hour, minute })
                  }}
                />
              </Field>
              {scheduleState.frequency === 'monthly' ? (
                <Field label="Day of Month">
                  <select className="input" value={scheduleState.monthDay} onChange={(e) => updateSchedule({ monthDay: e.target.value })}>
                    {Array.from({ length: 31 }, (_, index) => String(index + 1)).map((day) => (
                      <option key={day} value={day}>Day {day}</option>
                    ))}
                  </select>
                </Field>
              ) : (
                <Field label="Timezone">
                  <input className="input bg-slate-50 text-slate-500" value={GMT8_LABEL} disabled />
                </Field>
              )}
            </div>
          )}
          {scheduleState.frequency === 'weekly' && (
            <div>
              <label className="label">Repeat On</label>
              <div className="grid grid-cols-7 gap-1.5">
                {WEEKDAYS.map((day) => (
                  <button
                    key={day.value}
                    type="button"
                    className={clsx(
                      'rounded-md border px-2 py-2 text-xs font-medium transition-colors',
                      scheduleState.weekdays.includes(day.value)
                        ? 'border-brand-600 bg-brand-50 text-brand-700'
                        : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50',
                    )}
                    onClick={() => toggleWeekday(day.value)}
                  >
                    {day.label}
                  </button>
                ))}
              </div>
            </div>
          )}
          {scheduleState.frequency === 'custom' && (
            <Field label="Custom Cron">
              <input
                className="input font-mono text-sm"
                value={form.cron ?? ''}
                onChange={(e) => updateSchedule({ customCron: e.target.value })}
              />
              <p className="text-[11px] text-slate-400 mt-1">Advanced custom schedule. Five-field cron is evaluated in {GMT8_LABEL}.</p>
            </Field>
          )}
          <p className="text-xs text-slate-500">Runs {scheduleSentence(form.cron ?? cronFromSchedule(scheduleState))}.</p>
          <Field label="Profile">
            <select className="input" value={form.profile_id ?? ''} onChange={(e) => update({ profile_id: e.target.value })}>
              <option value="">Select profile</option>
              {profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.name}</option>)}
            </select>
          </Field>
          <Field label="Scope">
            <select
              className="input"
              value={scopeMode}
              onChange={(e) => update({ scope: e.target.value === 'assets' ? { asset_ids: [] } : { all_enabled: true } })}
            >
              <option value="all">All enabled assets</option>
              <option value="assets">Specific assets</option>
            </select>
          </Field>
          {scopeMode === 'assets' && (
            <Field label="Asset Selection">
              <select
                className="input min-h-32"
                multiple
                value={form.scope?.asset_ids ?? []}
                onChange={(e) => update({ scope: { asset_ids: Array.from(e.target.selectedOptions).map((opt) => opt.value) } })}
              >
                {assets.map((asset) => <option key={asset.id} value={asset.id}>{asset.hostname}</option>)}
              </select>
            </Field>
          )}
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={!!form.enabled} onChange={(e) => update({ enabled: e.target.checked })} />
            Schedule enabled
          </label>
          <label className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={!!form.requires_approval} onChange={(e) => update({ requires_approval: e.target.checked })} />
            Require approval before execution
          </label>
          <div className="flex gap-2 pt-2">
            <button className="btn-primary" onClick={onSave} disabled={saving}>Save</button>
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
