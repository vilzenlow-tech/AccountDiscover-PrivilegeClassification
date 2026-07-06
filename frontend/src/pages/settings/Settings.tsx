import { useState } from 'react'
import {
  useCreateScanProfileMutation, useCreateScheduleMutation, useDeleteScanProfileMutation,
  useDeleteScheduleMutation, useGetScanProfilesQuery, useGetSchedulesQuery,
  useSeedScanProfilesMutation, useUpdateScanProfileMutation, useUpdateScheduleMutation,
} from '../../api/apiSlice'
import type { Platform, ScanProfile, ScanProfileRequest, ScheduledScan, ScheduledScanRequest } from '../../api/types'
import { useCan } from '../../app/rbac'
import { changePassword, selectAuth } from '../../store/authSlice'
import { useAppDispatch, useAppSelector } from '../../store/hooks'
import {
  ActionButton, CheckChips, DataPanel, DataTable, ErrorState, Field, InlineAlert, LoadingPanel,
  NativeSelect, PageFrame, StatusBadge, TextArea, TextInput, apiErrorMessage, cx, type Column,
} from '../../components/ui'

type Tab = 'profile' | 'scan-profiles' | 'schedules'
type ProfileForm = { id?: string; name: string; description: string; platforms: Platform[]; mode: 'safe' | 'deep'; timeout_seconds: string; retry_count: string; concurrency_limit: string; collect_password_policy: boolean }
type ScheduleForm = { id?: string; name: string; description: string; run_date: string; run_time: string; profile_id: string; all_enabled: boolean; enabled: boolean; requires_approval: boolean }
type PasswordForm = { currentPassword: string; newPassword: string; confirmPassword: string }

const PLATFORMS: Platform[] = ['rhel', 'centos', 'ubuntu', 'sles', 'solaris', 'aix', 'hpux', 'windows', 'mysql', 'mssql', 'mongodb', 'oracle_db', 'postgresql', 'redis']
const emptyProfile: ProfileForm = { name: '', description: '', platforms: [], mode: 'safe', timeout_seconds: '300', retry_count: '1', concurrency_limit: '10', collect_password_policy: false }
const emptySchedule: ScheduleForm = { name: '', description: '', run_date: '', run_time: '02:00', profile_id: '', all_enabled: true, enabled: true, requires_approval: false }
const fmt = (ts: string | null) => ts ? new Date(ts).toLocaleString() : '—'
const cronToDateTime = (cron: string) => {
  const [minute = '0', hour = '2', day = '*', month = '*'] = cron.split(/\s+/)
  return { run_date: day === '*' || month === '*' ? '' : `${String(new Date().getFullYear())}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`, run_time: `${hour.padStart(2, '0')}:${minute.padStart(2, '0')}` }
}
const dateTimeToCron = (runDate: string, runTime: string) => {
  const [hour = '2', minute = '0'] = runTime.split(':')
  if (!runDate) return `${Number(minute)} ${Number(hour)} * * *`
  const [, month, day] = runDate.split('-')
  return `${Number(minute)} ${Number(hour)} ${Number(day)} ${Number(month)} *`
}
const describeCron = (cron: string) => {
  const [minute = '0', hour = '2', day = '*', month = '*'] = cron.split(/\s+/)
  const time = `${hour.padStart(2, '0')}:${minute.padStart(2, '0')}`
  return day === '*' || month === '*' ? `Daily at ${time}` : `${day.padStart(2, '0')}/${month.padStart(2, '0')} at ${time}`
}

export default function Settings() {
  const can = useCan()
  const dispatch = useAppDispatch()
  const auth = useAppSelector(selectAuth)
  const [tab, setTab] = useState<Tab>('profile')
  const [profileForm, setProfileForm] = useState<ProfileForm | null>(null)
  const [scheduleForm, setScheduleForm] = useState<ScheduleForm | null>(null)
  const [passwordForm, setPasswordForm] = useState<PasswordForm>({ currentPassword: '', newPassword: '', confirmPassword: '' })
  const [passwordBusy, setPasswordBusy] = useState(false)
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const profilesQ = useGetScanProfilesQuery(undefined, { skip: tab !== 'scan-profiles' && tab !== 'schedules' })
  const schedulesQ = useGetSchedulesQuery(undefined, { skip: tab !== 'schedules' })
  const [seed, seedState] = useSeedScanProfilesMutation()
  const [createProfile, createProfileState] = useCreateScanProfileMutation()
  const [updateProfile, updateProfileState] = useUpdateScanProfileMutation()
  const [deleteProfile] = useDeleteScanProfileMutation()
  const [createSchedule, createScheduleState] = useCreateScheduleMutation()
  const [updateSchedule, updateScheduleState] = useUpdateScheduleMutation()
  const [deleteSchedule] = useDeleteScheduleMutation()
  const busy = createProfileState.isLoading || updateProfileState.isLoading || createScheduleState.isLoading || updateScheduleState.isLoading
  const passwordRules = [
    { label: '12 or more characters', met: passwordForm.newPassword.length >= 12 },
    { label: 'Uppercase and lowercase letters', met: /[A-Z]/.test(passwordForm.newPassword) && /[a-z]/.test(passwordForm.newPassword) },
    { label: 'At least one number', met: /\d/.test(passwordForm.newPassword) },
    { label: 'At least one symbol', met: /[^A-Za-z0-9]/.test(passwordForm.newPassword) },
  ]
  const hasPasswordInput = Boolean(passwordForm.currentPassword || passwordForm.newPassword || passwordForm.confirmPassword)
  const passwordMismatch = Boolean(passwordForm.confirmPassword && passwordForm.newPassword !== passwordForm.confirmPassword)
  const passwordReady = Boolean(passwordForm.currentPassword && passwordForm.newPassword && passwordForm.confirmPassword && !passwordMismatch)

  const profileCols: Column<ScanProfile>[] = [
    { key: 'name', header: 'Profile', render: (p) => <span className="font-medium text-slate-900">{p.name}</span> },
    { key: 'platforms', header: 'Platforms', render: (p) => p.platforms.join(', ') || 'all' },
    { key: 'mode', header: 'Mode', render: (p) => p.mode },
    { key: 'policy', header: 'Password policy', render: (p) => (p.collect_password_policy ? 'yes' : 'no') },
    { key: 'timeout', header: 'Timeout', render: (p) => `${p.timeout_seconds}s` },
    { key: 'actions', header: 'Actions', render: (p) => can('settings:manage') ? <RowActions onEdit={() => editProfile(p)} onDelete={() => removeProfile(p)} /> : '—' },
  ]
  const scheduleCols: Column<ScheduledScan>[] = [
    { key: 'name', header: 'Schedule', render: (s) => <span className="font-medium text-slate-900">{s.name}</span> },
    { key: 'cron', header: 'Schedule', render: (s) => <span className="text-sm text-slate-700">{describeCron(s.cron)}</span> },
    { key: 'enabled', header: 'Enabled', render: (s) => <StatusBadge value={s.enabled ? 'enabled' : 'disabled'} /> },
    { key: 'approval', header: 'Approval', render: (s) => (s.requires_approval ? 'required' : 'no') },
    { key: 'next', header: 'Next run', render: (s) => <span className="whitespace-nowrap text-xs text-slate-500">{fmt(s.next_run_at)}</span> },
    { key: 'actions', header: 'Actions', render: (s) => can('settings:manage') ? <RowActions onEdit={() => editSchedule(s)} onDelete={() => removeSchedule(s)} /> : '—' },
  ]

  function editProfile(p: ScanProfile) {
    setError(null); setMessage(null)
    setProfileForm({ id: p.id, name: p.name, description: p.description ?? '', platforms: p.platforms, mode: p.mode, timeout_seconds: String(p.timeout_seconds), retry_count: String(p.retry_count), concurrency_limit: String(p.concurrency_limit), collect_password_policy: p.collect_password_policy })
  }
  function profileBody(f: ProfileForm): ScanProfileRequest {
    return { name: f.name.trim(), description: f.description || null, platforms: f.platforms, mode: f.mode, target_scope: { all_enabled: true }, timeout_seconds: Number(f.timeout_seconds), retry_count: Number(f.retry_count), concurrency_limit: Number(f.concurrency_limit), throttle_ms: 0, credential_strategy: 'asset', collect_password_policy: f.collect_password_policy }
  }
  async function saveProfile() {
    if (!profileForm?.name.trim()) return setError('Profile name is required.')
    setError(null)
    try {
      if (profileForm.id) await updateProfile({ id: profileForm.id, body: profileBody(profileForm) }).unwrap()
      else await createProfile(profileBody(profileForm)).unwrap()
      setProfileForm(null); setMessage('Scan profile saved.')
    } catch (err) { setError(apiErrorMessage(err)) }
  }
  async function removeProfile(p: ScanProfile) {
    if (!confirm(`Delete scan profile "${p.name}"?`)) return
    try { await deleteProfile(p.id).unwrap(); setMessage('Scan profile deleted.') } catch (err) { setError(apiErrorMessage(err)) }
  }

  function editSchedule(s: ScheduledScan) {
    setError(null); setMessage(null)
    setScheduleForm({ id: s.id, name: s.name, description: s.description ?? '', ...cronToDateTime(s.cron), profile_id: s.profile_id, all_enabled: Boolean(s.scope?.all_enabled ?? true), enabled: s.enabled, requires_approval: s.requires_approval })
  }
  function scheduleBody(f: ScheduleForm): ScheduledScanRequest {
    return { name: f.name.trim(), description: f.description || null, cron: dateTimeToCron(f.run_date, f.run_time), profile_id: f.profile_id, scope: { all_enabled: f.all_enabled }, enabled: f.enabled, requires_approval: f.requires_approval }
  }
  async function saveSchedule() {
    if (!scheduleForm?.name.trim()) return setError('Schedule name is required.')
    if (!scheduleForm.profile_id) return setError('Schedule profile is required.')
    if (!scheduleForm.run_time) return setError('Schedule time is required.')
    setError(null)
    try {
      if (scheduleForm.id) await updateSchedule({ id: scheduleForm.id, body: scheduleBody(scheduleForm) }).unwrap()
      else await createSchedule(scheduleBody(scheduleForm)).unwrap()
      setScheduleForm(null); setMessage('Schedule saved.')
    } catch (err) { setError(apiErrorMessage(err)) }
  }
  async function removeSchedule(s: ScheduledScan) {
    if (!confirm(`Delete schedule "${s.name}"?`)) return
    try { await deleteSchedule(s.id).unwrap(); setMessage('Schedule deleted.') } catch (err) { setError(apiErrorMessage(err)) }
  }
  async function savePassword() {
    setMessage(null); setError(null)
    if (!passwordForm.currentPassword || !passwordForm.newPassword) return setError('Current password and new password are required.')
    if (passwordForm.newPassword !== passwordForm.confirmPassword) return setError('New password and confirmation do not match.')
    setPasswordBusy(true)
    const result = await dispatch(changePassword({ currentPassword: passwordForm.currentPassword, newPassword: passwordForm.newPassword }))
    setPasswordBusy(false)
    if (changePassword.fulfilled.match(result)) {
      setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' })
      setMessage('Password updated.')
    } else {
      setError(result.error.message ?? 'Unable to update password.')
    }
  }

  return (
    <PageFrame eyebrow="Administration" title="Settings" subtitle="Account profile, scan profiles, and scheduled discovery.">
      <div className="flex flex-wrap gap-2">{(['profile', 'scan-profiles', 'schedules'] as Tab[]).map((t) => <button key={t} onClick={() => setTab(t)} className={cx('rounded-md border px-3 py-1.5 text-sm font-semibold capitalize', tab === t ? 'border-blue-600 bg-blue-50 text-blue-700' : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50')}>{t.replace('-', ' ')}</button>)}</div>
      {message && <InlineAlert tone="green">{message}</InlineAlert>}
      {error && <InlineAlert tone="red">{error}</InlineAlert>}

      {tab === 'profile' && (
        <div className="space-y-4">
          <div className="grid gap-4 xl:grid-cols-[minmax(0,0.85fr)_minmax(0,1.35fr)]">
            <DataPanel title="Signed-in user" detail="Current session and account posture.">
              <dl className="divide-y divide-slate-100 text-sm">
                <Item k="Email" v={auth.user?.email} />
                <Item k="Name" v={auth.user?.fullName ?? '—'} />
                <Item k="Roles" v={auth.user?.roles?.join(', ') ?? '—'} />
                <Item k="Account status" v={auth.user?.isActive ? 'Active' : 'Inactive'} />
                <Item k="Password action" v={auth.user?.mustChangePassword ? 'Change required' : 'No forced change'} />
              </dl>
            </DataPanel>

            <DataPanel title="Password settings" detail="Change only your own password. User resets stay under User Management.">
              <div className="grid gap-5 p-4 lg:grid-cols-[minmax(0,1fr)_280px]">
                <div className="space-y-4">
                  <div className="rounded-md border border-blue-100 bg-blue-50 px-3 py-2 text-sm text-blue-800">
                    Password changes apply immediately after verification. Use a unique password for this ITAC console.
                  </div>
                  <div className="max-w-xl space-y-4">
                    <Field label="Current password" required>
                      <TextInput type="password" autoComplete="current-password" placeholder="Enter current password" value={passwordForm.currentPassword} onChange={(e) => setPasswordForm({ ...passwordForm, currentPassword: e.target.value })} />
                    </Field>
                    <Field label="New password" required>
                      <TextInput type="password" autoComplete="new-password" placeholder="Enter new password" value={passwordForm.newPassword} onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })} />
                    </Field>
                    <Field label="Confirm new password" required error={passwordMismatch ? 'Confirmation does not match.' : undefined}>
                      <TextInput type="password" autoComplete="new-password" placeholder="Re-enter new password" value={passwordForm.confirmPassword} onChange={(e) => setPasswordForm({ ...passwordForm, confirmPassword: e.target.value })} />
                    </Field>
                  </div>
                </div>

                <aside className="rounded-md border border-slate-200 bg-slate-50 p-4">
                  <div className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500">Password standard</div>
                  <ul className="mt-3 space-y-2">
                    {passwordRules.map((rule) => (
                      <li key={rule.label} className="flex items-start gap-2 text-sm text-slate-700">
                        <span className={cx('mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full text-[10px] font-bold', rule.met ? 'bg-emerald-600 text-white' : 'bg-white text-slate-400 ring-1 ring-slate-300')}>
                          {rule.met ? '✓' : '•'}
                        </span>
                        <span>{rule.label}</span>
                      </li>
                    ))}
                  </ul>
                  <div className="mt-4 rounded-md border border-slate-200 bg-white px-3 py-2 text-xs leading-5 text-slate-600">
                    Admin reset, expiry, and forced-change controls are managed from User Management.
                  </div>
                </aside>
              </div>
              <div className="flex flex-col gap-3 border-t border-slate-200 bg-slate-50/80 p-4 sm:flex-row sm:items-center sm:justify-between">
                <p className="text-xs text-slate-500">For audit safety, the current password is required before any change is accepted.</p>
                <div className="flex flex-wrap gap-2">
                  <ActionButton variant="ghost" disabled={passwordBusy || !hasPasswordInput} onClick={() => setPasswordForm({ currentPassword: '', newPassword: '', confirmPassword: '' })}>Clear form</ActionButton>
                  <ActionButton variant="primary" disabled={passwordBusy || !passwordReady} onClick={savePassword}>{passwordBusy ? 'Updating…' : 'Update password'}</ActionButton>
                </div>
              </div>
            </DataPanel>
          </div>
        </div>
      )}

      {tab === 'scan-profiles' && (profilesQ.isLoading ? <LoadingPanel /> : profilesQ.isError ? <ErrorState detail={apiErrorMessage(profilesQ.error)} onRetry={profilesQ.refetch} /> : <DataPanel title="Scan profiles" detail={`${profilesQ.data?.total ?? 0} profile(s) · presets used by the Scan wizard`}>
        {can('settings:manage') && <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 p-3"><ActionButton variant="primary" onClick={() => { setProfileForm(emptyProfile); setMessage(null); setError(null) }}>New profile</ActionButton><ActionButton disabled={seedState.isLoading} onClick={() => seed()}>{seedState.isLoading ? 'Seeding…' : 'Seed defaults'}</ActionButton>{seedState.isSuccess && <InlineAlert tone="green">{seedState.data?.message ?? 'Defaults seeded.'}</InlineAlert>}{seedState.isError && <InlineAlert tone="red">{apiErrorMessage(seedState.error)}</InlineAlert>}</div>}
        {profileForm && <ProfileEditor form={profileForm} setForm={setProfileForm} busy={busy} onSave={saveProfile} onCancel={() => setProfileForm(null)} />}
        <DataTable columns={profileCols} rows={profilesQ.data?.items ?? []} getRowKey={(p) => p.id} empty="No scan profiles. Seed defaults or create a custom profile." minWidth={880} />
      </DataPanel>)}

      {tab === 'schedules' && (schedulesQ.isLoading || profilesQ.isLoading ? <LoadingPanel /> : schedulesQ.isError ? <ErrorState detail={apiErrorMessage(schedulesQ.error)} onRetry={schedulesQ.refetch} /> : <DataPanel title="Scheduled scans" detail={`${schedulesQ.data?.total ?? 0} schedule(s)`}>
        {can('settings:manage') && <div className="flex items-center gap-3 border-b border-slate-200 p-3"><ActionButton variant="primary" onClick={() => { setScheduleForm({ ...emptySchedule, profile_id: profilesQ.data?.items[0]?.id ?? '' }); setMessage(null); setError(null) }}>New schedule</ActionButton></div>}
        {scheduleForm && <ScheduleEditor form={scheduleForm} profiles={profilesQ.data?.items ?? []} setForm={setScheduleForm} busy={busy} onSave={saveSchedule} onCancel={() => setScheduleForm(null)} />}
        <DataTable columns={scheduleCols} rows={schedulesQ.data?.items ?? []} getRowKey={(s) => s.id} empty="No scheduled scans configured." minWidth={900} />
      </DataPanel>)}
    </PageFrame>
  )
}

function ProfileEditor({ form, setForm, busy, onSave, onCancel }: { form: ProfileForm; setForm: (f: ProfileForm) => void; busy: boolean; onSave: () => void; onCancel: () => void }) {
  const togglePlatform = (p: string) => setForm({ ...form, platforms: form.platforms.includes(p as Platform) ? form.platforms.filter((x) => x !== p) : [...form.platforms, p as Platform] })
  return <div className="space-y-4 border-b border-slate-200 bg-slate-50/60 p-4">
    <div className="grid gap-3 md:grid-cols-2"><Field label="Name" required><TextInput value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field><Field label="Mode"><NativeSelect value={form.mode} options={[{ value: 'safe', label: 'safe' }, { value: 'deep', label: 'deep' }]} onChange={(v) => setForm({ ...form, mode: v as 'safe' | 'deep' })} /></Field></div>
    <Field label="Description"><TextArea rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
    <Field label="Platforms" hint="Leave empty for all platforms."><CheckChips values={form.platforms} options={PLATFORMS.map((p) => ({ value: p, label: p }))} onToggle={togglePlatform} /></Field>
    <div className="grid gap-3 md:grid-cols-4"><Field label="Timeout seconds"><TextInput type="number" value={form.timeout_seconds} onChange={(e) => setForm({ ...form, timeout_seconds: e.target.value })} /></Field><Field label="Retries"><TextInput type="number" value={form.retry_count} onChange={(e) => setForm({ ...form, retry_count: e.target.value })} /></Field><Field label="Concurrency"><TextInput type="number" value={form.concurrency_limit} onChange={(e) => setForm({ ...form, concurrency_limit: e.target.value })} /></Field><Field label="Password policy"><label className="flex h-9 items-center gap-2 text-sm"><input type="checkbox" checked={form.collect_password_policy} onChange={(e) => setForm({ ...form, collect_password_policy: e.target.checked })} />Collect</label></Field></div>
    <div className="flex gap-2"><ActionButton variant="primary" disabled={busy} onClick={onSave}>{busy ? 'Saving…' : 'Save profile'}</ActionButton><ActionButton variant="ghost" onClick={onCancel}>Cancel</ActionButton></div>
  </div>
}

function ScheduleEditor({ form, profiles, setForm, busy, onSave, onCancel }: { form: ScheduleForm; profiles: ScanProfile[]; setForm: (f: ScheduleForm) => void; busy: boolean; onSave: () => void; onCancel: () => void }) {
  return <div className="space-y-4 border-b border-slate-200 bg-slate-50/60 p-4">
    <div className="grid gap-3 md:grid-cols-3"><Field label="Name" required><TextInput value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field><Field label="Run date" hint="Leave blank to run daily."><TextInput type="date" value={form.run_date} onChange={(e) => setForm({ ...form, run_date: e.target.value })} /></Field><Field label="Run time" required hint="24-hour format."><TextInput type="time" value={form.run_time} onChange={(e) => setForm({ ...form, run_time: e.target.value })} /></Field></div>
    <p className="rounded-md border border-blue-100 bg-blue-50 px-3 py-2 text-xs font-medium text-blue-800">Schedule preview: {describeCron(dateTimeToCron(form.run_date, form.run_time || '02:00'))}</p>
    <Field label="Description"><TextArea rows={2} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} /></Field>
    <Field label="Scan profile" required><NativeSelect value={form.profile_id} options={profiles.map((p) => ({ value: p.id, label: p.name }))} onChange={(v) => setForm({ ...form, profile_id: v })} placeholder="Select profile" /></Field>
    <div className="flex flex-wrap gap-4 text-sm"><label className="flex items-center gap-2"><input type="checkbox" checked={form.all_enabled} onChange={(e) => setForm({ ...form, all_enabled: e.target.checked })} />All enabled assets</label><label className="flex items-center gap-2"><input type="checkbox" checked={form.enabled} onChange={(e) => setForm({ ...form, enabled: e.target.checked })} />Enabled</label><label className="flex items-center gap-2"><input type="checkbox" checked={form.requires_approval} onChange={(e) => setForm({ ...form, requires_approval: e.target.checked })} />Requires approval</label></div>
    <div className="flex gap-2"><ActionButton variant="primary" disabled={busy} onClick={onSave}>{busy ? 'Saving…' : 'Save schedule'}</ActionButton><ActionButton variant="ghost" onClick={onCancel}>Cancel</ActionButton></div>
  </div>
}

function RowActions({ onEdit, onDelete }: { onEdit: () => void; onDelete: () => void }) {
  return <div className="flex gap-2"><button className="text-xs font-medium text-blue-700 hover:underline" onClick={(e) => { e.stopPropagation(); onEdit() }}>Edit</button><button className="text-xs font-medium text-red-600 hover:underline" onClick={(e) => { e.stopPropagation(); onDelete() }}>Delete</button></div>
}

function Item({ k, v }: { k: string; v?: string | null }) {
  return <div className="grid gap-2 px-4 py-3 sm:grid-cols-[150px_minmax(0,1fr)]"><dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">{k}</dt><dd className="break-words font-medium text-slate-900">{v || '—'}</dd></div>
}
