import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  useGetAssetsQuery, useGetConnectorsQuery, useGetCredentialsQuery, useLaunchScanMutation,
} from '../../api/apiSlice'
import type { Asset, CredentialMode, ScanLaunchRequest, ScanType } from '../../api/types'
import { useCan } from '../../app/rbac'
import {
  ActionButton, CheckChips, DataPanel, DataTable, ErrorState, Field, InlineAlert, LoadingPanel,
  NativeSelect, PageFrame, RadioCards, Stepper, TextArea, TextInput, apiErrorMessage, cx, type Column,
} from '../../components/ui'
import {
  CREDENTIAL_MODE_OPTIONS, PLATFORM_OPTIONS, SCAN_TYPE_OPTIONS, SCOPE_OPTIONS,
  selectorMatchesPlatform, type ScopeKind,
} from './constants'

const STEPS = ['Intent', 'Targeting', 'Access', 'Launch']

type Draft = {
  name: string
  scanType: ScanType | null
  allPlatforms: boolean
  platforms: string[]
  scopeKind: ScopeKind | null
  tagId: string
  environment: string
  connectorId: string
  bulkText: string
  selectedAssetIds: string[]
  credentialMode: CredentialMode
  note: string
}

const initial: Draft = {
  name: '', scanType: null, allPlatforms: false, platforms: [], scopeKind: null,
  tagId: '', environment: '', connectorId: '', bulkText: '', selectedAssetIds: [],
  credentialMode: 'asset', note: '',
}

export default function ScanWizard() {
  const navigate = useNavigate()
  const can = useCan()
  const [step, setStep] = useState(0)
  const [draft, setDraft] = useState<Draft>(initial)
  const set = (patch: Partial<Draft>) => setDraft((d) => ({ ...d, ...patch }))

  const assetsQ = useGetAssetsQuery({ limit: 500 })
  const connectorsQ = useGetConnectorsQuery()
  const credentialsQ = useGetCredentialsQuery()
  const [launch, launchState] = useLaunchScanMutation()

  const assets = useMemo(() => assetsQ.data?.items ?? [], [assetsQ.data?.items])
  const connectors = useMemo(() => connectorsQ.data?.items ?? [], [connectorsQ.data?.items])
  const credentials = useMemo(() => credentialsQ.data?.items ?? [], [credentialsQ.data?.items])
  const activeSelectors = useMemo(() => draft.allPlatforms ? ['all'] : draft.platforms, [draft.allPlatforms, draft.platforms])
  const selectedScan = SCAN_TYPE_OPTIONS.find((o) => o.value === draft.scanType)
  const selectedScope = SCOPE_OPTIONS.find((o) => o.value === draft.scopeKind)

  const tagOptions = useMemo(() => {
    const tags = new Map<string, string>()
    assets.forEach((asset) => asset.tag_summaries?.forEach((tag) => tags.set(tag.id, tag.tag_name)))
    return [...tags.entries()].map(([value, label]) => ({ value, label }))
  }, [assets])
  const envOptions = useMemo(() => {
    const environments = new Set<string>()
    assets.forEach((asset) => asset.environment && environments.add(asset.environment))
    return [...environments].map((value) => ({ value, label: value }))
  }, [assets])
  const bulkTokens = useMemo(() => draft.bulkText.split(/[\s,;]+/).map((t) => t.trim().toLowerCase()).filter(Boolean), [draft.bulkText])

  const targets = useMemo<Asset[]>(() => {
    const platformMatch = (asset: Asset) => activeSelectors.length > 0 && activeSelectors.some((selector) => selectorMatchesPlatform(selector, asset.platform))
    switch (draft.scopeKind) {
      case 'selected':
        return assets.filter((asset) => draft.selectedAssetIds.includes(asset.id))
      case 'tag':
        return assets.filter((asset) => platformMatch(asset) && asset.tag_summaries?.some((tag) => tag.id === draft.tagId))
      case 'environment':
        return assets.filter((asset) => platformMatch(asset) && asset.environment === draft.environment)
      case 'connector':
        return assets.filter((asset) => platformMatch(asset) && asset.connector_id === draft.connectorId)
      case 'bulk':
        return assets.filter((asset) => platformMatch(asset) && bulkTokens.some((token) => asset.hostname.toLowerCase() === token || (asset.ip_address ?? '').toLowerCase() === token))
      case 'platform':
      case 'all_enabled':
        return assets.filter((asset) => asset.discovery_enabled && platformMatch(asset))
      default:
        return []
    }
  }, [assets, draft.scopeKind, draft.selectedAssetIds, draft.tagId, draft.environment, draft.connectorId, bulkTokens, activeSelectors])

  const checks = useMemo(() => {
    const credentialed = draft.credentialMode !== 'none'
    const connectorActive = connectors.find((connector) => connector.id === draft.connectorId)?.is_active
    return [
      { ok: !!draft.scanType, label: 'Scan intent selected' },
      { ok: activeSelectors.length > 0, label: 'Platform coverage selected' },
      { ok: !!draft.scopeKind, label: 'Targeting scope selected' },
      { ok: targets.length > 0, label: 'At least one asset resolved' },
      { ok: !(draft.scopeKind === 'connector') || !!draft.connectorId, label: 'Connector scope selected' },
      { ok: !(draft.credentialMode === 'connector') || !!draft.connectorId, label: 'Connector credential source selected' },
      { ok: !(draft.scopeKind === 'connector' && draft.connectorId) || !!connectorActive, label: 'Selected connector is active' },
      { ok: !credentialed || credentials.some((credential) => credential.is_active), label: 'Active credential exists' },
      { ok: can('scan:launch'), label: 'Launch permission granted' },
    ]
  }, [draft, activeSelectors, targets, connectors, credentials, can])
  const allPass = checks.every((check) => check.ok)

  function buildPayload(): ScanLaunchRequest {
    return {
      name: draft.name.trim() || null,
      scan_type: draft.scanType as ScanType,
      selected_platforms: activeSelectors,
      asset_ids: targets.map((target) => target.id),
      all_enabled: false,
      credential_mode: draft.credentialMode,
      connector_id: draft.credentialMode === 'connector' || draft.scopeKind === 'connector' ? draft.connectorId || null : null,
      collect_password_policy: selectedScan?.collectPasswordPolicy ?? null,
      note: draft.note.trim() || null,
    }
  }

  async function onLaunch() {
    try {
      const job = await launch(buildPayload()).unwrap()
      navigate(`/scans/${job.id}`)
    } catch {
      /* RTK Query exposes the launch error in the UI. */
    }
  }

  const canAdvance = (() => {
    switch (step) {
      case 0:
        return !!draft.scanType && activeSelectors.length > 0
      case 1:
        return !!draft.scopeKind && targets.length > 0
      case 2:
        return checks.slice(4).every((check) => check.ok)
      default:
        return allPass
    }
  })()

  if (assetsQ.isLoading) return <PageFrame eyebrow="Discovery operations" title="New scan" subtitle="Configure a discovery job."><LoadingPanel label="Loading inventory..." /></PageFrame>
  if (assetsQ.isError) return <PageFrame eyebrow="Discovery operations" title="New scan" subtitle="Configure a discovery job."><ErrorState detail={apiErrorMessage(assetsQ.error)} onRetry={assetsQ.refetch} /></PageFrame>

  return (
    <PageFrame
      eyebrow="Discovery operations"
      title="New scan"
      subtitle="A focused launch path for account discovery and privilege classification."
      actions={<ActionButton variant="ghost" onClick={() => navigate('/scans')}>Cancel</ActionButton>}
    >
      <div className="grid gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
        <div className="space-y-4">
          <Stepper steps={STEPS} current={step} />
          <DataPanel title={STEPS[step]} detail={stageDetail(step)}>
            <div className="space-y-5 p-5">
              {step === 0 && (
                <div className="space-y-5">
                  <Field label="Scan intent" required hint="Choose the job outcome first. Defaults are applied automatically.">
                    <RadioCards value={draft.scanType} options={SCAN_TYPE_OPTIONS.map((option) => ({ value: option.value, label: option.label, hint: option.hint }))}
                      onChange={(value) => { const option = SCAN_TYPE_OPTIONS.find((item) => item.value === value); set({ scanType: value as ScanType, credentialMode: option?.defaultCredentialMode ?? 'asset' }) }} />
                  </Field>
                  <Field label="Platform coverage" required hint="Use All platforms for broad inventory sweeps, or pick specific platforms for controlled scans.">
                    <CheckChips
                      values={draft.platforms}
                      options={PLATFORM_OPTIONS.map((option) => ({ ...option, disabled: draft.allPlatforms }))}
                      onToggle={(value) => set({ platforms: draft.platforms.includes(value) ? draft.platforms.filter((platform) => platform !== value) : [...draft.platforms, value] })}
                    />
                    <label className="mt-3 flex items-center gap-2 text-sm text-slate-700">
                      <input type="checkbox" checked={draft.allPlatforms} onChange={(event) => set({ allPlatforms: event.target.checked })} />
                      All platforms
                    </label>
                  </Field>
                </div>
              )}

              {step === 1 && (
                <TargetingStage
                  draft={draft}
                  set={set}
                  assets={assets}
                  targets={targets}
                  tagOptions={tagOptions}
                  envOptions={envOptions}
                  connectorOptions={connectors.map((connector) => ({ value: connector.id, label: `${connector.name} (${connector.kind})${connector.is_active ? '' : ' - inactive'}` }))}
                  activeSelectors={activeSelectors}
                  bulkTokens={bulkTokens}
                />
              )}

              {step === 2 && (
                <div className="space-y-5">
                  <Field label="Credential source" required hint="This controls how collectors authenticate during scan execution.">
                    <RadioCards value={draft.credentialMode} columns={3} options={CREDENTIAL_MODE_OPTIONS.map((option) => ({ value: option.value, label: option.label, hint: option.hint }))} onChange={(value) => set({ credentialMode: value as CredentialMode })} />
                  </Field>
                  {(draft.scopeKind === 'connector' || draft.credentialMode === 'connector') ? (
                    <Field label="Connector" required>
                      {connectors.length ? <NativeSelect value={draft.connectorId} options={connectors.map((connector) => ({ value: connector.id, label: `${connector.name} (${connector.kind})${connector.is_active ? '' : ' - inactive'}` }))} onChange={(value) => set({ connectorId: value })} placeholder="Select connector..." />
                        : <InlineAlert tone="red">No connectors are configured.</InlineAlert>}
                    </Field>
                  ) : <InlineAlert tone="slate">No specific connector is required for the selected scope and credential mode.</InlineAlert>}
                  <div className="grid gap-2">
                    {checks.slice(4).map((check) => <CheckRow key={check.label} ok={check.ok} label={check.label} />)}
                  </div>
                </div>
              )}

              {step === 3 && (
                <div className="space-y-5">
                  <Field label="Scan name" hint="Optional label shown in the scan list.">
                    <TextInput value={draft.name} onChange={(event) => set({ name: event.target.value })} placeholder={`${selectedScan?.label ?? 'Scan'} ${new Date().toLocaleDateString()}`} />
                  </Field>
                  <Field label="Operational note" hint="Optional context recorded with the job.">
                    <TextInput value={draft.note} onChange={(event) => set({ note: event.target.value })} />
                  </Field>
                  <div className="grid gap-2">
                    {checks.map((check) => <CheckRow key={check.label} ok={check.ok} label={check.label} />)}
                  </div>
                  {launchState.isError && <ErrorState title="Launch failed" detail={apiErrorMessage(launchState.error)} />}
                </div>
              )}
            </div>

            <div className="flex items-center justify-between border-t border-slate-200 bg-slate-50 px-5 py-3">
              <ActionButton onClick={() => setStep((current) => Math.max(0, current - 1))} disabled={step === 0}>Back</ActionButton>
              {step < STEPS.length - 1 ? (
                <ActionButton variant="primary" onClick={() => setStep((current) => current + 1)} disabled={!canAdvance}>Continue</ActionButton>
              ) : (
                <ActionButton variant="primary" onClick={onLaunch} disabled={!allPass || launchState.isLoading}>{launchState.isLoading ? 'Launching...' : 'Launch scan'}</ActionButton>
              )}
            </div>
          </DataPanel>
        </div>

        <ScanBriefing
          scanLabel={selectedScan?.label}
          scopeLabel={selectedScope?.label}
          platforms={activeSelectors}
          targets={targets}
          credentialMode={draft.credentialMode}
          connectorName={connectors.find((connector) => connector.id === draft.connectorId)?.name}
          checks={checks}
        />
      </div>
    </PageFrame>
  )
}

function TargetingStage({
  draft, set, assets, targets, tagOptions, envOptions, connectorOptions, activeSelectors, bulkTokens,
}: {
  draft: Draft
  set: (patch: Partial<Draft>) => void
  assets: Asset[]
  targets: Asset[]
  tagOptions: { value: string; label: string }[]
  envOptions: { value: string; label: string }[]
  connectorOptions: { value: string; label: string }[]
  activeSelectors: string[]
  bulkTokens: string[]
}) {
  return (
    <div className="space-y-5">
      <Field label="Targeting method" required>
        <RadioCards value={draft.scopeKind} columns={3} options={SCOPE_OPTIONS.map((option) => ({ value: option.value, label: option.label, hint: option.hint }))} onChange={(value) => set({ scopeKind: value as ScopeKind })} />
      </Field>
      {draft.scopeKind === 'tag' && (
        <Field label="Application or tag" required>
          {tagOptions.length ? <NativeSelect value={draft.tagId} options={tagOptions} onChange={(value) => set({ tagId: value })} placeholder="Select tag..." /> : <InlineAlert>No tags are assigned to assets yet.</InlineAlert>}
        </Field>
      )}
      {draft.scopeKind === 'environment' && (
        <Field label="Environment" required>
          {envOptions.length ? <NativeSelect value={draft.environment} options={envOptions} onChange={(value) => set({ environment: value })} placeholder="Select environment..." /> : <InlineAlert>No environments are set on assets.</InlineAlert>}
        </Field>
      )}
      {draft.scopeKind === 'connector' && (
        <Field label="Connector" required>
          {connectorOptions.length ? <NativeSelect value={draft.connectorId} options={connectorOptions} onChange={(value) => set({ connectorId: value })} placeholder="Select connector..." /> : <InlineAlert tone="red">No connectors are configured.</InlineAlert>}
        </Field>
      )}
      {draft.scopeKind === 'bulk' && (
        <Field label="Hostnames or IPs" required hint="Separate entries by space, comma, or newline.">
          <TextArea rows={4} value={draft.bulkText} onChange={(event) => set({ bulkText: event.target.value })} placeholder={'host01\n10.0.4.10'} />
          {bulkTokens.length > 0 && <div className="mt-1 text-xs text-slate-500">{targets.length} of {bulkTokens.length} token(s) matched inventory.</div>}
        </Field>
      )}
      {draft.scopeKind === 'selected' && (
        <Field label="Selected assets" required hint={`${draft.selectedAssetIds.length} selected`}>
          <div className="max-h-72 overflow-y-auto rounded-md border border-slate-200">
            {assets.filter((asset) => activeSelectors.length === 0 || activeSelectors.some((selector) => selectorMatchesPlatform(selector, asset.platform))).map((asset) => (
              <label key={asset.id} className="flex items-center gap-2 border-b border-slate-100 px-3 py-2 text-sm last:border-0 hover:bg-slate-50">
                <input type="checkbox" checked={draft.selectedAssetIds.includes(asset.id)} onChange={() => set({ selectedAssetIds: draft.selectedAssetIds.includes(asset.id) ? draft.selectedAssetIds.filter((id) => id !== asset.id) : [...draft.selectedAssetIds, asset.id] })} />
                <span className="font-medium text-slate-800">{asset.hostname}</span>
                <span className="text-xs text-slate-500">{asset.platform} | {asset.environment ?? 'no env'}</span>
              </label>
            ))}
          </div>
        </Field>
      )}
      <TargetsPreview targets={targets} />
    </div>
  )
}

function TargetsPreview({ targets }: { targets: Asset[] }) {
  const columns: Column<Asset>[] = [
    { key: 'hostname', header: 'Hostname', render: (asset) => <span className="font-medium text-slate-900">{asset.hostname}</span> },
    { key: 'ip', header: 'IP', render: (asset) => asset.ip_address ?? '-' },
    { key: 'platform', header: 'Platform', render: (asset) => asset.platform },
    { key: 'env', header: 'Environment', render: (asset) => asset.environment ?? '-' },
  ]
  return (
    <DataPanel title="Resolved target preview" detail={`${targets.length} asset(s) matched`}>
      <DataTable columns={columns} rows={targets.slice(0, 8)} getRowKey={(asset) => asset.id} empty="No assets match this targeting setup." minWidth={620} />
      {targets.length > 8 && <div className="border-t border-slate-200 px-4 py-2 text-xs text-slate-500">Showing first 8 of {targets.length} targets.</div>}
    </DataPanel>
  )
}

function ScanBriefing({
  scanLabel, scopeLabel, platforms, targets, credentialMode, connectorName, checks,
}: {
  scanLabel?: string
  scopeLabel?: string
  platforms: string[]
  targets: Asset[]
  credentialMode: CredentialMode
  connectorName?: string
  checks: { ok: boolean; label: string }[]
}) {
  const failing = checks.filter((check) => !check.ok).length
  return (
    <aside className="space-y-4 xl:sticky xl:top-4 xl:self-start">
      <DataPanel title="Scan briefing" detail="Live summary of what will launch.">
        <dl className="grid gap-3 p-4 text-sm">
          <Summary label="Intent" value={scanLabel ?? 'Not selected'} />
          <Summary label="Platforms" value={platforms.length ? platforms.join(', ') : 'Not selected'} />
          <Summary label="Scope" value={scopeLabel ?? 'Not selected'} />
          <Summary label="Targets" value={`${targets.length} asset(s)`} />
          <Summary label="Credentials" value={credentialMode} />
          <Summary label="Connector" value={connectorName ?? 'Not required'} />
        </dl>
      </DataPanel>
      <DataPanel title="Readiness">
        <div className="space-y-2 p-4">
          <div className={cx('rounded-lg border px-3 py-2 text-sm font-semibold', failing ? 'border-amber-200 bg-amber-50 text-amber-800' : 'border-emerald-200 bg-emerald-50 text-emerald-800')}>
            {failing ? `${failing} item(s) need attention` : 'Ready to launch'}
          </div>
          {checks.slice(0, 5).map((check) => <CheckRow key={check.label} ok={check.ok} label={check.label} compact />)}
        </div>
      </DataPanel>
    </aside>
  )
}

function CheckRow({ ok, label, compact }: { ok: boolean; label: string; compact?: boolean }) {
  return (
    <div className={cx(
      'flex items-center gap-2 rounded-md border text-sm',
      compact ? 'px-2 py-1.5' : 'px-3 py-2',
      ok ? 'border-emerald-200 bg-emerald-50 text-emerald-800' : 'border-red-200 bg-red-50 text-red-700',
    )}>
      <span className="font-semibold">{ok ? 'OK' : '!'}</span>{label}
    </div>
  )
}

function Summary({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt><dd className="mt-0.5 font-medium text-slate-900">{value}</dd></div>
}

function stageDetail(step: number) {
  return [
    'Pick the scan outcome and platform coverage.',
    'Choose how assets are resolved and preview the target set.',
    'Select credential behavior and confirm operational readiness.',
    'Name the job, review checks, and launch.',
  ][step]
}
