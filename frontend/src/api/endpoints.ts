import { api } from './client'

// --- Types ---
// --- Tag types ---
export type TagCategory = 'application' | 'environment' | 'business_unit' | 'criticality' | 'compliance' | 'ownership' | 'technology' | 'custom'
export type TagStatus = 'active' | 'inactive'
export interface TagSummary {
  id: string; tag_name: string; tag_code: string | null
  color: string; category: TagCategory
  assigned_at: string | null; assigned_by: string | null
}
export interface Tag extends TagSummary {
  description: string | null; status: TagStatus; usage_count: number
  created_by: string | null; updated_by: string | null
  created_at: string; updated_at: string
}

export type Platform =
  // Unix / Linux
  | 'rhel' | 'centos' | 'ubuntu' | 'sles' | 'solaris' | 'aix' | 'hpux'
  // Windows
  | 'windows'
  // Databases
  | 'mysql' | 'mssql' | 'mongodb' | 'oracle_db' | 'postgresql' | 'redis'
export type PrivilegeClass =
  | 'full_admin' | 'admin_equivalent' | 'operator_high_impact' | 'delegated_admin'
  | 'privileged_service' | 'sensitive_non_admin' | 'dormant_privileged'
  | 'non_privileged' | 'unknown_review_required'
export type JobStatus = 'pending' | 'queued' | 'running' | 'success' | 'partial_success' | 'failed' | 'timed_out' | 'unreachable' | 'auth_failed' | 'cancelled'

export interface Page<T> { items: T[]; total: number; limit: number; offset: number }

export interface Asset {
  id: string; hostname: string; ip_address: string | null; instance: string | null
  port: number | null; environment: string | null; platform: Platform; owner: string | null
  business_unit: string | null; criticality: string | null; discovery_enabled: boolean
  connector_id: string | null; connector_name: string | null
  tag_summaries: TagSummary[]
  group_summaries: AssetGroupSummary[]
  created_at: string; updated_at: string
}
export interface AssetGroupSummary {
  id: string; name: string; description: string | null; asset_count: number
}
export interface AssetGroup extends AssetGroupSummary {
  asset_ids: string[]; created_at: string | null; updated_at: string | null
}
export interface BulkImportResult {
  total_rows: number; imported_rows: number; duplicate_rows: number
  invalid_rows: number; errors: Array<{ row: number; error: string }>; job_id: string
}
export interface Account {
  id: string; asset_id: string; asset_hostname: string | null; platform: Platform; source_type: string; account_name: string
  principal_type: string; auth_source: string; enabled_status: string; interactive_status: string
  last_login: string | null; privilege_classification: PrivilegeClass; privilege_confidence: number
  risk_score: number; is_shared: boolean; password_never_expires: boolean; owner: string | null
  evidence_summary: Record<string, unknown> | null; discovered_at: string; updated_at: string
  // Windows interactive classification (null on non-Windows accounts)
  interactive_confidence: number | null
  interactive_detection_method: string | null
  interactive_last_observed_logon_type: string | null
  allows_local_logon: boolean | null
  allows_remote_interactive_logon: boolean | null
  allows_service_logon: boolean | null
  allows_batch_logon: boolean | null
  allows_network_logon: boolean | null
  review_required_reason: string | null
  principal_source: string | null
}
export interface AccountDetail extends Account {
  entitlements: Entitlement[]; raw_evidence_refs: unknown[] | null
  interactive_evidence_summary: Record<string, unknown> | null
}
export interface Entitlement {
  id: string; kind: string; name: string; scope: string | null; source: string | null
  inherited: boolean; via: string | null; attributes: Record<string, unknown> | null
}
export interface Finding {
  id: string; job_id: string | null; connector_agent_job_id: string | null; account_id: string; rule_id: string; rule_key: string
  rule_version: number; classification: PrivilegeClass; confidence: number; risk_score: number
  is_winning: boolean; direct: boolean; inheritance_path: string | null; explanation: string
  matched_evidence: Record<string, unknown> | null; evaluated_at: string
}
export interface Rule {
  id: string; rule_key: string; name: string; description: string | null; platform: Platform | null
  predicate: Record<string, unknown>; classify_as: PrivilegeClass; confidence: number
  risk_modifier: number; explanation_template: string; priority: number; enabled: boolean
  version: number; created_at: string; updated_at: string
}
export interface ScanJob {
  id: string; scope_description: string; status: JobStatus; triggered_by: string | null
  triggered_kind: string; started_at: string | null; finished_at: string | null
  totals: Record<string, number> | null; created_at: string
}
export interface ScanTarget {
  id: string; job_id: string; asset_id: string
  hostname: string | null; ip_address: string | null
  platform: Platform; status: JobStatus
  attempt: number; started_at: string | null; finished_at: string | null
  duration_ms: number | null; error_bucket: string | null; error_detail: string | null
  stats: Record<string, number> | null
}
export interface ScanProfile {
  id: string; name: string; description: string | null; platforms: Platform[]
  mode: 'safe' | 'deep'; timeout_seconds: number; retry_count: number
  concurrency_limit: number; collect_password_policy: boolean
  target_scope: { all_enabled?: boolean; use_group_scope?: boolean; use_asset_scope?: boolean; group_ids?: string[]; asset_ids?: string[] }
  created_at: string; updated_at: string
}
export interface DashboardMetrics {
  total_assets: number; total_accounts: number; privileged_accounts: number
  newly_privileged_last_7d: number; dormant_privileged: number; shared_privileged: number
  unknown_review_required: number; last_scan_at: string | null; open_alerts: number
  by_platform: Record<string, number>; by_classification: Record<string, number>
  local_admin_sprawl: { asset_id: string; hostname: string; count: number }[]
}
export interface Connector {
  id: string; name: string; kind: string; default_port: number | null
  options: Record<string, unknown> | null; credential_id: string | null
  is_active: boolean; created_at: string; updated_at: string
}
export interface Credential {
  id: string; name: string; description: string | null; vault_backend: string
  vault_ref: string; username: string; auth_method: string
  rotation_policy_days: number | null; last_rotated_at: string | null
  rotation_overdue: boolean; is_active: boolean; created_at: string; updated_at: string
}
export interface Schedule {
  id: string; name: string; description: string | null; cron: string
  profile_id: string; scope: Record<string, unknown>; enabled: boolean
  requires_approval: boolean; last_run_at: string | null; next_run_at: string | null
  created_at: string; updated_at: string
}
export interface ExceptionRule {
  id: string; name: string; description: string | null; scope: string
  target: Record<string, unknown>; rule_keys: string[] | null
  downgrade_to: PrivilegeClass | null; approved_by: string
  approved_at: string; expires_at: string | null; active: boolean
  created_at: string; updated_at: string
}
export interface AuditLogItem {
  id: string; actor_id: string | null; actor_email: string | null; action: string
  subject_type: string | null; subject_id: string | null; ip: string | null
  context: Record<string, unknown> | null; occurred_at: string
}

// --- Auth ---
export const login = (email: string, password: string) =>
  api.post<{ access_token: string; refresh_token: string; expires_in: number; must_change_password: boolean }>('/auth/login', { email, password })
export const getMe = () => api.get<{ id: string; email: string; full_name: string | null; roles: string[]; is_active: boolean; must_change_password: boolean }>('/auth/me')

// --- Dashboard ---
export const getDashboardMetrics = () => api.get<DashboardMetrics>('/dashboard/metrics')

// --- Assets ---
export const getAssets = (params?: Record<string, unknown>) => api.get<Page<Asset>>('/assets', { params })
export const getAsset = (id: string) => api.get<Asset>(`/assets/${id}`)
export const createAsset = (data: Partial<Asset>) => api.post<Asset>('/assets', data)
export const updateAsset = (id: string, data: Partial<Asset>) => api.put<Asset>(`/assets/${id}`, data)
export const deleteAsset = (id: string) => api.delete(`/assets/${id}`)
export const toggleAsset = (id: string) => api.patch<Asset>(`/assets/${id}/toggle`)
export const importAssetsCsv = (file: File) => {
  const form = new FormData()
  form.append('file', file)
  return api.post<BulkImportResult>('/assets/import/csv', form, { headers: { 'Content-Type': 'multipart/form-data' } })
}
export const getAssetGroups = () => api.get<AssetGroup[]>('/asset-groups')
export const createAssetGroup = (data: { name: string; description?: string | null; asset_ids: string[] }) =>
  api.post<AssetGroup>('/asset-groups', data)
export const updateAssetGroup = (id: string, data: { name: string; description?: string | null; asset_ids: string[] }) =>
  api.put<AssetGroup>(`/asset-groups/${id}`, data)
export const deleteAssetGroup = (id: string) => api.delete(`/asset-groups/${id}`)

// --- Connectors ---
export const getConnectors = (params?: Record<string, unknown>) => api.get<Page<Connector>>('/connectors', { params })
export const createConnector = (data: Partial<Connector>) => api.post<Connector>('/connectors', data)
export const updateConnector = (id: string, data: Partial<Connector>) => api.put<Connector>(`/connectors/${id}`, data)
export const deleteConnector = (id: string) => api.delete(`/connectors/${id}`)
export const testConnection = (asset_id: string) =>
  api.post<{ success: boolean; latency_ms: number; message: string }>('/connectors/test', { asset_id })

// --- Credentials ---
export const getCredentials = (params?: Record<string, unknown>) => api.get<Page<Credential>>('/credentials', { params })
export const createCredential = (data: Record<string, unknown>) => api.post<Credential>('/credentials', data)
export const updateCredential = (id: string, data: Record<string, unknown>) => api.put<Credential>(`/credentials/${id}`, data)
export const deleteCredential = (id: string) => api.delete(`/credentials/${id}`)

// --- Schedules ---
export const getSchedules = (params?: Record<string, unknown>) => api.get<Page<Schedule>>('/schedules', { params })
export const createSchedule = (data: Record<string, unknown>) => api.post<Schedule>('/schedules', data)
export const updateSchedule = (id: string, data: Record<string, unknown>) => api.put<Schedule>(`/schedules/${id}`, data)
export const deleteSchedule = (id: string) => api.delete(`/schedules/${id}`)

// --- Exceptions ---
export const getExceptions = (params?: Record<string, unknown>) => api.get<Page<ExceptionRule>>('/exceptions', { params })
export const createException = (data: Record<string, unknown>) => api.post<ExceptionRule>('/exceptions', data)
export const updateException = (id: string, data: Record<string, unknown>) => api.put<ExceptionRule>(`/exceptions/${id}`, data)
export const deleteException = (id: string) => api.delete(`/exceptions/${id}`)

// --- Scans ---
export const launchScan = (data: { asset_ids?: string[]; group_ids?: string[]; all_enabled?: boolean; profile_id?: string; note?: string }) =>
  api.post<ScanJob>('/scans', data)
export const getScans = (params?: Record<string, unknown>) => api.get<Page<ScanJob>>('/scans', { params })
export const getScan = (id: string) => api.get<ScanJob>(`/scans/${id}`)
export const getScanTargets = (id: string) => api.get<ScanTarget[]>(`/scans/${id}/targets`)
export const cancelScan = (id: string) => api.post<ScanJob>(`/scans/${id}/cancel`)
export const retryFailed = (id: string) => api.post<ScanJob>(`/scans/${id}/retry-failed`)

// --- Scan Profiles ---
export const getScanProfiles = () => api.get<Page<ScanProfile>>('/scan-profiles')
export const createScanProfile = (data: Partial<ScanProfile>) => api.post<ScanProfile>('/scan-profiles', data)
export const updateScanProfile = (id: string, data: Partial<ScanProfile>) => api.put<ScanProfile>(`/scan-profiles/${id}`, data)
export const deleteScanProfile = (id: string) => api.delete(`/scan-profiles/${id}`)
export const seedScanProfiles = () => api.post<{ created: string[]; message: string }>('/scan-profiles/seed-defaults')

// --- Accounts ---
export const getAccounts = (params?: Record<string, unknown>) => api.get<Page<Account>>('/accounts', { params })
export const getAccount = (id: string) => api.get<AccountDetail>(`/accounts/${id}`)
export const getPrivilegedAccounts = (params?: Record<string, unknown>) =>
  api.get<Page<Account>>('/accounts/privileged', { params })
export const getDormantPrivileged = () => api.get<Page<Account>>('/accounts/dormant-privileged')

// --- Findings ---
export const getFindings = (params?: Record<string, unknown>) => api.get<Page<Finding>>('/findings', { params })
export const getFinding = (id: string) => api.get<Finding>(`/findings/${id}`)
export const setReviewState = (finding_id: string, state: string, comment?: string) =>
  api.post('/findings/review', { finding_id, state, comment })

// --- Rules ---
export const getRules = (params?: Record<string, unknown>) => api.get<Page<Rule>>('/rules', { params })
export const createRule = (data: Partial<Rule>) => api.post<Rule>('/rules', data)
export const updateRule = (id: string, data: Partial<Rule>) => api.put<Rule>(`/rules/${id}`, data)
export const deleteRule = (id: string) => api.delete(`/rules/${id}`)

// --- Audit ---
export const getAuditLog = (params?: Record<string, unknown>) => api.get<Page<AuditLogItem>>('/audit', { params })

// --- Exports ---
export const exportCsv = (only_privileged = false) =>
  api.get('/exports/accounts/csv', { params: { only_privileged }, responseType: 'blob' })
export const exportExcel = (only_privileged = false) =>
  api.get('/exports/accounts/excel', { params: { only_privileged }, responseType: 'blob' })

// --- Tags ---
export const getTags = (params?: Record<string, unknown>) => api.get<Page<Tag>>('/tags', { params })
export const getTag = (id: string) => api.get<Tag>(`/tags/${id}`)
export const createTag = (data: Partial<Tag>) => api.post<Tag>('/tags', data)
export const updateTag = (id: string, data: Partial<Tag>) => api.put<Tag>(`/tags/${id}`, data)
export const patchTagStatus = (id: string, status: TagStatus) => api.patch<Tag>(`/tags/${id}/status`, { status })
export const deleteTag = (id: string) => api.delete(`/tags/${id}`)
export const getAssetTags = (assetId: string) => api.get<TagSummary[]>(`/assets/${assetId}/tags`)
export const assignAssetTags = (assetId: string, tagIds: string[]) =>
  api.post<TagSummary[]>(`/assets/${assetId}/tags`, { tag_ids: tagIds })
export const removeAssetTags = (assetId: string, tagIds: string[]) =>
  api.delete(`/assets/${assetId}/tags`, { data: { tag_ids: tagIds } })
export const bulkAssignTags = (assetIds: string[], tagIds: string[]) =>
  api.post<{ assets_affected: number; tags_assigned: number; pairs_added: number }>(
    '/assets/tags/bulk-assign', { asset_ids: assetIds, tag_ids: tagIds }
  )
export const bulkRemoveTags = (assetIds: string[], tagIds: string[]) =>
  api.post<{ assets_affected: number; tags_removed: number; pairs_removed: number }>(
    '/assets/tags/bulk-remove', { asset_ids: assetIds, tag_ids: tagIds }
  )

// --- Connector Agents ---
export type ConnectorAgentStatus =
  | 'pending' | 'approved' | 'online' | 'offline' | 'stale' | 'disabled' | 'revoked' | 'error'
export type ConnectorAgentJobStatus =
  | 'pending' | 'accepted' | 'running' | 'partial_success' | 'success' | 'failed' | 'cancelled' | 'timed_out'
export type ConnectorAgentJobType =
  | 'discovery_basic' | 'discovery_credentialed' | 'bulk_scan' | 'scheduled' | 'on_demand' | 'config_sync' | 'health_check'

export interface ConnectorAgentSettings {
  id: string; agent_id: string
  heartbeat_interval_seconds: number; job_poll_interval_seconds: number; config_refresh_interval_seconds: number
  retry_max_attempts: number; retry_backoff_base_seconds: number; retry_backoff_max_seconds: number
  job_timeout_seconds: number; max_concurrent_jobs: number; result_chunk_size_mb: number
  offline_queue_max_mb: number; result_retention_hours: number; log_retention_days: number
  verify_console_certificate: boolean; verify_console_fingerprint: boolean
  console_fingerprint: string | null; token_rotation_days: number
  proxy_config: Record<string, unknown> | null
  log_level: string; sanitize_secrets_in_logs: boolean
  allowed_scan_profiles: string[] | null; allowed_scan_modes: string[] | null
  allowed_environments: string[] | null; allowed_tags: string[] | null; denied_tags: string[] | null
  max_targets_per_job: number; auto_upgrade: boolean; upgrade_channel: string
  updated_by: string | null; updated_at: string
}
export interface ConnectorAgentOut {
  id: string; name: string; description: string | null
  hostname: string | null; ip_address: string | null
  os_platform: string | null; os_version: string | null; agent_version: string | null
  site: string | null; location: string | null; environment: string | null
  token_prefix: string | null; cert_fingerprint: string | null; cert_expires_at: string | null
  status: ConnectorAgentStatus; is_enabled: boolean
  last_seen_at: string | null; last_heartbeat_at: string | null
  approved_by: string | null; approved_at: string | null; revoked_at: string | null
  created_by: string | null; created_at: string; updated_at: string
  settings: ConnectorAgentSettings | null
}
export interface ConnectorAgentJobOut {
  id: string; agent_id: string; discovery_job_id: string | null
  job_type: ConnectorAgentJobType; status: ConnectorAgentJobStatus
  priority: number; progress_pct: number; progress_message: string | null
  targets_total: number; targets_done: number; targets_failed: number
  error_message: string | null
  scheduled_at: string | null; accepted_at: string | null
  started_at: string | null; completed_at: string | null; expires_at: string | null
  cancel_requested_by: string | null; created_by: string | null
  created_at: string; updated_at: string; result_id: string | null
}
export interface ConnectorAgentHeartbeat {
  id: string; received_at: string; agent_version: string | null; status: string | null
  active_jobs: number; queued_results: number; queue_size_mb: number | null
  cpu_percent: number | null; memory_mb: number | null; disk_free_mb: number | null; error_count: number
}

export const getConnectorAgents = (params?: Record<string, unknown>) =>
  api.get<Page<ConnectorAgentOut>>('/connector-agents', { params })
export const getConnectorAgent = (id: string) => api.get<ConnectorAgentOut>(`/connector-agents/${id}`)
export const createConnectorAgent = (data: { name: string; description?: string; site?: string; location?: string; environment?: string }) =>
  api.post<ConnectorAgentOut>('/connector-agents', data)
export const updateConnectorAgent = (id: string, data: Record<string, unknown>) =>
  api.patch<ConnectorAgentOut>(`/connector-agents/${id}`, data)
export const approveConnectorAgent = (id: string, notes?: string) =>
  api.post<ConnectorAgentOut>(`/connector-agents/${id}/approve`, { notes })
export const revokeConnectorAgent = (id: string, reason: string) =>
  api.post<ConnectorAgentOut>(`/connector-agents/${id}/revoke`, { reason })
export const disableConnectorAgent = (id: string) =>
  api.post<ConnectorAgentOut>(`/connector-agents/${id}/disable`)
export const enableConnectorAgent = (id: string) =>
  api.post<ConnectorAgentOut>(`/connector-agents/${id}/enable`)
export const rotateConnectorToken = (id: string) =>
  api.post<{ token: string; token_prefix: string; expires_at: string }>(`/connector-agents/${id}/rotate-token`)
export const generateEnrollmentToken = (data: { expected_hostname?: string; expected_site?: string; expected_environment?: string; auto_approve?: boolean; expires_in_seconds?: number }) =>
  api.post<{ token: string; token_prefix: string; expires_at: string; auto_approve: boolean }>('/connector-agents/enrollment-tokens', data)
export const getConnectorAgentSettings = (id: string) =>
  api.get<ConnectorAgentSettings>(`/connector-agents/${id}/settings`)
export const updateConnectorAgentSettings = (id: string, data: Partial<ConnectorAgentSettings>) =>
  api.put<ConnectorAgentSettings>(`/connector-agents/${id}/settings`, data)
export const getConnectorAgentJobs = (id: string, params?: Record<string, unknown>) =>
  api.get<Page<ConnectorAgentJobOut>>(`/connector-agents/${id}/jobs`, { params })
export const dispatchConnectorJob = (id: string, data: { job_type?: ConnectorAgentJobType; payload: Record<string, unknown>; priority?: number }) =>
  api.post<ConnectorAgentJobOut>(`/connector-agents/${id}/jobs`, data)
export const cancelConnectorJob = (agentId: string, jobId: string) =>
  api.post<ConnectorAgentJobOut>(`/connector-agents/${agentId}/jobs/${jobId}/cancel`)
export const getConnectorHeartbeats = (id: string) =>
  api.get<ConnectorAgentHeartbeat[]>(`/connector-agents/${id}/heartbeats`)
export const getConnectorLogs = (id: string, params?: Record<string, unknown>) =>
  api.get<unknown[]>(`/connector-agents/${id}/logs`, { params })

// --- Password Policy ---
export type PolicySource =
  | 'local_policy' | 'domain_policy' | 'fine_grained_ad'
  | 'pam_module' | 'pam_tally' | 'login_defs'
  | 'database_native' | 'external_idp' | 'unknown'
export type PolicyScope =
  | 'host' | 'domain' | 'database' | 'database_login' | 'account' | 'group' | 'global_'
export type PolicyFindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type PolicyFindingReviewState = 'open' | 'acknowledged' | 'risk_accepted' | 'remediated' | 'false_positive'

export interface PasswordPolicy {
  id: string; asset_id: string; job_id: string | null
  platform: Platform; policy_source: PolicySource; policy_scope: PolicyScope
  policy_name: string | null; is_effective_policy: boolean
  applies_to: Record<string, unknown> | null; precedence: number | null
  // Core settings
  min_password_length: number | null; complexity_enabled: boolean | null
  password_history_count: number | null; min_password_age_days: number | null
  max_password_age_days: number | null; reversible_encryption_enabled: boolean | null
  // Lockout
  lockout_threshold: number | null; lockout_duration_minutes: number | null
  reset_lockout_counter_after_minutes: number | null
  // Unix / PAM
  dictionary_check_enabled: boolean | null; min_char_classes: number | null
  min_uppercase: number | null; min_lowercase: number | null
  min_digits: number | null; min_special_chars: number | null
  // External
  external_policy_enforced: boolean | null; requires_external_review: boolean | null
  // Evidence
  evidence_summary: Record<string, unknown> | null
  raw_evidence_ref: string | null; collection_error: string | null
  // Metadata
  confidence_score: number; discovered_at: string
  created_at: string; updated_at: string
  // Computed by API
  has_weak_length: boolean | null; has_no_complexity: boolean | null
  has_no_lockout: boolean | null; has_no_expiry: boolean | null
  finding_count: number; critical_finding_count: number
  hostname: string | null
}

export interface AccountPolicyException {
  id: string; asset_id: string; account_id: string | null; policy_id: string | null
  exception_type: string; description: string | null
  effective_policy_source: string | null; expected_policy_source: string | null
  evidence: Record<string, unknown> | null; discovered_at: string
  account_name: string | null; asset_hostname: string | null
  created_at: string; updated_at: string
}

export interface PasswordPolicyFinding {
  id: string; asset_id: string; account_id: string | null
  policy_id: string | null; exception_id: string | null
  rule_key: string; severity: PolicyFindingSeverity
  title: string; description: string; recommendation: string | null
  affected_scope: string | null; evidence: Record<string, unknown> | null
  is_exception_finding: boolean
  review_state: PolicyFindingReviewState
  reviewed_by: string | null; reviewed_at: string | null; review_comment: string | null
  discovered_at: string; created_at: string
  hostname: string | null; platform: Platform | null; account_name: string | null
}

export interface PolicyCompareCell {
  asset_id: string; hostname: string; value: unknown
  source: string | null; is_effective: boolean; is_weak: boolean
}
export interface PolicyCompareRow {
  setting: string; label: string; baseline: unknown
  values: PolicyCompareCell[]; has_inconsistency: boolean
  worst_severity: PolicyFindingSeverity | null
}
export interface PolicyCompareResult {
  assets: { id: string; hostname: string; platform: Platform }[]
  rows: PolicyCompareRow[]
  inconsistency_count: number
  worst_severity: PolicyFindingSeverity | null
}

export interface PasswordPolicySummary {
  total_assets_with_policy: number; total_policies: number; effective_policies: number
  assets_with_no_policy: number; critical_findings: number; high_findings: number
  medium_findings: number; low_findings: number; open_findings: number
  total_exceptions: number; privileged_account_exceptions: number
  assets_with_weak_length: number; assets_with_no_complexity: number
  assets_with_no_lockout: number; assets_with_reversible_encryption: number
  by_platform: Record<string, number>; by_policy_source: Record<string, number>
}

export const getPasswordPolicies = (params?: Record<string, unknown>) =>
  api.get<Page<PasswordPolicy>>('/password-policy', { params })
export const getPasswordPolicy = (id: string) =>
  api.get<PasswordPolicy>(`/password-policy/${id}`)
export const upsertPasswordPolicy = (data: Record<string, unknown>) =>
  api.post<PasswordPolicy>('/password-policy', data)
export const updatePasswordPolicy = (id: string, data: Record<string, unknown>) =>
  api.put<PasswordPolicy>(`/password-policy/${id}`, data)
export const deletePasswordPolicy = (id: string) =>
  api.delete(`/password-policy/${id}`)
export const getPasswordPolicySummary = () =>
  api.get<PasswordPolicySummary>('/password-policy/summary')
export const getPolicyFindings = (params?: Record<string, unknown>) =>
  api.get<Page<PasswordPolicyFinding>>('/password-policy/findings', { params })
export const getPolicyFinding = (id: string) =>
  api.get<PasswordPolicyFinding>(`/password-policy/findings/${id}`)
export const reviewPolicyFinding = (id: string, state: PolicyFindingReviewState, comment?: string) =>
  api.post<{ detail: string; state: string }>(`/password-policy/findings/${id}/review`, { state, comment })
export const getPolicyExceptions = (params?: Record<string, unknown>) =>
  api.get<Page<AccountPolicyException>>('/password-policy/exceptions', { params })
export const createPolicyException = (data: Record<string, unknown>) =>
  api.post<AccountPolicyException>('/password-policy/exceptions', data)
export const comparePolicies = (assetIds: string[]) =>
  api.post<PolicyCompareResult>('/password-policy/compare', { asset_ids: assetIds })
export const exportPolicyCsv = (params?: Record<string, unknown>) =>
  api.get('/password-policy/export/csv', { params, responseType: 'blob' })
export const exportPolicyExcel = (params?: Record<string, unknown>) =>
  api.get('/password-policy/export/excel', { params, responseType: 'blob' })
export const getAssetPasswordPolicies = (assetId: string) =>
  api.get<Page<PasswordPolicy>>('/password-policy', { params: { asset_id: assetId } })
export const getPolicyExceptionsForPolicy = (policyId: string) =>
  api.get<AccountPolicyException[]>(`/password-policy/${policyId}/exceptions`)

// --- AI Assistant ---
export interface ChatMessage { role: 'user' | 'assistant'; content: string }
export interface ChatRequest {
  message: string
  history?: ChatMessage[]
  context?: Record<string, string | null>
}
export const chatAssistant = (data: ChatRequest) =>
  api.post<{ reply: string }>('/assistant/chat', data)
