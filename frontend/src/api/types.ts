// Shared API types — mirror the FastAPI backend schemas (app/schemas/*).
// Keep in sync with backend/app/models/enums.py and backend/app/schemas.

export interface Page<T> {
  items: T[]
  total: number
  limit: number
  offset: number
}

export type Platform =
  | 'rhel' | 'centos' | 'ubuntu' | 'sles' | 'solaris' | 'aix' | 'hpux'
  | 'windows'
  | 'mysql' | 'mssql' | 'mongodb' | 'oracle_db' | 'postgresql' | 'redis'

// Platform selectors accepted by the scan launch endpoint (superset of Platform).
export type PlatformSelector = Platform | 'all' | 'windows_server' | 'windows_desktop'

export type ScanType =
  | 'basic_discovery'
  | 'credentialed_discovery'
  | 'privileged_accounts'
  | 'password_policy'
  | 'interactive_classification'
  | 'full_discovery'

export type CredentialMode = 'none' | 'asset' | 'connector'

export type JobStatus =
  | 'pending' | 'queued' | 'running' | 'success' | 'partial_success'
  | 'failed' | 'timed_out' | 'unreachable' | 'auth_failed' | 'cancelled'

export type PrivilegeClass =
  | 'full_admin' | 'admin_equivalent' | 'operator_high_impact' | 'delegated_admin'
  | 'privileged_service' | 'sensitive_non_admin' | 'dormant_privileged'
  | 'non_privileged' | 'unknown_review_required'

export interface DashboardMetrics {
  total_assets: number
  total_accounts: number
  privileged_accounts: number
  newly_privileged_last_7d: number
  dormant_privileged: number
  shared_privileged: number
  unknown_review_required: number
  last_scan_at: string | null
  open_alerts: number
  by_platform: Record<string, number>
  by_classification: Record<string, number>
  local_admin_sprawl: { asset_id: string; hostname: string; count: number }[]
}

export interface TagSummary {
  id: string
  tag_name: string
  tag_code: string | null
  color: string
  category: string
  assigned_at: string | null
  assigned_by: string | null
}

export interface AssetGroupSummary { id: string; name: string; description: string | null; asset_count: number }

export interface Asset {
  id: string
  hostname: string
  ip_address: string | null
  instance: string | null
  port: number | null
  environment: string | null
  platform: Platform
  owner: string | null
  business_unit: string | null
  criticality: string | null
  discovery_enabled: boolean
  connector_id: string | null
  connector_name: string | null
  tags: Record<string, unknown> | null
  tag_summaries: TagSummary[]
  group_summaries: AssetGroupSummary[]
  created_at: string
  updated_at: string
}

export interface AssetRequest {
  hostname: string
  ip_address?: string | null
  instance?: string | null
  port?: number | null
  environment?: string | null
  platform: Platform
  owner?: string | null
  business_unit?: string | null
  criticality?: string | null
  connection_type?: string | null
  discovery_enabled: boolean
  jump_host_id?: string | null
  tags?: Record<string, unknown> | null
  connector_id?: string | null
}

export interface BulkImportResult { total_rows: number; imported_rows: number; duplicate_rows: number; invalid_rows: number; errors: Array<Record<string, unknown>>; job_id: string }
export interface AssetGroup { id: string; name: string; description: string | null; asset_ids: string[]; asset_count: number; created_at: string | null; updated_at: string | null }
export interface AssetGroupRequest { name: string; description?: string | null; asset_ids: string[] }


export interface ScanProfile {
  id: string
  name: string
  description: string | null
  platforms: Platform[]
  mode: 'safe' | 'deep'
  target_scope?: Record<string, unknown>
  throttle_ms?: number
  credential_strategy?: string
  collect_password_policy: boolean
  timeout_seconds: number
  retry_count: number
  concurrency_limit: number
  created_at: string
  updated_at: string
}

export interface ScanProfileRequest { name: string; description?: string | null; platforms: Platform[]; mode: 'safe' | 'deep'; target_scope: Record<string, unknown>; timeout_seconds: number; retry_count: number; concurrency_limit: number; throttle_ms: number; credential_strategy: string; collect_password_policy: boolean }

export interface Connector {
  id: string
  name: string
  kind: string
  default_port: number | null
  options: Record<string, unknown> | null
  credential_id: string | null
  proxy_host?: string | null
  proxy_port?: number | null
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface ConnectorUpdateRequest { name: string; kind: string; default_port?: number | null; options?: Record<string, unknown> | null; credential_id?: string | null; proxy_host?: string | null; proxy_port?: number | null; is_active: boolean }

export interface TestConnectionResult { success: boolean; latency_ms: number; message: string; details?: Record<string, unknown> | null }

export interface Credential {
  id: string
  name: string
  description: string | null
  vault_backend: string
  vault_ref: string
  username: string
  auth_method: string
  rotation_policy_days: number | null
  last_rotated_at: string | null
  rotation_overdue: boolean
  is_active: boolean
  created_at: string
  updated_at: string
}

export interface CredentialUpdateRequest { name: string; description?: string | null; vault_backend: string; vault_ref: string; username: string; auth_method: string; rotation_policy_days?: number | null; is_active: boolean; secret_material?: string | null }
export type CredentialCreateRequest = CredentialUpdateRequest

export interface ScanJob {
  id: string
  name: string | null
  scan_type: ScanType | null
  selected_platforms: string[]
  credential_mode: CredentialMode | null
  collect_password_policy: boolean
  scope_description: string
  status: JobStatus
  triggered_by: string | null
  triggered_kind: string
  started_at: string | null
  finished_at: string | null
  totals: Record<string, number> | null
  created_at: string
}

export interface ScanTarget {
  id: string
  job_id: string
  asset_id: string
  hostname: string | null
  ip_address: string | null
  platform: Platform
  scan_type: ScanType | null
  connector_id: string | null
  status: JobStatus
  attempt: number
  started_at: string | null
  finished_at: string | null
  duration_ms: number | null
  error_bucket: string | null
  error_detail: string | null
  stats: Record<string, number> | null
}

export interface ScanLaunchRequest { name?: string | null; scan_type: ScanType; selected_platforms: string[]; asset_ids?: string[]; group_ids?: string[]; all_enabled?: boolean; profile_id?: string | null; credential_mode?: CredentialMode; connector_id?: string | null; note?: string | null; collect_password_policy?: boolean | null }

export interface Account {
  id: string
  asset_id: string
  asset_hostname: string | null
  platform: Platform
  source_type: string
  account_origin: string
  account_domain: string | null
  account_name: string
  principal_type: string
  auth_source: string
  enabled_status: string
  interactive_status: string
  last_login: string | null
  privilege_classification: PrivilegeClass
  privilege_confidence: number
  risk_score: number
  is_shared: boolean
  password_never_expires: boolean
  owner: string | null
  activity_status: string
  schema_name?: string | null
  evidence_summary: Record<string, unknown> | null
  discovered_at: string
  updated_at: string
  // Optional provenance / classification fields (null where not applicable)
  last_login_source?: string | null
  principal_source?: string | null
  review_required_reason?: string | null
  never_logged_in?: boolean | null
  password_last_changed?: string | null
  password_expires_at?: string | null
  interactive_confidence?: number | null
  interactive_detection_method?: string | null
  allows_local_logon?: boolean | null
  allows_remote_interactive_logon?: boolean | null
  allows_service_logon?: boolean | null
  allows_batch_logon?: boolean | null
  allows_network_logon?: boolean | null
}

export interface Entitlement {
  id: string
  kind: string
  name: string
  scope: string | null
  source: string | null
  inherited: boolean
  via: string | null
  attributes: Record<string, unknown> | null
}

export interface AccountDetail extends Account {
  entitlements: Entitlement[]
  raw_evidence_refs: unknown[] | null
  interactive_evidence_summary: Record<string, unknown> | null
}

export type ReviewState = 'unreviewed' | 'acknowledged' | 'risk_accepted' | 'remediated' | 'false_positive'

export interface Finding {
  id: string
  job_id: string | null
  connector_agent_job_id?: string | null
  account_id: string
  rule_id: string
  rule_key: string
  rule_version: number
  classification: PrivilegeClass
  confidence: number
  risk_score: number
  is_winning: boolean
  direct: boolean
  inheritance_path: string | null
  explanation: string
  matched_evidence: Record<string, unknown> | null
  evaluated_at: string
  latest_review_state?: ReviewState | null
  latest_review_comment?: string | null
  latest_review_reviewer?: string | null
  latest_review_at?: string | null
  account_name?: string | null
  normalized_account_name?: string | null
  asset_id?: string | null
  asset_hostname?: string | null
  asset_ip_address?: string | null
  platform?: Platform | null
  application_tag?: string | null
  environment?: string | null
  account_source?: string | null
  account_type?: string | null
  enabled_status?: string | null
  interactive_status?: string | null
  last_login?: string | null
  activity_status?: string | null
  pam_managed?: boolean | null
  owner?: string | null
  password_never_expires?: boolean | null
  is_shared?: boolean | null
  discovered_at?: string | null
  updated_at?: string | null
}

export type PolicySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type PolicyReviewState = 'open' | 'acknowledged' | 'risk_accepted' | 'remediated' | 'false_positive'

export interface PasswordPolicy {
  id: string; asset_id: string; hostname: string | null; platform: Platform; policy_source: string; policy_scope: string; policy_name: string | null; is_effective_policy: boolean
  min_password_length: number | null; complexity_enabled: boolean | null; max_password_age_days: number | null; lockout_threshold: number | null; reversible_encryption_enabled?: boolean | null
  has_weak_length: boolean | null; has_no_complexity: boolean | null; has_no_lockout: boolean | null; has_no_expiry: boolean | null; finding_count: number; critical_finding_count: number
}

export interface PasswordPolicyFinding {
  id: string
  asset_id: string
  account_id: string | null
  rule_key: string
  severity: PolicySeverity
  title: string
  description: string
  recommendation: string | null
  affected_scope: string | null
  is_exception_finding: boolean
  review_state: PolicyReviewState
  reviewed_by: string | null
  reviewed_at: string | null
  hostname?: string | null
  account_name?: string | null
}

export interface PolicyCompareCell {
  asset_id: string
  hostname: string
  value: unknown
  source: string | null
  is_effective: boolean
  is_weak: boolean
}

export interface PolicyCompareRow {
  setting: string
  label: string
  baseline: unknown
  values: PolicyCompareCell[]
  has_inconsistency: boolean
  worst_severity: PolicySeverity | null
}

export interface PolicyCompareResult {
  assets: { id: string; hostname: string; platform: Platform }[]
  rows: PolicyCompareRow[]
  inconsistency_count: number
  worst_severity: PolicySeverity | null
}

export interface PolicyException {
  id: string
  asset_id: string
  policy_id?: string | null
  account_id: string | null
  exception_type: string
  description: string | null
  effective_policy_source?: string | null
  expected_policy_source?: string | null
  evidence?: Record<string, unknown> | null
  account_name: string | null
  asset_hostname: string | null
  discovered_at?: string
  created_at: string
}

export interface PolicyExceptionRequest { asset_id: string; account_id?: string | null; policy_id?: string | null; exception_type: string; description?: string | null; effective_policy_source?: string | null; expected_policy_source?: string | null; evidence?: Record<string, unknown> | null; discovered_at: string }

export interface PasswordPolicySummary {
  total_assets_with_policy: number
  total_policies: number
  effective_policies: number
  assets_with_no_policy: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  open_findings: number
  total_exceptions: number
  privileged_account_exceptions: number
  assets_with_weak_length: number
  assets_with_no_complexity: number
  assets_with_no_lockout: number
  assets_with_reversible_encryption: number
  by_platform: Record<string, number>
  by_policy_source: Record<string, number>
}

export type TagCategory = 'application' | 'environment' | 'business_unit' | 'criticality' | 'compliance' | 'ownership' | 'technology' | 'custom'
export type TagStatus = 'active' | 'inactive'

export interface Tag {
  id: string
  tag_name: string
  tag_code: string | null
  description: string | null
  category: TagCategory
  color: string
  status: TagStatus
  usage_count: number
  created_by: string | null
  updated_by: string | null
  created_at: string
  updated_at: string
}

export type AgentStatus = 'pending' | 'approved' | 'online' | 'offline' | 'stale' | 'disabled' | 'revoked' | 'error'

export interface ConnectorAgent {
  id: string
  name: string
  description: string | null
  hostname: string | null
  ip_address: string | null
  os_platform: string | null
  agent_version: string | null
  site: string | null
  location: string | null
  environment: string | null
  status: AgentStatus
  is_enabled: boolean
  last_seen_at: string | null
  last_heartbeat_at: string | null
  cert_expires_at?: string | null
  cert_fingerprint?: string | null
  token_prefix?: string | null
  approved_by?: string | null
  created_at: string
}

export interface ConnectorAgentCreateRequest {
  name: string
  description?: string | null
  site?: string | null
  location?: string | null
  environment?: string | null
}

export interface ConnectorAgentUpdateRequest {
  name?: string | null
  description?: string | null
  site?: string | null
  location?: string | null
  environment?: string | null
  is_enabled?: boolean | null
}

export interface ConnectorAgentSettings {
  heartbeat_interval_seconds: number
  job_poll_interval_seconds: number
  config_refresh_interval_seconds: number
  retry_max_attempts: number
  retry_backoff_base_seconds: number
  retry_backoff_max_seconds: number
  job_timeout_seconds: number
  max_concurrent_jobs: number
  result_chunk_size_mb: number
  offline_queue_max_mb: number
  result_retention_hours: number
  log_retention_days: number
  verify_console_certificate: boolean
  verify_console_fingerprint: boolean
  console_fingerprint: string | null
  token_rotation_days: number
}

export interface TokenRotateResponse {
  token: string
  token_prefix: string
  expires_at: string
}

export interface ConnectorAgentJob {
  id: string
  agent_id: string
  discovery_job_id: string | null
  job_type: string
  status: string
  priority: number
  progress_pct: number
  progress_message: string | null
  targets_total: number
  targets_done: number
  targets_failed: number
  error_message: string | null
  scheduled_at: string | null
  started_at: string | null
}

export interface ConnectorAgentHeartbeat {
  id: string
  received_at: string
  agent_version: string | null
  status: string | null
  active_jobs: number
  queued_results: number
  cpu_percent: number | null
  memory_mb: number | null
  disk_free_mb: number | null
  error_count: number
}

export interface ConnectorAgentLog {
  id: string
  level: string
  message: string
  context: Record<string, unknown> | null
  job_id: string | null
  agent_timestamp: string | null
  received_at: string
}

export interface EnrollmentTokenRequest {
  expected_hostname?: string | null
  expected_site?: string | null
  expected_environment?: string | null
  auto_approve?: boolean
  expires_in_seconds?: number
}

export interface EnrollmentTokenResponse {
  token: string
  token_prefix: string
  expires_at: string
  auto_approve: boolean
}

export interface ConnectorCreateRequest { name: string; kind: string; default_port?: number | null; credential_id?: string | null; is_active?: boolean }

export interface AuditLogItem { id: string; actor_id: string | null; actor_email: string | null; action: string; subject_type: string | null; subject_id: string | null; ip: string | null; context: Record<string, unknown> | null; occurred_at: string }
export interface ManagedUser { id: string; username: string; display_name: string | null; email: string; roles: string[]; status: 'active' | 'disabled' | 'locked' | 'pending_password_change'; must_change_password: boolean; last_login_at: string | null; created_by: string | null; created_at: string; updated_by: string | null; updated_at: string }
export interface ManagedRole { id: string; name: string; description: string | null; permissions: string[] }
export interface UserCreateRequest { username: string; display_name?: string | null; email: string; role: string; temporary_password: string; must_change_password: boolean; is_active: boolean }
export interface UserUpdateRequest { username?: string; display_name?: string | null; email?: string; role?: string; must_change_password?: boolean }
export interface ResetPasswordRequest { temporary_password: string; must_change_password: boolean }
export interface ScheduledScan { id: string; name: string; description: string | null; cron: string; profile_id: string; scope: Record<string, unknown>; enabled: boolean; requires_approval: boolean; last_run_at: string | null; next_run_at: string | null; created_at: string; updated_at: string }

export interface ScheduledScanRequest { name: string; description?: string | null; cron: string; profile_id: string; scope: Record<string, unknown>; enabled: boolean; requires_approval: boolean }

export interface AppStatus {
  env: 'development' | 'test' | 'uat' | 'staging' | 'production'
  demo_mode: boolean
  collector_mode: 'mock' | 'live'
}
