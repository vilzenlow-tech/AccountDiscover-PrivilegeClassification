import type { CredentialMode, ScanType } from '../../api/types'
import type { Option } from '../../components/ui'

export const SCAN_TYPE_OPTIONS: { value: ScanType; label: string; hint: string; defaultCredentialMode: CredentialMode; collectPasswordPolicy?: boolean }[] = [
  { value: 'basic_discovery', label: 'Basic discovery', hint: 'Account inventory without credentials (where supported).', defaultCredentialMode: 'none' },
  { value: 'credentialed_discovery', label: 'Credentialed discovery', hint: 'Full account collection using stored credentials.', defaultCredentialMode: 'asset' },
  { value: 'privileged_accounts', label: 'Privileged account scan', hint: 'Focus on admin / root / high-impact identities.', defaultCredentialMode: 'asset' },
  { value: 'password_policy', label: 'Password policy scan', hint: 'Collect and evaluate password / dormancy policy.', defaultCredentialMode: 'asset', collectPasswordPolicy: true },
  { value: 'interactive_classification', label: 'Interactive / non-interactive classification', hint: 'Classify logon capability (interactive vs service).', defaultCredentialMode: 'asset' },
  { value: 'full_discovery', label: 'Full discovery', hint: 'Accounts, privilege, policy and classification together.', defaultCredentialMode: 'asset', collectPasswordPolicy: true },
]

// Platform selectors accepted by POST /scans (selected_platforms[]).
export const PLATFORM_OPTIONS: Option[] = [
  { value: 'windows_server', label: 'Windows Server' },
  { value: 'windows_desktop', label: 'Windows Desktop' },
  { value: 'windows', label: 'Windows (all)' },
  { value: 'rhel', label: 'RHEL' },
  { value: 'solaris', label: 'Solaris' },
  { value: 'aix', label: 'AIX' },
  { value: 'oracle_db', label: 'Oracle' },
  { value: 'mssql', label: 'MSSQL' },
  { value: 'mysql', label: 'MySQL' },
  { value: 'mongodb', label: 'MongoDB' },
]

// Map a platform selector to the underlying asset.platform value(s) for matching.
export function selectorMatchesPlatform(selector: string, platform: string): boolean {
  if (selector === 'all') return true
  if (selector === 'windows' || selector === 'windows_server' || selector === 'windows_desktop') return platform === 'windows'
  return selector === platform
}

export const CREDENTIAL_MODE_OPTIONS: { value: CredentialMode; label: string; hint: string }[] = [
  { value: 'none', label: 'No credentials', hint: 'Unauthenticated discovery only.' },
  { value: 'asset', label: 'Per-asset credentials', hint: 'Use the credential linked to each asset / connector.' },
  { value: 'connector', label: 'Connector credentials', hint: 'Use a specific connector and its linked credential.' },
]

export type ScopeKind = 'all_enabled' | 'platform' | 'selected' | 'tag' | 'environment' | 'connector' | 'bulk'

export const SCOPE_OPTIONS: { value: ScopeKind; label: string; hint: string }[] = [
  { value: 'platform', label: 'Platform-based', hint: 'All enabled assets matching the selected platforms.' },
  { value: 'selected', label: 'Selected assets', hint: 'Pick specific assets from the inventory.' },
  { value: 'tag', label: 'Tag / application', hint: 'Assets carrying a chosen application/governance tag.' },
  { value: 'environment', label: 'Environment', hint: 'All assets in a given environment (prod, dev, …).' },
  { value: 'connector', label: 'Connector-based', hint: 'Assets reached through a specific connector.' },
  { value: 'bulk', label: 'Bulk hostname / IP', hint: 'Paste hostnames or IPs to match against inventory.' },
  { value: 'all_enabled', label: 'All enabled assets', hint: 'Every discovery-enabled asset (filtered by platform).' },
]
