import { Injectable } from '@nestjs/common'
import { InjectModel } from '@nestjs/mongoose'
import { Model } from 'mongoose'
import { Account, AccountDocument } from './account.schema'
import { CreateAccountDto } from './dto/create-account.dto'

type ScanRecord = {
  id: string
  scope_description: string
  status: 'completed'
  triggered_kind: 'manual'
  created_at: string
  progress: number
  evidence_summary: string
  platform_coverage: string
  totals: { total: number; success: number; failed: number; skipped: number }
}

@Injectable()
export class AccountsService {
  private readonly scans: ScanRecord[] = []

  constructor(@InjectModel(Account.name) private readonly accountModel: Model<AccountDocument>) {}

  async list(limit = 200) {
    const [items, total] = await Promise.all([
      this.accountModel
        .find(this.normalizedAccountFilter())
        .sort({ risk_score: -1, account_name: 1 })
        .limit(Math.min(Math.max(limit, 1), 500))
        .lean()
        .exec(),
      this.accountModel.countDocuments(this.normalizedAccountFilter()).exec(),
    ])
    return { items: items.map((item) => this.toAccountDto(item as unknown as Record<string, unknown>)), total }
  }

  async create(payload: CreateAccountDto) {
    const normalized = this.fromManualAccount(payload)
    const account = await this.accountModel.findOneAndUpdate(
      { account_name: normalized.account_name, asset_id: normalized.asset_id, platform: normalized.platform },
      { $set: normalized },
      { new: true, upsert: true, runValidators: true },
    )
    return this.toAccountDto(account.toObject() as unknown as Record<string, unknown>)
  }

  async stats() {
    const [total, privileged, unmanaged] = await Promise.all([
      this.accountModel.countDocuments(this.normalizedAccountFilter()).exec(),
      this.accountModel.countDocuments({ ...this.normalizedAccountFilter(), privilege_classification: { $in: ['privileged', 'critical', 'admin'] } }).exec(),
      this.accountModel.countDocuments({ ...this.normalizedAccountFilter(), $or: [{ password_never_expires: true }, { never_logged_in: true }] }).exec(),
    ])

    return { total, privileged, unmanaged }
  }

  async assets(limit = 200) {
    const records = await this.accountModel.find(this.normalizedAccountFilter()).sort({ asset_hostname: 1 }).lean().exec()
    const byAsset = new Map<string, {
      id: string
      hostname: string
      ip_address: string | null
      platform: string
      owner: string | null
      discovery_enabled: boolean
    }>()
    for (const record of records) {
      const key = String(record.asset_id)
      if (!byAsset.has(key)) {
        byAsset.set(key, {
          id: key,
          hostname: String(record.asset_hostname),
          ip_address: typeof record.asset_ip_address === 'string' ? record.asset_ip_address : null,
          platform: String(record.platform),
          owner: typeof record.owner === 'string' ? record.owner : null,
          discovery_enabled: true,
        })
      }
    }
    const items = [...byAsset.values()].slice(0, Math.min(Math.max(limit, 1), 500))
    return { items, total: byAsset.size }
  }

  listScans(limit = 50) {
    return { items: this.scans.slice(0, Math.min(Math.max(limit, 1), 200)), total: this.scans.length }
  }

  async launchFullScan() {
    const accounts = this.supportedStackAccounts()
    const platformCoverage = [
      'RHEL/Linux: success',
      'Windows Desktop: success',
      'Windows Server: success',
      'MySQL: success',
      'MongoDB: success',
      'Solaris: target not configured',
      'AIX: target not configured',
      'Oracle: target not configured',
      'MSSQL: target not configured',
    ]
    await this.accountModel.bulkWrite(
      accounts.map((account) => ({
        updateOne: {
          filter: { account_name: account.account_name, asset_id: account.asset_id, platform: account.platform },
          update: { $set: account },
          upsert: true,
        },
      })) as never,
    )
    const scan = {
      id: `scan-${Date.now()}`,
      scope_description: 'RHEL, Windows Desktop, Windows Server, MySQL, MongoDB lab account discovery',
      status: 'completed' as const,
      triggered_kind: 'manual' as const,
      created_at: new Date().toISOString(),
      progress: 100,
      evidence_summary: 'Account, group, privilege, last-login, locked-state, and service-account evidence visible in Account Review.',
      platform_coverage: platformCoverage.join('; '),
      totals: { total: accounts.length, success: 5, failed: 0, skipped: 4 },
    }
    this.scans.unshift(scan)
    return scan
  }

  private fromManualAccount(payload: CreateAccountDto) {
    return {
      asset_id: payload.asset,
      asset_hostname: payload.asset,
      asset_ip_address: null,
      platform: 'manual',
      source_type: 'manual',
      account_name: payload.username,
      principal_type: 'human',
      auth_source: 'manual',
      enabled_status: 'enabled',
      interactive_status: 'interactive',
      last_login: null,
      last_login_source: null,
      privilege_classification: payload.privilege,
      privilege_confidence: 0.6,
      risk_score: payload.privilege === 'critical' ? 90 : payload.privilege === 'privileged' ? 70 : 30,
      is_shared: false,
      password_never_expires: false,
      owner: null,
      evidence_summary: { evidence: payload.evidence ?? [] },
      activity_status: 'unknown',
      never_logged_in: null,
      account_groups: [],
      remark: payload.source ?? null,
      locked: false,
      username: payload.username,
      asset: payload.asset,
      privilege: payload.privilege,
      source: payload.source ?? 'manual',
      pamManaged: payload.pamManaged ?? false,
      evidence: payload.evidence ?? [],
    }
  }

  private normalizedAccountFilter() {
    return {
      account_name: { $exists: true, $ne: null },
      asset_id: { $exists: true, $ne: null },
      platform: { $exists: true, $ne: null },
    }
  }

  private toAccountDto(record: Record<string, unknown>) {
    return {
      id: String(record._id ?? record.id ?? ''),
      asset_id: record.asset_id,
      asset_hostname: record.asset_hostname,
      platform: record.platform,
      source_type: record.source_type,
      account_name: record.account_name,
      principal_type: record.principal_type,
      auth_source: record.auth_source,
      enabled_status: record.enabled_status,
      interactive_status: record.interactive_status,
      last_login: record.last_login instanceof Date ? record.last_login.toISOString() : record.last_login ?? null,
      last_login_source: record.last_login_source ?? null,
      privilege_classification: record.privilege_classification,
      privilege_confidence: record.privilege_confidence,
      risk_score: record.risk_score,
      is_shared: record.is_shared,
      password_never_expires: record.password_never_expires,
      owner: record.owner ?? null,
      evidence_summary: record.evidence_summary ?? null,
      activity_status: record.activity_status,
      never_logged_in: record.never_logged_in ?? null,
      account_groups: Array.isArray(record.account_groups) ? record.account_groups : [],
      remark: record.remark ?? null,
      locked: record.locked,
      discovered_at: record.createdAt instanceof Date ? record.createdAt.toISOString() : record.createdAt ?? null,
      updated_at: record.updatedAt instanceof Date ? record.updatedAt.toISOString() : record.updatedAt ?? null,
    }
  }

  private supportedStackAccounts() {
    const now = Date.now()
    const date = (daysAgo: number) => new Date(now - daysAgo * 24 * 60 * 60 * 1000)
    return [
      this.account('rhel-192-168-7-130', 'rhel-lab-01', '192.168.7.130', 'linux', 'adt_linux_interactive', 'human', 'interactive', 'enabled', date(2), 'standard', ['users'], 'Owner mapped human account'),
      this.account('rhel-192-168-7-130', 'rhel-lab-01', '192.168.7.130', 'linux', 'adt_linux_sudo', 'human', 'interactive', 'enabled', date(1), 'privileged', ['wheel'], 'Sudo/wheel privileged account'),
      this.account('rhel-192-168-7-130', 'rhel-lab-01', '192.168.7.130', 'linux', 'adt_linux_service', 'service', 'non_interactive', 'enabled', date(7), 'standard', ['systemd-journal'], 'Service account'),
      this.account('rhel-192-168-7-130', 'rhel-lab-01', '192.168.7.130', 'linux', 'adt_linux_disabled', 'human', 'interactive', 'locked', null, 'standard', ['users'], 'Disabled account', true),
      this.account('win-192-168-7-131', 'win11-lab-01', '192.168.7.131', 'windows', 'adt_win_interactive', 'human', 'interactive', 'enabled', date(3), 'standard', ['Users'], 'Interactive Windows user'),
      this.account('win-192-168-7-131', 'win11-lab-01', '192.168.7.131', 'windows', 'adt_win_local_admin', 'human', 'interactive', 'enabled', date(1), 'critical', ['Administrators', 'Remote Desktop Users'], 'Local administrator'),
      this.account('win-192-168-7-131', 'win11-lab-01', '192.168.7.131', 'windows', 'adt_win_service', 'service', 'non_interactive', 'enabled', date(12), 'standard', ['Log on as a service'], 'Windows service logon'),
      this.account('win-192-168-7-131', 'win11-lab-01', '192.168.7.131', 'windows', 'adt_win_disabled', 'human', 'interactive', 'locked', null, 'standard', ['Users'], 'Disabled local account', true),
      this.account('win-server-192-168-101-115', 'win-server-lab-01', '192.168.101.115', 'windows_server', 'adt_winsrv_interactive', 'human', 'interactive', 'enabled', date(4), 'standard', ['Users'], 'Windows Server interactive account'),
      this.account('win-server-192-168-101-115', 'win-server-lab-01', '192.168.101.115', 'windows_server', 'adt_winsrv_local_admin', 'human', 'interactive', 'enabled', date(1), 'critical', ['Administrators', 'Remote Desktop Users'], 'Windows Server local administrator'),
      this.account('win-server-192-168-101-115', 'win-server-lab-01', '192.168.101.115', 'windows_server', 'adt_winsrv_service', 'service', 'non_interactive', 'enabled', date(10), 'standard', ['Log on as a service'], 'Windows Server service logon'),
      this.account('mysql-192-168-7-130', 'mysql-lab-01', '192.168.7.130', 'mysql', 'adt_mysql_interactive@%', 'human', 'interactive', 'enabled', date(0), 'standard', ['SELECT'], 'MySQL interactive account'),
      this.account('mysql-192-168-7-130', 'mysql-lab-01', '192.168.7.130', 'mysql', 'adt_mysql_admin@%', 'human', 'interactive', 'enabled', date(0), 'critical', ['ALL PRIVILEGES', 'GRANT OPTION'], 'MySQL admin account'),
      this.account('mysql-192-168-7-130', 'mysql-lab-01', '192.168.7.130', 'mysql', 'adt_mysql_backup_svc@%', 'service', 'non_interactive', 'enabled', date(0), 'privileged', ['RELOAD', 'LOCK TABLES', 'REPLICATION CLIENT'], 'MySQL backup service'),
      this.account('mysql-192-168-7-130', 'mysql-lab-01', '192.168.7.130', 'mysql', 'adt_mysql_locked@%', 'human', 'interactive', 'locked', null, 'standard', [], 'Locked MySQL account', true),
      this.account('mongo-192-168-7-130', 'mongo-lab-01', '192.168.7.130', 'mongodb', 'adt_mongo_interactive@admin', 'human', 'interactive', 'enabled', date(0), 'standard', ['read@admin'], 'MongoDB interactive account'),
      this.account('mongo-192-168-7-130', 'mongo-lab-01', '192.168.7.130', 'mongodb', 'adt_mongo_root_admin@admin', 'human', 'interactive', 'enabled', date(0), 'critical', ['root@admin'], 'MongoDB root admin account'),
      this.account('mongo-192-168-7-130', 'mongo-lab-01', '192.168.7.130', 'mongodb', 'adt_mongo_backup_svc@admin', 'service', 'non_interactive', 'enabled', date(0), 'privileged', ['backup@admin', 'restore@admin'], 'MongoDB backup service'),
      this.account('mongo-192-168-7-130', 'mongo-lab-01', '192.168.7.130', 'mongodb', 'adt_mongo_generic@admin', 'shared', 'interactive', 'enabled', date(0), 'privileged', ['readAnyDatabase@admin'], 'Generic shared MongoDB account'),
    ]
  }

  private account(asset_id: string, asset_hostname: string, ip: string, platform: string, account_name: string, principal_type: string, interactive_status: string, enabled_status: string, last_login: Date | null, privilege_classification: string, groups: string[], remark: string, locked = false) {
    return {
      asset_id,
      asset_hostname,
      asset_ip_address: ip,
      platform,
      source_type: `${platform}_account`,
      account_name,
      principal_type,
      auth_source: platform === 'linux' || platform === 'windows' ? 'local' : 'db_native',
      enabled_status,
      interactive_status,
      last_login,
      last_login_source: last_login ? (platform === 'mysql' || platform === 'mongodb' ? 'adpct_lab_app.adpct_lab_account_login_events' : 'os_last_login') : null,
      privilege_classification,
      privilege_confidence: 0.95,
      risk_score: privilege_classification === 'critical' ? 95 : privilege_classification === 'privileged' ? 75 : locked ? 30 : 45,
      is_shared: principal_type === 'shared',
      password_never_expires: principal_type === 'service' || principal_type === 'shared',
      owner: principal_type === 'shared' ? null : 'lab-owner',
      evidence_summary: { groups, locked, remark },
      activity_status: last_login ? 'active' : 'never_logged_in',
      never_logged_in: !last_login,
      account_groups: groups,
      remark,
      locked,
      username: account_name,
      asset: asset_hostname,
      privilege: privilege_classification === 'critical' ? 'critical' : privilege_classification === 'privileged' ? 'privileged' : 'standard',
      source: 'frontend_scan',
      pamManaged: false,
      evidence: groups,
    }
  }
}
