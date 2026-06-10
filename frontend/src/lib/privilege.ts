import type { PrivilegeClass } from '@/api/endpoints'

export const PRIVILEGE_LABELS: Record<PrivilegeClass, string> = {
  full_admin: 'Full Admin',
  admin_equivalent: 'Admin Equivalent',
  operator_high_impact: 'Operator – High Impact',
  delegated_admin: 'Delegated Admin',
  privileged_service: 'Privileged Service',
  sensitive_non_admin: 'Sensitive Non-Admin',
  dormant_privileged: 'Dormant Privileged',
  non_privileged: 'Non-Privileged',
  unknown_review_required: 'Unknown – Review Required',
}

export const PRIVILEGE_COLORS: Record<PrivilegeClass, { bg: string; text: string; border: string }> = {
  full_admin:              { bg: 'bg-red-100',    text: 'text-red-800',    border: 'border-red-300' },
  admin_equivalent:        { bg: 'bg-orange-100', text: 'text-orange-800', border: 'border-orange-300' },
  operator_high_impact:    { bg: 'bg-amber-100',  text: 'text-amber-800',  border: 'border-amber-300' },
  delegated_admin:         { bg: 'bg-yellow-100', text: 'text-yellow-800', border: 'border-yellow-300' },
  privileged_service:      { bg: 'bg-purple-100', text: 'text-purple-800', border: 'border-purple-300' },
  sensitive_non_admin:     { bg: 'bg-sky-100',    text: 'text-sky-800',    border: 'border-sky-300' },
  dormant_privileged:      { bg: 'bg-pink-100',   text: 'text-pink-800',   border: 'border-pink-300' },
  non_privileged:          { bg: 'bg-slate-100',  text: 'text-slate-600',  border: 'border-slate-200' },
  unknown_review_required: { bg: 'bg-gray-100',   text: 'text-gray-700',   border: 'border-gray-300' },
}

export const PLATFORM_LABELS: Record<string, string> = {
  // Unix / Linux
  rhel:       'RHEL',
  centos:     'CentOS',
  ubuntu:     'Ubuntu',
  sles:       'SLES',
  solaris:    'Solaris',
  aix:        'AIX',
  hpux:       'HP-UX',
  // Windows
  windows:    'Windows',
  // Databases
  mysql:      'MySQL',
  mssql:      'MSSQL',
  mongodb:    'MongoDB',
  oracle_db:  'Oracle DB',
  postgresql: 'PostgreSQL',
  redis:      'Redis',
}

export const JOB_STATUS_COLORS: Record<string, string> = {
  pending: 'bg-slate-100 text-slate-600',
  queued: 'bg-blue-100 text-blue-700',
  running: 'bg-brand-100 text-brand-700',
  success: 'bg-green-100 text-green-700',
  partial_success: 'bg-yellow-100 text-yellow-700',
  failed: 'bg-red-100 text-red-700',
  timed_out: 'bg-orange-100 text-orange-700',
  unreachable: 'bg-gray-100 text-gray-600',
  auth_failed: 'bg-pink-100 text-pink-700',
  cancelled: 'bg-slate-100 text-slate-500',
}
