// Frontend RBAC — UX layer only. The backend remains the authorization boundary.
// Roles come from backend seed: admin, security_analyst, viewer, auditor.
import { useAppSelector } from '../store/hooks'
import { selectAuth } from '../store/authSlice'

export type Permission =
  | 'scan:launch'
  | 'scan:manage'
  | 'export:run'
  | 'connector:manage'   // admin + security_analyst: connector CRUD/test, agent enable/disable
  | 'connector:admin'    // admin only: agent approve/revoke, token rotation, delete
  | 'credential:manage'
  | 'tag:manage'
  | 'settings:manage'
  | 'user:manage'
  | 'findings:view'
  | 'findings:review'
  | 'policy:review'
  | 'policy:manage'
  | 'audit:view'

const ROLE_PERMISSIONS: Record<string, Permission[]> = {
  admin: [
    'scan:launch', 'scan:manage', 'export:run', 'connector:manage', 'connector:admin', 'credential:manage',
    'tag:manage', 'settings:manage', 'user:manage', 'findings:view', 'findings:review', 'policy:review', 'policy:manage', 'audit:view',
  ],
  security_analyst: [
    'scan:launch', 'scan:manage', 'export:run', 'connector:manage', 'credential:manage',
    'tag:manage', 'findings:view', 'findings:review', 'policy:review', 'policy:manage',
  ],
  auditor: ['export:run', 'findings:view', 'policy:review', 'audit:view'],
  viewer: [],
}

export function permissionsForRoles(roles: string[]): Set<Permission> {
  const perms = new Set<Permission>()
  for (const role of roles) {
    for (const p of ROLE_PERMISSIONS[role] ?? []) perms.add(p)
  }
  return perms
}

/** Returns a `can(permission)` checker for the current user's roles. */
export function useCan() {
  const auth = useAppSelector(selectAuth)
  const perms = permissionsForRoles(auth.user?.roles ?? [])
  return (permission: Permission) => perms.has(permission)
}
