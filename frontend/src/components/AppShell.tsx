import type React from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { useGetAppStatusQuery, useGetDashboardMetricsQuery } from '../api/apiSlice'
import { permissionsForRoles, type Permission } from '../app/rbac'
import { cx } from './ui'

export type NavItem = { to: string; label: string; permission?: Permission }
export type NavGroup = { label: string; items: NavItem[] }

export const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Operations',
    items: [
      { to: '/', label: 'Dashboard' },
      { to: '/assets', label: 'Assets' },
      { to: '/scans', label: 'Scans' },
      { to: '/accounts', label: 'Accounts' },
      { to: '/findings', label: 'Privileged Findings', permission: 'findings:view' },
    ],
  },
  {
    label: 'Governance',
    items: [
      { to: '/password-policy', label: 'Password Policy' },
      { to: '/connectors', label: 'Connectors / Agents' },
      { to: '/tags', label: 'Tags / Applications' },
    ],
  },
  {
    label: 'Assurance',
    items: [
      { to: '/reports', label: 'Reports / Exports' },
      { to: '/audit', label: 'Audit Logs' },
      { to: '/users', label: 'User Management', permission: 'user:manage' },
      { to: '/settings', label: 'Settings' },
    ],
  },
]

function HealthPill() {
  // Honest backend health derived from a real API query (not a hardcoded value).
  const { isLoading, isError } = useGetDashboardMetricsQuery()
  const tone = isLoading ? 'amber' : isError ? 'red' : 'green'
  const label = isLoading ? 'Checking…' : isError ? 'API offline' : 'API online'
  const dot = { green: 'bg-emerald-500', amber: 'bg-amber-500', red: 'bg-red-500' }[tone]
  return (
    <span className="inline-flex items-center gap-2 rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-600">
      <span className={cx('h-1.5 w-1.5 rounded-full', dot)} />{label}
    </span>
  )
}

function DataSourcePill() {
  const { data, isError } = useGetAppStatusQuery()
  if (isError) {
    return (
      <span className="inline-flex items-center gap-2 rounded-md border border-red-200 bg-red-50 px-2.5 py-1 text-xs font-semibold text-red-700">
        Backend support not available
      </span>
    )
  }
  if (!data) return null
  const showDemo = data.env === 'development' && data.demo_mode
  if (showDemo) {
    return (
      <span className="inline-flex items-center gap-2 rounded-md border border-amber-200 bg-amber-50 px-2.5 py-1 text-xs font-semibold text-amber-800">
        Demo mode · {data.collector_mode} collectors
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-2 rounded-md border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-semibold text-emerald-700">
      Real backend data
    </span>
  )
}

export function AppShell({
  userEmail, roles, children, onLogout,
}: {
  userEmail?: string
  roles?: string[]
  children: React.ReactNode
  onLogout: () => void
}) {
  const location = useLocation()
  const permissions = permissionsForRoles(roles ?? [])
  const visibleGroups = NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => !item.permission || permissions.has(item.permission)),
  })).filter((group) => group.items.length)
  const current = NAV_GROUPS.flatMap((g) => g.items).find((i) =>
    i.to === '/' ? location.pathname === '/' : location.pathname.startsWith(i.to),
  )

  return (
    <div className="min-h-screen bg-[#eef2f6] text-slate-950">
      <div className="grid min-h-screen grid-cols-1 lg:grid-cols-[272px_minmax(0,1fr)]">
        <aside className="hidden border-r border-slate-800 bg-slate-950 text-slate-200 lg:flex lg:flex-col">
          <div className="border-b border-slate-800 px-5 py-5">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-md bg-blue-600 text-sm font-bold text-white">AD</div>
              <div>
                <div className="text-sm font-semibold text-white">Account Discovery</div>
                <div className="text-xs text-slate-500">Privilege control console</div>
              </div>
            </div>
          </div>
          <nav className="flex-1 overflow-y-auto px-3 py-4">
            {visibleGroups.map((group) => (
              <div key={group.label} className="mb-5">
                <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">{group.label}</div>
                <div className="space-y-1">
                  {group.items.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={item.to === '/'}
                      className={({ isActive }) => cx(
                        'flex items-center justify-between rounded-md px-3 py-2.5 text-sm font-medium transition',
                        isActive ? 'bg-blue-600 text-white' : 'text-slate-300 hover:bg-slate-900 hover:text-white',
                      )}
                    >
                      <span>{item.label}</span>
                    </NavLink>
                  ))}
                </div>
              </div>
            ))}
          </nav>
          <div className="border-t border-slate-800 p-4">
            <div className="rounded-md bg-slate-900 p-3">
              <div className="text-[11px] uppercase tracking-wide text-slate-500">Signed in</div>
              <div className="mt-1 truncate text-xs font-medium text-slate-200">{userEmail ?? 'Operator'}</div>
              {roles?.length ? <div className="mt-1 truncate text-[11px] text-slate-500">{roles.join(', ')}</div> : null}
              <button className="mt-3 text-xs font-medium text-slate-400 transition hover:text-white" onClick={onLogout}>Sign out</button>
            </div>
          </div>
        </aside>

        <div className="min-w-0">
          <header className="sticky top-0 z-20 border-b border-slate-200 bg-white/95 backdrop-blur">
            <div className="flex h-14 items-center justify-between gap-4 px-4 lg:px-6">
              <div>
                <div className="text-xs font-medium text-slate-500">{current?.label ?? 'Workspace'}</div>
                <div className="text-sm font-semibold text-slate-950">Account Discovery &amp; Privilege Classification</div>
              </div>
              <div className="flex items-center gap-2">
                <DataSourcePill />
                <HealthPill />
              </div>
            </div>
          </header>
          <main className="min-w-0 px-4 py-5 lg:px-6">{children}</main>
        </div>
      </div>
    </div>
  )
}
