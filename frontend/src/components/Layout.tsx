import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuthStore } from '@/lib/auth'
import clsx from 'clsx'

const NAV = [
  { to: '/', label: 'Dashboard', icon: '▦' },
  { to: '/accounts', label: 'Accounts', icon: 'A' },
  { to: '/assets', label: 'Assets', icon: 'S' },
  { to: '/connectors', label: 'Connectors', icon: 'C' },
  { to: '/scans', label: 'Scans', icon: 'J' },
  { to: '/findings', label: 'Findings', icon: 'F' },
  { to: '/password-policy', label: 'Password Policy', icon: '🔑' },
  { to: '/rules', label: 'Rules', icon: 'R' },
  { to: '/exceptions', label: 'Exceptions', icon: 'E' },
  { to: '/tags', label: 'Tags', icon: '#' },
  { to: '/connector-agents', label: 'Agent Connectors', icon: '⇄' },
  { to: '/audit', label: 'Audit Log', icon: 'L' },
  { to: '/help', label: 'Help', icon: '?' },
]

export function Layout() {
  const { user, logout } = useAuthStore()
  const navigate = useNavigate()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <div className="flex h-screen overflow-hidden bg-slate-50">
      {/* Sidebar */}
      <aside className="w-56 flex-shrink-0 bg-slate-900 text-slate-200 flex flex-col">
        <div className="px-4 py-4 border-b border-slate-700">
          <div className="text-xs font-bold text-brand-400 tracking-wider uppercase">ADPCT</div>
          <div className="text-[10px] text-slate-500 mt-0.5">Account Discovery &amp; Privilege</div>
        </div>
        <nav className="flex-1 overflow-y-auto py-2">
          {NAV.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === '/'}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-2.5 px-4 py-2 text-sm transition-colors',
                  isActive
                    ? 'bg-brand-700 text-white'
                    : 'text-slate-300 hover:bg-slate-800 hover:text-white',
                )
              }
            >
              <span className="text-base leading-none w-5 text-center">{n.icon}</span>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="px-4 py-3 border-t border-slate-700 text-xs">
          <div className="text-slate-400 truncate">{user?.email}</div>
          <div className="text-slate-500 text-[10px]">{user?.roles.join(', ')}</div>
          <button onClick={handleLogout} className="mt-2 text-slate-400 hover:text-white transition-colors text-xs">
            Sign out
          </button>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  )
}
