import { useMemo, useState } from 'react'
import type React from 'react'
import { NavLink, useLocation } from 'react-router-dom'

export type NavGroup = { label: string; items: Array<{ to: string; label: string }> }
export type DataRow = Record<string, string | number | boolean | null | undefined>
export type Tone = 'slate' | 'blue' | 'green' | 'amber' | 'red' | 'purple'

const toneClasses: Record<Tone, string> = {
  slate: 'bg-slate-100 text-slate-700 ring-slate-200',
  blue: 'bg-blue-50 text-blue-700 ring-blue-200',
  green: 'bg-emerald-50 text-emerald-700 ring-emerald-200',
  amber: 'bg-amber-50 text-amber-800 ring-amber-200',
  red: 'bg-red-50 text-red-700 ring-red-200',
  purple: 'bg-violet-50 text-violet-700 ring-violet-200',
}

export function EnterpriseShell({
  navGroups,
  userEmail,
  children,
  onLogout,
}: {
  navGroups: NavGroup[]
  userEmail?: string
  children: React.ReactNode
  onLogout: () => void
}) {
  const location = useLocation()
  const current = navGroups.flatMap((group) => group.items).find((item) => item.to === location.pathname)

  return (
    <div className="min-h-screen bg-[#eef2f6] text-slate-950">
      <div className="grid min-h-screen grid-cols-1 lg:grid-cols-[272px_minmax(0,1fr)]">
        <aside className="hidden border-r border-slate-800 bg-slate-950 text-slate-200 lg:flex lg:flex-col">
          <div className="border-b border-slate-800 px-5 py-5">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-md bg-blue-600 text-sm font-bold text-white shadow-sm shadow-blue-950/30">AD</div>
              <div>
                <div className="text-sm font-semibold text-white">Account Discovery</div>
                <div className="text-xs text-slate-500">Identity control console</div>
              </div>
            </div>
          </div>
          <nav className="flex-1 overflow-y-auto px-3 py-4">
            {navGroups.map((group) => (
              <div key={group.label} className="mb-5">
                <div className="px-3 pb-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-500">{group.label}</div>
                <div className="space-y-1">
                  {group.items.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      end={item.to === '/'}
                      className={({ isActive }) =>
                        `flex items-center justify-between rounded-md px-3 py-2.5 text-sm font-medium transition ${
                          isActive ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-300 hover:bg-slate-900 hover:text-white'
                        }`
                      }
                    >
                      <span>{item.label}</span>
                      {item.label.includes('Audit') || item.label.includes('Findings') ? <span className="h-1.5 w-1.5 rounded-full bg-amber-400" /> : null}
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
              <button className="mt-3 text-xs font-medium text-slate-400 transition hover:text-white" onClick={onLogout}>Sign out</button>
            </div>
          </div>
        </aside>

        <div className="min-w-0">
          <header className="sticky top-0 z-20 border-b border-slate-200 bg-white/95 backdrop-blur">
            <div className="flex h-14 items-center justify-between gap-4 px-4 lg:px-6">
              <div>
                <div className="text-xs font-medium text-slate-500">ITAC / {current?.label ?? 'Workspace'}</div>
                <div className="text-sm font-semibold text-slate-950">Identity and access control operations</div>
              </div>
              <div className="hidden items-center gap-2 md:flex">
                <HealthPill label="API" tone="green" />
                <HealthPill label="MongoDB" tone="green" />
                <HealthPill label="Redis" tone="green" />
              </div>
            </div>
          </header>
          <main className="min-w-0 px-4 py-5 lg:px-6">{children}</main>
        </div>
      </div>
    </div>
  )
}

export function PageFrame({
  eyebrow,
  title,
  subtitle,
  actions,
  children,
}: {
  eyebrow: string
  title: string
  subtitle: string
  actions?: React.ReactNode
  children: React.ReactNode
}) {
  return (
    <section className="space-y-5">
      <div className="flex flex-col justify-between gap-4 border-b border-slate-200 pb-5 lg:flex-row lg:items-end">
        <div>
          <div className="text-xs font-semibold uppercase tracking-[0.18em] text-blue-700">{eyebrow}</div>
          <h1 className="mt-2 text-2xl font-semibold tracking-tight text-slate-950 lg:text-3xl">{title}</h1>
          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">{subtitle}</p>
        </div>
        {actions ? <div className="flex flex-wrap gap-2">{actions}</div> : null}
      </div>
      {children}
    </section>
  )
}

export function DataPanel({ title, detail, children }: { title: string; detail?: string; children: React.ReactNode }) {
  return (
    <section className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-50/80 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-950">{title}</h2>
        {detail ? <p className="mt-1 text-xs text-slate-500">{detail}</p> : null}
      </div>
      {children}
    </section>
  )
}

export function MetricTile({ label, value, detail, tone = 'slate' }: { label: string; value: string | number; detail: string; tone?: Tone }) {
  const valueTone = { slate: 'text-slate-950', blue: 'text-blue-700', green: 'text-emerald-700', amber: 'text-amber-700', red: 'text-red-700', purple: 'text-violet-700' }[tone]
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</div>
          <div className={`mt-3 text-2xl font-semibold tracking-tight ${valueTone}`}>{value}</div>
        </div>
        <span className={`h-2.5 w-2.5 rounded-full ring-4 ${toneClasses[tone]}`} />
      </div>
      <div className="mt-3 text-xs leading-5 text-slate-500">{detail}</div>
    </div>
  )
}

export function StatusBadge({ value }: { value: string }) {
  return <Badge tone={toneForStatus(value)}>{value}</Badge>
}

export function Badge({ tone = 'slate', children }: { tone?: Tone | string; children: React.ReactNode }) {
  return <span className={`inline-flex whitespace-nowrap rounded-md px-2 py-1 text-xs font-semibold ring-1 ${toneClasses[(tone as Tone) in toneClasses ? tone as Tone : 'slate']}`}>{children}</span>
}

export function ActionButton({
  children,
  variant = 'secondary',
  disabled,
  onClick,
  type = 'button',
}: {
  children: React.ReactNode
  variant?: 'primary' | 'secondary' | 'destructive' | 'ghost'
  disabled?: boolean
  onClick?: () => void
  type?: 'button' | 'submit'
}) {
  const classes = {
    primary: 'border-blue-700 bg-blue-700 text-white hover:bg-blue-800',
    secondary: 'border-slate-300 bg-white text-slate-700 hover:bg-slate-50',
    destructive: 'border-red-700 bg-red-700 text-white hover:bg-red-800',
    ghost: 'border-transparent bg-transparent text-slate-600 hover:bg-slate-100',
  }[variant]
  return (
    <button type={type} disabled={disabled} onClick={onClick} className={`inline-flex h-9 items-center justify-center rounded-md border px-3 text-sm font-semibold transition disabled:cursor-not-allowed disabled:opacity-60 ${classes}`}>
      {children}
    </button>
  )
}

export function EnterpriseTable({ title, rows, searchable = true, empty = 'No records found.' }: { title: string; rows: DataRow[]; searchable?: boolean; empty?: string }) {
  const [query, setQuery] = useState('')
  const columns = Object.keys(rows[0] ?? {})
  const filteredRows = useMemo(() => {
    const needle = query.trim().toLowerCase()
    if (!needle) return rows
    return rows.filter((row) => columns.some((column) => String(row[column] ?? '').toLowerCase().includes(needle)))
  }, [columns, query, rows])

  return (
    <DataPanel title={title} detail={`${filteredRows.length} of ${rows.length} records`}>
      {searchable ? (
        <div className="flex flex-col gap-2 border-b border-slate-200 p-3 sm:flex-row sm:items-center sm:justify-between">
          <input
            className="h-9 w-full max-w-sm rounded-md border border-slate-300 px-3 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
            placeholder="Search table in browser"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </div>
      ) : null}
      {filteredRows.length === 0 ? <EmptyState title={rows.length === 0 ? empty : 'No matching records.'} detail="Adjust filters or refresh the source system." /> : (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-left">
            <thead className="bg-slate-50 text-[11px] uppercase tracking-[0.08em] text-slate-500">
              <tr>{columns.map((column) => <th key={column} className="border-b border-slate-200 px-4 py-3 font-semibold">{labelize(column)}</th>)}</tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {filteredRows.map((row, index) => (
                <tr key={index} className="bg-white text-sm hover:bg-slate-50">
                  {columns.map((column) => <td key={column} className="whitespace-nowrap px-4 py-3 text-slate-700">{formatValue(column, row[column])}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </DataPanel>
  )
}

export function AlertBox({ message, tone = 'red' }: { message: string; tone?: Tone }) {
  return <div className={`rounded-lg px-4 py-3 text-sm font-medium ring-1 ${toneClasses[tone]}`}>{message}</div>
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return <div className="p-8 text-center"><div className="text-sm font-semibold text-slate-800">{title}</div><div className="mt-1 text-sm text-slate-500">{detail}</div></div>
}

function HealthPill({ label, tone }: { label: string; tone: Tone }) {
  return <span className="inline-flex items-center gap-2 rounded-md border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-slate-600"><span className={`h-1.5 w-1.5 rounded-full ${tone === 'green' ? 'bg-emerald-500' : 'bg-amber-500'}`} />{label}</span>
}

function formatValue(column: string, value: DataRow[string]) {
  if (typeof value === 'boolean') return <StatusBadge value={value ? 'Enabled' : 'Disabled'} />
  if (value === null || value === undefined || value === '') return <span className="text-slate-400">—</span>
  if (['status', 'result', 'pam', 'discovery'].includes(column)) return <StatusBadge value={String(value)} />
  if (['severity', 'criticality', 'risk', 'privilege'].includes(column)) return <Badge tone={toneForStatus(String(value))}>{String(value)}</Badge>
  return <span>{String(value)}</span>
}

export function toneForStatus(value: string): Tone {
  const normalized = value.toLowerCase()
  if (/domain account/.test(normalized)) return 'purple'
  if (/local account/.test(normalized)) return 'blue'
  if (/database account|database native/.test(normalized)) return 'green'
  if (/(critical|failed|disabled|locked|expired|open|unmanaged|revoked)/.test(normalized)) return 'red'
  if (/(high|pending|queued|scheduled|review|dormant|warning|partial)/.test(normalized)) return 'amber'
  if (/(active|enabled|online|ready|success|completed|managed)/.test(normalized)) return 'green'
  if (/(privileged|scan|running|info)/.test(normalized)) return 'blue'
  return 'slate'
}

function labelize(value: string) {
  return value.replace(/_/g, ' ').replace(/([A-Z])/g, ' $1').replace(/^./, (letter) => letter.toUpperCase())
}
