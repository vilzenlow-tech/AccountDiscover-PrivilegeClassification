import type React from 'react'
// Re-export the existing design-system primitives so pages import from one place.
export {
  PageFrame, DataPanel, MetricTile, ActionButton, Badge, AlertBox, EmptyState, toneForStatus,
} from './EnterpriseDesign'
import { Badge, EmptyState, toneForStatus } from './EnterpriseDesign'
import type { Tone } from './EnterpriseDesign'

export function cx(...parts: Array<string | false | null | undefined>) {
  return parts.filter(Boolean).join(' ')
}

// ── Status badge with human labels for JobStatus and friends ──────────────────
const STATUS_LABELS: Record<string, string> = {
  success: 'Completed',
  partial_success: 'Partial success',
  auth_failed: 'Auth failed',
  timed_out: 'Timed out',
  never_logged_in: 'Never logged in',
}

export function StatusBadge({ value }: { value: string | null | undefined }) {
  if (!value) return <span className="text-slate-400">—</span>
  const label = STATUS_LABELS[value] ?? value.replace(/_/g, ' ')
  return <Badge tone={toneForStatus(value)}>{label}</Badge>
}

// ── Loading / error / empty / unavailable states ──────────────────────────────
export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-slate-500">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-blue-600" />
      {label ?? 'Loading…'}
    </div>
  )
}

export function LoadingPanel({ label }: { label?: string }) {
  return (
    <div className="rounded-lg border border-slate-200 bg-white p-8">
      <div className="space-y-3">
        <div className="h-4 w-1/3 animate-pulse rounded bg-slate-200" />
        <div className="h-3 w-2/3 animate-pulse rounded bg-slate-100" />
        <div className="h-3 w-1/2 animate-pulse rounded bg-slate-100" />
      </div>
      <div className="mt-4"><Spinner label={label} /></div>
    </div>
  )
}

export function ErrorState({ title = 'Backend support not available', detail, onRetry }: { title?: string; detail?: string; onRetry?: () => void }) {
  return (
    <div className="rounded-lg border border-red-200 bg-red-50 p-6 text-center">
      <div className="text-sm font-semibold text-red-800">{title}</div>
      {detail ? <div className="mt-1 text-sm text-red-700">{detail}</div> : null}
      {onRetry ? (
        <button onClick={onRetry} className="mt-3 rounded-md border border-red-300 bg-white px-3 py-1.5 text-sm font-semibold text-red-700 hover:bg-red-100">Retry</button>
      ) : null}
    </div>
  )
}

export function UnavailableState({ title, detail }: { title: string; detail?: string }) {
  return (
    <div className="rounded-lg border border-dashed border-slate-300 bg-slate-50 p-10 text-center">
      <div className="text-sm font-semibold text-slate-700">{title}</div>
      <div className="mt-1 text-sm text-slate-500">{detail ?? 'Backend support required for this module.'}</div>
    </div>
  )
}

// Resolve an RTK Query error into a readable message.
export function apiErrorMessage(error: unknown): string {
  if (!error) return 'Unknown error'
  const e = error as { status?: number | string; data?: { detail?: unknown; message?: unknown }; error?: string }
  const detail = e.data?.detail ?? e.data?.message
  if (typeof detail === 'string') return detail
  if (Array.isArray(detail)) return detail.map((d) => (typeof d === 'string' ? d : JSON.stringify(d))).join(', ')
  if (e.error) return e.error
  if (e.status) return `Request failed (${e.status})`
  return 'Request failed'
}

// ── Typed data table ──────────────────────────────────────────────────────────
export type Column<T> = {
  key: string
  header: string
  render?: (row: T) => React.ReactNode
  className?: string
}

export function DataTable<T>({
  columns, rows, getRowKey, onRowClick, empty = 'No records found.', minWidth = 760,
}: {
  columns: Column<T>[]
  rows: T[]
  getRowKey: (row: T) => string
  onRowClick?: (row: T) => void
  empty?: string
  minWidth?: number
}) {
  if (rows.length === 0) return <EmptyState title={empty} detail="Adjust filters or run a discovery scan to populate this view." />
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left" style={{ minWidth }}>
        <thead className="bg-slate-50 text-[11px] uppercase tracking-[0.08em] text-slate-500">
          <tr>{columns.map((c) => <th key={c.key} className={cx('border-b border-slate-200 px-4 py-3 font-semibold', c.className)}>{c.header}</th>)}</tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rows.map((row) => (
            <tr
              key={getRowKey(row)}
              onClick={onRowClick ? () => onRowClick(row) : undefined}
              className={cx('bg-white text-sm', onRowClick && 'cursor-pointer hover:bg-blue-50/50')}
            >
              {columns.map((c) => (
                <td key={c.key} className={cx('px-4 py-3 align-middle text-slate-700', c.className)}>
                  {c.render ? c.render(row) : '—'}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Wizard stepper ────────────────────────────────────────────────────────────
export function Stepper({ steps, current }: { steps: string[]; current: number }) {
  return (
    <ol className="flex flex-wrap gap-2">
      {steps.map((label, i) => {
        const state = i < current ? 'done' : i === current ? 'active' : 'todo'
        return (
          <li key={label} className={cx(
            'flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs font-semibold',
            state === 'active' && 'border-blue-600 bg-blue-50 text-blue-700',
            state === 'done' && 'border-emerald-200 bg-emerald-50 text-emerald-700',
            state === 'todo' && 'border-slate-200 bg-white text-slate-400',
          )}>
            <span className={cx(
              'flex h-5 w-5 items-center justify-center rounded-full text-[11px]',
              state === 'active' && 'bg-blue-600 text-white',
              state === 'done' && 'bg-emerald-600 text-white',
              state === 'todo' && 'bg-slate-200 text-slate-500',
            )}>{state === 'done' ? '✓' : i + 1}</span>
            {label}
          </li>
        )
      })}
    </ol>
  )
}

// ── Form controls ─────────────────────────────────────────────────────────────
export function Field({ label, hint, error, required, children }: { label: string; hint?: string; error?: string; required?: boolean; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-sm font-semibold text-slate-800">{label}{required ? <span className="text-red-600"> *</span> : null}</span>
      {hint ? <span className="mt-0.5 block text-xs text-slate-500">{hint}</span> : null}
      <div className="mt-2">{children}</div>
      {error ? <span className="mt-1 block text-xs font-medium text-red-600">{error}</span> : null}
    </label>
  )
}

export function TextInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={cx('h-9 w-full rounded-md border border-slate-300 px-3 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100', props.className)} />
}

export function TextArea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={cx('w-full rounded-md border border-slate-300 px-3 py-2 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100', props.className)} />
}

export type Option = { value: string; label: string; hint?: string; disabled?: boolean }

export function RadioCards({ value, options, onChange, columns = 2 }: { value: string | null; options: Option[]; onChange: (v: string) => void; columns?: number }) {
  return (
    <div className={cx('grid gap-2', columns === 3 ? 'sm:grid-cols-3' : columns === 1 ? 'grid-cols-1' : 'sm:grid-cols-2')}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          disabled={o.disabled}
          onClick={() => onChange(o.value)}
          className={cx(
            'rounded-lg border p-3 text-left transition disabled:cursor-not-allowed disabled:opacity-50',
            value === o.value ? 'border-blue-600 bg-blue-50 ring-1 ring-blue-200' : 'border-slate-200 bg-white hover:border-slate-300',
          )}
        >
          <div className="text-sm font-semibold text-slate-900">{o.label}</div>
          {o.hint ? <div className="mt-0.5 text-xs text-slate-500">{o.hint}</div> : null}
        </button>
      ))}
    </div>
  )
}

export function CheckChips({ values, options, onToggle }: { values: string[]; options: Option[]; onToggle: (v: string) => void }) {
  return (
    <div className="flex flex-wrap gap-2">
      {options.map((o) => {
        const active = values.includes(o.value)
        return (
          <button
            key={o.value}
            type="button"
            disabled={o.disabled}
            onClick={() => onToggle(o.value)}
            className={cx(
              'rounded-md border px-3 py-1.5 text-sm font-medium transition disabled:opacity-50',
              active ? 'border-blue-600 bg-blue-600 text-white' : 'border-slate-300 bg-white text-slate-700 hover:bg-slate-50',
            )}
          >
            {o.label}
          </button>
        )
      })}
    </div>
  )
}

export function NativeSelect({ value, options, onChange, placeholder }: { value: string; options: Option[]; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="h-9 w-full rounded-md border border-slate-300 bg-white px-2 text-sm outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100"
    >
      {placeholder ? <option value="">{placeholder}</option> : null}
      {options.map((o) => <option key={o.value} value={o.value} disabled={o.disabled}>{o.label}</option>)}
    </select>
  )
}

export function InlineAlert({ tone = 'amber', children }: { tone?: Tone; children: React.ReactNode }) {
  const tones: Record<string, string> = {
    amber: 'border-amber-200 bg-amber-50 text-amber-800',
    red: 'border-red-200 bg-red-50 text-red-700',
    blue: 'border-blue-200 bg-blue-50 text-blue-700',
    green: 'border-emerald-200 bg-emerald-50 text-emerald-700',
    slate: 'border-slate-200 bg-slate-50 text-slate-700',
    purple: 'border-violet-200 bg-violet-50 text-violet-700',
  }
  return <div className={cx('rounded-md border px-3 py-2 text-sm', tones[tone])}>{children}</div>
}
