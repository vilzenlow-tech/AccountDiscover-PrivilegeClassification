import clsx from 'clsx'

interface Props {
  label: string
  value: number | string
  sub?: string
  color?: 'red' | 'orange' | 'amber' | 'blue' | 'green' | 'slate' | 'purple' | 'pink'
  className?: string
  onClick?: () => void
}

const COLORS = {
  red:    'border-red-300 bg-red-50',
  orange: 'border-orange-300 bg-orange-50',
  amber:  'border-amber-300 bg-amber-50',
  blue:   'border-blue-300 bg-blue-50',
  green:  'border-green-300 bg-green-50',
  slate:  'border-slate-200 bg-white',
  purple: 'border-purple-300 bg-purple-50',
  pink:   'border-pink-300 bg-pink-50',
}

const VALUE_COLORS = {
  red:    'text-red-700',
  orange: 'text-orange-700',
  amber:  'text-amber-700',
  blue:   'text-blue-700',
  green:  'text-green-700',
  slate:  'text-slate-900',
  purple: 'text-purple-700',
  pink:   'text-pink-700',
}

export function StatCard({ label, value, sub, color = 'slate', className, onClick }: Props) {
  return (
    <div
      className={clsx('card border px-4 py-3', COLORS[color], className, onClick && 'cursor-pointer hover:shadow-md transition-shadow')}
      onClick={onClick}
    >
      <div className="text-xs text-slate-500 font-medium">{label}</div>
      <div className={clsx('text-2xl font-bold mt-1', VALUE_COLORS[color])}>{value}</div>
      {sub && <div className="text-xs text-slate-400 mt-0.5">{sub}</div>}
    </div>
  )
}
