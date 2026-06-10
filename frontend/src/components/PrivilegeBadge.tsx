import { PRIVILEGE_COLORS, PRIVILEGE_LABELS } from '@/lib/privilege'
import type { PrivilegeClass } from '@/api/endpoints'
import clsx from 'clsx'

interface Props { classification: PrivilegeClass; size?: 'sm' | 'md' }

export function PrivilegeBadge({ classification, size = 'md' }: Props) {
  const c = PRIVILEGE_COLORS[classification]
  const label = PRIVILEGE_LABELS[classification]
  return (
    <span
      className={clsx(
        'badge border',
        c.bg, c.text, c.border,
        size === 'sm' && 'text-[10px] px-1.5 py-0.5',
      )}
    >
      {label}
    </span>
  )
}
