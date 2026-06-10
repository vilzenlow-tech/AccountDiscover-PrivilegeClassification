/**
 * TagBadge — renders a colored pill for a managed tag.
 *
 * The text color is automatically computed (dark or light) based on the
 * background color luminance so the label is always readable.
 */
import type { TagSummary } from '@/api/endpoints'

/** Returns true if white text should be used on the given hex background. */
function useWhiteText(hex: string): boolean {
  const h = hex.replace('#', '')
  const r = parseInt(h.slice(0, 2), 16)
  const g = parseInt(h.slice(2, 4), 16)
  const b = parseInt(h.slice(4, 6), 16)
  // Relative luminance (WCAG)
  const luminance = (0.299 * r + 0.587 * g + 0.114 * b) / 255
  return luminance < 0.55
}

interface TagBadgeProps {
  tag: Pick<TagSummary, 'tag_name' | 'color'>
  onRemove?: () => void
  size?: 'sm' | 'xs'
}

export function TagBadge({ tag, onRemove, size = 'sm' }: TagBadgeProps) {
  const white = useWhiteText(tag.color || '#6366f1')
  const textColor = white ? '#ffffff' : '#1e293b'
  const px = size === 'xs' ? 'px-1.5 py-0' : 'px-2 py-0.5'
  const fontSize = size === 'xs' ? 'text-[10px]' : 'text-[11px]'

  return (
    <span
      className={`inline-flex items-center gap-1 rounded-full font-medium leading-none ${px} ${fontSize}`}
      style={{ backgroundColor: tag.color || '#6366f1', color: textColor }}
    >
      {tag.tag_name}
      {onRemove && (
        <button
          onClick={(e) => { e.stopPropagation(); onRemove() }}
          className="leading-none opacity-70 hover:opacity-100 transition-opacity"
          aria-label={`Remove tag ${tag.tag_name}`}
          style={{ color: textColor }}
        >
          ×
        </button>
      )}
    </span>
  )
}
