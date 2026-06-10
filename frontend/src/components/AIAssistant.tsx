/**
 * AIAssistant — floating chat panel for the ADPCT product assistant.
 *
 * Renders a bottom-right bubble that expands into a slide-in chat panel.
 * Sends messages to POST /api/v1/assistant/chat and streams back replies.
 *
 * Context: the current page pathname is passed so the assistant can give
 * page-specific answers without the user having to explain where they are.
 */
import { useEffect, useRef, useState } from 'react'
import { useLocation } from 'react-router-dom'
import { chatAssistant } from '@/api/endpoints'
import type { ChatMessage } from '@/api/endpoints'
import { Spinner } from '@/components/Spinner'

// ── Icons (inline SVG — no dependency on icon library) ─────────────────────

function ChatIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
    </svg>
  )
}

function CloseIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4">
      <line x1="18" y1="6" x2="6" y2="18" />
      <line x1="6" y1="6" x2="18" y2="18" />
    </svg>
  )
}

function SendIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
      strokeLinecap="round" strokeLinejoin="round" className="w-4 h-4 rotate-90">
      <line x1="22" y1="2" x2="11" y2="13" />
      <polygon points="22 2 15 22 11 13 2 9 22 2" />
    </svg>
  )
}

function SparkleIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" className="w-3.5 h-3.5">
      <path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6z" />
    </svg>
  )
}

// ── Types ───────────────────────────────────────────────────────────────────

interface DisplayMessage {
  role: 'user' | 'assistant' | 'error'
  content: string
}

// ── Component ───────────────────────────────────────────────────────────────

export function AIAssistant() {
  const [open, setOpen] = useState(false)
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [messages, setMessages] = useState<DisplayMessage[]>([])
  // API history (only user + assistant turns — no error messages)
  const [apiHistory, setApiHistory] = useState<ChatMessage[]>([])

  const location = useLocation()
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Scroll to bottom whenever messages change
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  // Auto-focus input when panel opens
  useEffect(() => {
    if (open) textareaRef.current?.focus()
  }, [open])

  const handleSend = async () => {
    const text = input.trim()
    if (!text || loading) return

    const userMsg: DisplayMessage = { role: 'user', content: text }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setLoading(true)

    try {
      const res = await chatAssistant({
        message: text,
        history: apiHistory,
        context: {
          page_url: location.pathname,
        },
      })

      const reply = res.data.reply
      setMessages((prev) => [...prev, { role: 'assistant', content: reply }])
      // Keep the last 10 round-trips (20 turns) in history
      setApiHistory((prev) => [
        ...prev.slice(-18),
        { role: 'user', content: text },
        { role: 'assistant', content: reply },
      ])
    } catch (err: unknown) {
      const detail =
        (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
      const msg =
        detail === 'AI Assistant is not configured. Set ANTHROPIC_API_KEY to enable it.'
          ? 'The AI Assistant is not configured yet. Ask your administrator to set ANTHROPIC_API_KEY.'
          : detail ?? 'Something went wrong. Please try again.'
      setMessages((prev) => [...prev, { role: 'error', content: msg }])
    } finally {
      setLoading(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend()
    }
  }

  const handleClear = () => {
    setMessages([])
    setApiHistory([])
  }

  return (
    <>
      {/* ── Floating bubble ─────────────────────────────────────────────── */}
      {!open && (
        <button
          onClick={() => setOpen(true)}
          aria-label="Open AI Assistant"
          className={
            'fixed bottom-6 right-6 z-50 flex h-13 w-13 items-center justify-center ' +
            'rounded-full bg-brand-600 text-white shadow-lg transition-all ' +
            'hover:bg-brand-700 hover:shadow-xl active:scale-95 ' +
            'h-[52px] w-[52px]'
          }
        >
          <ChatIcon />
          <span
            className={
              'absolute -top-1 -right-1 flex h-4 w-4 items-center justify-center ' +
              'rounded-full bg-amber-400 text-[8px] font-bold text-amber-900'
            }
          >
            AI
          </span>
        </button>
      )}

      {/* ── Chat panel ──────────────────────────────────────────────────── */}
      {open && (
        <div
          className={
            'fixed bottom-6 right-6 z-50 flex flex-col overflow-hidden rounded-2xl ' +
            'bg-white shadow-2xl border border-slate-200 ' +
            'w-[380px] h-[560px]'
          }
        >
          {/* Header */}
          <div className="flex items-center justify-between bg-brand-600 px-4 py-3 text-white">
            <div className="flex items-center gap-2">
              <span className="flex h-7 w-7 items-center justify-center rounded-full bg-white/20">
                <SparkleIcon />
              </span>
              <div>
                <div className="text-sm font-semibold leading-none">ADPCT Assistant</div>
                <div className="mt-0.5 text-[10px] text-white/70">Tool-specific help only</div>
              </div>
            </div>
            <div className="flex items-center gap-1">
              {messages.length > 0 && (
                <button
                  onClick={handleClear}
                  className="rounded px-2 py-1 text-[10px] text-white/70 hover:bg-white/10 hover:text-white transition-colors"
                  aria-label="Clear conversation"
                >
                  Clear
                </button>
              )}
              <button
                onClick={() => setOpen(false)}
                aria-label="Close assistant"
                className="ml-1 flex h-7 w-7 items-center justify-center rounded-full text-white/70 hover:bg-white/20 hover:text-white transition-colors"
              >
                <CloseIcon />
              </button>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-slate-50">
            {messages.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full text-center gap-3 text-slate-400">
                <div className="flex h-12 w-12 items-center justify-center rounded-full bg-brand-50 text-brand-500">
                  <ChatIcon />
                </div>
                <div>
                  <p className="text-sm font-medium text-slate-500">Ask about this tool</p>
                  <p className="text-xs mt-1 leading-relaxed">
                    Privilege classes · Interactive logon status<br />
                    Scan jobs · Findings · Rules · Exports
                  </p>
                </div>
                <div className="mt-1 flex flex-wrap gap-1.5 justify-center">
                  {SUGGESTED_QUESTIONS.map((q) => (
                    <button
                      key={q}
                      onClick={() => { setInput(q); textareaRef.current?.focus() }}
                      className="rounded-full border border-slate-200 bg-white px-3 py-1 text-[11px] text-slate-600 hover:border-brand-100 hover:text-brand-600 transition-colors"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {messages.map((msg, i) => (
              <MessageBubble key={i} msg={msg} />
            ))}

            {loading && (
              <div className="flex gap-2 items-start">
                <AssistantAvatar />
                <div className="rounded-2xl rounded-tl-none bg-white border border-slate-200 px-3 py-2 shadow-sm">
                  <Spinner className="h-4 w-4 border-brand-500" />
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div className="border-t border-slate-200 bg-white px-3 py-3">
            <div className="flex items-end gap-2">
              <textarea
                ref={textareaRef}
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask about accounts, findings, logon status…"
                rows={1}
                className={
                  'flex-1 resize-none rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 ' +
                  'text-sm text-slate-800 placeholder:text-slate-400 ' +
                  'focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent ' +
                  'max-h-28 overflow-y-auto leading-relaxed'
                }
                style={{ fieldSizing: 'content' } as React.CSSProperties}
              />
              <button
                onClick={handleSend}
                disabled={!input.trim() || loading}
                aria-label="Send message"
                className={
                  'flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-xl transition-colors ' +
                  (input.trim() && !loading
                    ? 'bg-brand-600 text-white hover:bg-brand-700'
                    : 'bg-slate-100 text-slate-300 cursor-not-allowed')
                }
              >
                <SendIcon />
              </button>
            </div>
            <p className="mt-1.5 text-center text-[10px] text-slate-400">
              Press Enter to send · Shift+Enter for new line
            </p>
          </div>
        </div>
      )}
    </>
  )
}

// ── Sub-components ──────────────────────────────────────────────────────────

function AssistantAvatar() {
  return (
    <div className="flex-shrink-0 flex h-6 w-6 items-center justify-center rounded-full bg-brand-600 text-white mt-1">
      <SparkleIcon />
    </div>
  )
}

function MessageBubble({ msg }: { msg: DisplayMessage }) {
  if (msg.role === 'user') {
    return (
      <div className="flex justify-end">
        <div className="max-w-[85%] rounded-2xl rounded-tr-none bg-brand-600 px-3.5 py-2.5 text-sm text-white shadow-sm">
          <MessageText content={msg.content} />
        </div>
      </div>
    )
  }

  if (msg.role === 'error') {
    return (
      <div className="flex gap-2 items-start">
        <AssistantAvatar />
        <div className="max-w-[85%] rounded-2xl rounded-tl-none bg-red-50 border border-red-200 px-3.5 py-2.5 text-sm text-red-700 shadow-sm">
          <MessageText content={msg.content} />
        </div>
      </div>
    )
  }

  // assistant
  return (
    <div className="flex gap-2 items-start">
      <AssistantAvatar />
      <div className="max-w-[85%] rounded-2xl rounded-tl-none bg-white border border-slate-200 px-3.5 py-2.5 text-sm text-slate-800 shadow-sm">
        <MessageText content={msg.content} />
      </div>
    </div>
  )
}

/**
 * Renders assistant text with minimal formatting:
 * - Lines starting with "**text**:" become bold labels
 * - Bullet lines (•, -, *) become indented items
 * - Blank lines become paragraph breaks
 */
function MessageText({ content }: { content: string }) {
  const lines = content.split('\n')
  const elements: React.ReactNode[] = []
  let key = 0

  for (const line of lines) {
    const trimmed = line.trim()

    if (!trimmed) {
      elements.push(<div key={key++} className="h-2" />)
      continue
    }

    // Bold label pattern: **Foo:** or **Foo**
    const boldMatch = trimmed.match(/^\*\*(.+?)\*\*:?\s*(.*)$/)
    if (boldMatch) {
      elements.push(
        <p key={key++} className="leading-relaxed">
          <span className="font-semibold text-slate-900">{boldMatch[1]}:</span>
          {boldMatch[2] ? ' ' + boldMatch[2] : ''}
        </p>
      )
      continue
    }

    // Bullet / list item
    const bulletMatch = trimmed.match(/^[•\-\*]\s+(.+)$/)
    if (bulletMatch) {
      elements.push(
        <div key={key++} className="flex gap-1.5 leading-relaxed">
          <span className="mt-1.5 flex-shrink-0 h-1 w-1 rounded-full bg-slate-400" />
          <span>{bulletMatch[1]}</span>
        </div>
      )
      continue
    }

    // Numbered list
    const numberedMatch = trimmed.match(/^(\d+)\.\s+(.+)$/)
    if (numberedMatch) {
      elements.push(
        <div key={key++} className="flex gap-1.5 leading-relaxed">
          <span className="flex-shrink-0 text-slate-400 text-xs mt-0.5 w-4">{numberedMatch[1]}.</span>
          <span>{numberedMatch[2]}</span>
        </div>
      )
      continue
    }

    elements.push(<p key={key++} className="leading-relaxed">{trimmed}</p>)
  }

  return <div className="space-y-0.5 text-[13px]">{elements}</div>
}

// ── Suggested questions shown in empty state ────────────────────────────────

const SUGGESTED_QUESTIONS = [
  'What is full_admin?',
  'Why is an account unknown_review_required?',
  'What does interactive_capable mean?',
  'How do I read a risk score?',
]
