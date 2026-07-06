// Authenticated file download for server-side export endpoints (blob responses).
const baseUrl = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api/v1'

function token(): string | null {
  try {
    return (JSON.parse(sessionStorage.getItem('adpct.auth') ?? 'null') as { accessToken?: string } | null)?.accessToken ?? null
  } catch {
    return null
  }
}

export async function downloadServerFile(path: string, filename: string): Promise<void> {
  const res = await fetch(`${baseUrl}${path}`, {
    headers: token() ? { Authorization: `Bearer ${token()}` } : {},
  })
  if (!res.ok) throw new Error(`Export failed (${res.status})`)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  URL.revokeObjectURL(url)
}
