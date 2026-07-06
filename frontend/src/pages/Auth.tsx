import { useEffect } from 'react'
import { Button, TextInput } from 'flowbite-react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { changePassword, fetchMe, login, logout, selectAuth } from '../store/authSlice'
import { useAppDispatch, useAppSelector } from '../store/hooks'

export function LoginPage() {
  const dispatch = useAppDispatch()
  const navigate = useNavigate()
  const location = useLocation()
  const auth = useAppSelector(selectAuth)

  useEffect(() => {
    if (auth.accessToken && auth.user?.mustChangePassword) navigate('/change-password', { replace: true })
    else if (auth.accessToken) navigate((location.state as { from?: string } | null)?.from ?? '/', { replace: true })
  }, [auth.accessToken, auth.user?.mustChangePassword, location.state, navigate])

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    await dispatch(login({ email: String(form.get('email') ?? ''), password: String(form.get('password') ?? '') }))
  }

  return (
    <AuthCard title="Sign in" subtitle="Use your operator account to access the discovery console.">
      <form onSubmit={submit} className="space-y-4">
        <TextInput name="email" type="email" placeholder="admin@local" required />
        <TextInput name="password" type="password" placeholder="Password" required />
        {auth.error ? <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800">{auth.error}</div> : null}
        <Button type="submit" color="dark" className="w-full" disabled={auth.status === 'loading'}>{auth.status === 'loading' ? 'Signing in…' : 'Sign in'}</Button>
        <p className="text-xs text-slate-500">Default first run: admin@local / ChangeMe!123</p>
      </form>
    </AuthCard>
  )
}

export function ChangePasswordPage() {
  const dispatch = useAppDispatch()
  const navigate = useNavigate()
  const auth = useAppSelector(selectAuth)

  useEffect(() => {
    async function validateSession() {
      if (!auth.accessToken) return
      const result = await dispatch(fetchMe())
      if (fetchMe.rejected.match(result)) {
        dispatch(logout())
        navigate('/login', { replace: true })
      }
    }
    void validateSession()
  }, [auth.accessToken, dispatch, navigate])

  if (!auth.accessToken) return <Navigate to="/login" replace />

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const result = await dispatch(changePassword({ currentPassword: String(form.get('currentPassword') ?? ''), newPassword: String(form.get('newPassword') ?? '') }))
    if (changePassword.fulfilled.match(result)) navigate('/', { replace: true })
    if (changePassword.rejected.match(result) && result.error.message?.toLowerCase().includes('token')) {
      dispatch(logout())
      navigate('/login', { replace: true })
    }
  }

  return (
    <AuthCard title="Change password" subtitle="The seeded administrator must set a stronger password before continuing.">
      <form onSubmit={submit} className="space-y-4">
        <TextInput name="currentPassword" type="password" placeholder="Current password" required />
        <TextInput name="newPassword" type="password" placeholder="New password, minimum 12 characters" minLength={12} required />
        {auth.error ? <div className="rounded border border-red-200 bg-red-50 p-3 text-sm text-red-800">{auth.error}</div> : null}
        <Button type="submit" color="dark" className="w-full" disabled={auth.status === 'loading'}>Update password</Button>
      </form>
    </AuthCard>
  )
}

function AuthCard({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-100 px-4">
      <div className="w-full max-w-md rounded border border-slate-200 bg-white p-6 shadow-sm">
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded bg-slate-950 text-xs font-semibold text-white">AD</div>
          <div>
            <h1 className="text-xl font-semibold text-slate-950">{title}</h1>
            <p className="text-sm text-slate-500">{subtitle}</p>
          </div>
        </div>
        {children}
      </div>
    </div>
  )
}
