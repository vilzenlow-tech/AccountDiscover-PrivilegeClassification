import { createAsyncThunk, createSlice } from '@reduxjs/toolkit'
import type { RootState } from './index'

const apiBaseUrl = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000/api/v1'
const tokenKey = 'adpct.auth'

type User = { id: string; email: string; fullName: string | null; roles: string[]; isActive: boolean; mustChangePassword: boolean }
type AuthState = { accessToken: string | null; refreshToken: string | null; user: User | null; status: 'idle' | 'loading' | 'ready' | 'failed'; error: string | null }
type ApiUser = {
  id: string
  email: string
  fullName?: string | null
  full_name?: string | null
  roles: string[]
  isActive?: boolean
  is_active?: boolean
  mustChangePassword?: boolean
  must_change_password?: boolean
}
type ApiToken = {
  accessToken?: string
  access_token?: string
  refreshToken?: string
  refresh_token?: string
  user?: ApiUser
  mustChangePassword?: boolean
  must_change_password?: boolean
}

const saved = readSavedAuth()
const initialState: AuthState = { accessToken: saved?.accessToken ?? null, refreshToken: saved?.refreshToken ?? null, user: saved?.user ?? null, status: saved ? 'ready' : 'idle', error: null }

async function authRequest<T>(path: string, init?: RequestInit, token?: string | null): Promise<T> {
  const response = await fetch(`${apiBaseUrl}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(init?.headers ?? {}) },
    ...init,
  })
  if (!response.ok) throw new Error(await errorMessage(response) || `API request failed with ${response.status}`)
  return response.json() as Promise<T>
}

async function errorMessage(response: Response) {
  try {
    const body = await response.json()
    if (Array.isArray(body.detail)) {
      return body.detail.map((item: { msg?: string }) => item.msg ?? JSON.stringify(item)).join(', ')
    }
    return Array.isArray(body.message) ? body.message.join(', ') : body.message ?? body.detail
  } catch {
    return response.statusText
  }
}

function mapUser(user: ApiUser): User {
  return {
    id: user.id,
    email: user.email,
    fullName: user.fullName ?? user.full_name ?? null,
    roles: user.roles,
    isActive: user.isActive ?? user.is_active ?? true,
    mustChangePassword: user.mustChangePassword ?? user.must_change_password ?? false,
  }
}

export const login = createAsyncThunk('auth/login', async (payload: { email: string; password: string }) => {
  const token = await authRequest<ApiToken>('/auth/login', { method: 'POST', body: JSON.stringify(payload) })
  const accessToken = token.accessToken ?? token.access_token ?? ''
  const refreshToken = token.refreshToken ?? token.refresh_token ?? ''
  return {
    accessToken,
    refreshToken,
    user: token.user ? mapUser(token.user) : { id: '', email: payload.email, fullName: null, roles: [], isActive: true, mustChangePassword: token.mustChangePassword ?? token.must_change_password ?? false },
  }
})

export const changePassword = createAsyncThunk('auth/changePassword', async (payload: { currentPassword: string; newPassword: string }, { getState }) => {
  const { auth } = getState() as RootState
  await authRequest<{ detail: string }>('/auth/change-password', {
    method: 'POST',
    body: JSON.stringify({
      current_password: payload.currentPassword,
      new_password: payload.newPassword,
    }),
  }, auth.accessToken)
  return {
    accessToken: auth.accessToken ?? '',
    refreshToken: auth.refreshToken ?? '',
    user: { ...auth.user!, mustChangePassword: false },
  }
})

export const fetchMe = createAsyncThunk('auth/me', async (_, { getState }) => {
  const { auth } = getState() as RootState
  return mapUser(await authRequest<ApiUser>('/auth/me', undefined, auth.accessToken))
})

const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
    logout(state) {
      state.accessToken = null
      state.refreshToken = null
      state.user = null
      state.status = 'idle'
      sessionStorage.removeItem(tokenKey)
    },
    tokensRefreshed(state, action: { payload: { accessToken: string; refreshToken: string } }) {
      state.accessToken = action.payload.accessToken
      state.refreshToken = action.payload.refreshToken
      persist(state)
    },
  },
  extraReducers: (builder) => {
    builder
      .addCase(login.pending, markLoading)
      .addCase(changePassword.pending, markLoading)
      .addCase(login.fulfilled, saveSession)
      .addCase(changePassword.fulfilled, saveSession)
      .addCase(fetchMe.fulfilled, (state, action) => {
        state.user = action.payload
        state.status = 'ready'
        persist(state)
      })
      .addCase(login.rejected, markFailed)
      .addCase(changePassword.rejected, markFailed)
      .addCase(fetchMe.rejected, (state) => {
        state.accessToken = null
        state.refreshToken = null
        state.user = null
        state.status = 'failed'
        sessionStorage.removeItem(tokenKey)
      })
  },
})

function markLoading(state: AuthState) {
  state.status = 'loading'
  state.error = null
}

function markFailed(state: AuthState, action: { error: { message?: string } }) {
  state.status = 'failed'
  state.error = action.error.message ?? 'Authentication failed'
}

function saveSession(state: AuthState, action: { payload: { accessToken: string; refreshToken: string; user: User } }) {
  state.accessToken = action.payload.accessToken
  state.refreshToken = action.payload.refreshToken
  state.user = action.payload.user
  state.status = 'ready'
  state.error = null
  persist(state)
}

function persist(state: AuthState) {
  sessionStorage.setItem(tokenKey, JSON.stringify({ accessToken: state.accessToken, refreshToken: state.refreshToken, user: state.user }))
}

function readSavedAuth(): Pick<AuthState, 'accessToken' | 'refreshToken' | 'user'> | null {
  try {
    return JSON.parse(sessionStorage.getItem(tokenKey) ?? 'null')
  } catch {
    return null
  }
}

export const { logout, tokensRefreshed } = authSlice.actions
export const selectAuth = (state: RootState) => state.auth
export default authSlice.reducer
