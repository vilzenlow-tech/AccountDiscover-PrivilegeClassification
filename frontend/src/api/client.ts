import axios, { type AxiosError } from 'axios'
import qs from 'qs'
import toast from 'react-hot-toast'
import { useAuthStore } from '@/lib/auth'

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? '/api/v1',
  timeout: 30_000,
  paramsSerializer: (params) => {
    return qs.stringify(params, { arrayFormat: 'repeat' })
  },
})

api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().accessToken
  if (token) config.headers.Authorization = `Bearer ${token}`
  // Log requests with tag_ids for debugging
  if (config.params?.tag_ids) {
    console.log('[API] GET with tag_ids:', config.params.tag_ids)
  }
  return config
})

api.interceptors.response.use(
  (res) => res,
  async (err: AxiosError) => {
    if (err.response?.status === 401) {
      // Try refresh once.
      const { refreshToken, setTokens, logout } = useAuthStore.getState()
      if (refreshToken && !err.config?.url?.includes('/auth/refresh')) {
        try {
          const r = await axios.post(`${api.defaults.baseURL}/auth/refresh`, { refresh_token: refreshToken })
          setTokens(r.data.access_token, r.data.refresh_token)
          if (err.config) {
            err.config.headers.Authorization = `Bearer ${r.data.access_token}`
            return api.request(err.config)
          }
        } catch {
          logout()
          window.location.href = '/login'
        }
      } else {
        logout()
        window.location.href = '/login'
      }
    } else if (err.response?.status === 403) {
      toast.error('You do not have permission to perform this action.')
    } else if (err.response?.status && err.response.status >= 500) {
      toast.error('Server error. Please try again.')
    }
    return Promise.reject(err)
  },
)
