import { useEffect } from 'react'
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { PageFrame, UnavailableState } from './components/ui'
import Dashboard from './pages/Dashboard'
import AssetsList from './pages/AssetsList'
import AssetDetail from './pages/assets/AssetDetail'
import AccountsList from './pages/accounts/AccountsList'
import AccountDetail from './pages/accounts/AccountDetail'
import ScansList from './pages/scans/ScansList'
import ScanWizard from './pages/scans/ScanWizard'
import ScanDetail from './pages/scans/ScanDetail'
import FindingsList from './pages/findings/FindingsList'
import PasswordPolicy from './pages/policy/PasswordPolicy'
import TagsAdmin from './pages/tags/TagsAdmin'
import ConnectorsAgents from './pages/connectors/ConnectorsAgents'
import AgentDetail from './pages/connectors/AgentDetail'
import Reports from './pages/reports/Reports'
import AuditLogs from './pages/audit/AuditLogs'
import Settings from './pages/settings/Settings'
import UserManagement from './pages/users/UserManagement'
import { ChangePasswordPage, LoginPage } from './pages/Auth'
import { fetchMe, logout, selectAuth } from './store/authSlice'
import { useAppDispatch, useAppSelector } from './store/hooks'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/change-password" element={<ChangePasswordPage />} />
        <Route path="/*" element={<ProtectedConsole />} />
      </Routes>
    </BrowserRouter>
  )
}

function ProtectedConsole() {
  const dispatch = useAppDispatch()
  const location = useLocation()
  const auth = useAppSelector(selectAuth)

  useEffect(() => {
    if (auth.accessToken && (!auth.user || !auth.user.id)) void dispatch(fetchMe())
  }, [auth.accessToken, auth.user, dispatch])

  if (!auth.accessToken) return <Navigate to="/login" replace state={{ from: location.pathname }} />
  if (auth.user?.mustChangePassword) return <Navigate to="/change-password" replace />

  return (
    <AppShell userEmail={auth.user?.email} roles={auth.user?.roles} onLogout={() => dispatch(logout())}>
      <ConsoleRoutes />
    </AppShell>
  )
}

function ConsoleRoutes() {
  return (
    <Routes>
      <Route index element={<Dashboard />} />
      <Route path="assets" element={<AssetsList />} />
      <Route path="assets/:id" element={<AssetDetail />} />
      <Route path="scans" element={<ScansList />} />
      <Route path="scans/new" element={<ScanWizard />} />
      <Route path="scans/:id" element={<ScanDetail />} />
      <Route path="accounts" element={<AccountsList />} />
      <Route path="accounts/:id" element={<AccountDetail />} />
      <Route path="findings" element={<FindingsList />} />
      <Route path="password-policy" element={<PasswordPolicy />} />
      <Route path="connectors" element={<ConnectorsAgents />} />
      <Route path="connectors/agents/:id" element={<AgentDetail />} />
      <Route path="tags" element={<TagsAdmin />} />
      <Route path="reports" element={<Reports />} />
      <Route path="audit" element={<AuditLogs />} />
      <Route path="users" element={<UserManagement />} />
      <Route path="settings" element={<Settings />} />
      <Route path="*" element={<Pending title="Not found" note="This route does not exist." />} />
    </Routes>
  )
}

function Pending({ title, note }: { title: string; note: string }) {
  return (
    <PageFrame eyebrow="Module" title={title} subtitle="This module is part of the staged frontend redesign.">
      <UnavailableState title={`${title} — pending redesign`} detail={note} />
    </PageFrame>
  )
}
