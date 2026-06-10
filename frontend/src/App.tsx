import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from '@/lib/auth'
import { Layout } from '@/components/Layout'
import { AIAssistant } from '@/components/AIAssistant'
import Login from '@/pages/Login'
import Dashboard from '@/pages/Dashboard'
import Accounts from '@/pages/Accounts'
import AccountDetail from '@/pages/AccountDetail'
import Assets from '@/pages/Assets'
import AssetDetail from '@/pages/AssetDetail'
import Connectors from '@/pages/Connectors'
import Scans from '@/pages/Scans'
import Findings from '@/pages/Findings'
import Rules from '@/pages/Rules'
import Exceptions from '@/pages/Exceptions'
import AuditLog from '@/pages/AuditLog'
import Tags from '@/pages/Tags'
import ConnectorAgents from '@/pages/ConnectorAgents'
import ConnectorAgentDetail from '@/pages/ConnectorAgentDetail'
import PasswordPolicies from '@/pages/PasswordPolicies'
import Help from '@/pages/Help'

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { accessToken } = useAuthStore()
  if (!accessToken) return <Navigate to="/login" replace />
  return (
    <>
      {children}
      <AIAssistant />
    </>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="accounts" element={<Accounts />} />
          <Route path="accounts/:id" element={<AccountDetail />} />
          <Route path="assets" element={<Assets />} />
          <Route path="assets/:id" element={<AssetDetail />} />
          <Route path="connectors" element={<Connectors />} />
          <Route path="scans" element={<Scans />} />
          <Route path="findings" element={<Findings />} />
          <Route path="rules" element={<Rules />} />
          <Route path="exceptions" element={<Exceptions />} />
          <Route path="tags" element={<Tags />} />
          <Route path="connector-agents" element={<ConnectorAgents />} />
          <Route path="connector-agents/:id" element={<ConnectorAgentDetail />} />
          <Route path="password-policy" element={<PasswordPolicies />} />
          <Route path="audit" element={<AuditLog />} />
          <Route path="help" element={<Help />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  )
}
