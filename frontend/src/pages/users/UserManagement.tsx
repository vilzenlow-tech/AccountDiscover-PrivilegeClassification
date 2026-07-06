import { useState } from 'react'
import {
  useCreateUserMutation, useGetRolesQuery, useGetUsersQuery, useResetUserPasswordMutation,
  useUpdateUserMutation, useUpdateUserStatusMutation,
} from '../../api/apiSlice'
import type { ManagedUser, UserCreateRequest, UserUpdateRequest } from '../../api/types'
import { useCan } from '../../app/rbac'
import {
  ActionButton, DataPanel, DataTable, ErrorState, Field, InlineAlert, LoadingPanel,
  NativeSelect, PageFrame, StatusBadge, TextInput, apiErrorMessage, type Column,
} from '../../components/ui'

const emptyCreate: UserCreateRequest = {
  username: '',
  display_name: '',
  email: '',
  role: '',
  temporary_password: '',
  must_change_password: true,
  is_active: true,
}

export default function UserManagement() {
  const can = useCan()
  const allowed = can('user:manage')
  const usersQ = useGetUsersQuery({ limit: 200 }, { skip: !allowed })
  const rolesQ = useGetRolesQuery(undefined, { skip: !allowed })
  const [createUser, createState] = useCreateUserMutation()
  const [updateUser, updateState] = useUpdateUserMutation()
  const [updateStatus, statusState] = useUpdateUserStatusMutation()
  const [resetPassword, resetState] = useResetUserPasswordMutation()
  const [showCreate, setShowCreate] = useState(false)
  const [createForm, setCreateForm] = useState(emptyCreate)
  const [editForm, setEditForm] = useState<{ id: string; body: UserUpdateRequest } | null>(null)
  const [resetForm, setResetForm] = useState<{ id: string; password: string } | null>(null)
  const roles = rolesQ.data ?? []
  const roleOptions = roles.map((role) => ({ value: role.name, label: role.name.replace(/_/g, ' ') }))

  const columns: Column<ManagedUser>[] = [
    { key: 'user', header: 'User', render: (u) => <div><div className="font-medium text-slate-900">{u.username}</div><div className="text-xs text-slate-500">{u.email}</div></div> },
    { key: 'name', header: 'Display name', render: (u) => u.display_name ?? '—' },
    { key: 'role', header: 'Role', render: (u) => u.roles.join(', ') || '—' },
    { key: 'status', header: 'Status', render: (u) => <StatusBadge value={u.status} /> },
    { key: 'last', header: 'Last login', render: (u) => fmt(u.last_login_at) },
    { key: 'created', header: 'Created', render: (u) => fmt(u.created_at) },
    {
      key: 'actions',
      header: 'Actions',
      render: (u) => (
        <div className="flex flex-wrap gap-2" onClick={(e) => e.stopPropagation()}>
          <button className="text-xs font-semibold text-blue-700 hover:underline" onClick={() => setEditForm({ id: u.id, body: { username: u.username, display_name: u.display_name, email: u.email, role: u.roles[0] ?? '', must_change_password: u.must_change_password } })}>Edit</button>
          <button className="text-xs font-semibold text-slate-600 hover:underline" onClick={() => setResetForm({ id: u.id, password: '' })}>Reset password</button>
          <button className="text-xs font-semibold text-red-600 hover:underline" onClick={() => updateStatus({ id: u.id, is_active: u.status === 'disabled' })}>{u.status === 'disabled' ? 'Enable' : 'Disable'}</button>
        </div>
      ),
    },
  ]

  async function submitCreate() {
    await createUser(createForm).unwrap().then(() => {
      setCreateForm(emptyCreate)
      setShowCreate(false)
    }).catch(() => {})
  }

  async function submitEdit() {
    if (!editForm) return
    await updateUser(editForm).unwrap().then(() => setEditForm(null)).catch(() => {})
  }

  async function submitReset() {
    if (!resetForm) return
    await resetPassword({ id: resetForm.id, body: { temporary_password: resetForm.password, must_change_password: true } }).unwrap().then(() => setResetForm(null)).catch(() => {})
  }

  if (!allowed) {
    return (
      <PageFrame eyebrow="Administration" title="User Management" subtitle="Admin-only identity administration.">
        <InlineAlert tone="red">Access denied. User management requires the `user:manage` permission.</InlineAlert>
      </PageFrame>
    )
  }

  return (
    <PageFrame
      eyebrow="Administration"
      title="User Management"
      subtitle="Create users, assign roles, deactivate accounts, and reset passwords."
      actions={<ActionButton variant="primary" onClick={() => setShowCreate((value) => !value)}>{showCreate ? 'Close' : 'Add user'}</ActionButton>}
    >
      {showCreate && (
        <UserForm
          title="Add user"
          roles={roleOptions}
          value={createForm}
          onChange={(body) => setCreateForm(body as UserCreateRequest)}
          onSubmit={submitCreate}
          busy={createState.isLoading}
          error={createState.isError ? apiErrorMessage(createState.error) : null}
          create
        />
      )}

      {editForm && (
        <UserForm
          title="Edit user"
          roles={roleOptions}
          value={editForm.body}
          onChange={(body) => setEditForm({ ...editForm, body })}
          onSubmit={submitEdit}
          busy={updateState.isLoading}
          error={updateState.isError ? apiErrorMessage(updateState.error) : null}
          onCancel={() => setEditForm(null)}
        />
      )}

      {resetForm && (
        <DataPanel title="Reset password" detail="Temporary password is submitted once and not logged by the backend.">
          <div className="grid gap-3 p-4 md:grid-cols-[minmax(0,1fr)_auto_auto] md:items-end">
            <Field label="Temporary password" hint="Minimum 12 chars with upper, lower, digit, and symbol.">
              <TextInput type="password" value={resetForm.password} onChange={(e) => setResetForm({ ...resetForm, password: e.target.value })} />
            </Field>
            <ActionButton variant="primary" disabled={resetState.isLoading || resetForm.password.length < 12} onClick={submitReset}>{resetState.isLoading ? 'Resetting…' : 'Reset'}</ActionButton>
            <ActionButton variant="ghost" onClick={() => setResetForm(null)}>Cancel</ActionButton>
          </div>
          {resetState.isError && <div className="border-t border-slate-200 p-4"><InlineAlert tone="red">{apiErrorMessage(resetState.error)}</InlineAlert></div>}
        </DataPanel>
      )}

      {usersQ.isLoading || rolesQ.isLoading ? <LoadingPanel label="Loading users…" /> : usersQ.isError ? (
        <ErrorState detail={apiErrorMessage(usersQ.error)} onRetry={usersQ.refetch} />
      ) : (
        <DataPanel title="Users" detail={`${usersQ.data?.total ?? 0} account(s)`}>
          <DataTable columns={columns} rows={usersQ.data?.items ?? []} getRowKey={(u) => u.id} empty="No users found." minWidth={980} />
        </DataPanel>
      )}

      {statusState.isError && <InlineAlert tone="red">{apiErrorMessage(statusState.error)}</InlineAlert>}
    </PageFrame>
  )
}

function UserForm({
  title, roles, value, onChange, onSubmit, busy, error, create = false, onCancel,
}: {
  title: string
  roles: Array<{ value: string; label: string }>
  value: UserCreateRequest | UserUpdateRequest
  onChange: (value: UserCreateRequest | UserUpdateRequest) => void
  onSubmit: () => void
  busy: boolean
  error: string | null
  create?: boolean
  onCancel?: () => void
}) {
  return (
    <DataPanel title={title}>
      <div className="grid gap-3 p-4 md:grid-cols-2 xl:grid-cols-4">
        <Field label="Username" required><TextInput value={value.username ?? ''} onChange={(e) => onChange({ ...value, username: e.target.value })} /></Field>
        <Field label="Display name"><TextInput value={value.display_name ?? ''} onChange={(e) => onChange({ ...value, display_name: e.target.value })} /></Field>
        <Field label="Email" required><TextInput type="email" value={value.email ?? ''} onChange={(e) => onChange({ ...value, email: e.target.value })} /></Field>
        <Field label="Role" required><NativeSelect value={value.role ?? ''} options={roles} onChange={(role) => onChange({ ...value, role })} placeholder="Select role…" /></Field>
        {create && <Field label="Temporary password" required><TextInput type="password" value={(value as UserCreateRequest).temporary_password} onChange={(e) => onChange({ ...value, temporary_password: e.target.value })} /></Field>}
        <label className="flex items-center gap-2 pt-7 text-sm text-slate-700"><input type="checkbox" checked={value.must_change_password ?? true} onChange={(e) => onChange({ ...value, must_change_password: e.target.checked })} />Must change password</label>
        {create && <label className="flex items-center gap-2 pt-7 text-sm text-slate-700"><input type="checkbox" checked={(value as UserCreateRequest).is_active} onChange={(e) => onChange({ ...value, is_active: e.target.checked })} />Active</label>}
      </div>
      <div className="flex flex-wrap items-center gap-3 border-t border-slate-200 px-4 py-3">
        <ActionButton variant="primary" disabled={busy || !value.username || !value.email || !value.role} onClick={onSubmit}>{busy ? 'Saving…' : 'Save user'}</ActionButton>
        {onCancel && <ActionButton variant="ghost" onClick={onCancel}>Cancel</ActionButton>}
        {error && <InlineAlert tone="red">{error}</InlineAlert>}
      </div>
    </DataPanel>
  )
}

function fmt(value: string | null) {
  if (!value) return '—'
  return new Date(value).toLocaleString()
}
