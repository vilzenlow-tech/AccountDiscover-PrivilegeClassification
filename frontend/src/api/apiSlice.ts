import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react'
import type { BaseQueryFn, FetchArgs, FetchBaseQueryError } from '@reduxjs/toolkit/query/react'
import { tokensRefreshed, logout } from '../store/authSlice'
import type { RootState } from '../store'
import type {
  Account,
  AccountDetail,
  AppStatus,
  Asset,
  AssetGroup,
  AssetGroupRequest,
  AuditLogItem,
  BulkImportResult,
  Connector,
  ConnectorAgent,
  ConnectorAgentCreateRequest,
  ConnectorAgentHeartbeat,
  ConnectorAgentJob,
  ConnectorAgentLog,
  ConnectorAgentSettings,
  ConnectorAgentUpdateRequest,
  ConnectorCreateRequest,
  ConnectorUpdateRequest,
  AssetRequest,
  EnrollmentTokenRequest,
  EnrollmentTokenResponse,
  TokenRotateResponse,
  Credential,
  CredentialCreateRequest,
  CredentialUpdateRequest,
  TestConnectionResult,
  DashboardMetrics,
  Finding,
  ManagedRole,
  ManagedUser,
  Page,
  PasswordPolicy,
  PasswordPolicyFinding,
  PasswordPolicySummary,
  PolicyCompareResult,
  PolicyException,
  PolicyExceptionRequest,
  ReviewState,
  ScanJob,
  ScanLaunchRequest,
  ScanProfile,
  ScanProfileRequest,
  ScanTarget,
  ScheduledScan,
  ScheduledScanRequest,
  Tag,
  ResetPasswordRequest,
  UserCreateRequest,
  UserUpdateRequest,
} from './types'

const baseUrl = (import.meta.env.VITE_API_BASE_URL as string | undefined) ?? '/api/v1'

const rawBaseQuery = fetchBaseQuery({
  baseUrl,
  prepareHeaders: (headers, { getState }) => {
    const token = (getState() as RootState).auth.accessToken
    if (token) headers.set('Authorization', `Bearer ${token}`)
    return headers
  },
})

// Wrap base query to attempt a single token refresh on 401.
const baseQueryWithReauth: BaseQueryFn<string | FetchArgs, unknown, FetchBaseQueryError> = async (
  args,
  apiCtx,
  extraOptions,
) => {
  let result = await rawBaseQuery(args, apiCtx, extraOptions)
  if (result.error?.status === 401) {
    const refreshToken = (apiCtx.getState() as RootState).auth.refreshToken
    if (refreshToken) {
      const refresh = await rawBaseQuery(
        { url: '/auth/refresh', method: 'POST', body: { refresh_token: refreshToken } },
        apiCtx,
        extraOptions,
      )
      const data = refresh.data as
        | { access_token?: string; refresh_token?: string }
        | undefined
      if (data?.access_token) {
        apiCtx.dispatch(
          tokensRefreshed({ accessToken: data.access_token, refreshToken: data.refresh_token ?? refreshToken }),
        )
        result = await rawBaseQuery(args, apiCtx, extraOptions)
      } else {
        apiCtx.dispatch(logout())
      }
    } else {
      apiCtx.dispatch(logout())
    }
  }
  return result
}

export const api = createApi({
  reducerPath: 'api',
  baseQuery: baseQueryWithReauth,
  tagTypes: ['Scans', 'Scan', 'Assets', 'Accounts', 'Profiles', 'Tags', 'Connectors', 'Credentials', 'Dashboard', 'Findings', 'Policies', 'Users'],
  endpoints: (build) => ({
    getAppStatus: build.query<AppStatus, void>({
      query: () => '/status',
    }),

    getDashboardMetrics: build.query<DashboardMetrics, void>({
      query: () => '/dashboard/metrics',
      providesTags: ['Dashboard'],
    }),

    getUsers: build.query<Page<ManagedUser>, Record<string, unknown> | void>({
      query: (params) => ({ url: '/users', params: params ?? { limit: 100 } }),
      providesTags: ['Users'],
    }),

    getRoles: build.query<ManagedRole[], void>({
      query: () => '/roles',
      providesTags: ['Users'],
    }),

    getPermissions: build.query<string[], void>({
      query: () => '/permissions',
      providesTags: ['Users'],
    }),

    createUser: build.mutation<ManagedUser, UserCreateRequest>({
      query: (body) => ({ url: '/users', method: 'POST', body }),
      invalidatesTags: ['Users'],
    }),

    updateUser: build.mutation<ManagedUser, { id: string; body: UserUpdateRequest }>({
      query: ({ id, body }) => ({ url: `/users/${id}`, method: 'PATCH', body }),
      invalidatesTags: ['Users'],
    }),

    updateUserStatus: build.mutation<ManagedUser, { id: string; is_active: boolean }>({
      query: ({ id, is_active }) => ({ url: `/users/${id}/status`, method: 'PATCH', body: { is_active } }),
      invalidatesTags: ['Users'],
    }),

    resetUserPassword: build.mutation<unknown, { id: string; body: ResetPasswordRequest }>({
      query: ({ id, body }) => ({ url: `/users/${id}/reset-password`, method: 'POST', body }),
      invalidatesTags: ['Users'],
    }),

    getAssets: build.query<Page<Asset>, Record<string, unknown> | void>({
      query: (params) => ({ url: '/assets', params: params ?? { limit: 500 } }),
      providesTags: ['Assets'],
    }),

    getAsset: build.query<Asset, string>({
      query: (id) => `/assets/${id}`,
      providesTags: ['Assets'],
    }),

    createAsset: build.mutation<Asset, AssetRequest>({
      query: (body) => ({ url: '/assets', method: 'POST', body }),
      invalidatesTags: ['Assets', 'Dashboard'],
    }),

    updateAsset: build.mutation<Asset, { id: string; body: AssetRequest }>({
      query: ({ id, body }) => ({ url: `/assets/${id}`, method: 'PUT', body }),
      invalidatesTags: ['Assets', 'Dashboard'],
    }),

    importAssetsCsv: build.mutation<BulkImportResult, File>({
      query: (file) => {
        const body = new FormData()
        body.append('file', file)
        return { url: '/assets/import/csv', method: 'POST', body }
      },
      invalidatesTags: ['Assets', 'Dashboard'],
    }),

    getAssetGroups: build.query<AssetGroup[], void>({
      query: () => '/asset-groups',
      providesTags: ['Assets'],
    }),

    createAssetGroup: build.mutation<AssetGroup, AssetGroupRequest>({
      query: (body) => ({ url: '/asset-groups', method: 'POST', body }),
      invalidatesTags: ['Assets'],
    }),

    updateAssetGroup: build.mutation<AssetGroup, { id: string; body: AssetGroupRequest }>({
      query: ({ id, body }) => ({ url: `/asset-groups/${id}`, method: 'PUT', body }),
      invalidatesTags: ['Assets'],
    }),

    deleteAssetGroup: build.mutation<unknown, string>({
      query: (id) => ({ url: `/asset-groups/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Assets'],
    }),

    getScanProfiles: build.query<Page<ScanProfile>, void>({
      query: () => '/scan-profiles',
      providesTags: ['Profiles'],
    }),

    getConnectors: build.query<Page<Connector>, void>({
      query: () => ({ url: '/connectors', params: { limit: 1000 } }),
      providesTags: ['Connectors'],
    }),

    updateConnector: build.mutation<Connector, { id: string; body: ConnectorUpdateRequest }>({
      query: ({ id, body }) => ({ url: `/connectors/${id}`, method: 'PUT', body }),
      invalidatesTags: ['Connectors'],
    }),

    testConnection: build.mutation<TestConnectionResult, { asset_id: string; connector_id?: string; credential_id?: string }>({
      query: (body) => ({ url: '/connectors/test', method: 'POST', body }),
    }),

    createConnector: build.mutation<Connector, ConnectorCreateRequest>({
      query: (body) => ({ url: '/connectors', method: 'POST', body }),
      invalidatesTags: ['Connectors'],
    }),

    deleteConnector: build.mutation<unknown, string>({
      query: (id) => ({ url: `/connectors/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Connectors'],
    }),

    getCredentials: build.query<Page<Credential>, void>({
      query: () => ({ url: '/credentials', params: { limit: 1000 } }),
      providesTags: ['Credentials'],
    }),

    createCredential: build.mutation<Credential, CredentialCreateRequest>({
      query: (body) => ({ url: '/credentials', method: 'POST', body }),
      invalidatesTags: ['Credentials', 'Connectors'],
    }),

    updateCredential: build.mutation<Credential, { id: string; body: CredentialUpdateRequest }>({
      query: ({ id, body }) => ({ url: `/credentials/${id}`, method: 'PUT', body }),
      invalidatesTags: ['Credentials', 'Connectors'],
    }),

    getScans: build.query<Page<ScanJob>, Record<string, unknown> | void>({
      query: (params) => ({ url: '/scans', params: params ?? { limit: 100 } }),
      providesTags: ['Scans'],
    }),

    getScan: build.query<ScanJob, string>({
      query: (id) => `/scans/${id}`,
      providesTags: (_r, _e, id) => [{ type: 'Scan', id }],
    }),

    getScanTargets: build.query<ScanTarget[], string>({
      query: (id) => `/scans/${id}/targets`,
      providesTags: (_r, _e, id) => [{ type: 'Scan', id }],
    }),

    launchScan: build.mutation<ScanJob, ScanLaunchRequest>({
      query: (body) => ({ url: '/scans', method: 'POST', body }),
      invalidatesTags: ['Scans'],
    }),

    cancelScan: build.mutation<ScanJob, string>({
      query: (id) => ({ url: `/scans/${id}/cancel`, method: 'POST' }),
      invalidatesTags: (_r, _e, id) => ['Scans', { type: 'Scan', id }],
    }),

    retryFailedTargets: build.mutation<ScanJob, string>({
      query: (id) => ({ url: `/scans/${id}/retry-failed`, method: 'POST' }),
      invalidatesTags: (_r, _e, id) => ['Scans', { type: 'Scan', id }],
    }),

    getAccounts: build.query<Page<Account>, Record<string, unknown> | void>({
      query: (params) => ({ url: '/accounts', params: params ?? { limit: 200 } }),
      providesTags: ['Accounts'],
    }),

    getAccount: build.query<AccountDetail, string>({
      query: (id) => `/accounts/${id}`,
      providesTags: ['Accounts'],
    }),

    // ── Findings ──
    getFindings: build.query<Page<Finding>, Record<string, unknown> | void>({
      query: (params) => ({ url: '/findings', params: params ?? { limit: 200 } }),
      providesTags: ['Findings'],
    }),
    reviewFinding: build.mutation<unknown, { finding_id: string; state: ReviewState; comment?: string }>({
      query: (body) => ({ url: '/findings/review', method: 'POST', body }),
      invalidatesTags: ['Findings'],
    }),

    // ── Password policy ──
    getPolicySummary: build.query<PasswordPolicySummary, void>({
      query: () => '/password-policy/summary',
      providesTags: ['Policies'],
    }),
    getPolicies: build.query<Page<PasswordPolicy>, Record<string, unknown> | void>({
      query: (params) => ({ url: '/password-policy', params: params ?? { limit: 200 } }),
      providesTags: ['Policies'],
    }),
    getPolicyFindings: build.query<Page<PasswordPolicyFinding>, Record<string, unknown> | void>({
      query: (params) => ({ url: '/password-policy/findings', params: params ?? { limit: 200 } }),
      providesTags: ['Policies'],
    }),
    getPolicyExceptions: build.query<Page<PolicyException>, Record<string, unknown> | void>({
      query: (params) => ({ url: '/password-policy/exceptions', params: params ?? { limit: 200 } }),
      providesTags: ['Policies'],
    }),
    createPolicyException: build.mutation<PolicyException, PolicyExceptionRequest>({
      query: (body) => ({ url: '/password-policy/exceptions', method: 'POST', body }),
      invalidatesTags: ['Policies'],
    }),
    reviewPolicyFinding: build.mutation<unknown, { id: string; state: string; comment?: string }>({
      query: ({ id, state, comment }) => ({ url: `/password-policy/findings/${id}/review`, method: 'POST', body: { state, comment } }),
      invalidatesTags: ['Policies'],
    }),
    comparePolicies: build.mutation<PolicyCompareResult, string[]>({
      query: (asset_ids) => ({ url: '/password-policy/compare', method: 'POST', body: { asset_ids } }),
    }),

    // ── Tags ──
    getTags: build.query<Page<Tag>, Record<string, unknown> | void>({
      query: (params) => ({ url: '/tags', params: params ?? { limit: 200 } }),
      providesTags: ['Tags'],
    }),
    createTag: build.mutation<Tag, Partial<Tag>>({
      query: (body) => ({ url: '/tags', method: 'POST', body }),
      invalidatesTags: ['Tags'],
    }),
    updateTag: build.mutation<Tag, { id: string; body: Partial<Tag> }>({
      query: ({ id, body }) => ({ url: `/tags/${id}`, method: 'PUT', body }),
      invalidatesTags: ['Tags'],
    }),
    patchTagStatus: build.mutation<Tag, { id: string; status: 'active' | 'inactive' }>({
      query: ({ id, status }) => ({ url: `/tags/${id}/status`, method: 'PATCH', body: { status } }),
      invalidatesTags: ['Tags'],
    }),
    deleteTag: build.mutation<unknown, string>({
      query: (id) => ({ url: `/tags/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Tags'],
    }),
    bulkAssignTags: build.mutation<unknown, { asset_ids: string[]; tag_ids: string[] }>({
      query: (body) => ({ url: '/assets/tags/bulk-assign', method: 'POST', body }),
      invalidatesTags: ['Tags', 'Assets'],
    }),
    assignAssetTags: build.mutation<unknown, { assetId: string; tag_ids: string[] }>({
      query: ({ assetId, tag_ids }) => ({ url: `/assets/${assetId}/tags`, method: 'POST', body: { tag_ids } }),
      invalidatesTags: ['Tags', 'Assets'],
    }),
    removeAssetTags: build.mutation<unknown, { assetId: string; tag_ids: string[] }>({
      query: ({ assetId, tag_ids }) => ({ url: `/assets/${assetId}/tags`, method: 'DELETE', body: { tag_ids } }),
      invalidatesTags: ['Tags', 'Assets'],
    }),

    // ── Connectors / agents ──
    getConnectorAgents: build.query<Page<ConnectorAgent>, void>({
      query: () => ({ url: '/connector-agents', params: { limit: 200 } }),
      providesTags: ['Connectors'],
    }),

    createConnectorAgent: build.mutation<ConnectorAgent, ConnectorAgentCreateRequest>({
      query: (body) => ({ url: '/connector-agents', method: 'POST', body }),
      invalidatesTags: ['Connectors'],
    }),

    updateConnectorAgent: build.mutation<ConnectorAgent, { id: string; body: ConnectorAgentUpdateRequest }>({
      query: ({ id, body }) => ({ url: `/connector-agents/${id}`, method: 'PATCH', body }),
      invalidatesTags: ['Connectors'],
    }),

    agentAction: build.mutation<ConnectorAgent, { id: string; action: 'approve' | 'revoke' | 'enable' | 'disable' }>({
      query: ({ id, action }) => ({ url: `/connector-agents/${id}/${action}`, method: 'POST' }),
      invalidatesTags: ['Connectors'],
    }),
    getAgent: build.query<ConnectorAgent, string>({
      query: (id) => `/connector-agents/${id}`,
      providesTags: ['Connectors'],
    }),
    getAgentSettings: build.query<ConnectorAgentSettings, string>({
      query: (id) => `/connector-agents/${id}/settings`,
      providesTags: ['Connectors'],
    }),
    updateAgentSettings: build.mutation<ConnectorAgentSettings, { id: string; body: ConnectorAgentSettings }>({
      query: ({ id, body }) => ({ url: `/connector-agents/${id}/settings`, method: 'PUT', body }),
      invalidatesTags: ['Connectors'],
    }),
    rotateAgentToken: build.mutation<TokenRotateResponse, string>({
      query: (id) => ({ url: `/connector-agents/${id}/rotate-token`, method: 'POST' }),
      invalidatesTags: ['Connectors'],
    }),
    getAgentJobs: build.query<Page<ConnectorAgentJob>, string>({
      query: (id) => ({ url: `/connector-agents/${id}/jobs`, params: { limit: 50 } }),
      providesTags: ['Connectors'],
    }),
    getAgentHeartbeats: build.query<ConnectorAgentHeartbeat[], string>({
      query: (id) => ({ url: `/connector-agents/${id}/heartbeats`, params: { limit: 50 } }),
    }),
    getAgentLogs: build.query<ConnectorAgentLog[], string>({
      query: (id) => ({ url: `/connector-agents/${id}/logs`, params: { limit: 100 } }),
    }),
    createEnrollmentToken: build.mutation<EnrollmentTokenResponse, EnrollmentTokenRequest>({
      query: (body) => ({ url: '/connector-agents/enrollment-tokens', method: 'POST', body }),
      invalidatesTags: ['Connectors'],
    }),

    // ── Audit ──
    getAuditLog: build.query<Page<AuditLogItem>, Record<string, unknown> | void>({
      query: (params) => ({ url: '/audit', params: params ?? { limit: 200 } }),
    }),

    // ── Settings: scan profiles + schedules ──
    seedScanProfiles: build.mutation<{ created: string[]; message: string }, void>({
      query: () => ({ url: '/scan-profiles/seed-defaults', method: 'POST' }),
      invalidatesTags: ['Profiles'],
    }),
    createScanProfile: build.mutation<ScanProfile, ScanProfileRequest>({
      query: (body) => ({ url: '/scan-profiles', method: 'POST', body }),
      invalidatesTags: ['Profiles'],
    }),
    updateScanProfile: build.mutation<ScanProfile, { id: string; body: ScanProfileRequest }>({
      query: ({ id, body }) => ({ url: `/scan-profiles/${id}`, method: 'PUT', body }),
      invalidatesTags: ['Profiles'],
    }),
    deleteScanProfile: build.mutation<unknown, string>({
      query: (id) => ({ url: `/scan-profiles/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Profiles'],
    }),
    getSchedules: build.query<Page<ScheduledScan>, void>({
      query: () => ({ url: '/schedules', params: { limit: 200 } }),
      providesTags: ['Profiles'],
    }),
    createSchedule: build.mutation<ScheduledScan, ScheduledScanRequest>({
      query: (body) => ({ url: '/schedules', method: 'POST', body }),
      invalidatesTags: ['Profiles'],
    }),
    updateSchedule: build.mutation<ScheduledScan, { id: string; body: ScheduledScanRequest }>({
      query: ({ id, body }) => ({ url: `/schedules/${id}`, method: 'PUT', body }),
      invalidatesTags: ['Profiles'],
    }),
    deleteSchedule: build.mutation<unknown, string>({
      query: (id) => ({ url: `/schedules/${id}`, method: 'DELETE' }),
      invalidatesTags: ['Profiles'],
    }),
  }),
})

export const {
  useGetAppStatusQuery,
  useGetDashboardMetricsQuery,
  useGetUsersQuery,
  useGetRolesQuery,
  useGetPermissionsQuery,
  useCreateUserMutation,
  useUpdateUserMutation,
  useUpdateUserStatusMutation,
  useResetUserPasswordMutation,
  useGetAssetsQuery,
  useGetAssetQuery,
  useCreateAssetMutation,
  useUpdateAssetMutation,
  useImportAssetsCsvMutation,
  useGetAssetGroupsQuery,
  useCreateAssetGroupMutation,
  useUpdateAssetGroupMutation,
  useDeleteAssetGroupMutation,
  useGetAccountQuery,
  useGetScanProfilesQuery,
  useGetConnectorsQuery,
  useUpdateConnectorMutation,
  useTestConnectionMutation,
  useCreateConnectorMutation,
  useDeleteConnectorMutation,
  useGetCredentialsQuery,
  useCreateCredentialMutation,
  useUpdateCredentialMutation,
  useGetScansQuery,
  useGetScanQuery,
  useGetScanTargetsQuery,
  useLaunchScanMutation,
  useCancelScanMutation,
  useRetryFailedTargetsMutation,
  useGetAccountsQuery,
  useGetFindingsQuery,
  useReviewFindingMutation,
  useGetPolicySummaryQuery,
  useGetPoliciesQuery,
  useGetPolicyFindingsQuery,
  useGetPolicyExceptionsQuery,
  useCreatePolicyExceptionMutation,
  useReviewPolicyFindingMutation,
  useComparePoliciesMutation,
  useGetTagsQuery,
  useCreateTagMutation,
  useUpdateTagMutation,
  usePatchTagStatusMutation,
  useDeleteTagMutation,
  useBulkAssignTagsMutation,
  useAssignAssetTagsMutation,
  useRemoveAssetTagsMutation,
  useGetConnectorAgentsQuery,
  useCreateConnectorAgentMutation,
  useUpdateConnectorAgentMutation,
  useAgentActionMutation,
  useGetAgentQuery,
  useGetAgentSettingsQuery,
  useUpdateAgentSettingsMutation,
  useRotateAgentTokenMutation,
  useGetAgentJobsQuery,
  useGetAgentHeartbeatsQuery,
  useGetAgentLogsQuery,
  useCreateEnrollmentTokenMutation,
  useGetAuditLogQuery,
  useSeedScanProfilesMutation,
  useCreateScanProfileMutation,
  useUpdateScanProfileMutation,
  useDeleteScanProfileMutation,
  useGetSchedulesQuery,
  useCreateScheduleMutation,
  useUpdateScheduleMutation,
  useDeleteScheduleMutation,
} = api
