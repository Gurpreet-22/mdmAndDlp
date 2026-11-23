import type {
  AdminRole,
  AssignDeviceRequest,
  AuditEntryResponse,
  AuthModeResponse,
  ChainVerificationResponse,
  CheckOfflineDevicesResponse,
  CreateEmployeeRequest,
  CreateEnrollmentTokenResponse,
  DeviceAssignment,
  DeviceCounts,
  DeviceDetail,
  DeviceListQuery,
  DeviceSummary,
  DeviceUsbPolicyView,
  DebPackageInfoResponse,
  DirectoryRefreshResponse,
  DirectorySearchResponse,
  Employee,
  EnrollmentTokenResponse,
  InstallerInfoResponse,
  MeResponse,
  OffboardingReviewResponse,
  PolicyDetail,
  PolicySummary,
  Problem,
  RegisterDeviceRequest,
  RegisterDeviceResponse,
  SetUsbPolicyRequest,
  TokenResponse,
  UpdateEmployeeRequest,
  UserResponse,
} from "./types";

/**
 * Typed client for the UbuntuGuard REST API.
 *
 * Plain JSON over HTTP via fetch. The types live in `./types.ts`, hand-written
 * and kept honest by `server/tests/test_dashboard_types_match_api.py`, which
 * compares them against the schema FastAPI derives from the Pydantic models.
 *
 * Two decisions that matter:
 *
 * The access token is held in a module variable, never in localStorage or a
 * readable cookie. localStorage survives reloads and is readable by any script
 * on the origin, so one XSS bug there leaks a token that keeps working for 15
 * minutes. In memory, a reload loses it and the refresh cookie silently gets a
 * new one, which is the behaviour we want anyway.
 *
 * A 401 triggers exactly ONE refresh-and-retry, and concurrent 401s share a
 * single refresh call. Without the sharing, a page that fires five requests at
 * once would send five refreshes; since refresh tokens are single use and
 * replaying one revokes the whole family, that would log the user out as a
 * punishment for loading a busy page.
 */

export type {
  AdminRole,
  AssignDeviceRequest,
  AuditEntryResponse,
  AuthModeResponse,
  ChainVerificationResponse,
  ChangePasswordRequest,
  ChangeRoleRequest,
  CheckOfflineDevicesResponse,
  CreateEmployeeRequest,
  CreateEnrollmentTokenResponse,
  CreateUserRequest,
  ResetPasswordRequest,
  DeviceAssignment,
  DeviceCounts,
  DeviceDetail,
  DeviceListQuery,
  DebPackageInfoResponse,
  DevicePlatform,
  DeviceSummary,
  DirectoryRefreshResponse,
  DirectorySearchResponse,
  DirectoryUserResponse,
  Employee,
  EnrollmentTokenResponse,
  FieldError,
  InstallerInfoResponse,
  MeResponse,
  OffboardingFlagResponse,
  OffboardingReviewResponse,
  Problem,
  RegisterDeviceRequest,
  RegisterDeviceResponse,
  TokenEmployeeSummary,
  TokenResponse,
  UpdateEmployeeRequest,
  UserResponse,
} from "./types";

/** An error carrying the server's RFC 9457 problem document. */
export class ApiError extends Error {
  readonly status: number;
  readonly problem: Problem | null;

  constructor(status: number, problem: Problem | null, fallback: string) {
    super(problem?.detail ?? problem?.title ?? fallback);
    this.name = "ApiError";
    this.status = status;
    this.problem = problem;
  }

  /** The stable machine-readable code. Branch on this, never on `detail`. */
  get code(): string {
    return this.problem?.code ?? `http_${this.status}`;
  }

  get fieldErrors(): { field: string; message: string }[] {
    return this.problem?.fields ?? [];
  }
}

let accessToken: string | null = null;
let refreshInFlight: Promise<boolean> | null = null;
let onSessionLost: (() => void) | null = null;

/** Called when the session cannot be recovered, so the UI can show the login page. */
export function setSessionLostHandler(handler: (() => void) | null): void {
  onSessionLost = handler;
}

async function parseProblem(response: Response): Promise<Problem | null> {
  try {
    const body = (await response.json()) as unknown;
    if (body && typeof body === "object" && "code" in body) {
      return body as Problem;
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Refresh the session. Concurrent callers share one in-flight attempt, because
 * refresh tokens are single use and a second concurrent attempt would present
 * an already-used token, which the server treats as theft and responds to by
 * revoking the whole family.
 */
async function refreshSession(): Promise<boolean> {
  if (refreshInFlight) return refreshInFlight;

  refreshInFlight = (async () => {
    try {
      const response = await fetch("/api/v1/auth/refresh", {
        method: "POST",
        credentials: "same-origin",
      });
      if (!response.ok) {
        accessToken = null;
        return false;
      }
      const body = (await response.json()) as TokenResponse;
      accessToken = body.access_token;
      return true;
    } catch {
      accessToken = null;
      return false;
    } finally {
      refreshInFlight = null;
    }
  })();

  return refreshInFlight;
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined | null>;
  /** Internal: prevents an endless refresh loop. */
  retrying?: boolean;
  /** Skip the bearer header, for login and refresh. */
  anonymous?: boolean;
}

function buildUrl(path: string, query?: RequestOptions["query"]): string {
  if (!query) return path;
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, String(value));
    }
  }
  const rendered = search.toString();
  return rendered ? `${path}?${rendered}` : path;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = {};
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  if (!options.anonymous && accessToken) headers["Authorization"] = `Bearer ${accessToken}`;

  const response = await fetch(buildUrl(path, options.query), {
    method: options.method ?? "GET",
    headers,
    // Same-origin so the httpOnly SameSite=Strict refresh cookie is sent. The
    // Vite dev server proxies /api for exactly this reason.
    credentials: "same-origin",
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });

  if (response.status === 401 && !options.retrying && !options.anonymous) {
    if (await refreshSession()) {
      return request<T>(path, { ...options, retrying: true });
    }
    onSessionLost?.();
  }

  if (!response.ok) {
    throw new ApiError(response.status, await parseProblem(response), response.statusText);
  }

  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get("content-type") ?? "";
  if (!contentType.includes("json")) return (await response.text()) as unknown as T;
  return (await response.json()) as T;
}

// --------------------------------------------------------------------------- //
// Endpoints
// --------------------------------------------------------------------------- //

export const api = {
  async login(email: string, password: string): Promise<MeResponse> {
    const token = await request<TokenResponse>("/api/v1/auth/login", {
      method: "POST",
      body: { email, password },
      anonymous: true,
    });
    accessToken = token.access_token;
    return request<MeResponse>("/api/v1/auth/me");
  },

  /**
   * Restore a session on page load using the refresh cookie alone.
   * The access token is gone after a reload by design; this is how the user
   * stays logged in without it ever being persisted anywhere readable.
   */
  async restoreSession(): Promise<MeResponse | null> {
    if (!(await refreshSession())) return null;
    try {
      return await request<MeResponse>("/api/v1/auth/me");
    } catch {
      return null;
    }
  },

  async logout(): Promise<void> {
    try {
      await request<void>("/api/v1/auth/logout", { method: "POST" });
    } finally {
      accessToken = null;
    }
  },

  /**
   * The current user, re-read.
   *
   * Reachable even by an account that owes a forced password change - it is
   * one of the two routes the server leaves open in that state, and is how the
   * dashboard discovers both that the change is required and that it has been
   * completed.
   */
  me: () => request<MeResponse>("/api/v1/auth/me"),

  /** Unauthenticated: the login page needs this before anyone has signed in. */
  authMode: () => request<AuthModeResponse>("/api/v1/auth/mode", { anonymous: true }),

  /**
   * Metadata for the agent installer. PUBLIC, and `anonymous` is load-bearing.
   *
   * The employee enrollment page is reached by someone with no UbuntuGuard
   * account. Sending a bearer header would be pointless, and leaving the
   * default behaviour in place would be worse than pointless: a 401 triggers
   * `refreshSession`, and a failed refresh calls `onSessionLost`, which would
   * bounce an employee to the admin login page they have no business seeing.
   */
  installerInfo: () =>
    request<InstallerInfoResponse>("/api/v1/installer", { anonymous: true }),

  /**
   * Metadata for the double-clickable `.deb`. PUBLIC, for the same reasons.
   *
   * Answers 503 when the server has published the script but not the package,
   * which is a normal deployment state rather than an error: the two artifacts
   * are built and published independently. The enrollment page treats a
   * failure here as "offer the script only" and not as a page-level error.
   */
  debInfo: () =>
    request<DebPackageInfoResponse>("/api/v1/installer/deb", { anonymous: true }),

  /**
   * Admin accounts, newest first. `search` is a substring of the address.
   *
   * The search argument is not a nicety: the response is capped at one page, so
   * on a deployment with more accounts than that, browsing alone cannot show
   * that a given address exists. `buildUrl` drops an empty value, so an unused
   * search box sends no parameter at all.
   */
  listUsers: (limit = 50, search?: string) =>
    request<UserResponse[]>("/api/v1/users", { query: { q: search, limit } }),

  /**
   * Create an admin account. `manage_users` only, so super_admin only.
   *
   * There is deliberately no public equivalent: an unauthenticated route that
   * creates a privileged account is a backdoor into the whole fleet, however
   * carefully it is guarded. See the note in server/src/ubuntuguard/cli.py.
   */
  createUser: (email: string, password: string, role: AdminRole) =>
    request<UserResponse>("/api/v1/users", {
      method: "POST",
      body: { email, password, role },
    }),

  disableUser: (userId: string) =>
    request<void>(`/api/v1/users/${encodeURIComponent(userId)}:disable`, { method: "POST" }),

  /**
   * Re-enable a disabled account, keeping its identity, role and password.
   *
   * The counterpart `disableUser` lacked. Until this existed, disabling was
   * one-way through the API and two super_admins disabling each other was an
   * unrecoverable lockout.
   */
  enableUser: (userId: string) =>
    request<void>(`/api/v1/users/${encodeURIComponent(userId)}:enable`, { method: "POST" }),

  /**
   * Change another account's role. Revokes that account's sessions, because a
   * live access token carries the role it was issued against.
   *
   * Refused for your own account, and for the last active super_admin.
   */
  changeUserRole: (userId: string, role: AdminRole) =>
    request<void>(`/api/v1/users/${encodeURIComponent(userId)}:role`, {
      method: "POST",
      body: { role },
    }),

  /**
   * Set a temporary password on another account.
   *
   * Returns nothing: the caller supplied the password, so echoing it back
   * would put a live credential in a response for no gain. The target is
   * signed out everywhere and must change the password before using the
   * console.
   */
  resetUserPassword: (userId: string, password: string) =>
    request<void>(`/api/v1/users/${encodeURIComponent(userId)}:reset-password`, {
      method: "POST",
      body: { password },
    }),

  /**
   * Change your own password. Requires the current one.
   *
   * An access token is not authority to replace a credential, so the current
   * password is verified server-side. The response is a fresh token pair which
   * is installed here, because the change revokes every existing session
   * including this one - without the swap, a user completing a *forced* change
   * would be signed out by the act of satisfying it.
   */
  async changeOwnPassword(currentPassword: string, newPassword: string): Promise<void> {
    const token = await request<TokenResponse>("/api/v1/auth/password", {
      method: "POST",
      body: { current_password: currentPassword, new_password: newPassword },
    });
    accessToken = token.access_token;
  },

  listDevices: (query: DeviceListQuery = {}) =>
    request<DeviceSummary[]>("/api/v1/devices", { query: query as RequestOptions["query"] }),

  /** Fleet totals. Counted server-side, so filters and paging cannot skew them. */
  deviceCounts: () => request<DeviceCounts>("/api/v1/devices:counts"),

  /**
   * Register an employee laptop before it has been enrolled.
   *
   * Creates the record and, by default, mints the single-use enrollment token
   * the agent will present. That token is in the response exactly once.
   */
  registerDevice: (body: RegisterDeviceRequest) =>
    request<RegisterDeviceResponse>("/api/v1/devices", { method: "POST", body }),

  getDevice: (deviceId: string) =>
    request<DeviceDetail>(`/api/v1/devices/${encodeURIComponent(deviceId)}`),

  revokeDevice: (deviceId: string, reason: string) =>
    request<void>(`/api/v1/devices/${encodeURIComponent(deviceId)}:revoke`, {
      method: "POST",
      body: { reason },
    }),

  listEnrollmentTokens: (limit = 50) =>
    request<EnrollmentTokenResponse[]>("/api/v1/enrollment-tokens", { query: { limit } }),

  /**
   * Mint a token, optionally for a named employee.
   *
   * Takes an object rather than positional arguments because there are now
   * four ways to describe the recipient and `create(null, 86400, null, …)` at
   * the call site says nothing about which is which.
   *
   * Send `employeeId` for somebody already on the Employees page, or
   * `employeeName` plus `employeeEmail` to match-or-create. Sending both is
   * refused by the server, so the caller must pick one.
   */
  createEnrollmentToken: (body: {
    label?: string | null;
    ttlSeconds: number;
    employeeId?: string | null;
    employeeName?: string | null;
    employeeEmail?: string | null;
    department?: string | null;
  }) =>
    request<CreateEnrollmentTokenResponse>("/api/v1/enrollment-tokens", {
      method: "POST",
      // Omitted rather than sent as null when absent: the request model is
      // `extra="forbid"` with a validator that rejects an employee id
      // alongside an email, and sending both keys - even with one null - is
      // clearer to read as "not provided" when it simply is not there.
      body: {
        label: body.label || null,
        ttl_seconds: body.ttlSeconds,
        ...(body.employeeId
          ? { employee_id: body.employeeId }
          : body.employeeEmail
            ? {
                employee_name: body.employeeName,
                employee_email: body.employeeEmail,
                department: body.department || null,
              }
            : {}),
      },
    }),

  /**
   * Search the Microsoft Entra ID directory.
   *
   * Only people who appear to still work here, unless `includeInactive`.
   * Returns `configured: false` rather than failing when no Entra credentials
   * are set, which the caller should treat as "offer manual entry".
   */
  searchDirectory: (query: string, limit = 25, includeInactive = false) =>
    request<DirectorySearchResponse>("/api/v1/employees/directory", {
      query: {
        q: query || undefined,
        limit,
        // Omitted when false so the common request has a stable URL and the
        // browser's own cache is not split in two by a redundant parameter.
        include_inactive: includeInactive ? true : undefined,
      },
    }),

  /**
   * Re-read the directory now instead of waiting for the server's cache to
   * expire. For a joiner who started this morning, or a leaver who did.
   */
  refreshDirectory: () =>
    request<DirectoryRefreshResponse>("/api/v1/employees/directory:refresh", {
      method: "POST",
    }),

  /**
   * Working devices still assigned to somebody the directory says has left.
   * Read-only: it reports, it does not revoke or unassign.
   */
  offboardingReview: () =>
    request<OffboardingReviewResponse>("/api/v1/employees/offboarding-review"),

  revokeEnrollmentToken: (tokenId: string) =>
    request<void>(`/api/v1/enrollment-tokens/${encodeURIComponent(tokenId)}:revoke`, {
      method: "POST",
    }),

  listAuditEntries: (afterSeq: number | null, limit = 50) =>
    request<AuditEntryResponse[]>("/api/v1/audit-logs", {
      query: { after_seq: afterSeq ?? undefined, limit },
    }),

  verifyAuditChain: () =>
    request<ChainVerificationResponse>("/api/v1/audit-logs:verify"),

  // --- Employees ---
  listEmployees: (params?: { q?: string; department?: string; status?: string }) =>
    request<Employee[]>("/api/v1/employees", {
      query: {
        q: params?.q || undefined,
        department: params?.department || undefined,
        status: params?.status || undefined,
      },
    }),

  getEmployee: (employeeId: string) =>
    request<Employee>(`/api/v1/employees/${encodeURIComponent(employeeId)}`),

  createEmployee: (body: CreateEmployeeRequest) =>
    request<Employee>("/api/v1/employees", { method: "POST", body }),

  updateEmployee: (employeeId: string, body: UpdateEmployeeRequest) =>
    request<Employee>(`/api/v1/employees/${encodeURIComponent(employeeId)}`, {
      method: "PATCH",
      body,
    }),

  deleteEmployee: (employeeId: string) =>
    request<void>(`/api/v1/employees/${encodeURIComponent(employeeId)}`, { method: "DELETE" }),

  // --- Device Assignments & History ---
  assignDevice: (deviceId: string, body: AssignDeviceRequest) =>
    request<DeviceAssignment>(`/api/v1/devices/${encodeURIComponent(deviceId)}:assign`, {
      method: "POST",
      body,
    }),

  unassignDevice: (deviceId: string) =>
    request<void>(`/api/v1/devices/${encodeURIComponent(deviceId)}:unassign`, {
      method: "POST",
    }),

  getDeviceAssignments: (deviceId: string) =>
    request<DeviceAssignment[]>(`/api/v1/devices/${encodeURIComponent(deviceId)}/assignments`),

  // --- Monitoring & Health: Offline Alerts ---
  checkOfflineDevices: (thresholdSeconds = 900) =>
    request<CheckOfflineDevicesResponse>("/api/v1/devices:check-offline", {
      method: "POST",
      body: { threshold_seconds: thresholdSeconds },
    }),

  // --- USB policy ---
  //
  // Two reads and one write. The write always creates a new version; there is
  // no edit endpoint, because a policy is immutable once signed and the
  // version is what lets an agent refuse a replayed older one.
  deviceUsbPolicy: (deviceId: string) =>
    request<DeviceUsbPolicyView>(
      `/api/v1/policies/device/${encodeURIComponent(deviceId)}`,
    ),

  listPolicies: (policyType?: string, limit = 50) =>
    request<PolicySummary[]>("/api/v1/policies", {
      query: { policy_type: policyType, limit },
    }),

  setUsbPolicy: (body: SetUsbPolicyRequest) =>
    request<PolicyDetail>("/api/v1/policies/usb-control", {
      method: "POST",
      body: body as unknown as Record<string, unknown>,
    }),
};
