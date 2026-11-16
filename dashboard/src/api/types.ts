/**
 * Response and request shapes for the UbuntuGuard REST API.
 *
 * Hand-written on request, replacing generated types.
 *
 * THE RISK THIS INTRODUCES: nothing here is checked against the server. Rename
 * a field in a Pydantic model and this file keeps compiling while the dashboard
 * quietly reads `undefined`. Generated types broke the build instead.
 *
 * THE MITIGATION: `server/tests/test_dashboard_types_match_api.py` parses this
 * file and compares every interface against the live OpenAPI schema FastAPI
 * produces from the Pydantic models. A renamed, added or removed field fails
 * that test. It is weaker than generation - it checks field names, not types -
 * but it turns silent drift into a failing test.
 *
 * So: when you change a server model, update the matching interface here. The
 * test will tell you if you forget.
 *
 * Timestamps are RFC 3339 strings with an explicit Z, exactly as the server
 * sends them. They are deliberately NOT parsed into Date at this boundary: the
 * raw value is what gets displayed next to relative times, so an operator can
 * always see the precise instant.
 */

/** RFC 9457 problem document. Every error response has this shape. */
export interface Problem {
  type: string;
  title: string;
  status: number;
  /** Stable machine-readable code. Branch on this, never on `detail`. */
  code: string;
  detail?: string | null;
  request_id?: string | null;
  fields?: FieldError[] | null;
  retry_after?: number | null;
}

export interface FieldError {
  field: string;
  message: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
}

/**
 * How the server authenticates.
 *
 * `any_login` true means the server accepts any address and password and
 * creates the account on first sight - the development placeholder standing in
 * for Microsoft SSO. The login page uses it to say so, rather than collecting
 * credentials it knows are being discarded.
 */
export interface AuthModeResponse {
  any_login: boolean;
}

export interface MeResponse {
  user_id: string;
  email: string;
  role: string;
  /** Capabilities the role holds. Cosmetic: the server checks every call. */
  capabilities: string[];
  /**
   * True when an administrator reset this account's password.
   *
   * Also cosmetic. The server already refuses every capability-guarded route
   * with `password_change_required` while this is set, so this field is how the
   * UI learns to show the change-password screen rather than what stops the
   * user doing anything.
   */
  must_change_password: boolean;
}

/** The four roles the server accepts. Mirrors `Role` in security/rbac.py. */
export type AdminRole = "super_admin" | "it_admin" | "security_analyst" | "auditor";

export interface UserResponse {
  id: string;
  email: string;
  role: string;
  is_active: boolean;
  /** True when this account owes a password change after an admin reset. */
  must_change_password: boolean;
  created_at: string;
  /** Null until the account's first successful sign-in. */
  last_login_at: string | null;
}

/**
 * Body for POST /api/v1/users.
 *
 * The password is the account's FIRST password, set by the administrator and
 * handed to its owner. The server refuses anything under 12 characters.
 */
/** Body of `POST /users/{id}:role`. The target comes from the path. */
export interface ChangeRoleRequest {
  role: AdminRole;
}

/**
 * Body of `POST /users/{id}:reset-password`.
 *
 * The administrator supplies the temporary password, so the response carries
 * no credential at all — the caller already has the value it just sent.
 */
export interface ResetPasswordRequest {
  password: string;
}

/** Body of `POST /auth/password`. Changing your own password. */
export interface ChangePasswordRequest {
  current_password: string;
  new_password: string;
}

export interface CreateUserRequest {
  email: string;
  password: string;
  role: AdminRole;
}

export interface DeviceSummary {
  id: string;
  /** Null until the agent enrolls: only the device can report its hostname. */
  hostname: string | null;
  status: string;
  /** Computed by the server from last_heartbeat_at, never self-reported. */
  online: boolean;
  /** Derived server-side from enrolled_at, so the two cannot disagree. */
  enrolled: boolean;
  last_heartbeat_at: string | null;
  agent_version: string | null;
  os_id: string | null;
  os_version_id: string | null;
  kernel: string | null;
  /** Null means registered by an administrator but never enrolled. */
  enrolled_at: string | null;
  /** When an administrator added the record. Always present. */
  registered_at: string;
  clone_suspected: boolean;
  release_build: boolean | null;

  // Administrator-supplied, known before the device is ever seen.
  display_name: string | null;
  manufacturer: string | null;
  model: string | null;
  assigned_to_name: string | null;
  assigned_to_email: string | null;
  department: string | null;
  assigned_to_id: string | null;
  platform: string | null;
  asset_tag: string | null;
  /** Self-reported by the agent. Informational only, never used to authorise. */
  primary_adapter_ip: string | null;
}

/** Fleet totals counted across every row, not over the current page. */
export interface DeviceCounts {
  total: number;
  enrolled: number;
  unenrolled: number;
  revoked: number;
  clone_suspected: number;
}

/** Body for POST /api/v1/devices. Everything here is an admin's assertion. */
export interface RegisterDeviceRequest {
  display_name: string;
  platform: DevicePlatform;
  manufacturer?: string | null;
  model?: string | null;
  assigned_to_name?: string | null;
  assigned_to_email?: string | null;
  department?: string | null;
  assigned_to_id?: string | null;
  asset_tag?: string | null;
  issue_enrollment_token?: boolean;
  token_ttl_seconds?: number;
}

export interface RegisterDeviceResponse {
  device: DeviceDetail;
  /** Returned exactly once, and only if a token was requested. */
  enrollment_token: string | null;
  enrollment_token_id: string | null;
  enrollment_token_expires_at: string | null;
}

/**
 * Platforms the server will record.
 *
 * Only `linux` has an agent. The other two exist so an inventory can be honest
 * about what a company owns without implying anything manages it.
 */
export type DevicePlatform = "linux" | "macos" | "windows";

export interface DeviceDetail extends DeviceSummary {
  arch: string | null;
  cert_fingerprint: string | null;
  cert_not_after: string | null;
  last_inventory_at: string | null;
  revoked_at: string | null;
  revoke_reason: string | null;
  virtualization: string | null;
  cpu_model: string | null;
  cpu_cores: number | null;
  total_ram_bytes: number | null;
  disk_total_bytes: number | null;
  disk_free_bytes: number | null;
}

export interface EnrollmentTokenResponse {
  id: string;
  label: string | null;
  created_at: string;
  expires_at: string;
  consumed_at: string | null;
  revoked_at: string | null;
  consumed_by_device_id: string | null;
  status: "active" | "consumed" | "expired" | "revoked";
}

export interface CreateEnrollmentTokenResponse {
  id: string;
  /** Returned exactly once. Only the hash is stored server-side. */
  enrollment_token: string;
  expires_at: string;
  label: string | null;
}

export interface AuditEntryResponse {
  seq: number;
  occurred_at: string;
  action: string;
  actor_id: string | null;
  actor_role: string | null;
  target_type: string | null;
  target_id: string | null;
  request_id: string | null;
  detail: Record<string, unknown>;
  entry_hash: string;
}

export interface ChainVerificationResponse {
  ok: boolean;
  checked: number;
  broken_at_seq: number | null;
  reason: string | null;
}

/**
 * Metadata for the employee-facing agent installer. From a PUBLIC endpoint.
 *
 * `target_os_versions` and `validated_os_versions` are two different claims and
 * the enrollment page renders them as two. The first is the releases the agent
 * is written for; the second is the releases it has actually been run on, and
 * it is empty. Showing one combined "supported" list would be a compatibility
 * claim nobody has earned yet.
 */
export interface InstallerInfoResponse {
  agent_version: string;
  filename: string;
  /** Recomputed by the server from the file on every request. */
  sha256: string;
  size_bytes: number;
  built_at: string;
  /** The API URL baked into the installer, so an employee can confirm it. */
  server_url: string;
  minimum_python: string;
  supported_os_id: string;
  supported_arch: string[];
  target_os_versions: string[];
  validated_os_versions: string[];
}

/** Query parameters for GET /api/v1/devices. */
export interface DeviceListQuery {
  /** Matches label, hostname, assignee or asset tag. */
  q?: string | undefined;
  status?: string | undefined;
  os_version_id?: string | undefined;
  agent_version?: string | undefined;
  platform?: string | undefined;
  /** True for enrolled only, false for those still awaiting enrollment. */
  enrolled?: boolean | undefined;
  limit?: number | undefined;
}

export interface Employee {
  id: string;
  full_name: string;
  email: string;
  department: string | null;
  job_title: string | null;
  phone: string | null;
  status: "active" | "suspended" | "offboarded";
  assigned_device_count: number;
  created_at: string;
  updated_at: string;
}

export interface CreateEmployeeRequest {
  full_name: string;
  email: string;
  department?: string | null;
  job_title?: string | null;
  phone?: string | null;
}

export interface UpdateEmployeeRequest {
  full_name?: string | null;
  email?: string | null;
  department?: string | null;
  job_title?: string | null;
  phone?: string | null;
  status?: "active" | "suspended" | "offboarded" | null;
}

export interface AssignDeviceRequest {
  employee_id?: string | null;
  assigned_to_name: string;
  assigned_to_email?: string | null;
  department?: string | null;
  notes?: string | null;
}

export interface DeviceAssignment {
  id: string;
  device_id: string;
  employee_id: string | null;
  assigned_to_name: string;
  assigned_to_email: string | null;
  department: string | null;
  notes: string | null;
  assigned_at: string;
  unassigned_at: string | null;
  assigned_by: string | null;
  unassigned_by: string | null;
}

export interface CheckOfflineDevicesResponse {
  checked_count: number;
  flagged_offline_count: number;
  new_incidents_created: number;
  device_ids: string[];
}
