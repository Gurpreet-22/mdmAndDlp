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

/**
 * Who a token was issued for. Read from the employee record when the response
 * is built, so a corrected name shows up here rather than being frozen onto
 * the token at the moment it was minted.
 */
export interface TokenEmployeeSummary {
  id: string;
  full_name: string;
  email: string;
  department: string | null;
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
  /** Null for a token minted without an employee; that device enrols unassigned. */
  employee: TokenEmployeeSummary | null;
}

export interface CreateEnrollmentTokenResponse {
  id: string;
  /** Returned exactly once. Only the hash is stored server-side. */
  enrollment_token: string;
  expires_at: string;
  label: string | null;
  employee: TokenEmployeeSummary | null;
}

/** One person from Microsoft Entra ID, as offered in the employee picker. */
export interface DirectoryUserResponse {
  /** The Entra object id. Stable across renames. */
  external_id: string;
  full_name: string;
  email: string;
  department: string | null;
  job_title: string | null;
  /** Set when this address already matches an employee record. */
  employee_id: string | null;
  /**
   * Whether this person still appears to work here, inferred from holding a
   * paid licence. A proxy, not a fact: somebody can leave and keep a licence.
   */
  active: boolean;
}

export interface DirectorySearchResponse {
  /** False when no Entra credentials are set; the form falls back to manual entry. */
  configured: boolean;
  users: DirectoryUserResponse[];
  /** True when more people matched than were returned. */
  truncated: boolean;
  /** People who appear to still work here. */
  active_count: number;
  /** Everybody in the directory. The gap to active_count is what the filter hides. */
  total_count: number;
  included_inactive: boolean;
}

export interface DirectoryRefreshResponse {
  active_count: number;
  total_count: number;
}

/** A working device still assigned to somebody who appears to have left. */
export interface OffboardingFlagResponse {
  device_id: string;
  hostname: string | null;
  status: string;
  assigned_to_name: string | null;
  assigned_to_email: string;
  last_heartbeat_at: string | null;
  /**
   * no_licence: in Entra ID with no licence, which usually means offboarded.
   * not_in_directory: not in Entra ID at all, so typed in by hand or deleted.
   */
  reason: "no_licence" | "not_in_directory";
}

export interface OffboardingReviewResponse {
  configured: boolean;
  /**
   * Assigned, non-revoked devices examined. Reported so an empty `flagged`
   * cannot be read as "we did not look".
   */
  checked: number;
  flagged: OffboardingFlagResponse[];
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

/**
 * Metadata for the double-clickable `.deb`. From a PUBLIC endpoint.
 *
 * A second artifact beside the shell installer, not a replacement. The script
 * installs and prompts for a token in one command, which suits someone already
 * in a terminal; the `.deb` is what a browser and GNOME Software can open.
 *
 * `enrols_on_install` is always false and is rendered rather than assumed. The
 * package installs the agent and stops there; a desktop application does the
 * enrollment afterwards, with a token the employee types. The page has to say
 * so, because an employee who installs and then sees nothing happen would
 * otherwise reasonably conclude it had failed.
 */
export interface DebPackageInfoResponse {
  package: string;
  agent_version: string;
  /** The agent version plus a packaging revision, e.g. `0.1.0-1`. */
  deb_version: string;
  architecture: string;
  filename: string;
  /** Recomputed by the server from the file on every request. */
  sha256: string;
  size_bytes: number;
  installed_size_kib: number;
  built_at: string;
  /** The API URL baked into the package, so an employee can confirm it. */
  server_url: string;
  /** Debian dependencies apt resolves on install, usbguard among them. */
  depends: string[];
  /** Wheels carried inside the package, so the install needs no PyPI access. */
  bundled_wheels: string[];
  target_pythons: string[];
  /** Always false. Installing does not enrol; the desktop app does. */
  enrols_on_install: boolean;
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


// --- USB policy ------------------------------------------------------------
//
// `UsbPolicyMode` is the one choice an administrator actually makes. The three
// values are not a progression of strictness so much as three different
// postures, and the dashboard should describe them rather than rank them:
//
//   monitor_only       nothing is blocked. The safe first step on a fleet
//                      whose allowlist nobody has built yet.
//   allowlist_enforce  the protected classes are blocked except for approved
//                      devices.
//   block_all_storage  the allowlist is ignored on purpose. Unexpired
//                      exceptions still apply.
export type UsbPolicyMode = "monitor_only" | "allowlist_enforce" | "block_all_storage";

export type UsbProtectedClass = "mass_storage" | "image";

export type UsbAlwaysAllowClass =
  | "hid"
  | "hub"
  | "audio"
  | "video"
  | "printer"
  | "network"
  | "smartcard"
  | "wireless"
  | "billboard"
  | "cdc"
  | "physical"
  | "vendor_specific";

/** Matches `deviceMatch` in policy.usb_control.v1.schema.json. */
export interface UsbDeviceMatch {
  vendor_id: string;
  product_id: string;
  serial?: string | null;
  serial_match: "exact" | "any";
}

export interface UsbAllowlistEntry {
  entry_id: string;
  match: UsbDeviceMatch;
  label: string;
  added_by: string;
  added_at: string;
}

export interface UsbException {
  exception_id: string;
  match: UsbDeviceMatch;
  reason: string;
  created_by: string;
  created_at: string;
  expires_at: string;
}

/** The decoded policy payload, for display. */
export interface UsbControlPayload {
  schema: string;
  mode: UsbPolicyMode;
  protected_classes: UsbProtectedClass[];
  always_allow_classes: UsbAlwaysAllowClass[];
  allowlist: UsbAllowlistEntry[];
  exceptions: UsbException[];
  reporting: {
    report_allowed: boolean;
    report_blocked: boolean;
    report_present_at_start: boolean;
  };
  enforcement?: { apply_to_present_devices?: boolean };
}

export interface PolicySummary {
  policy_id: string;
  policy_type: string;
  version: number;
  scope_kind: string;
  scope_id: string;
  signing_key_id: string;
  payload_sha256: string;
  issued_at: string;
  expires_at: string | null;
  summary: string;
  created_at: string;
}

export interface PolicyDetail extends PolicySummary {
  payload: UsbControlPayload;
}

/**
 * What the device reported back.
 *
 * `verified_state` is the agent's readback from the operating system, not what
 * it set out to do. A status of `applied` without it would be a claim; with it
 * the dashboard can show which rules usbguard actually loaded.
 */
export interface DevicePolicyStatus {
  policy_id: string;
  policy_type: string;
  policy_version: number;
  status: "pending" | "applied" | "failed" | "unsupported" | "rolled_back";
  reason_code: string | null;
  detail: string | null;
  reported_at: string;
  verified_state: {
    rules_fingerprint?: string | null;
    loaded_rule_count?: number;
    loaded_rules?: string[];
    daemon_params?: Record<string, string>;
    daemon_active?: boolean;
    daemon_conf_readable?: boolean;
    /** Non-empty means a non-root user on that host can switch policy off. */
    ipc_exposure?: string[];
    /** null, not false, when the daemon config could not be read. */
    enforcement_bypassable_without_root?: boolean | null;
    foreign_rules?: string[];
  } | null;
}

export interface DeviceUsbPolicyView {
  policy: PolicyDetail | null;
  status: DevicePolicyStatus | null;
}

export interface SetUsbPolicyRequest {
  mode: UsbPolicyMode;
  scope_kind?: "device" | "fleet";
  device_id?: string | null;
  protected_classes?: UsbProtectedClass[] | null;
  always_allow_classes?: UsbAlwaysAllowClass[] | null;
  allowlist?: { match: UsbDeviceMatch; label: string }[];
  exceptions?: { match: UsbDeviceMatch; reason: string; expires_in_hours?: number }[];
  apply_to_present_devices?: boolean;
}
