import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import ErrorBanner from "../components/ErrorBanner";
import UsbPolicyCard from "../components/UsbPolicyCard";
import { api } from "../api/client";
import type {
  AssignDeviceRequest,
  DeviceAssignment,
  DeviceDetail,
  Employee,
} from "../api/client";
import { useAuth } from "../auth";

const MIN_REASON_LENGTH = 8;

function formatBytes(bytes: number | null | undefined): string | null {
  if (bytes === null || bytes === undefined || bytes <= 0) return null;
  const gb = bytes / (1024 * 1024 * 1024);
  return `${gb.toFixed(1)} GB`;
}

function Field({ label, value, mono }: { label: string; value: string | null; mono?: boolean }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd className={mono ? "mono small" : undefined}>{value ?? "—"}</dd>
    </div>
  );
}

export default function DeviceDetailPage() {
  const { deviceId = "" } = useParams();
  const { can } = useAuth();
  const [device, setDevice] = useState<DeviceDetail | null>(null);
  const [assignments, setAssignments] = useState<DeviceAssignment[]>([]);
  const [employees, setEmployees] = useState<Employee[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  // Assign Modal state
  const [isAssignOpen, setIsAssignOpen] = useState(false);
  const [selectedEmpId, setSelectedEmpId] = useState("");
  const [assignName, setAssignName] = useState("");
  const [assignEmail, setAssignEmail] = useState("");
  const [assignDept, setAssignDept] = useState("");
  const [assignNotes, setAssignNotes] = useState("");
  const [assignBusy, setAssignBusy] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [dev, hist, emps] = await Promise.all([
        api.getDevice(deviceId),
        api.getDeviceAssignments(deviceId),
        api.listEmployees(),
      ]);
      setDevice(dev);
      setAssignments(hist);
      setEmployees(emps);
    } catch (caught) {
      setError(caught);
    }
  }, [deviceId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function revoke() {
    setBusy(true);
    setError(null);
    try {
      await api.revokeDevice(deviceId, reason);
      setReason("");
      setNotice("Device successfully revoked.");
      await load();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  function openAssignModal() {
    setSelectedEmpId(device?.assigned_to_id ?? "");
    setAssignName(device?.assigned_to_name ?? "");
    setAssignEmail(device?.assigned_to_email ?? "");
    setAssignDept(device?.department ?? "");
    setAssignNotes("");
    setIsAssignOpen(true);
  }

  function onSelectEmployee(empId: string) {
    setSelectedEmpId(empId);
    const emp = employees.find((e) => e.id === empId);
    if (emp) {
      setAssignName(emp.full_name);
      setAssignEmail(emp.email);
      setAssignDept(emp.department ?? "");
    }
  }

  async function handleAssignSubmit(e: React.FormEvent) {
    e.preventDefault();
    setAssignBusy(true);
    setError(null);
    try {
      const body: AssignDeviceRequest = {
        employee_id: selectedEmpId || null,
        assigned_to_name: assignName.trim(),
        assigned_to_email: assignEmail.trim() || null,
        department: assignDept.trim() || null,
        notes: assignNotes.trim() || null,
      };
      await api.assignDevice(deviceId, body);
      setIsAssignOpen(false);
      setNotice(`Device assigned to ${body.assigned_to_name}.`);
      await load();
    } catch (caught) {
      setError(caught);
    } finally {
      setAssignBusy(false);
    }
  }

  async function handleUnassign() {
    if (!window.confirm("Unassign this device from the current employee?")) return;
    setBusy(true);
    setError(null);
    try {
      await api.unassignDevice(deviceId);
      setNotice("Device unassigned.");
      await load();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  if (!device) {
    return (
      <section>
        <ErrorBanner error={error} />
        {!error && <p className="muted">Loading…</p>}
      </section>
    );
  }

  return (
    <section>
      <div className="page-head">
        <div>
          <Link to="/devices" className="muted small">
            ← All devices
          </Link>
          <h1>{device.display_name ?? device.hostname ?? "unnamed device"}</h1>
          <p className="muted">
            {device.status === "revoked" ? (
              <span className="pill revoked">revoked</span>
            ) : !device.enrolled ? (
              <span className="pill expired">awaiting enrollment</span>
            ) : device.online ? (
              <span className="pill online">online</span>
            ) : (
              <span className="pill offline">offline</span>
            )}{" "}
            {device.enrolled
              ? `last heartbeat ${device.last_heartbeat_at ?? "never"}`
              : `registered ${device.registered_at}`}
          </p>
        </div>
      </div>

      <ErrorBanner error={error} />
      {notice && (
        <div className="banner ok" role="status">
          <p>{notice}</p>
        </div>
      )}

      {device.clone_suspected && (
        <div className="banner warn">
          <strong>Clone suspected</strong>
          <p>
            This device's hardware fingerprint matches another enrolled device. It was
            enrolled as a distinct device on purpose: a reimaged laptop and a cloned VM look
            identical from the server, so this is raised for a human to judge rather than
            blocked automatically.
          </p>
        </div>
      )}

      {!device.enrolled && device.status !== "revoked" && (
        <div className="banner warn">
          <strong>Awaiting enrollment</strong>
          <p>
            This record was created by an administrator. Nothing has been installed on
            the laptop, so it has no certificate, no identity and no inventory — the
            empty fields below are genuinely unknown rather than missing. It becomes
            enrolled when an agent completes enrollment with a keypair generated on the
            machine itself.
          </p>
        </div>
      )}

      <div className="grid-two">
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <h2>Assignment</h2>
            {can("enrollment_token_manage") && device.status !== "revoked" && (
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <button
                  type="button"
                  className="button primary small"
                  onClick={openAssignModal}
                >
                  {device.assigned_to_name ? "Reassign" : "Assign"}
                </button>
                {device.assigned_to_name && (
                  <button
                    type="button"
                    className="button subtle small"
                    onClick={handleUnassign}
                    disabled={busy}
                  >
                    Unassign
                  </button>
                )}
              </div>
            )}
          </div>
          <dl>
            <Field label="Device name" value={device.display_name} />
            <Field label="Manufacturer" value={device.manufacturer} />
            <Field label="Model" value={device.model} />
            <Field label="Issued to" value={device.assigned_to_name} />
            <Field label="Employee email" value={device.assigned_to_email} />
            <Field label="Department" value={device.department} />
            <Field label="Asset tag" value={device.asset_tag} mono />
            <Field label="Platform" value={device.platform} />
            <Field label="Registered" value={device.registered_at} />
          </dl>
          <p className="muted small">
            Supplied by an administrator, never by the device: a laptop does not get to
            rename itself or choose who it belongs to. The owner is filled in from the
            enrollment token when one named an employee, and an assignment already made
            here is never overwritten by an enrolling device.
          </p>
        </div>

        <div className="card">
          <h2>Identity</h2>
          <dl>
            <Field label="Device id" value={device.id} mono />
            <Field label="Status" value={device.status} />
            <Field label="Hostname" value={device.hostname} mono />
            <Field label="Enrolled" value={device.enrolled_at} />
            <Field label="Certificate fingerprint" value={device.cert_fingerprint} mono />
            <Field label="Certificate expires" value={device.cert_not_after} />
          </dl>
          <p className="muted small">
            Certificates live 30 days and the agent renews at the half-way point. The
            fingerprint is checked on every device request, which is what makes revocation
            take effect immediately.
          </p>
        </div>

        <div className="card">
          <h2>Inventory</h2>
          <dl>
            <Field
              label="Ubuntu"
              value={
                device.os_version_id
                  ? `${device.os_id ?? "ubuntu"} ${device.os_version_id}`
                  : null
              }
            />
            <Field label="Kernel" value={device.kernel} mono />
            <Field label="Architecture" value={device.arch} />
            <Field
              label="Processor (CPU)"
              value={
                device.cpu_model
                  ? `${device.cpu_model}${device.cpu_cores ? ` (${device.cpu_cores} cores)` : ""}`
                  : null
              }
            />
            <Field label="Memory (RAM)" value={formatBytes(device.total_ram_bytes)} />
            <Field
              label="Disk capacity"
              value={
                device.disk_total_bytes
                  ? `${formatBytes(device.disk_total_bytes)}${device.disk_free_bytes ? ` (${formatBytes(device.disk_free_bytes)} free)` : ""}`
                  : null
              }
            />
            <Field label="Agent version" value={device.agent_version} />
            <Field
              label="Build"
              value={
                device.release_build === null
                  ? null
                  : device.release_build
                    ? "release"
                    : "development (env overrides compiled in)"
              }
            />
            <Field label="Virtualisation" value={device.virtualization} />
            <Field label="Primary adapter IP" value={device.primary_adapter_ip} mono />
            <Field label="Last inventory" value={device.last_inventory_at} />
          </dl>
          <p className="muted small">
            Discovered at runtime by the agent, never hardcoded. The adapter address is
            self-reported and informational only — it is never used to identify or
            authorise a device. Full inventory reporting arrives with the agent in Phase 2.
          </p>
        </div>

        <UsbPolicyCard deviceId={deviceId} />
      </div>

      {/* Assignment History */}
      <div className="card" style={{ marginTop: "1rem" }}>
        <h2>Ownership & Assignment History</h2>
        {assignments.length === 0 ? (
          <p className="muted small">No assignment history recorded yet for this device.</p>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Assigned To</th>
                <th>Department</th>
                <th>Assigned Date</th>
                <th>Unassigned Date</th>
                <th>Notes</th>
              </tr>
            </thead>
            <tbody>
              {assignments.map((a) => (
                <tr key={a.id}>
                  <td>
                    <strong>{a.assigned_to_name}</strong>
                    {a.assigned_to_email && (
                      <div className="muted small">{a.assigned_to_email}</div>
                    )}
                  </td>
                  <td>{a.department ?? "—"}</td>
                  <td>{a.assigned_at}</td>
                  <td>
                    {a.unassigned_at ? (
                      a.unassigned_at
                    ) : (
                      <span className="pill online">Current</span>
                    )}
                  </td>
                  <td>{a.notes ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {device.status === "revoked" ? (
        <div className="card">
          <h2>Revoked</h2>
          <dl>
            <Field label="Revoked at" value={device.revoked_at} />
            <Field label="Reason" value={device.revoke_reason} />
          </dl>
          <p className="muted small">
            The server refuses this device's next request. It does not make the laptop stop
            enforcing: an offline or cut-off device keeps its last verified policy by
            design. Removing enforcement needs a new signed policy or an uninstall.
          </p>
        </div>
      ) : (
        can("device_revoke") && (
          <div className="card danger" style={{ marginTop: "1rem" }}>
            <h2>Revoke this device</h2>
            <p className="muted">
              Takes effect on the device's next request. The reason is recorded in the
              audit log, so it needs to be meaningful.
            </p>
            <label htmlFor="reason">Reason</label>
            <input
              id="reason"
              value={reason}
              placeholder="e.g. laptop reported lost by the user"
              onChange={(event) => setReason(event.target.value)}
            />
            <button
              type="button"
              className="danger"
              disabled={busy || reason.trim().length < MIN_REASON_LENGTH}
              onClick={() => void revoke()}
            >
              {busy ? "Revoking…" : "Revoke device"}
            </button>
            {reason.length > 0 && reason.trim().length < MIN_REASON_LENGTH && (
              <p className="muted small">
                At least {MIN_REASON_LENGTH} characters. The server enforces this too; the
                check here only saves a round trip.
              </p>
            )}
          </div>
        )
      )}

      {/* Assign / Reassign Dialog */}
      {isAssignOpen && (
        <div className="dialog-overlay">
          <div className="dialog card">
            <h2>{device.assigned_to_name ? "Reassign Device" : "Assign Device"}</h2>
            <form onSubmit={handleAssignSubmit}>
              {employees.length > 0 && (
                <div className="form-group">
                  <label htmlFor="select-emp">Choose Existing Employee</label>
                  <select
                    id="select-emp"
                    value={selectedEmpId}
                    onChange={(e) => onSelectEmployee(e.target.value)}
                  >
                    <option value="">— Or enter manually below —</option>
                    {employees.map((e) => (
                      <option key={e.id} value={e.id}>
                        {e.full_name} ({e.email}){e.department ? ` - ${e.department}` : ""}
                      </option>
                    ))}
                  </select>
                </div>
              )}

              <div className="form-group">
                <label htmlFor="assign-name">Employee Full Name *</label>
                <input
                  id="assign-name"
                  type="text"
                  required
                  value={assignName}
                  onChange={(e) => setAssignName(e.target.value)}
                  placeholder="e.g. Alex Mercer"
                />
              </div>

              <div className="form-group">
                <label htmlFor="assign-email">Employee Email</label>
                <input
                  id="assign-email"
                  type="email"
                  value={assignEmail}
                  onChange={(e) => setAssignEmail(e.target.value)}
                  placeholder="alex@company.com"
                />
              </div>

              <div className="form-group">
                <label htmlFor="assign-dept">Department</label>
                <input
                  id="assign-dept"
                  type="text"
                  value={assignDept}
                  onChange={(e) => setAssignDept(e.target.value)}
                  placeholder="e.g. Security, Devops"
                />
              </div>

              <div className="form-group">
                <label htmlFor="assign-notes">Assignment Notes</label>
                <input
                  id="assign-notes"
                  type="text"
                  value={assignNotes}
                  onChange={(e) => setAssignNotes(e.target.value)}
                  placeholder="e.g. Handed over at headquarters"
                />
              </div>

              <div className="dialog-actions" style={{ display: "flex", justifyContent: "flex-end", gap: "0.5rem", marginTop: "1.25rem" }}>
                <button
                  type="button"
                  className="button"
                  onClick={() => setIsAssignOpen(false)}
                  disabled={assignBusy}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="button primary"
                  disabled={assignBusy}
                >
                  {assignBusy ? "Saving…" : "Save Assignment"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </section>
  );
}
