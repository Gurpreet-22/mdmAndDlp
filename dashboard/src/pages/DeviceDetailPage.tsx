import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";

import ErrorBanner from "../components/ErrorBanner";
import { api } from "../api/client";
import type { DeviceDetail } from "../api/client";
import { useAuth } from "../auth";

const MIN_REASON_LENGTH = 8;

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
  const [error, setError] = useState<unknown>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      setDevice(await api.getDevice(deviceId));
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
          <h2>Assignment</h2>
          <dl>
            <Field label="Device name" value={device.display_name} />
            <Field label="Manufacturer" value={device.manufacturer} />
            <Field label="Model" value={device.model} />
            <Field label="Issued to" value={device.assigned_to_name} />
            <Field label="Employee email" value={device.assigned_to_email} />
            <Field label="Asset tag" value={device.asset_tag} mono />
            <Field label="Platform" value={device.platform} />
            <Field label="Registered" value={device.registered_at} />
          </dl>
          <p className="muted small">
            Supplied by an administrator, not by the device. Enrollment deliberately does
            not overwrite any of it: a laptop does not get to rename itself or reassign
            who it belongs to.
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
      </div>

      <div className="card">
        <h2>USB policy</h2>
        <p className="muted">
          No USB policy is assigned, because USB enforcement is not built yet. When it is,
          a device without usbguard will report this capability as{" "}
          <code>unsupported</code> rather than showing a false green.
        </p>
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
          <div className="card danger">
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
    </section>
  );
}
