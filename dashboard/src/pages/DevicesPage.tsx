import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";

import AddDeviceDialog from "../components/AddDeviceDialog";
import ErrorBanner from "../components/ErrorBanner";
import { api } from "../api/client";
import type { DeviceCounts, DeviceSummary } from "../api/client";
import { useAuth } from "../auth";

/** Relative time, with the absolute value always shown alongside it. */
function sinceLabel(timestamp: string | null): string {
  if (!timestamp) return "never";
  const seconds = Math.max(0, (Date.now() - new Date(timestamp).getTime()) / 1000);
  if (seconds < 90) return `${Math.round(seconds)}s ago`;
  if (seconds < 5400) return `${Math.round(seconds / 60)}m ago`;
  if (seconds < 172800) return `${Math.round(seconds / 3600)}h ago`;
  return `${Math.round(seconds / 86400)}d ago`;
}

const PLATFORM_LABELS: Record<string, string> = {
  linux: "Linux",
  macos: "macOS",
  windows: "Windows",
};

/** What the OS column shows, preferring what the device reported. */
function osLabel(device: DeviceSummary): string {
  if (device.os_id && device.os_version_id) {
    const name = device.os_id === "ubuntu" ? "Ubuntu" : device.os_id;
    return `${name} ${device.os_version_id}`;
  }
  if (device.platform) return `${PLATFORM_LABELS[device.platform] ?? device.platform} (expected)`;
  return "—";
}

/**
 * The state cell.
 *
 * Four states, not two, because "enabled/disabled" would collapse the one
 * distinction this page exists to show. A device that has never enrolled is not
 * offline - nothing has ever been installed on it - and saying "offline" would
 * imply an agent that fell silent.
 */
function StateCell({ device }: { device: DeviceSummary }) {
  if (device.status === "revoked") return <span className="pill revoked">revoked</span>;
  if (!device.enrolled) return <span className="pill expired">awaiting enrollment</span>;
  if (device.online) return <span className="pill online">online</span>;
  return <span className="pill offline">offline</span>;
}

export default function DevicesPage() {
  const { can } = useAuth();
  const [devices, setDevices] = useState<DeviceSummary[]>([]);
  const [counts, setCounts] = useState<DeviceCounts | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [adding, setAdding] = useState(false);

  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [enrolled, setEnrolled] = useState("");
  const [osVersion, setOsVersion] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rows, totals] = await Promise.all([
        api.listDevices({
          q: search || undefined,
          status: status || undefined,
          enrolled: enrolled === "" ? undefined : enrolled === "yes",
          os_version_id: osVersion || undefined,
          limit: 200,
        }),
        api.deviceCounts(),
      ]);
      setDevices(rows);
      setCounts(totals);
    } catch (caught) {
      setError(caught);
    } finally {
      setLoading(false);
    }
  }, [search, status, enrolled, osVersion]);

  // Debounced so typing in the search box does not fire a request per keystroke.
  useEffect(() => {
    const handle = setTimeout(() => void load(), 250);
    return () => clearTimeout(handle);
  }, [load]);

  const osVersions = useMemo(
    () => [...new Set(devices.map((device) => device.os_version_id).filter(Boolean))].sort(),
    [devices],
  );

  const canAdd = can("enrollment_token_manage");

  return (
    <section>
      <div className="page-head">
        <div>
          <h1>Devices</h1>
          <p className="muted">
            Every company laptop, registered or enrolled. Online is computed by the
            server from the last heartbeat it received, never self-reported, and
            last contact is always shown beside it.
          </p>
        </div>
        {canAdd && (
          <button type="button" onClick={() => setAdding(true)}>
            + Add device
          </button>
        )}
      </div>

      <div className="stats">
        <div className="stat">
          <span className="stat-value">{counts?.total ?? "—"}</span>
          <span className="stat-label">total</span>
        </div>
        <div className="stat">
          <span className="stat-value good">{counts?.enrolled ?? "—"}</span>
          <span className="stat-label">enrolled</span>
        </div>
        <div className="stat">
          <span className="stat-value warn">{counts?.unenrolled ?? "—"}</span>
          <span className="stat-label">awaiting enrollment</span>
        </div>
        <div className="stat">
          <span className="stat-value warn">{counts?.revoked ?? "—"}</span>
          <span className="stat-label">revoked</span>
        </div>
        <div className="stat">
          <span className="stat-value warn">{counts?.clone_suspected ?? "—"}</span>
          <span className="stat-label">clone suspected</span>
        </div>
      </div>

      <div className="filters">
        <input
          type="search"
          placeholder="Search name, hostname, employee or asset tag…"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
          aria-label="Search devices"
        />
        <select
          value={enrolled}
          onChange={(event) => setEnrolled(event.target.value)}
          aria-label="Enrollment"
        >
          <option value="">Enrolled and not</option>
          <option value="yes">Enrolled only</option>
          <option value="no">Awaiting enrollment</option>
        </select>
        <select
          value={status}
          onChange={(event) => setStatus(event.target.value)}
          aria-label="Status"
        >
          <option value="">Any status</option>
          <option value="pending">pending</option>
          <option value="active">active</option>
          <option value="revoked">revoked</option>
        </select>
        <select
          value={osVersion}
          onChange={(event) => setOsVersion(event.target.value)}
          aria-label="Ubuntu version"
        >
          <option value="">Any OS version</option>
          {osVersions.map((version) => (
            <option key={version} value={version ?? ""}>
              {version}
            </option>
          ))}
        </select>
      </div>

      <ErrorBanner error={error} />

      <div className="card table-card">
        <table>
          <thead>
            <tr>
              <th>Device</th>
              <th>State</th>
              <th>Issued to</th>
              <th>OS</th>
              <th>Primary adapter IP</th>
              <th>Last contact</th>
              <th>Flags</th>
            </tr>
          </thead>
          <tbody>
            {devices.map((device) => (
              <tr key={device.id}>
                <td>
                  <div className="product-cell">
                    <Link to={`/devices/${device.id}`}>
                      {device.display_name ?? device.hostname ?? "unnamed device"}
                    </Link>
                    <span className="sub">
                      {[device.manufacturer, device.model].filter(Boolean).join(" ") ||
                        (device.hostname ? device.hostname : "no hardware detail")}
                    </span>
                  </div>
                </td>
                <td>
                  <StateCell device={device} />
                </td>
                <td>
                  {device.assigned_to_name ?? device.assigned_to_email ?? (
                    <span className="muted">—</span>
                  )}
                </td>
                <td>{osLabel(device)}</td>
                <td className="mono small">
                  {device.primary_adapter_ip ?? <span className="muted">—</span>}
                </td>
                <td
                  className="muted"
                  title={
                    device.last_heartbeat_at ??
                    (device.enrolled ? "no heartbeat received" : "never enrolled")
                  }
                >
                  {device.enrolled ? sinceLabel(device.last_heartbeat_at) : "—"}
                </td>
                <td>
                  {device.clone_suspected && <span className="pill warn">clone?</span>}
                  {device.release_build === false && (
                    <span
                      className="pill warn"
                      title="Dev build: environment overrides are compiled in, so effective settings may not match policy"
                    >
                      dev build
                    </span>
                  )}
                </td>
              </tr>
            ))}
            {devices.length === 0 && !loading && (
              <tr>
                <td colSpan={7} className="muted centred-cell">
                  {counts && counts.total > 0
                    ? "No devices match these filters."
                    : canAdd
                      ? "No devices yet. Use “Add device” to register an employee laptop."
                      : "No devices yet."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {loading && <p className="muted small">Loading…</p>}
        <p className="muted small">
          Showing {devices.length}
          {counts ? ` of ${counts.total}` : ""} device
          {devices.length === 1 ? "" : "s"}. “Primary adapter IP” is reported by the
          agent and is informational only — it is never used to identify or
          authorise a device.
        </p>
      </div>

      {canAdd && (
        <AddDeviceDialog
          open={adding}
          onClose={() => setAdding(false)}
          onRegistered={() => void load()}
        />
      )}
    </section>
  );
}
