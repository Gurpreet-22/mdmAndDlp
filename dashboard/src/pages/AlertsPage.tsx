import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";

import ErrorBanner from "../components/ErrorBanner";
import Icon from "../components/Icon";
import { api } from "../api/client";
import type { IncidentResponse, IncidentStatus } from "../api/client";
import { useAuth } from "../auth";

/** Plain English for each kind, so the page is not a list of identifiers. */
const KIND_LABELS: Record<string, string> = {
  device_offline: "Stopped checking in",
  usb_blocked: "USB device blocked",
  clone_suspected: "Possible clone",
  policy_rollback_failed: "Policy rollback failed",
  enforcer_unavailable: "Enforcer unavailable",
  capability_lost: "Capability lost",
  audit_chain_broken: "Audit chain broken",
};

/** Which pill class each status borrows. */
const STATUS_PILL: Record<IncidentStatus, string> = {
  open: "bad",
  acknowledged: "warn",
  investigating: "warn",
  resolved: "active",
  false_positive: "neutral",
};

const STATUS_LABELS: Record<IncidentStatus, string> = {
  open: "open",
  acknowledged: "acknowledged",
  investigating: "investigating",
  resolved: "resolved",
  false_positive: "false positive",
};

/** The transitions offered, given where an incident currently is. */
function nextStatuses(current: IncidentStatus): IncidentStatus[] {
  if (current === "resolved" || current === "false_positive") return ["open"];
  if (current === "open") return ["acknowledged", "investigating", "resolved", "false_positive"];
  return ["investigating", "resolved", "false_positive"];
}

export default function AlertsPage() {
  const { can } = useAuth();
  const [incidents, setIncidents] = useState<IncidentResponse[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [openOnly, setOpenOnly] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [noteDraft, setNoteDraft] = useState("");

  const canTriage = can("incident_update");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setIncidents(await api.listIncidents({ openOnly, limit: 100 }));
    } catch (caught) {
      setError(caught);
    } finally {
      setLoading(false);
    }
  }, [openOnly]);

  useEffect(() => {
    void load();
  }, [load]);

  async function triage(id: string, status?: IncidentStatus, note?: string) {
    setBusyId(id);
    setError(null);
    try {
      await api.updateIncident(id, {
        status: status ?? null,
        note: note?.trim() ? note.trim() : null,
      });
      setNoteDraft("");
      setExpanded(null);
      await load();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <section>
      <div className="page-head">
        <div>
          <h1>Alerts</h1>
          <p className="muted">
            Raised by the server from what it observed, never from a device's own claim.
            Resolving one records who decided it did not matter.
          </p>
        </div>
        <div>
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={openOnly}
              onChange={(event) => setOpenOnly(event.target.checked)}
            />
            Only alerts nobody has closed
          </label>
        </div>
      </div>

      <ErrorBanner error={error} />

      <div className="card table-card">
        {loading && incidents.length === 0 ? (
          <p className="muted">Loading…</p>
        ) : incidents.length === 0 ? (
          <p className="muted">
            {openOnly
              ? "Nothing needs attention. Alerts appear here when a device stops checking in, or when the agent reports something it could not do."
              : "No alerts have ever been raised."}
          </p>
        ) : (
          <table>
            <thead>
              <tr>
                <th>What happened</th>
                <th>Device</th>
                <th>Status</th>
                <th>Opened</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {incidents.map((incident) => (
                <>
                  <tr key={incident.id}>
                    <td>
                      <div>{KIND_LABELS[incident.kind] ?? incident.kind}</div>
                      <div className="muted small">{incident.summary}</div>
                    </td>
                    <td className="small">
                      {incident.device_id ? (
                        <Link to={`/devices/${incident.device_id}`}>
                          {incident.device_hostname ?? `${incident.device_id.slice(0, 8)}…`}
                        </Link>
                      ) : (
                        /* The device was deleted after the alert was raised.
                           ON DELETE SET NULL keeps the alert, deliberately. */
                        <span className="muted">device removed</span>
                      )}
                    </td>
                    <td>
                      <span className={`pill ${STATUS_PILL[incident.status]}`}>
                        {STATUS_LABELS[incident.status]}
                      </span>
                    </td>
                    <td className="muted small">{incident.opened_at}</td>
                    <td>
                      <button
                        type="button"
                        className="ghost small"
                        onClick={() =>
                          setExpanded(expanded === incident.id ? null : incident.id)
                        }
                      >
                        {expanded === incident.id ? "Close" : "Details"}
                      </button>
                    </td>
                  </tr>

                  {expanded === incident.id && (
                    <tr key={`${incident.id}-detail`}>
                      <td colSpan={5}>
                        <div className="alert-detail">
                          <div>
                            <span className="field-label">History</span>
                            {/* Pre-wrapped: the note is an append-only log of
                                what raised the alert and who said what since,
                                and collapsing its newlines would lose that. */}
                            <pre className="note-log">{incident.note ?? "No notes."}</pre>
                          </div>

                          {canTriage ? (
                            <div className="alert-actions">
                              <label htmlFor={`note-${incident.id}`}>Add a note</label>
                              <input
                                id={`note-${incident.id}`}
                                value={noteDraft}
                                placeholder="e.g. spoke to the owner, laptop is in a drawer"
                                onChange={(event) => setNoteDraft(event.target.value)}
                              />
                              <div className="alert-buttons">
                                {nextStatuses(incident.status).map((status) => (
                                  <button
                                    key={status}
                                    type="button"
                                    className="ghost small"
                                    disabled={busyId === incident.id}
                                    onClick={() => void triage(incident.id, status, noteDraft)}
                                  >
                                    {status === "open"
                                      ? "Reopen"
                                      : `Mark ${STATUS_LABELS[status]}`}
                                  </button>
                                ))}
                                <button
                                  type="button"
                                  className="ghost small"
                                  disabled={busyId === incident.id || !noteDraft.trim()}
                                  onClick={() => void triage(incident.id, undefined, noteDraft)}
                                >
                                  Add note only
                                </button>
                              </div>
                            </div>
                          ) : (
                            <p className="muted small">
                              <Icon name="lock" size={14} /> Your role can read alerts but not
                              triage them.
                            </p>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              ))}
            </tbody>
          </table>
        )}
        <p className="muted small">
          A device that reconnects resolves its own offline alert automatically, with the
          reconnection time appended to the note.
        </p>
      </div>
    </section>
  );
}
