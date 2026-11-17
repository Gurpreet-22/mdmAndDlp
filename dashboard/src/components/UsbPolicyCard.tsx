import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type {
  DeviceUsbPolicyView,
  UsbPolicyMode,
  UsbProtectedClass,
} from "../api/types";
import { useAuth } from "../auth";
import ErrorBanner from "./ErrorBanner";

/**
 * USB policy for one device: choose a mode, see what the laptop did about it.
 *
 * Two halves on purpose. The top is intent -- what an administrator asked
 * for. The bottom is what the device reported after reading its own operating
 * system back. Showing only the first would make this a wish list; the gap
 * between them is the only thing that distinguishes enforcement from a
 * dashboard that looks green.
 *
 * Nothing here is applied by the server. Saving creates a new signed version
 * and assigns it; the laptop notices on its next heartbeat, pulls it, verifies
 * the signature and applies it locally. So the honest thing to tell the
 * operator after saving is "queued", not "done", and that is what it says
 * until a status report arrives.
 */

const MODES: {
  value: UsbPolicyMode;
  label: string;
  blurb: string;
}[] = [
  {
    value: "monitor_only",
    label: "Monitor only",
    blurb:
      "Nothing is blocked. Connections are still reported, so an allowlist can " +
      "be built from what people actually use. The safe first step.",
  },
  {
    value: "allowlist_enforce",
    label: "Allowlist",
    blurb:
      "Storage is blocked except for devices approved below. Keyboards, mice " +
      "and hubs keep working.",
  },
  {
    value: "block_all_storage",
    label: "Block all storage",
    blurb:
      "Storage is blocked and the allowlist is ignored. Unexpired exceptions " +
      "still apply.",
  },
];

function StatusPill({ status }: { status: string }) {
  const className =
    status === "applied"
      ? "pill online"
      : status === "unsupported"
        ? "pill expired"
        : status === "pending"
          ? "pill"
          : "pill revoked";
  return <span className={className}>{status}</span>;
}

/** Plain-language explanation of a reason code, for an operator. */
function explainReason(code: string | null): string | null {
  if (!code) return null;
  const table: Record<string, string> = {
    capability_missing:
      "usbguard is not installed on that laptop, so nothing can be enforced. " +
      "Install it there, and this will apply on the next check-in.",
    enforce_failed: "The rules were written but usbguard would not load them.",
    verify_failed:
      "usbguard restarted without error but reported no loaded rules, so the " +
      "policy is not actually in effect. The previous policy was restored.",
    verify_drift:
      "What usbguard loaded does not match the policy. Something else on that " +
      "machine is changing the rules. The previous policy was restored.",
    rollback_failed:
      "The policy failed AND the previous one could not be restored. That " +
      "laptop is in a state nobody chose; it needs attention.",
    enforcer_unavailable:
      "The root enforcer is not running on that laptop, so the agent had " +
      "nothing to hand the policy to.",
    enforcer_rejected: "The laptop refused the policy as malformed or unsafe.",
    invalid_snapshot_id: "The laptop refused a rollback request as malformed.",
  };
  return table[code] ?? null;
}

export default function UsbPolicyCard({ deviceId }: { deviceId: string }) {
  const { can } = useAuth();
  const canWrite = can("policy_write");

  const [view, setView] = useState<DeviceUsbPolicyView | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [mode, setMode] = useState<UsbPolicyMode>("monitor_only");
  const [blockPhones, setBlockPhones] = useState(false);

  const load = useCallback(async () => {
    try {
      const next = await api.deviceUsbPolicy(deviceId);
      setView(next);
      if (next.policy) {
        setMode(next.policy.payload.mode);
        setBlockPhones(next.policy.payload.protected_classes.includes("image"));
      }
      setError(null);
    } catch (caught) {
      setError(caught);
    } finally {
      setLoading(false);
    }
  }, [deviceId]);

  useEffect(() => {
    void load();
  }, [load]);

  // The laptop checks in once a minute, so a status report lands shortly after
  // saving. Polling while something is outstanding beats asking the operator
  // to reload to find out whether it worked.
  useEffect(() => {
    const outstanding =
      view?.policy &&
      (!view.status || view.status.policy_version !== view.policy.version);
    if (!outstanding) return;
    const timer = setInterval(() => void load(), 15000);
    return () => clearInterval(timer);
  }, [view, load]);

  async function save() {
    setSaving(true);
    setNotice(null);
    try {
      const protectedClasses: UsbProtectedClass[] = blockPhones
        ? ["mass_storage", "image"]
        : ["mass_storage"];
      await api.setUsbPolicy({
        mode,
        scope_kind: "device",
        device_id: deviceId,
        protected_classes: protectedClasses,
        // Existing approvals are carried over. Omitting them would silently
        // revoke every approved device on a mode change, which is not what
        // changing a dropdown should mean.
        allowlist: (view?.policy?.payload.allowlist ?? []).map((entry) => ({
          match: entry.match,
          label: entry.label,
        })),
      });
      setNotice(
        "Policy saved and queued. The laptop applies it on its next check-in, " +
          "normally within a minute; this card updates when it reports back.",
      );
      await load();
    } catch (caught) {
      setError(caught);
    } finally {
      setSaving(false);
    }
  }

  const policy = view?.policy ?? null;
  const status = view?.status ?? null;
  const verified = status?.verified_state ?? null;
  const stale = policy && status && status.policy_version !== policy.version;
  const bypassable = verified?.enforcement_bypassable_without_root === true;
  const unknownBypass = verified?.enforcement_bypassable_without_root === null;

  return (
    <div className="card">
      <h2>USB policy</h2>
      <ErrorBanner error={error} />

      {loading ? (
        <p className="muted small">Loading…</p>
      ) : (
        <>
          <div className="field-group">
            <label htmlFor="usb-mode">Mode</label>
            <select
              id="usb-mode"
              value={mode}
              disabled={!canWrite || saving}
              onChange={(event) => setMode(event.target.value as UsbPolicyMode)}
            >
              {MODES.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <p className="muted small">
              {MODES.find((option) => option.value === mode)?.blurb}
            </p>
          </div>

          <label className="small" style={{ display: "block", margin: "0.5rem 0" }}>
            <input
              type="checkbox"
              checked={blockPhones}
              disabled={!canWrite || saving}
              onChange={(event) => setBlockPhones(event.target.checked)}
            />{" "}
            Also block phones and cameras (USB class 06)
          </label>
          <p className="muted small">
            Off by default. A phone in file-transfer mode is class 06, not
            storage, so a storage-only policy does not stop it — but blocking it
            also stops phone charging and tethering for everyone.
          </p>

          {canWrite ? (
            <button type="button" onClick={() => void save()} disabled={saving}>
              {saving ? "Saving…" : "Save and send to device"}
            </button>
          ) : (
            <p className="muted small">
              Your role can view this policy but not change it.
            </p>
          )}

          {notice && (
            <div className="banner ok" role="status">
              <p>{notice}</p>
            </div>
          )}

          <hr />

          {!policy ? (
            <p className="muted small">
              No USB policy is assigned to this device yet. Choose a mode above
              and save; nothing is enforced until you do.
            </p>
          ) : (
            <>
              <dl className="fields">
                <div className="field">
                  <dt>In force</dt>
                  <dd>
                    {policy.payload.mode} (v{policy.version})
                  </dd>
                </div>
                <div className="field">
                  <dt>Approved devices</dt>
                  <dd>{policy.payload.allowlist.length}</dd>
                </div>
                <div className="field">
                  <dt>Signed by</dt>
                  <dd className="mono small">{policy.signing_key_id}</dd>
                </div>
              </dl>

              <h3 className="small">What the laptop reported</h3>
              {!status ? (
                <p className="muted small">
                  Nothing yet. The device reports after it applies the policy,
                  usually within a minute of the next check-in. A laptop that is
                  offline will report when it returns.
                </p>
              ) : (
                <>
                  <p>
                    <StatusPill status={status.status} />{" "}
                    <span className="muted small">
                      v{status.policy_version}, {new Date(status.reported_at).toLocaleString()}
                    </span>
                  </p>

                  {stale && (
                    <div className="banner warn" role="status">
                      <p>
                        This report is for v{status.policy_version}, but v
                        {policy.version} is now assigned. The laptop has not
                        applied the latest version yet.
                      </p>
                    </div>
                  )}

                  {status.reason_code && (
                    <p className="small">
                      <code>{status.reason_code}</code>
                      {explainReason(status.reason_code) ? (
                        <> — {explainReason(status.reason_code)}</>
                      ) : null}
                    </p>
                  )}
                  {status.detail && <p className="muted small">{status.detail}</p>}

                  {bypassable && (
                    <div className="banner warn" role="alert">
                      <p>
                        <strong>Enforcement can be switched off on that laptop
                        without an administrator password.</strong>{" "}
                        usbguard's control socket is open to a non-root group
                        ({(verified?.ipc_exposure ?? []).join(", ")}), so a user
                        in it can authorise their own blocked device. The policy
                        below is applied, but it is advisory for that user until
                        this is narrowed.
                      </p>
                    </div>
                  )}
                  {unknownBypass && (
                    <p className="muted small">
                      Whether a non-root user could switch enforcement off is
                      unknown: the agent could not read usbguard's daemon
                      configuration.
                    </p>
                  )}

                  {verified?.loaded_rules && verified.loaded_rules.length > 0 && (
                    <>
                      <h3 className="small">
                        Rules usbguard actually loaded ({verified.loaded_rule_count})
                      </h3>
                      <p className="muted small">
                        Read back from the operating system on that machine, not
                        from what was sent to it.
                      </p>
                      <pre className="mono small">
                        {verified.loaded_rules.join("\n")}
                      </pre>
                    </>
                  )}

                  {verified?.foreign_rules && verified.foreign_rules.length > 0 && (
                    <>
                      <h3 className="small">Rules added by something else</h3>
                      <p className="muted small">
                        Present on that machine but not part of this policy.
                        They sit after it, so they do not override it. On an
                        Ubuntu desktop this is normally GNOME's own USB
                        protection.
                      </p>
                      <pre className="mono small">
                        {verified.foreign_rules.join("\n")}
                      </pre>
                    </>
                  )}

                  {verified?.daemon_params &&
                    Object.keys(verified.daemon_params).length > 0 && (
                      <>
                        <h3 className="small">usbguard settings</h3>
                        <pre className="mono small">
                          {Object.entries(verified.daemon_params)
                            .map(([key, value]) => `${key}=${value}`)
                            .join("\n")}
                        </pre>
                      </>
                    )}
                </>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}
