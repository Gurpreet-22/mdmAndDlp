import { useState } from "react";

import ErrorBanner from "./ErrorBanner";
import Modal from "./Modal";
import { api } from "../api/client";
import type { DevicePlatform, RegisterDeviceResponse } from "../api/client";

const TTL_CHOICES = [
  { label: "1 hour", seconds: 3600 },
  { label: "8 hours", seconds: 28800 },
  { label: "24 hours", seconds: 86400 },
];

/**
 * The platforms the server will record, and what each one actually gets.
 *
 * Only Ubuntu has an agent. The other two are selectable so an inventory can be
 * honest about what a company owns, and they say plainly that nothing will
 * manage them rather than implying a capability that does not exist.
 */
const PLATFORMS: {
  id: DevicePlatform;
  label: string;
  detail: string;
  available: boolean;
}[] = [
  {
    id: "linux",
    label: "Ubuntu",
    detail:
      "The only platform with an agent. Written for 22.04 and 24.04; neither is validated yet.",
    available: true,
  },
  {
    id: "macos",
    label: "macOS",
    detail: "Recorded for inventory only. No agent, and none planned.",
    available: false,
  },
  {
    id: "windows",
    label: "Windows",
    detail: "Recorded for inventory only. No agent, and none planned.",
    available: false,
  },
];

export default function AddDeviceDialog({
  open,
  onClose,
  onRegistered,
}: {
  open: boolean;
  onClose: () => void;
  onRegistered: () => void;
}) {
  const [platform, setPlatform] = useState<DevicePlatform>("linux");
  const [displayName, setDisplayName] = useState("");
  const [manufacturer, setManufacturer] = useState("");
  const [model, setModel] = useState("");
  const [assigneeName, setAssigneeName] = useState("");
  const [assigneeEmail, setAssigneeEmail] = useState("");
  const [assetTag, setAssetTag] = useState("");
  const [issueToken, setIssueToken] = useState(true);
  const [ttl, setTtl] = useState(86400);

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<RegisterDeviceResponse | null>(null);
  const [copied, setCopied] = useState(false);

  function reset() {
    setPlatform("linux");
    setDisplayName("");
    setManufacturer("");
    setModel("");
    setAssigneeName("");
    setAssigneeEmail("");
    setAssetTag("");
    setIssueToken(true);
    setTtl(86400);
    setError(null);
    setResult(null);
    setCopied(false);
  }

  function close() {
    reset();
    onClose();
  }

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      // Blank optional fields are sent as null, not "". The server rejects a
      // present-but-empty email, and "unknown manufacturer" is genuinely absent
      // data rather than an empty string.
      const registered = await api.registerDevice({
        display_name: displayName.trim(),
        platform,
        manufacturer: manufacturer.trim() || null,
        model: model.trim() || null,
        assigned_to_name: assigneeName.trim() || null,
        assigned_to_email: assigneeEmail.trim() || null,
        asset_tag: assetTag.trim() || null,
        issue_enrollment_token: issueToken,
        token_ttl_seconds: ttl,
      });
      setResult(registered);
      onRegistered();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  const chosen = PLATFORMS.find((entry) => entry.id === platform);

  // --- After a successful registration ----------------------------------- //
  if (result) {
    const token = result.enrollment_token;
    return (
      <Modal
        open={open}
        title="Device added"
        onClose={close}
        footer={
          <button type="button" onClick={close}>
            Done
          </button>
        }
      >
        <p>
          <strong>{result.device.display_name}</strong> is registered and listed as
          awaiting enrollment. It stays that way until an agent on the machine
          completes enrollment, which is the only thing that can mark it enrolled.
        </p>

        {token ? (
          <div className="banner success">
            <div className="banner-head">
              <strong>Enrollment token — copy it now</strong>
              <code className="code-chip">once only</code>
            </div>
            <p>
              Only the hash is stored, so this cannot be shown again. It is single
              use, bound to this device, and expires on its own.
            </p>
            <div className="token-row">
              <code className="token">{token}</code>
              <button
                type="button"
                className="ghost"
                onClick={() => {
                  void navigator.clipboard?.writeText(token).then(() => setCopied(true));
                }}
              >
                {copied ? "Copied" : "Copy"}
              </button>
            </div>
            {result.enrollment_token_expires_at && (
              <p className="muted small">Expires {result.enrollment_token_expires_at}</p>
            )}
            <div style={{ marginTop: "1rem" }}>
              <a
                href="/api/v1/installer/download"
                download="ubuntuguard-agent-installer.sh"
                className="download-button"
                style={{
                  margin: 0,
                  padding: "0.55rem 1rem",
                  fontSize: "0.92rem",
                  textAlign: "center",
                  display: "inline-block",
                }}
              >
                Download Agent Installer (.sh)
              </a>
            </div>
          </div>
        ) : (
          <div className="banner warn">
            <strong>No enrollment token was issued</strong>
            <p>
              The device is recorded but cannot enroll until you issue one from the
              Enrollment page.
            </p>
          </div>
        )}

        <div className="banner">
          <div className="banner-head">
            <strong>Send the employee to the enrollment page</strong>
            <code className="code-chip">/enroll</code>
          </div>
          <p>
            Give them the token above and the link to{" "}
            <a href="/enroll" target="_blank" rel="noreferrer">
              /enroll
            </a>
            , where they can download the agent installer. They run it, paste the
            token when asked, and this device moves from awaiting enrollment to
            enrolled.
          </p>
          <p className="muted small">
            Send the token and the link by company email or chat. The token is not
            recoverable from this dialog once it is closed.
          </p>
        </div>
      </Modal>
    );
  }

  // --- The form ----------------------------------------------------------- //
  return (
    <Modal
      open={open}
      title="Add device"
      onClose={close}
      footer={
        <>
          <button type="button" className="ghost" onClick={close}>
            Cancel
          </button>
          <button
            type="button"
            onClick={() => void submit()}
            disabled={busy || displayName.trim().length === 0}
          >
            {busy ? "Adding…" : "Add device"}
          </button>
        </>
      }
    >
      <ErrorBanner error={error} />

      <div className="tabs" role="tablist" aria-label="Platform">
        {PLATFORMS.map((entry) => (
          <button
            key={entry.id}
            type="button"
            role="tab"
            aria-selected={platform === entry.id}
            className={platform === entry.id ? "tab active" : "tab"}
            onClick={() => setPlatform(entry.id)}
          >
            {entry.label}
          </button>
        ))}
      </div>

      {chosen && (
        <p className="muted small" style={{ marginTop: 0 }}>
          {chosen.detail}
        </p>
      )}

      {chosen && !chosen.available && (
        <div className="banner warn">
          <strong>{chosen.label} is inventory only</strong>
          <p>
            You can record this device so the asset list is complete, but no agent
            will ever manage it and no policy will reach it. Out of scope for this
            prototype, deliberately.
          </p>
        </div>
      )}

      <div className="form-grid">
        <div className="form-row span-all">
          <label htmlFor="display_name">Device name</label>
          <input
            id="display_name"
            value={displayName}
            placeholder="e.g. Ethan's laptop"
            onChange={(event) => setDisplayName(event.target.value)}
          />
        </div>

        <div className="form-row">
          <label htmlFor="manufacturer">Manufacturer</label>
          <input
            id="manufacturer"
            value={manufacturer}
            placeholder="e.g. Lenovo"
            onChange={(event) => setManufacturer(event.target.value)}
          />
        </div>
        <div className="form-row">
          <label htmlFor="model">Model</label>
          <input
            id="model"
            value={model}
            placeholder="e.g. ThinkPad T14 Gen 4"
            onChange={(event) => setModel(event.target.value)}
          />
        </div>

        <div className="form-row">
          <label htmlFor="assignee_name">Issued to</label>
          <input
            id="assignee_name"
            value={assigneeName}
            placeholder="Employee name"
            onChange={(event) => setAssigneeName(event.target.value)}
          />
        </div>
        <div className="form-row">
          <label htmlFor="assignee_email">Employee email</label>
          <input
            id="assignee_email"
            type="email"
            autoComplete="off"
            value={assigneeEmail}
            placeholder="work email address"
            onChange={(event) => setAssigneeEmail(event.target.value)}
          />
        </div>

        <div className="form-row">
          <label htmlFor="asset_tag">Asset tag</label>
          <input
            id="asset_tag"
            value={assetTag}
            placeholder="e.g. IT-004912"
            onChange={(event) => setAssetTag(event.target.value)}
          />
        </div>
      </div>

      <div className="checkbox-row">
        <input
          id="issue_token"
          type="checkbox"
          checked={issueToken}
          onChange={(event) => setIssueToken(event.target.checked)}
        />
        <label htmlFor="issue_token">
          Issue a single-use enrollment token for this device
        </label>
      </div>

      {issueToken && (
        <div className="form-row" style={{ maxWidth: 220 }}>
          <label htmlFor="token_ttl">Token valid for</label>
          <select
            id="token_ttl"
            value={ttl}
            onChange={(event) => setTtl(Number(event.target.value))}
          >
            {TTL_CHOICES.map((choice) => (
              <option key={choice.seconds} value={choice.seconds}>
                {choice.label}
              </option>
            ))}
          </select>
        </div>
      )}

      <p className="muted small">
        Adding a device grants it nothing. It cannot reach the API, carries no
        identity, and proves nothing about the hardware until an agent enrolls with
        a keypair it generated on the machine itself.
      </p>
    </Modal>
  );
}
