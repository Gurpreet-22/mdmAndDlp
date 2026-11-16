import { useEffect, useState } from "react";

import ErrorBanner from "./ErrorBanner";
import Modal from "./Modal";
import { api } from "../api/client";
import type { AdminRole, UserResponse } from "../api/client";

/**
 * The three account actions that need more than a button: enable, change role,
 * reset password.
 *
 * One component rather than three, because they share everything that is
 * fiddly - the confirmation step, the busy state, the error surface, and the
 * rule that the dialog must not close until the server has answered. Three
 * copies of that would drift.
 *
 * Disable is deliberately NOT here. It is a single click with a single
 * consequence and already worked; folding it in would have meant rewriting a
 * working path for symmetry.
 *
 * What this component does not do is decide what is allowed. Every refusal
 * below comes from the server - `cannot_change_own_role`,
 * `cannot_demote_last_super_admin`, `user_already_active` - and is rendered by
 * `ErrorBanner` from the problem document. The UI hides what it can to save a
 * pointless round trip, and that is all it is doing.
 */

export type UserAction = "enable" | "role" | "reset-password";

const MIN_PASSWORD_LENGTH = 12;

const ROLE_SUMMARY: Record<AdminRole, string> = {
  super_admin: "Everything, including creating accounts and exporting the audit log",
  it_admin: "Runs the fleet: enrollment, devices, policy. Cannot export the audit log",
  security_analyst: "Investigates: events, incidents, USB exceptions. No fleet changes",
  auditor: "Read-only, plus audit export",
};

const ROLES = Object.keys(ROLE_SUMMARY) as AdminRole[];

/** A password the administrator does not have to invent. */
function generatePassword(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = new Uint32Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => alphabet[value % alphabet.length]).join("");
}

const TITLES: Record<UserAction, string> = {
  enable: "Re-enable account",
  role: "Change role",
  "reset-password": "Reset password",
};

export default function UserActionsDialog({
  action,
  user,
  onClose,
  onDone,
}: {
  /** Null closes the dialog. */
  action: UserAction | null;
  user: UserResponse | null;
  onClose: () => void;
  /** Called after the server confirms, so the caller can refresh and report. */
  onDone: (message: string) => void;
}) {
  const [role, setRole] = useState<AdminRole>("it_admin");
  const [password, setPassword] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const open = action !== null && user !== null;

  // Reset on every open, so a previous attempt's error or a half-typed
  // password never carries into the next account the administrator picks.
  useEffect(() => {
    if (!open) return;
    setError(null);
    setBusy(false);
    setPassword("");
    setRevealed(false);
    // Default the role selector to something other than the current role, so
    // submitting without touching it cannot produce a `role_unchanged` refusal.
    const current = user?.role as AdminRole | undefined;
    setRole(current === "it_admin" ? "auditor" : "it_admin");
  }, [open, user?.id, user?.role]);

  if (!open || !user || !action) return null;

  const passwordTooShort = password.length > 0 && password.length < MIN_PASSWORD_LENGTH;
  const canSubmit =
    !busy &&
    (action !== "reset-password" || password.length >= MIN_PASSWORD_LENGTH) &&
    (action !== "role" || role !== user.role);

  async function submit() {
    setBusy(true);
    setError(null);
    try {
      if (action === "enable") {
        await api.enableUser(user!.id);
        onDone(`${user!.email} can sign in again with their existing password.`);
      } else if (action === "role") {
        await api.changeUserRole(user!.id, role);
        onDone(
          `${user!.email} is now ${role.replace(/_/g, " ")}. Their sessions were signed out.`,
        );
      } else {
        await api.resetUserPassword(user!.id, password);
        onDone(
          `${user!.email} has a temporary password and was signed out everywhere. ` +
            "Send it to them now — it cannot be shown again.",
        );
      }
      onClose();
    } catch (caught) {
      // Left open on purpose: the administrator needs to read the refusal, and
      // several of them are actionable without leaving the dialog.
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      open={open}
      title={TITLES[action]}
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button type="button" className="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button type="button" onClick={() => void submit()} disabled={!canSubmit}>
            {busy ? "Working…" : TITLES[action]}
          </button>
        </>
      }
    >
      <ErrorBanner error={error} />

      <p>
        <strong>{user.email}</strong>
        <span className="role-badge">{user.role.replace(/_/g, " ")}</span>
      </p>

      {action === "enable" && (
        <>
          <p className="muted">
            The account keeps its address, its role, its id and its existing password, so
            its history in the audit log stays intact. Any standing sign-in lockout is
            cleared.
          </p>
          <p className="muted small">
            No session is created. They sign in themselves, with the password they already
            had.
          </p>
        </>
      )}

      {action === "role" && (
        <>
          <div className="form-row" style={{ maxWidth: 260 }}>
            <label htmlFor="action-role">New role</label>
            <select
              id="action-role"
              value={role}
              onChange={(event) => setRole(event.target.value as AdminRole)}
            >
              {ROLES.map((choice) => (
                <option key={choice} value={choice} disabled={choice === user.role}>
                  {choice.replace(/_/g, " ")}
                  {choice === user.role ? " (current)" : ""}
                </option>
              ))}
            </select>
          </div>
          <p className="muted small">
            {role.replace(/_/g, " ")}: {ROLE_SUMMARY[role]}
          </p>
          <div className="banner warn">
            <strong>This signs them out everywhere</strong>
            <p>
              A session carries the role it was created with, so it has to be ended for the
              new role to take effect. They sign in again with the same password.
            </p>
          </div>
          {role === "super_admin" && (
            <p className="muted small">
              super_admin can create, disable and reset any account, including yours.
            </p>
          )}
        </>
      )}

      {action === "reset-password" && (
        <>
          <p className="muted">
            Set a temporary password and hand it to them directly. They will have to choose
            their own before they can use the console.
          </p>
          <div className="inline-form">
            <div>
              <label htmlFor="action-password">Temporary password</label>
              <input
                id="action-password"
                type={revealed ? "text" : "password"}
                autoComplete="new-password"
                value={password}
                placeholder={`at least ${MIN_PASSWORD_LENGTH} characters`}
                onChange={(event) => setPassword(event.target.value)}
              />
            </div>
            <button type="button" className="ghost" onClick={() => setRevealed(!revealed)}>
              {revealed ? "Hide" : "Show"}
            </button>
            <button
              type="button"
              className="ghost"
              onClick={() => {
                setPassword(generatePassword());
                setRevealed(true);
              }}
            >
              Generate
            </button>
          </div>
          {passwordTooShort && (
            <p className="muted small">{MIN_PASSWORD_LENGTH} characters minimum.</p>
          )}
          <div className="banner warn">
            <strong>Copy it before you confirm</strong>
            <p>
              Only an Argon2id hash is stored, so the server cannot show it again and this
              dialog will not repeat it. They are signed out everywhere immediately, and
              every page of the console refuses them until they set their own password.
            </p>
          </div>
        </>
      )}
    </Modal>
  );
}
