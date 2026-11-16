import { useState } from "react";

import ErrorBanner from "../components/ErrorBanner";
import { api } from "../api/client";
import { useAuth } from "../auth";

/**
 * Change your own password.
 *
 * Serves two situations with one form, because the mechanics are identical and
 * only the framing differs:
 *
 * `forced` — an administrator reset this account, the server is refusing every
 * other route with `password_change_required`, and this screen is rendered
 * instead of the console. There is no navigation away from it other than
 * signing out, which matches what the backend will actually permit.
 *
 * `forced` false — an ordinary voluntary change, reached from the account menu.
 *
 * The distinction is cosmetic. The enforcement is entirely server-side: a user
 * who skipped this screen and called the API directly gets the same 403. This
 * component's job is to explain why, and to offer the one action that resolves
 * it.
 */

const MIN_PASSWORD_LENGTH = 12;

export default function ChangePasswordPage({ forced = false }: { forced?: boolean }) {
  const { user, logout, refresh } = useAuth();

  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [revealed, setRevealed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [done, setDone] = useState(false);

  const tooShort = next.length > 0 && next.length < MIN_PASSWORD_LENGTH;
  // Checked here as well as on the server, because a typo in a password the
  // user cannot see is the one mistake this form exists to prevent - and the
  // server cannot catch it, since both values look equally valid to it.
  const mismatch = confirm.length > 0 && next !== confirm;
  const sameAsCurrent = next.length > 0 && next === current;

  const canSubmit =
    !busy &&
    current.length > 0 &&
    next.length >= MIN_PASSWORD_LENGTH &&
    next === confirm &&
    !sameAsCurrent;

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.changeOwnPassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setDone(true);
      // Re-read /auth/me so `must_change_password` is refreshed and the app
      // leaves the forced screen. Without this the user would be holding a
      // valid new session while the UI still believed they owed a change.
      await refresh();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={forced ? "centred" : undefined}>
      <form className="card login" onSubmit={submit}>
        <div className="brand large">
          <span className="brand-mark" aria-hidden="true" />
          <span>UbuntuGuard</span>
        </div>

        <h2>{forced ? "Set a new password" : "Change your password"}</h2>

        {forced ? (
          <div className="banner warn">
            <div className="banner-head">
              <strong>An administrator reset your password</strong>
              <code className="code-chip">required</code>
            </div>
            <p>
              The password you just signed in with was chosen by somebody else, so it only
              lets you do one thing: replace it. The rest of the console is unavailable
              until you do — that is enforced by the server, not just hidden here.
            </p>
            <p className="muted small">
              If you did not expect this, sign out and contact your administrator before
              continuing. Every session you had was ended when the reset happened.
            </p>
          </div>
        ) : (
          <p className="muted">
            Signed in as {user?.email}. Changing your password ends every other session you
            have open; this one keeps working.
          </p>
        )}

        {done && !forced && (
          <div className="banner success" role="status">
            <strong>Password changed</strong>
            <p>Your other sessions have been signed out.</p>
          </div>
        )}

        <ErrorBanner error={error} />

        <label htmlFor="current-password">
          {forced ? "Temporary password" : "Current password"}
        </label>
        <input
          id="current-password"
          type="password"
          autoComplete="current-password"
          required
          value={current}
          onChange={(event) => setCurrent(event.target.value)}
        />

        <label htmlFor="new-password">New password</label>
        <input
          id="new-password"
          type={revealed ? "text" : "password"}
          autoComplete="new-password"
          required
          value={next}
          placeholder={`at least ${MIN_PASSWORD_LENGTH} characters`}
          onChange={(event) => setNext(event.target.value)}
        />

        <label htmlFor="confirm-password">Confirm new password</label>
        <input
          id="confirm-password"
          type={revealed ? "text" : "password"}
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(event) => setConfirm(event.target.value)}
        />

        <button type="button" className="ghost" onClick={() => setRevealed(!revealed)}>
          {revealed ? "Hide passwords" : "Show passwords"}
        </button>

        {tooShort && (
          <p className="muted small">
            {MIN_PASSWORD_LENGTH} characters minimum. Length is the only rule — there are no
            composition requirements, because those mostly produce
            &ldquo;Password1!&rdquo;.
          </p>
        )}
        {mismatch && <p className="muted small">The two new passwords do not match.</p>}
        {sameAsCurrent && (
          <p className="muted small">
            The new password must be different from the one you just entered.
          </p>
        )}

        <button type="submit" disabled={!canSubmit}>
          {busy ? "Changing…" : "Change password"}
        </button>

        {forced && (
          <button type="button" className="ghost" onClick={() => void logout()}>
            Sign out instead
          </button>
        )}
      </form>
    </div>
  );
}
