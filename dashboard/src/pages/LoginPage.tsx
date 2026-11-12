import { useEffect, useState } from "react";

import ErrorBanner from "../components/ErrorBanner";
import { api } from "../api/client";
import { useAuth } from "../auth";

export default function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  /**
   * Whether this server is checking credentials at all. Null until the answer
   * arrives, so the page never flashes the wrong explanation of what the form
   * is about to do.
   */
  const [anyLogin, setAnyLogin] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const mode = await api.authMode();
        if (!cancelled) setAnyLogin(mode.any_login);
      } catch {
        // An unreachable server will report itself through the login attempt.
        // Assume real authentication: claiming otherwise would be worse.
        if (!cancelled) setAnyLogin(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await login(email, password);
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="centred">
      <form className="card login" onSubmit={submit}>
        <div className="brand large">
          <span className="brand-mark" aria-hidden="true" />
          <span>UbuntuGuard</span>
        </div>
        <p className="muted">Sign in to the management console.</p>

        {anyLogin === true && (
          <div className="banner warn">
            <div className="banner-head">
              <strong>Authentication is disabled</strong>
              <code className="code-chip">dev only</code>
            </div>
            <p>
              Any email and password will sign you in, and the account is created the first
              time its address is used. Your password is not checked, not stored, and not
              recorded. This is a placeholder until Microsoft SSO is wired in.
            </p>
          </div>
        )}

        <ErrorBanner error={error} />

        <label htmlFor="email">Email</label>
        <input
          id="email"
          type="email"
          autoComplete="username"
          required
          value={email}
          onChange={(event) => setEmail(event.target.value)}
        />

        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(event) => setPassword(event.target.value)}
        />

        <button type="submit" disabled={busy || !email || !password}>
          {busy ? "Signing in…" : "Sign in"}
        </button>

        {/*
          With real authentication on, the server returns one identical body for
          a wrong password, an unknown account and a locked account, so this note
          explains the deliberate vagueness rather than the UI inventing a more
          specific message. With it off, none of that applies and saying so would
          be misleading.
        */}
        {anyLogin === false && (
          <p className="muted small">
            Five failed attempts in ten minutes locks the account for fifteen minutes.
            Failures are reported without saying which part was wrong.
          </p>
        )}
      </form>
    </div>
  );
}
