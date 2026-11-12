import { useCallback, useEffect, useState } from "react";

import ErrorBanner from "../components/ErrorBanner";
import { api } from "../api/client";
import type { CreateEnrollmentTokenResponse, EnrollmentTokenResponse } from "../api/client";

const TTL_CHOICES = [
  { label: "1 hour", seconds: 3600 },
  { label: "8 hours", seconds: 28800 },
  { label: "24 hours", seconds: 86400 },
];

export default function EnrollmentTokensPage() {
  const [tokens, setTokens] = useState<EnrollmentTokenResponse[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [label, setLabel] = useState("");
  const [ttl, setTtl] = useState(86400);
  const [busy, setBusy] = useState(false);
  /** Held only in component state. Gone on navigation, which is intended. */
  const [justCreated, setJustCreated] = useState<CreateEnrollmentTokenResponse | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    setError(null);
    try {
      setTokens(await api.listEnrollmentTokens(50));
    } catch (caught) {
      setError(caught);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function create() {
    setBusy(true);
    setError(null);
    setCopied(false);
    try {
      setJustCreated(await api.createEnrollmentToken(label, ttl));
      setLabel("");
      await load();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  async function revoke(tokenId: string) {
    setError(null);
    try {
      await api.revokeEnrollmentToken(tokenId);
      await load();
    } catch (caught) {
      setError(caught);
    }
  }

  return (
    <section>
      <div className="page-head">
        <div>
          <h1>Enrollment</h1>
          <p className="muted">
            A token is 32 random bytes, stored only as a hash, usable once, and expiring
            within 24 hours.
          </p>
        </div>
      </div>

      <ErrorBanner error={error} />

      {justCreated && (
        <div className="banner success">
          <div className="banner-head">
            <strong>Token created — copy it now</strong>
            <code className="code-chip">once only</code>
          </div>
          <p>
            Only the hash is stored on the server, so this value cannot be shown again. If
            it is lost, revoke it and issue another.
          </p>
          <div className="token-row">
            <code className="token">{justCreated.enrollment_token}</code>
            <button
              type="button"
              className="ghost"
              onClick={() => {
                void navigator.clipboard
                  ?.writeText(justCreated.enrollment_token)
                  .then(() => setCopied(true));
              }}
            >
              {copied ? "Copied" : "Copy"}
            </button>
            <button type="button" className="ghost" onClick={() => setJustCreated(null)}>
              Dismiss
            </button>
          </div>
          <p className="muted small">Expires {justCreated.expires_at}</p>
        </div>
      )}

      <div className="card">
        <h2>Create a token</h2>
        <div className="inline-form">
          <div>
            <label htmlFor="label">Label (optional)</label>
            <input
              id="label"
              value={label}
              placeholder="e.g. finance laptop 014"
              onChange={(event) => setLabel(event.target.value)}
            />
          </div>
          <div>
            <label htmlFor="ttl">Valid for</label>
            <select
              id="ttl"
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
          <button type="button" onClick={() => void create()} disabled={busy}>
            {busy ? "Creating…" : "Create token"}
          </button>
        </div>
      </div>

      <div className="card table-card">
        <h2>Issued tokens</h2>
        <table>
          <thead>
            <tr>
              <th>Label</th>
              <th>Status</th>
              <th>Created</th>
              <th>Expires</th>
              <th>Device</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {tokens.map((token) => (
              <tr key={token.id}>
                <td>{token.label ?? <span className="muted">no label</span>}</td>
                <td>
                  <span className={`pill ${token.status}`}>{token.status}</span>
                </td>
                <td className="muted small">{token.created_at}</td>
                <td className="muted small">{token.expires_at}</td>
                <td className="mono small">
                  {token.consumed_by_device_id ? (
                    <a href={`/devices/${token.consumed_by_device_id}`}>
                      {token.consumed_by_device_id.slice(0, 8)}…
                    </a>
                  ) : (
                    "—"
                  )}
                </td>
                <td>
                  {token.status === "active" && (
                    <button
                      type="button"
                      className="ghost small"
                      onClick={() => void revoke(token.id)}
                    >
                      Revoke
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {tokens.length === 0 && (
              <tr>
                <td colSpan={6} className="muted centred-cell">
                  No tokens yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
        <p className="muted small">
          Neither the token nor its hash appears in this list. A hash plus a captured
          plaintext would confirm which token was which.
        </p>
      </div>
    </section>
  );
}
