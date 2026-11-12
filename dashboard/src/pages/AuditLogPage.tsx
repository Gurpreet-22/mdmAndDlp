import { useCallback, useEffect, useState } from "react";

import ErrorBanner from "../components/ErrorBanner";
import { api } from "../api/client";
import type { AuditEntryResponse, ChainVerificationResponse } from "../api/client";

const PAGE_SIZE = 50;

export default function AuditLogPage() {
  const [entries, setEntries] = useState<AuditEntryResponse[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [verification, setVerification] = useState<ChainVerificationResponse | null>(null);
  const [cursor, setCursor] = useState<number | null>(null);
  const [exhausted, setExhausted] = useState(false);
  const [busy, setBusy] = useState(false);

  const loadPage = useCallback(async (afterSeq: number | null, replace: boolean) => {
    setBusy(true);
    setError(null);
    try {
      const page = await api.listAuditEntries(afterSeq, PAGE_SIZE);
      setEntries((previous) => (replace ? page : [...previous, ...page]));
      setExhausted(page.length < PAGE_SIZE);
      const last = page.at(-1);
      if (last) setCursor(last.seq);
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => {
    void loadPage(null, true);
  }, [loadPage]);

  async function verify() {
    setError(null);
    try {
      setVerification(await api.verifyAuditChain());
    } catch (caught) {
      setError(caught);
    }
  }

  return (
    <section>
      <div className="page-head">
        <div>
          <h1>Audit log</h1>
          <p className="muted">
            Append-only and hash-chained: each entry's hash covers the previous one, so an
            edit, a deletion or a reordered row is detectable and localised to a sequence
            number.
          </p>
        </div>
        <button type="button" className="ghost" onClick={() => void verify()}>
          Verify chain
        </button>
      </div>

      <ErrorBanner error={error} />

      {verification && (
        <div className={`banner ${verification.ok ? "success" : "error"}`}>
          <div className="banner-head">
            <strong>
              {verification.ok ? "Chain intact" : `Chain broken at entry ${verification.broken_at_seq}`}
            </strong>
            <code className="code-chip">{verification.checked} checked</code>
          </div>
          {verification.reason && <p>{verification.reason}</p>}
          {verification.ok && (
            <p className="muted small">
              The application's database role holds only SELECT and INSERT here, so
              PostgreSQL refuses an edit outright. This check catches a change made around
              the application. A database superuser could still rewrite the table and
              recompute every hash — detecting that needs the chain head anchored outside
              the database, which is not built.
            </p>
          )}
        </div>
      )}

      <div className="card table-card">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>When</th>
              <th>Action</th>
              <th>Actor</th>
              <th>Target</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr key={entry.seq}>
                <td className="mono small">{entry.seq}</td>
                <td className="muted small">{entry.occurred_at}</td>
                <td>
                  <span
                    className={`pill ${entry.action.includes("failed") || entry.action.includes("revoked") || entry.action.includes("reuse") ? "warn" : "neutral"}`}
                  >
                    {entry.action}
                  </span>
                </td>
                <td className="small">
                  {entry.actor_id ? (
                    <>
                      <span className="mono">{entry.actor_id.slice(0, 20)}</span>
                      {entry.actor_role && <span className="role-badge">{entry.actor_role}</span>}
                    </>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                <td className="mono small">
                  {entry.target_type ? `${entry.target_type}/${(entry.target_id ?? "").slice(0, 10)}` : "—"}
                </td>
                <td className="small detail-cell">
                  <code>{JSON.stringify(entry.detail)}</code>
                </td>
              </tr>
            ))}
            {entries.length === 0 && !busy && (
              <tr>
                <td colSpan={6} className="muted centred-cell">
                  No entries.
                </td>
              </tr>
            )}
          </tbody>
        </table>

        <div className="table-foot">
          {!exhausted && (
            <button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => void loadPage(cursor, false)}
            >
              {busy ? "Loading…" : "Load more"}
            </button>
          )}
          <span className="muted small">
            {entries.length} shown{exhausted ? ", end of log" : ""}. Ascending order, so a
            page stays independently verifiable.
          </span>
        </div>
      </div>
    </section>
  );
}
