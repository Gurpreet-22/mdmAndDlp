import { useCallback, useEffect, useState } from "react";

import ErrorBanner from "../components/ErrorBanner";
import { api } from "../api/client";
import type { AdminRole, UserResponse } from "../api/client";
import { useAuth } from "../auth";

/**
 * Administrator accounts.
 *
 * This is how accounts get created in normal operation: a super_admin fills in
 * this form, hands the address and first password to its owner, and that person
 * signs in on the login page with their own credentials.
 *
 * There is no self-service sign-up, and that is a deliberate decision rather
 * than an unfinished one. This console pushes policy to every enrolled laptop,
 * so an unauthenticated route that creates an account would let anyone who can
 * reach the login page become a fleet administrator. The only account that
 * cannot be made here is the first one, which comes from the CLI on the server's
 * own disk - the standard bootstrap, and the reason this page can be locked
 * behind `manage_users`.
 */

const ROLES: { value: AdminRole; summary: string }[] = [
  { value: "super_admin", summary: "Everything, including creating accounts and exporting the audit log" },
  { value: "it_admin", summary: "Runs the fleet: enrollment, devices, policy. Cannot export the audit log" },
  { value: "security_analyst", summary: "Investigates: events, incidents, USB exceptions. No fleet changes" },
  { value: "auditor", summary: "Read-only, plus audit export" },
];

const MIN_PASSWORD_LENGTH = 12;

/** Matches the server's default page size. The table says so when it is hit. */
const PAGE_LIMIT = 50;

/** Long enough not to fire on every keystroke, short enough to feel live. */
const SEARCH_DEBOUNCE_MS = 250;

/** A password the administrator does not have to invent. */
function generatePassword(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = new Uint32Array(24);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (value) => alphabet[value % alphabet.length]).join("");
}

export default function UsersPage() {
  const { user: signedInAs } = useAuth();

  const [users, setUsers] = useState<UserResponse[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  const [email, setEmail] = useState("");
  const [role, setRole] = useState<AdminRole>("it_admin");
  const [password, setPassword] = useState("");
  const [revealed, setRevealed] = useState(false);

  /** Held in component state only, so it disappears on navigation. */
  const [justCreated, setJustCreated] = useState<{ email: string; password: string } | null>(null);
  const [copied, setCopied] = useState(false);

  const [search, setSearch] = useState("");

  const load = useCallback(async () => {
    setError(null);
    try {
      setUsers(await api.listUsers(PAGE_LIMIT, search.trim() || undefined));
    } catch (caught) {
      setError(caught);
    }
  }, [search]);

  // Debounced, because `load` changes identity whenever the search box does and
  // an undebounced effect would issue a request per keystroke. `create` and
  // `disable` call `load` directly, so their refresh stays immediate.
  useEffect(() => {
    const timer = setTimeout(() => void load(), SEARCH_DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [load]);

  const tooShort = password.length > 0 && password.length < MIN_PASSWORD_LENGTH;
  const canSubmit = email.trim() !== "" && password.length >= MIN_PASSWORD_LENGTH && !busy;

  async function create() {
    setBusy(true);
    setError(null);
    setCopied(false);
    try {
      const created = await api.createUser(email.trim(), password, role);
      // Shown once, so the administrator can pass it on. The server stored only
      // an Argon2id hash and cannot reproduce it.
      setJustCreated({ email: created.email, password });
      setEmail("");
      setPassword("");
      setRevealed(false);
      await load();
    } catch (caught) {
      setError(caught);
    } finally {
      setBusy(false);
    }
  }

  async function disable(userId: string) {
    setError(null);
    try {
      await api.disableUser(userId);
      await load();
    } catch (caught) {
      setError(caught);
    }
  }

  return (
    <section>
      <div className="page-head">
        <div>
          <h1>Administrators</h1>
          <p className="muted">
            Each person gets their own account and their own password. Create one here, pass
            the credentials on, and they sign in on the login page.
          </p>
        </div>
      </div>

      <ErrorBanner error={error} />

      {justCreated && (
        <div className="banner success">
          <div className="banner-head">
            <strong>Account created — copy the password now</strong>
            <code className="code-chip">once only</code>
          </div>
          <p>
            Only an Argon2id hash is stored, so this password cannot be shown again. If it is
            lost, disable the account and create another.
          </p>
          <div className="token-row">
            <code className="token">
              {justCreated.email} · {justCreated.password}
            </code>
            <button
              type="button"
              className="ghost"
              onClick={() => {
                void navigator.clipboard
                  ?.writeText(justCreated.password)
                  .then(() => setCopied(true));
              }}
            >
              {copied ? "Copied" : "Copy password"}
            </button>
            <button type="button" className="ghost" onClick={() => setJustCreated(null)}>
              Dismiss
            </button>
          </div>
        </div>
      )}

      <div className="card">
        <h2>Create an account</h2>
        <div className="inline-form">
          <div>
            <label htmlFor="new-email">Email</label>
            <input
              id="new-email"
              type="email"
              autoComplete="off"
              value={email}
              placeholder="work email address"
              onChange={(event) => setEmail(event.target.value)}
            />
          </div>
          <div>
            <label htmlFor="new-role">Role</label>
            <select
              id="new-role"
              value={role}
              onChange={(event) => setRole(event.target.value as AdminRole)}
            >
              {ROLES.map((choice) => (
                <option key={choice.value} value={choice.value}>
                  {choice.value.replace(/_/g, " ")}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="new-password">First password</label>
            <input
              id="new-password"
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
          <button type="button" onClick={() => void create()} disabled={!canSubmit}>
            {busy ? "Creating…" : "Create account"}
          </button>
        </div>

        <p className="muted small">
          {role.replace(/_/g, " ")}: {ROLES.find((choice) => choice.value === role)?.summary}
        </p>
        {tooShort && (
          <p className="muted small">
            {MIN_PASSWORD_LENGTH} characters minimum. Length is the only rule — the server
            enforces no composition requirements, because those mostly produce
            &ldquo;Password1!&rdquo;.
          </p>
        )}
      </div>

      <div className="card table-card">
        <h2>Accounts</h2>
        <div className="inline-form">
          <div>
            <label htmlFor="user-search">Search by email</label>
            <input
              id="user-search"
              type="search"
              autoComplete="off"
              value={search}
              placeholder="any part of an address"
              onChange={(event) => setSearch(event.target.value)}
            />
          </div>
          {search !== "" && (
            <button type="button" className="ghost" onClick={() => setSearch("")}>
              Clear
            </button>
          )}
        </div>
        <table>
          <thead>
            <tr>
              <th>Email</th>
              <th>Role</th>
              <th>State</th>
              <th>Created</th>
              <th>Last sign-in</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.map((row) => {
              const isSelf = row.id === signedInAs?.user_id;
              return (
                <tr key={row.id}>
                  <td>
                    {row.email}
                    {isSelf && <span className="role-badge">you</span>}
                  </td>
                  <td>{row.role.replace(/_/g, " ")}</td>
                  <td>
                    <span className={`pill ${row.is_active ? "active" : "revoked"}`}>
                      {row.is_active ? "active" : "disabled"}
                    </span>
                  </td>
                  <td className="muted small">{row.created_at}</td>
                  <td className="muted small">
                    {row.last_login_at ?? <span className="muted">never</span>}
                  </td>
                  <td>
                    {row.is_active && !isSelf && (
                      <button
                        type="button"
                        className="ghost small"
                        onClick={() => void disable(row.id)}
                      >
                        Disable
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
            {users.length === 0 && (
              <tr>
                <td colSpan={6} className="muted centred-cell">
                  {search.trim() === ""
                    ? "No accounts yet."
                    : `No account's address contains "${search.trim()}".`}
                </td>
              </tr>
            )}
          </tbody>
        </table>
        {users.length === PAGE_LIMIT && (
          <p className="muted small">
            Showing the {PAGE_LIMIT} newest
            {search.trim() === "" ? " accounts" : " matches"}. There may be more — search for
            an address to reach it. A full list is available from the server with{" "}
            <code className="code-chip">list-admins</code>.
          </p>
        )}
        <p className="muted small">
          Disabling deactivates the account and revokes its sessions immediately, rather than
          deleting the row, so the audit log keeps pointing at a real account. You cannot
          disable the account you are signed in as.
        </p>
      </div>
    </section>
  );
}
