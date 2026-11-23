import { useCallback, useEffect, useId, useRef, useState } from "react";

import Icon from "./Icon";
import { api } from "../api/client";
import type { DirectoryUserResponse } from "../api/client";

/**
 * The person a device is being issued to.
 *
 * Either `employeeId` is set, meaning somebody already in the employees table,
 * or `name` and `email` are, meaning match-on-email-or-create. Never both: the
 * server refuses a request carrying two different answers to "who is this for".
 */
export interface SelectedEmployee {
  employeeId: string | null;
  name: string;
  email: string;
  department: string | null;
  /**
   * False when the directory thinks this person has left. Carried through to
   * the chosen state so the warning does not disappear the moment somebody is
   * picked, which is precisely when it matters.
   */
  active: boolean;
}

/** Wait this long after the last keystroke before searching. */
const DEBOUNCE_MS = 250;

/**
 * Pick an employee from Microsoft Entra ID, or type one in by hand.
 *
 * Why a picker at all: a token is handed to a specific person, and the admin
 * issuing it knows who. Typing the name produces typos and near-duplicate
 * employee records that differ by a capital letter, and the company already
 * maintains the authoritative list in Entra.
 *
 * Why manual entry survives: a deployment with no Entra credentials is
 * supported, and so is a contractor who is not in the directory. The directory
 * route answers `configured: false` rather than failing, and this falls back to
 * two plain fields.
 */
export default function EmployeePicker({
  value,
  onChange,
  disabled = false,
}: {
  value: SelectedEmployee | null;
  onChange: (next: SelectedEmployee | null) => void;
  disabled?: boolean;
}) {
  const inputId = useId();
  const listId = useId();

  const [query, setQuery] = useState("");
  const [results, setResults] = useState<DirectoryUserResponse[]>([]);
  const [truncated, setTruncated] = useState(false);
  const [open, setOpen] = useState(false);
  const [searching, setSearching] = useState(false);
  /**
   * Show people who appear to have left. Off by default, because most of the
   * 34 the filter hides really are gone, but reachable because the signal is a
   * licence rather than a leave date and it does miss people.
   */
  const [includeInactive, setIncludeInactive] = useState(false);
  const [counts, setCounts] = useState<{ active: number; total: number } | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  /**
   * null = not yet known. Distinguished from false so the fallback form does
   * not flash into view during the first request.
   */
  const [configured, setConfigured] = useState<boolean | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);

  // Manual-entry fields, used when Entra is unconfigured or unreachable, or
  // when the admin chooses to type somebody who is not in the directory.
  const [manual, setManual] = useState(false);
  const [manualName, setManualName] = useState("");
  const [manualEmail, setManualEmail] = useState("");

  const boxRef = useRef<HTMLDivElement | null>(null);
  /**
   * Guards against a slow earlier request overwriting a newer one's results.
   * Without it, typing "ad" then "aditya" can end with the "ad" response
   * landing last and the list disagreeing with the box.
   */
  const latestQuery = useRef("");

  const runSearch = useCallback(async (text: string, withInactive: boolean) => {
    // The key includes the toggle, so flipping it cannot be mistaken for a
    // stale response to the same text and discarded.
    const key = `${withInactive ? "all" : "active"}:${text}`;
    latestQuery.current = key;
    setSearching(true);
    setLookupError(null);
    try {
      const response = await api.searchDirectory(text, 25, withInactive);
      if (latestQuery.current !== key) return;
      setConfigured(response.configured);
      setResults(response.users);
      setTruncated(response.truncated);
      setCounts({ active: response.active_count, total: response.total_count });
      if (!response.configured) setManual(true);
    } catch (caught) {
      if (latestQuery.current !== key) return;
      // Reported inline rather than thrown: a directory that is down must not
      // block issuing a token, so this offers manual entry and says why.
      setLookupError(caught instanceof Error ? caught.message : "Directory lookup failed.");
      setResults([]);
      setManual(true);
    } finally {
      if (latestQuery.current === key) setSearching(false);
    }
  }, []);

  /**
   * Drop the server's cached copy and read Entra again.
   *
   * Offered because the two cases the cache gets wrong are routine: somebody
   * who joined today is missing, and somebody offboarded today is still there.
   */
  const refresh = useCallback(async () => {
    setRefreshing(true);
    setLookupError(null);
    try {
      const fresh = await api.refreshDirectory();
      setCounts({ active: fresh.active_count, total: fresh.total_count });
      await runSearch(query, includeInactive);
    } catch (caught) {
      setLookupError(caught instanceof Error ? caught.message : "Directory refresh failed.");
    } finally {
      setRefreshing(false);
    }
  }, [query, includeInactive, runSearch]);

  // One probe on mount, so an unconfigured directory shows the manual form
  // immediately instead of only after the admin types into a box that will
  // never return anything.
  useEffect(() => {
    void runSearch("", false);
  }, [runSearch]);

  useEffect(() => {
    if (manual || value) return;
    const timer = window.setTimeout(() => void runSearch(query, includeInactive), DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [query, includeInactive, manual, value, runSearch]);

  // Close the result list on an outside click. Without this it stays open over
  // the rest of the form after the admin's attention has moved on.
  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: MouseEvent) {
      if (boxRef.current && !boxRef.current.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onPointerDown);
    return () => document.removeEventListener("mousedown", onPointerDown);
  }, [open]);

  function choose(user: DirectoryUserResponse) {
    onChange({
      // Prefer the existing record. Sending the id keeps one person from
      // becoming two rows when their display name changes in the directory.
      employeeId: user.employee_id,
      name: user.full_name,
      email: user.email,
      department: user.department,
      active: user.active,
    });
    setOpen(false);
    setQuery("");
  }

  function clear() {
    onChange(null);
    setQuery("");
    setManualName("");
    setManualEmail("");
    setOpen(false);
  }

  function commitManual(name: string, email: string) {
    const trimmedName = name.trim();
    const trimmedEmail = email.trim();
    // Both or neither. The server requires them together, and committing a
    // half-filled pair would mint a token that looked assigned and was not.
    onChange(
      trimmedName && trimmedEmail
        ? {
            employeeId: null,
            name: trimmedName,
            email: trimmedEmail,
            department: null,
            // Typed in deliberately by an administrator, so there is nothing to
            // warn about. The directory's opinion is not involved.
            active: true,
          }
        : null,
    );
  }

  // --- Chosen ------------------------------------------------------------ //
  if (value) {
    return (
      <div>
        <span className="field-label">Issued to</span>
        <div className={value.active ? "picker-chosen" : "picker-chosen inactive"}>
          <Icon name={value.active ? "employees" : "alert"} size={16} />
          <div className="picker-chosen-text">
            <strong>{value.name}</strong>
            <span className="muted small">{value.email}</span>
          </div>
          <button type="button" className="ghost small" onClick={clear} disabled={disabled}>
            Change
          </button>
        </div>
        {value.active ? null : (
          <p className="muted small">
            <Icon name="alert" size={14} /> Entra ID has no licence assigned to this
            address, which usually means they have left. Issuing a token anyway is
            allowed — check first.
          </p>
        )}
      </div>
    );
  }

  // --- Manual entry ------------------------------------------------------ //
  if (manual) {
    return (
      <div className="picker-manual">
        <div>
          <label htmlFor={`${inputId}-name`}>Employee name</label>
          <input
            id={`${inputId}-name`}
            value={manualName}
            placeholder="e.g. Aditya Jain"
            disabled={disabled}
            onChange={(event) => {
              setManualName(event.target.value);
              commitManual(event.target.value, manualEmail);
            }}
          />
        </div>
        <div>
          <label htmlFor={`${inputId}-email`}>Employee email</label>
          <input
            id={`${inputId}-email`}
            type="email"
            value={manualEmail}
            placeholder="e.g. aditya@seesec.io"
            disabled={disabled}
            onChange={(event) => {
              setManualEmail(event.target.value);
              commitManual(manualName, event.target.value);
            }}
          />
        </div>
        <p className="muted small">
          {lookupError ? (
            <>
              <Icon name="alert" size={14} /> {lookupError} Enter the employee by hand for
              now.
            </>
          ) : configured === false ? (
            "Microsoft Entra ID is not configured, so employees are entered by hand. Set the Entra credentials on the server to search the company directory instead."
          ) : (
            "Matched against existing employees by email, so entering somebody twice will not create a duplicate record."
          )}
          {configured ? (
            <>
              {" "}
              <button
                type="button"
                className="link-button"
                onClick={() => {
                  setManual(false);
                  setLookupError(null);
                  clear();
                }}
              >
                Search the directory instead
              </button>
            </>
          ) : null}
        </p>
      </div>
    );
  }

  // --- Directory search -------------------------------------------------- //
  return (
    <div ref={boxRef} className="picker">
      <label htmlFor={inputId}>Issue to employee</label>
      <div className="picker-input">
        <Icon name="search" size={16} />
        <input
          id={inputId}
          value={query}
          placeholder="Search name or email…"
          autoComplete="off"
          role="combobox"
          aria-expanded={open}
          aria-controls={listId}
          disabled={disabled}
          onFocus={() => setOpen(true)}
          onChange={(event) => {
            setQuery(event.target.value);
            setOpen(true);
          }}
        />
        {searching ? <span className="muted small">…</span> : null}
      </div>

      {open && (
        <ul id={listId} className="picker-list" role="listbox">
          {results.map((user) => (
            <li key={user.external_id}>
              <button type="button" className="picker-option" onClick={() => choose(user)}>
                <span className="picker-option-name">
                  {user.full_name}
                  {user.employee_id ? (
                    <span className="pill small-pill" title="Already an employee record">
                      known
                    </span>
                  ) : null}
                  {user.active ? null : (
                    <span
                      className="pill warn-pill"
                      title="No licence assigned, which usually means they have left"
                    >
                      probably left
                    </span>
                  )}
                </span>
                <span className="muted small">
                  {user.email}
                  {user.job_title ? ` · ${user.job_title}` : ""}
                </span>
              </button>
            </li>
          ))}
          {results.length === 0 && !searching && (
            <li className="picker-empty muted small">
              {query ? (
                includeInactive ? (
                  `Nobody in the directory matches "${query}".`
                ) : (
                  <>
                    No current employee matches &ldquo;{query}&rdquo;.{" "}
                    {/* Offered here, not only in the line below the box: the
                        result list covers that line while it is open, and this
                        is the moment the admin wants it. */}
                    <button
                      type="button"
                      className="link-button"
                      onClick={() => setIncludeInactive(true)}
                    >
                      Search everyone, including people who have left
                    </button>
                  </>
                )
              ) : (
                "No employees found."
              )}
            </li>
          )}
          {truncated && (
            <li className="picker-empty muted small">
              More people match. Keep typing to narrow the list.
            </li>
          )}
        </ul>
      )}

      <p className="muted small picker-foot">
        {counts ? (
          <>
            Showing{" "}
            {includeInactive
              ? `all ${counts.total} people in Microsoft Entra ID`
              : `${counts.active} current employees`}
            {!includeInactive && counts.total > counts.active ? (
              <>
                {" "}
                · {counts.total - counts.active} hidden as probably left
                <span
                  className="hint-mark"
                  title="Somebody counts as current if they hold a paid licence. This tenant leaves a leaver's account enabled and records no leave date, so a licence is the best signal available - but it is a guess, not a fact."
                >
                  ?
                </span>
              </>
            ) : null}
          </>
        ) : (
          "Read from Microsoft Entra ID."
        )}{" "}
        <button
          type="button"
          className="link-button"
          onClick={() => setIncludeInactive((previous) => !previous)}
          disabled={disabled}
        >
          {includeInactive ? "Show current only" : "Show everyone"}
        </button>
        {" · "}
        <button
          type="button"
          className="link-button"
          onClick={() => void refresh()}
          disabled={disabled || refreshing}
          title="Re-read Entra ID now, for somebody who joined or left today"
        >
          {refreshing ? "Refreshing…" : "Refresh"}
        </button>
        {" · "}
        <button
          type="button"
          className="link-button"
          onClick={() => {
            setManual(true);
            setOpen(false);
          }}
        >
          Enter by hand
        </button>
      </p>
    </div>
  );
}
