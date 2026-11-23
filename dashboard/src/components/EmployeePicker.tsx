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
   * Show people who appear to have left. Off by default, and turned on only
   * from the empty result row - the one moment it is wanted - rather than
   * sitting on the form as a permanent control.
   */
  const [includeInactive, setIncludeInactive] = useState(false);
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
        {/* Only says something when there is something worth saying. A
            directory that is down needs explaining, because the admin asked
            for a search and got two text boxes. An unconfigured one needs
            nothing: typing a name is simply how this deployment works. */}
        {lookupError ? (
          <p className="muted small">
            <Icon name="alert" size={14} /> {lookupError} Enter the employee by hand for
            now.
          </p>
        ) : null}
        {configured ? (
          <p className="muted small">
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
          </p>
        ) : null}
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
            /* The only place the fallbacks are offered. Putting them on the
               form as permanent links made the enrollment page explain the
               directory's internals to somebody who just wants to pick a
               name; here they appear at the one moment they are useful. */
            <li className="picker-empty muted small">
              {query ? (
                <>
                  No {includeInactive ? "" : "current "}employee matches &ldquo;{query}
                  &rdquo;.{" "}
                  {!includeInactive && (
                    <button
                      type="button"
                      className="link-button"
                      onClick={() => setIncludeInactive(true)}
                    >
                      Include people who have left
                    </button>
                  )}
                  {!includeInactive && " · "}
                  <button
                    type="button"
                    className="link-button"
                    onClick={() => {
                      setManual(true);
                      setOpen(false);
                    }}
                  >
                    Enter manually
                  </button>
                </>
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

    </div>
  );
}
