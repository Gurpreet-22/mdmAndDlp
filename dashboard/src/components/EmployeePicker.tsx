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

  const runSearch = useCallback(async (text: string) => {
    latestQuery.current = text;
    setSearching(true);
    setLookupError(null);
    try {
      const response = await api.searchDirectory(text);
      if (latestQuery.current !== text) return;
      setConfigured(response.configured);
      setResults(response.users);
      setTruncated(response.truncated);
      if (!response.configured) setManual(true);
    } catch (caught) {
      if (latestQuery.current !== text) return;
      // Reported inline rather than thrown: a directory that is down must not
      // block issuing a token, so this offers manual entry and says why.
      setLookupError(caught instanceof Error ? caught.message : "Directory lookup failed.");
      setResults([]);
      setManual(true);
    } finally {
      if (latestQuery.current === text) setSearching(false);
    }
  }, []);

  // One probe on mount, so an unconfigured directory shows the manual form
  // immediately instead of only after the admin types into a box that will
  // never return anything.
  useEffect(() => {
    void runSearch("");
  }, [runSearch]);

  useEffect(() => {
    if (manual || value) return;
    const timer = window.setTimeout(() => void runSearch(query), DEBOUNCE_MS);
    return () => window.clearTimeout(timer);
  }, [query, manual, value, runSearch]);

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
        ? { employeeId: null, name: trimmedName, email: trimmedEmail, department: null }
        : null,
    );
  }

  // --- Chosen ------------------------------------------------------------ //
  if (value) {
    return (
      <div>
        <span className="field-label">Issued to</span>
        <div className="picker-chosen">
          <Icon name="employees" size={16} />
          <div className="picker-chosen-text">
            <strong>{value.name}</strong>
            <span className="muted small">{value.email}</span>
          </div>
          <button type="button" className="ghost small" onClick={clear} disabled={disabled}>
            Change
          </button>
        </div>
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
              {query ? `Nobody in the directory matches "${query}".` : "No employees found."}
            </li>
          )}
          {truncated && (
            <li className="picker-empty muted small">
              More people match. Keep typing to narrow the list.
            </li>
          )}
        </ul>
      )}

      <p className="muted small">
        Read from Microsoft Entra ID. The device assigns itself to this person when it
        enrols.{" "}
        <button
          type="button"
          className="link-button"
          onClick={() => {
            setManual(true);
            setOpen(false);
          }}
        >
          Not in the directory?
        </button>
      </p>
    </div>
  );
}
