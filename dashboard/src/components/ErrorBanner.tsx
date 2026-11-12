import { ApiError } from "../api/client";

/**
 * Renders a server problem document.
 *
 * Shows the machine-readable `code` alongside the human text, because the codes
 * are stable and are what a bug report should quote. Field errors are listed
 * individually so a form can be corrected without guessing.
 */
export default function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null;

  if (error instanceof ApiError) {
    return (
      <div className="banner error" role="alert">
        <div className="banner-head">
          <strong>{error.problem?.title ?? "Request failed"}</strong>
          <code className="code-chip">{error.code}</code>
        </div>
        <p>{error.message}</p>
        {error.fieldErrors.length > 0 && (
          <ul className="field-errors">
            {error.fieldErrors.map((field) => (
              <li key={`${field.field}:${field.message}`}>
                <code>{field.field || "body"}</code> {field.message}
              </li>
            ))}
          </ul>
        )}
        {error.problem?.request_id && (
          <p className="muted small">
            Request id <code>{error.problem.request_id}</code> — quote this when reporting it;
            the server log and the audit entry carry the same value.
          </p>
        )}
      </div>
    );
  }

  return (
    <div className="banner error" role="alert">
      <strong>Something went wrong</strong>
      <p>{error instanceof Error ? error.message : String(error)}</p>
    </div>
  );
}
