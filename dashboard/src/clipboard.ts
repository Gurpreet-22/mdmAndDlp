/**
 * Copy to clipboard, including on the plain-HTTP origins this console is
 * actually used from.
 *
 * The bug this exists to fix: every Copy button was
 * `navigator.clipboard?.writeText(value).then(...)`. `navigator.clipboard` is
 * only defined in a secure context - HTTPS, or localhost - and the dashboard
 * is routinely opened over the LAN as `http://10.197.21.245:5173`. There the
 * property is `undefined`, the `?.` short-circuits the entire chain, and the
 * button does nothing at all. No error, no console warning, no feedback. The
 * one value it exists to copy is an enrollment token shown exactly once, so a
 * silent failure means re-issuing it.
 *
 * Three attempts, most capable first, and the caller is always told which way
 * it went so "Copied" is never claimed falsely.
 */

/** What happened, so the caller can say something true. */
export type CopyOutcome = "copied" | "selected" | "failed";

/**
 * Copy `value`, or failing that select it so Ctrl+C works.
 *
 * Returns:
 * - "copied"   - it is on the clipboard.
 * - "selected" - the text is selected in `fallbackNode` and the user must
 *                press Ctrl+C. Offered because a token shown once is worth
 *                salvaging rather than losing.
 * - "failed"   - nothing worked; the caller should tell the user to select it
 *                by hand.
 */
export async function copyText(
  value: string,
  fallbackNode?: HTMLElement | null,
): Promise<CopyOutcome> {
  // 1. The real API, where it exists. Can still reject: the permission may be
  //    denied, or the document may not be focused, so this is not assumed to
  //    succeed just because it is present.
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);
      return "copied";
    } catch {
      // Fall through rather than report failure; the older path often works.
    }
  }

  // 2. `document.execCommand("copy")` against an off-screen textarea.
  //    Deprecated, and the only thing that works on a plain-HTTP origin.
  if (typeof document.execCommand === "function") {
    const area = document.createElement("textarea");
    area.value = value;
    area.setAttribute("readonly", "");
    // Positioned off-screen rather than hidden: `display: none` or
    // `visibility: hidden` cannot hold a selection, so the copy would fail.
    // `top` is kept on-screen-ish and opacity zero to avoid the page
    // scrolling to the element on focus.
    area.style.position = "fixed";
    area.style.top = "0";
    area.style.left = "0";
    area.style.width = "1px";
    area.style.height = "1px";
    area.style.padding = "0";
    area.style.border = "none";
    area.style.opacity = "0";
    document.body.appendChild(area);

    // Restore whatever the user had selected, so copying does not disturb an
    // unrelated selection on the page.
    const previous = document.activeElement as HTMLElement | null;
    try {
      area.focus({ preventScroll: true });
      area.select();
      // iOS Safari ignores select() on a readonly field without this.
      area.setSelectionRange(0, value.length);
      if (document.execCommand("copy")) return "copied";
    } catch {
      // Fall through to selecting the visible text.
    } finally {
      document.body.removeChild(area);
      previous?.focus?.();
    }
  }

  // 3. Nothing could write to the clipboard. Select the on-screen text so the
  //    user can copy it themselves, which is far better than losing a
  //    one-time token.
  if (fallbackNode) {
    try {
      const range = document.createRange();
      range.selectNodeContents(fallbackNode);
      const selection = window.getSelection();
      if (selection) {
        selection.removeAllRanges();
        selection.addRange(range);
        return "selected";
      }
    } catch {
      // Nothing left to try.
    }
  }

  return "failed";
}
