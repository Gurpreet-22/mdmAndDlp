import { useEffect, useRef } from "react";
import type { ReactNode } from "react";

/**
 * A modal built on the native `<dialog>` element.
 *
 * `showModal()` rather than a styled div with a high z-index, because the
 * browser then supplies the things a hand-rolled overlay almost always gets
 * wrong: focus is trapped inside the dialog, the page behind becomes inert,
 * Escape closes it, and assistive technology announces it as a dialog.
 *
 * The one behaviour that still has to be wired up by hand is the `cancel`
 * event. Escape fires that rather than a click on anything, so without
 * forwarding it the dialog would close visually while React still believed it
 * was open, and it could not be reopened.
 */
export default function Modal({
  open,
  title,
  onClose,
  children,
  footer,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);

  return (
    <dialog
      ref={ref}
      className="modal"
      aria-label={title}
      onCancel={(event) => {
        // Escape. Prevented and routed through onClose so React state stays
        // the single source of truth for whether the dialog is open.
        event.preventDefault();
        onClose();
      }}
    >
      <div className="modal-head">
        <h2>{title}</h2>
        <button type="button" className="modal-close" aria-label="Close" onClick={onClose}>
          ×
        </button>
      </div>
      <div className="modal-body">{children}</div>
      {footer && <div className="modal-foot">{footer}</div>}
    </dialog>
  );
}
