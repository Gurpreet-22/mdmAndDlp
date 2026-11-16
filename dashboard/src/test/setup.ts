import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

/**
 * Unmount everything between tests.
 *
 * Without this, components stay in the document and `getByLabelText` starts
 * finding two matching elements - the one from this test and the one from the
 * last. The failure reads as an ambiguous query rather than as leaked state,
 * which sends you looking in the wrong place.
 */
afterEach(() => {
  cleanup();
});

/**
 * Minimal `<dialog>` support, which jsdom does not implement.
 *
 * `Modal.tsx` deliberately uses the native element and `showModal()`, because
 * the browser then supplies focus trapping, inertness and Escape handling that
 * a hand-rolled overlay usually gets wrong. jsdom provides the element but
 * neither method, so without this every test that mounts a modal fails with
 * `dialog.showModal is not a function`.
 *
 * What is shimmed is only the part the component observes: the `open`
 * property, which is what it reads to decide whether to call `showModal` or
 * `close`. Focus trapping and inertness are real browser behaviour and are
 * deliberately NOT faked - a test asserting focus containment against this
 * shim would be asserting the shim, so no test here makes that claim.
 *
 * `cancel` is dispatched by `close()` so the component's Escape path stays
 * reachable from a test that wants it.
 */
if (typeof HTMLDialogElement !== "undefined") {
  if (!HTMLDialogElement.prototype.showModal) {
    HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
      this.open = true;
    };
  }
  if (!HTMLDialogElement.prototype.show) {
    HTMLDialogElement.prototype.show = function show(this: HTMLDialogElement) {
      this.open = true;
    };
  }
  if (!HTMLDialogElement.prototype.close) {
    HTMLDialogElement.prototype.close = function close(
      this: HTMLDialogElement,
      returnValue?: string,
    ) {
      this.open = false;
      if (returnValue !== undefined) this.returnValue = returnValue;
      this.dispatchEvent(new Event("close"));
    };
  }
}
