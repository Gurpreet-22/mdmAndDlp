import { beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import UserActionsDialog from "./UserActionsDialog";
import { api, ApiError } from "../api/client";
import type { UserResponse } from "../api/client";

/**
 * The enable / change-role / reset-password dialog.
 *
 * The server owns every decision here - `cannot_change_own_role`,
 * `cannot_demote_last_super_admin`, `user_already_active` are all refusals it
 * returns and this component only renders. So these tests cover what the
 * component is genuinely responsible for: calling the right endpoint with the
 * right arguments, not letting a half-filled form through, keeping the dialog
 * open on a refusal so the message can be read, and never echoing a password.
 */

const TARGET: UserResponse = {
  id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  email: "target@example.invalid",
  role: "it_admin",
  is_active: true,
  must_change_password: false,
  created_at: "2026-01-01T00:00:00Z",
  last_login_at: null,
};

function renderDialog(
  action: "enable" | "role" | "reset-password",
  user: UserResponse = TARGET,
) {
  const onClose = vi.fn();
  const onDone = vi.fn();
  const rendered = render(
    <UserActionsDialog action={action} user={user} onClose={onClose} onDone={onDone} />,
  );
  return { ...rendered, onClose, onDone };
}

function actionButton(label: RegExp): HTMLButtonElement {
  // The footer button, not the row button that opened the dialog - this
  // component renders only the dialog, so there is exactly one match.
  return screen.getByRole("button", { name: label }) as HTMLButtonElement;
}

describe("UserActionsDialog", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  describe("enable", () => {
    const disabled: UserResponse = { ...TARGET, is_active: false };

    it("calls the enable endpoint for the right account", async () => {
      const enable = vi.spyOn(api, "enableUser").mockResolvedValue(undefined);
      const { onDone, onClose } = renderDialog("enable", disabled);

      actionButton(/re-enable account/i).click();

      await waitFor(() => expect(enable).toHaveBeenCalledWith(disabled.id));
      await waitFor(() => expect(onDone).toHaveBeenCalledTimes(1));
      expect(onClose).toHaveBeenCalled();
      // Matcher rather than indexing into mock.calls: under `strict` the
      // element type is possibly-undefined, and a non-null assertion in a test
      // hides exactly the case worth seeing - onDone never being called.
      expect(onDone).toHaveBeenCalledWith(expect.stringContaining("existing password"));
    });

    it("says the account keeps its password and history", () => {
      renderDialog("enable", disabled);
      expect(screen.getByText(/keeps its address, its role, its id/i)).toBeTruthy();
      expect(screen.getByText(/lockout is\s+cleared/i)).toBeTruthy();
    });

    it("keeps the dialog open and shows the refusal when already active", async () => {
      vi.spyOn(api, "enableUser").mockRejectedValue(
        new ApiError(
          409,
          {
            type: "about:blank",
            title: "Conflict",
            status: 409,
            code: "user_already_active",
            detail: "That account is already active.",
          },
          "Conflict",
        ),
      );
      const { onClose } = renderDialog("enable", disabled);

      actionButton(/re-enable account/i).click();

      await waitFor(() => expect(screen.getByText("user_already_active")).toBeTruthy());
      expect(onClose).not.toHaveBeenCalled();
    });
  });

  describe("change role", () => {
    it("defaults to a role other than the one already held", () => {
      renderDialog("role");
      const select = screen.getByLabelText("New role") as HTMLSelectElement;
      // Submitting without touching the control must not produce a
      // `role_unchanged` refusal, so the default is never the current role.
      expect(select.value).not.toBe(TARGET.role);
    });

    it("marks the current role as the current one and disables it", () => {
      renderDialog("role");
      const option = screen
        .getAllByRole("option")
        .find((node) => (node as HTMLOptionElement).value === TARGET.role) as HTMLOptionElement;
      expect(option.disabled).toBe(true);
      expect(option.textContent).toContain("current");
    });

    it("sends the selected role", async () => {
      const change = vi.spyOn(api, "changeUserRole").mockResolvedValue(undefined);
      const { onDone } = renderDialog("role");

      fireEvent.change(screen.getByLabelText("New role"), { target: { value: "auditor" } });
      actionButton(/change role/i).click();

      await waitFor(() => expect(change).toHaveBeenCalledWith(TARGET.id, "auditor"));
      await waitFor(() => expect(onDone).toHaveBeenCalled());
      expect(onDone).toHaveBeenCalledWith(expect.stringContaining("auditor"));
    });

    it("warns that the change signs the account out", () => {
      renderDialog("role");
      expect(screen.getByText(/signs them out everywhere/i)).toBeTruthy();
    });

    it("renders the last-super_admin refusal from the server", async () => {
      // A decision the UI cannot make: it does not know how many active
      // super_admins exist, and must not guess.
      vi.spyOn(api, "changeUserRole").mockRejectedValue(
        new ApiError(
          409,
          {
            type: "about:blank",
            title: "Conflict",
            status: 409,
            code: "cannot_demote_last_super_admin",
            detail: "This is the last active super_admin.",
          },
          "Conflict",
        ),
      );
      const { onClose } = renderDialog("role", { ...TARGET, role: "super_admin" });

      fireEvent.change(screen.getByLabelText("New role"), { target: { value: "auditor" } });
      actionButton(/change role/i).click();

      await waitFor(() =>
        expect(screen.getByText("cannot_demote_last_super_admin")).toBeTruthy(),
      );
      expect(onClose).not.toHaveBeenCalled();
    });

    it("notes what promotion to super_admin grants", () => {
      renderDialog("role");
      fireEvent.change(screen.getByLabelText("New role"), {
        target: { value: "super_admin" },
      });
      expect(screen.getByText(/including yours/i)).toBeTruthy();
    });
  });

  describe("reset password", () => {
    it("will not submit without a password of at least the minimum length", () => {
      const reset = vi.spyOn(api, "resetUserPassword").mockResolvedValue(undefined);
      renderDialog("reset-password");

      expect(actionButton(/reset password/i).disabled).toBe(true);

      fireEvent.change(screen.getByLabelText("Temporary password"), {
        target: { value: "short" },
      });
      expect(actionButton(/reset password/i).disabled).toBe(true);
      expect(screen.getByText(/12 characters minimum/i)).toBeTruthy();
      expect(reset).not.toHaveBeenCalled();
    });

    it("sends the supplied password and reports what happened", async () => {
      const reset = vi.spyOn(api, "resetUserPassword").mockResolvedValue(undefined);
      const { onDone } = renderDialog("reset-password");

      fireEvent.change(screen.getByLabelText("Temporary password"), {
        target: { value: "a temporary passphrase" },
      });
      actionButton(/reset password/i).click();

      await waitFor(() =>
        expect(reset).toHaveBeenCalledWith(TARGET.id, "a temporary passphrase"),
      );
      await waitFor(() => expect(onDone).toHaveBeenCalled());
      expect(onDone).toHaveBeenCalledWith(expect.stringContaining("signed out everywhere"));
      // The message must NOT repeat the credential back into the page.
      expect(onDone).toHaveBeenCalledWith(
        expect.not.stringContaining("a temporary passphrase"),
      );
    });

    it("generates a password of usable length", async () => {
      renderDialog("reset-password");

      screen.getByRole("button", { name: /generate/i }).click();

      await waitFor(() => {
        const field = screen.getByLabelText("Temporary password") as HTMLInputElement;
        expect(field.value.length).toBeGreaterThanOrEqual(12);
        // Revealed on generate, because an administrator has to transcribe it.
        expect(field.type).toBe("text");
      });
    });

    it("masks the field by default", () => {
      renderDialog("reset-password");
      expect((screen.getByLabelText("Temporary password") as HTMLInputElement).type).toBe(
        "password",
      );
    });

    it("warns that the password cannot be shown again", () => {
      renderDialog("reset-password");
      expect(screen.getByText(/cannot show it again/i)).toBeTruthy();
      expect(screen.getByText(/refuses them until they set their own password/i)).toBeTruthy();
    });

    it("does not render the typed password as page text", () => {
      const { container } = renderDialog("reset-password");

      fireEvent.change(screen.getByLabelText("Temporary password"), {
        target: { value: "a temporary passphrase" },
      });

      expect(container.textContent).not.toContain("a temporary passphrase");
    });
  });

  it("renders nothing when no action is selected", () => {
    const { container } = render(
      <UserActionsDialog action={null} user={TARGET} onClose={vi.fn()} onDone={vi.fn()} />,
    );
    expect(container.textContent).toBe("");
  });

  it("always shows which account is being acted on", () => {
    renderDialog("role");
    // Three actions, one of which signs somebody out; the wrong row would be a
    // genuine incident, so the address is always on screen.
    expect(screen.getByText(TARGET.email)).toBeTruthy();
  });
});
