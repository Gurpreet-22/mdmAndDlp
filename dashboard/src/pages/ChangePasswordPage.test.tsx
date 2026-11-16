import { describe, expect, it, vi, beforeEach } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";

import ChangePasswordPage from "./ChangePasswordPage";
import { api, ApiError } from "../api/client";
import type { MeResponse } from "../api/client";
import { AuthContext } from "../auth";

/**
 * Behaviour of the self-service and forced password-change screen.
 *
 * What these tests are for, and what they are not. The server is the
 * enforcement: a user who never loads this page and calls the API directly is
 * refused by `require_capability`, and `test_user_management.py` proves that
 * with real HTTP. These tests cover the half the backend cannot - that the
 * form refuses to submit a mismatch the server could not detect, that the
 * forced variant offers no way into the console, and that completing a change
 * causes the app to re-read its own state rather than stay on the screen.
 */

const USER: MeResponse = {
  user_id: "11111111-2222-3333-4444-555555555555",
  email: "someone@example.invalid",
  role: "it_admin",
  capabilities: ["device_read"],
  must_change_password: false,
};

function renderPage(options: { forced?: boolean; user?: MeResponse } = {}) {
  const logout = vi.fn(async () => undefined);
  const refresh = vi.fn(async () => undefined);
  const value = {
    user: options.user ?? USER,
    loading: false,
    login: vi.fn(async () => undefined),
    logout,
    refresh,
    can: (capability: string) => (options.user ?? USER).capabilities.includes(capability),
  };
  const rendered = render(
    <AuthContext.Provider value={value}>
      <ChangePasswordPage forced={options.forced ?? false} />
    </AuthContext.Provider>,
  );
  return { ...rendered, logout, refresh };
}

function fill(current: string, next: string, confirm: string) {
  fireEvent.change(screen.getByLabelText(/current password|temporary password/i), {
    target: { value: current },
  });
  fireEvent.change(screen.getByLabelText("New password"), { target: { value: next } });
  fireEvent.change(screen.getByLabelText("Confirm new password"), {
    target: { value: confirm },
  });
}

function submitButton(): HTMLButtonElement {
  return screen.getByRole("button", { name: /change password/i }) as HTMLButtonElement;
}

describe("ChangePasswordPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("submits the current and new password to the API", async () => {
    const change = vi.spyOn(api, "changeOwnPassword").mockResolvedValue(undefined);
    const { refresh } = renderPage();

    fill("the current passphrase", "a brand new passphrase", "a brand new passphrase");
    submitButton().click();

    await waitFor(() => expect(change).toHaveBeenCalledTimes(1));
    expect(change).toHaveBeenCalledWith("the current passphrase", "a brand new passphrase");
    // The app must re-read /auth/me, or a completed forced change would leave
    // the user staring at the screen they just satisfied.
    await waitFor(() => expect(refresh).toHaveBeenCalled());
  });

  it("will not submit when the two new passwords differ", async () => {
    const change = vi.spyOn(api, "changeOwnPassword").mockResolvedValue(undefined);
    renderPage();

    fill("the current passphrase", "a brand new passphrase", "a brand new passphras");

    expect(submitButton().disabled).toBe(true);
    expect(screen.getByText(/do not match/i)).toBeTruthy();
    expect(change).not.toHaveBeenCalled();
  });

  it("will not submit a new password below the minimum length", async () => {
    const change = vi.spyOn(api, "changeOwnPassword").mockResolvedValue(undefined);
    renderPage();

    fill("the current passphrase", "short", "short");

    expect(submitButton().disabled).toBe(true);
    expect(screen.getByText(/12 characters minimum/i)).toBeTruthy();
    expect(change).not.toHaveBeenCalled();
  });

  it("will not submit a new password equal to the current one", async () => {
    const change = vi.spyOn(api, "changeOwnPassword").mockResolvedValue(undefined);
    renderPage();

    fill("the same long passphrase", "the same long passphrase", "the same long passphrase");

    expect(submitButton().disabled).toBe(true);
    expect(screen.getByText(/must be different/i)).toBeTruthy();
    expect(change).not.toHaveBeenCalled();
  });

  it("renders the server's refusal rather than inventing one", async () => {
    // `password_unchanged` is a server decision the form cannot make: it knows
    // only what was typed, not what the stored hash verifies against.
    vi.spyOn(api, "changeOwnPassword").mockRejectedValue(
      new ApiError(
        409,
        {
          type: "about:blank",
          title: "Conflict",
          status: 409,
          code: "password_unchanged",
          detail: "The new password must be different from the current one.",
        },
        "Conflict",
      ),
    );
    renderPage();

    fill("the current passphrase", "a different passphrase", "a different passphrase");
    submitButton().click();

    await waitFor(() => expect(screen.getByText(/must be different from the current one/i)).toBeTruthy());
    // The stable code is shown, because that is what a bug report should quote.
    expect(screen.getByText("password_unchanged")).toBeTruthy();
  });

  it("shows the wrong-current-password refusal without clearing the form", async () => {
    vi.spyOn(api, "changeOwnPassword").mockRejectedValue(
      new ApiError(
        401,
        {
          type: "about:blank",
          title: "Authentication failed",
          status: 401,
          code: "invalid_credentials",
          detail: "Authentication failed.",
        },
        "Unauthorized",
      ),
    );
    renderPage();

    fill("the wrong passphrase", "a brand new passphrase", "a brand new passphrase");
    submitButton().click();

    await waitFor(() => expect(screen.getByText("invalid_credentials")).toBeTruthy());
    // The new password is still there, so the user retypes one field not three.
    expect((screen.getByLabelText("New password") as HTMLInputElement).value).toBe(
      "a brand new passphrase",
    );
  });

  describe("the forced variant", () => {
    it("explains that an administrator reset the password", () => {
      renderPage({ forced: true, user: { ...USER, must_change_password: true } });
      expect(screen.getByText(/an administrator reset your password/i)).toBeTruthy();
    });

    it("says the restriction is enforced by the server", () => {
      renderPage({ forced: true, user: { ...USER, must_change_password: true } });
      // The honesty requirement: the UI must not imply it is the control.
      expect(screen.getByText(/enforced by the server, not just hidden here/i)).toBeTruthy();
    });

    it("offers signing out and nothing else as a way off the screen", () => {
      renderPage({ forced: true, user: { ...USER, must_change_password: true } });

      const buttons = screen
        .getAllByRole("button")
        .map((button) => button.textContent?.trim().toLowerCase() ?? "");

      expect(buttons).toContain("sign out instead");
      // No navigation into the console: any link would 403 on arrival.
      expect(screen.queryAllByRole("link")).toHaveLength(0);
    });

    it("signs out when asked", async () => {
      const { logout } = renderPage({
        forced: true,
        user: { ...USER, must_change_password: true },
      });

      screen.getByRole("button", { name: /sign out instead/i }).click();
      await waitFor(() => expect(logout).toHaveBeenCalledTimes(1));
    });

    it("labels the first field as the temporary password", () => {
      renderPage({ forced: true, user: { ...USER, must_change_password: true } });
      // "Current password" would be misleading: the user did not choose it.
      expect(screen.getByLabelText("Temporary password")).toBeTruthy();
    });

    it("tells the user to contact an administrator if unexpected", () => {
      renderPage({ forced: true, user: { ...USER, must_change_password: true } });
      expect(screen.getByText(/contact your administrator/i)).toBeTruthy();
    });
  });

  it("never renders either password into the document", async () => {
    vi.spyOn(api, "changeOwnPassword").mockResolvedValue(undefined);
    const { container } = renderPage();

    fill("the current passphrase", "a brand new passphrase", "a brand new passphrase");
    submitButton().click();
    await waitFor(() => expect(screen.queryByText(/changing…/i)).toBeNull());

    // Values live in input elements, which is unavoidable, but neither may
    // appear as page TEXT - a success banner echoing the new password would.
    expect(container.textContent).not.toContain("a brand new passphrase");
    expect(container.textContent).not.toContain("the current passphrase");
  });

  it("masks the password fields until the user asks to see them", async () => {
    renderPage();

    const next = screen.getByLabelText("New password") as HTMLInputElement;
    expect(next.type).toBe("password");

    screen.getByRole("button", { name: /show passwords/i }).click();
    await waitFor(() =>
      expect((screen.getByLabelText("New password") as HTMLInputElement).type).toBe("text"),
    );
  });
});
