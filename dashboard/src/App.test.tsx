import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import App from "./App";
import { AuthContext } from "./auth";
import type { MeResponse } from "./api/client";

/**
 * Top-level routing: who sees what.
 *
 * Three gates, in order, and the order is the behaviour being pinned:
 *
 *   1. a public path (`/enroll`) renders before anything about sessions;
 *   2. an account owing a password change gets only that screen;
 *   3. a signed-out visitor gets the login page.
 *
 * The second is the one worth testing hardest, and worth being precise about:
 * it is **not** the security control. The server refuses every
 * capability-guarded route with `password_change_required`, which
 * `test_user_management.py` proves over real HTTP. What these tests check is
 * that the dashboard does not present a console whose every button would 403.
 */

const BASE: MeResponse = {
  user_id: "11111111-2222-3333-4444-555555555555",
  email: "someone@example.invalid",
  role: "super_admin",
  capabilities: [
    "device_read",
    "manage_users",
    "enrollment_token_manage",
    "audit_read",
  ],
  must_change_password: false,
};

function renderApp(options: {
  user?: MeResponse | null;
  loading?: boolean;
  path?: string;
}) {
  const value = {
    user: options.user === undefined ? BASE : options.user,
    loading: options.loading ?? false,
    login: vi.fn(async () => undefined),
    logout: vi.fn(async () => undefined),
    refresh: vi.fn(async () => undefined),
    can: (capability: string) =>
      (options.user === undefined ? BASE : options.user)?.capabilities.includes(capability) ??
      false,
  };
  return render(
    <MemoryRouter initialEntries={[options.path ?? "/devices"]}>
      <AuthContext.Provider value={value}>
        <App />
      </AuthContext.Provider>
    </MemoryRouter>,
  );
}

describe("App routing", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    // Pages under the console fetch on mount. Stubbed so these tests are
    // about routing, not about what any one page displays.
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("[]", { status: 200, headers: { "content-type": "application/json" } }),
    );
  });

  describe("a user owing a password change", () => {
    const forced: MeResponse = { ...BASE, must_change_password: true };

    it("is shown the forced password-change screen", () => {
      renderApp({ user: forced });
      expect(screen.getByText(/an administrator reset your password/i)).toBeTruthy();
      expect(screen.getByText(/set a new password/i)).toBeTruthy();
    });

    it("is not shown the console navigation", () => {
      renderApp({ user: forced });
      // The forced screen renders outside `Layout`, so none of the tabs exist.
      // A visible "Devices" tab would be an invitation to a 403.
      expect(screen.queryByRole("link", { name: /devices/i })).toBeNull();
      expect(screen.queryByRole("link", { name: /enrollment/i })).toBeNull();
      expect(screen.queryByRole("link", { name: /administrators/i })).toBeNull();
      expect(screen.queryByRole("link", { name: /audit log/i })).toBeNull();
    });

    it("sees the same screen whatever path they land on", () => {
      // Including a deep link they bookmarked. The gate is on the session
      // state, not on the route, so no path escapes it.
      for (const path of ["/devices", "/users", "/audit", "/enrollment", "/devices/abc"]) {
        const { unmount } = renderApp({ user: forced, path });
        expect(screen.getByText(/an administrator reset your password/i)).toBeTruthy();
        unmount();
      }
    });

    it("still reaches the enrollment page, which belongs to employees", () => {
      // `/enroll` is public and has nothing to do with the admin session, so a
      // forced administrator must not be trapped away from it.
      renderApp({ user: forced, path: "/enroll" });
      expect(screen.getByText(/device enrollment for company ubuntu laptops/i)).toBeTruthy();
    });
  });

  describe("an ordinary signed-in user", () => {
    it("is shown the console, not the password screen", () => {
      renderApp({ user: BASE, path: "/devices" });
      expect(screen.queryByText(/an administrator reset your password/i)).toBeNull();
      expect(screen.getByRole("link", { name: /devices/i })).toBeTruthy();
    });

    it("can reach the self-service password page", () => {
      renderApp({ user: BASE, path: "/account/password" });
      expect(screen.getByText(/change your password/i)).toBeTruthy();
      // Inside the console, so navigation is still present - this is a
      // voluntary visit, not a lockout.
      expect(screen.getByRole("link", { name: /devices/i })).toBeTruthy();
    });

    it("is offered a link to the password page from the header", () => {
      renderApp({ user: BASE });
      expect(screen.getByRole("link", { name: /^password$/i })).toBeTruthy();
    });
  });

  describe("a signed-out visitor", () => {
    it("gets the login page", () => {
      renderApp({ user: null });
      expect(screen.getByLabelText(/email/i)).toBeTruthy();
      expect(screen.getByRole("button", { name: /sign in/i })).toBeTruthy();
    });

    it("gets the public enrollment page without a session", () => {
      renderApp({ user: null, path: "/enroll" });
      expect(screen.getByText(/device enrollment for company ubuntu laptops/i)).toBeTruthy();
      // No login form: an employee has no account and must not be asked for one.
      expect(screen.queryByRole("button", { name: /sign in/i })).toBeNull();
    });

    it("sees the enrollment page even while a session restore is in flight", () => {
      // The public branch is checked before the loading gate, so an employee
      // never sees "Restoring session…" on a page that has no session.
      renderApp({ user: null, loading: true, path: "/enroll" });
      expect(screen.queryByText(/restoring session/i)).toBeNull();
    });
  });

  it("shows a restoring message while the session is being recovered", () => {
    renderApp({ user: null, loading: true, path: "/devices" });
    expect(screen.getByText(/restoring session/i)).toBeTruthy();
  });
});
