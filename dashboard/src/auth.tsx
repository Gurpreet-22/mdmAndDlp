import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

import { api, setSessionLostHandler } from "./api/client";
import type { MeResponse } from "./api/client";

/**
 * Session state.
 *
 * On load it tries to restore from the refresh cookie alone, because the access
 * token is held in memory and is therefore gone after a reload. That is the
 * point: nothing readable by a script persists between page loads.
 */

interface AuthState {
  user: MeResponse | null;
  /** True until the initial session-restore attempt finishes. */
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  /**
   * Re-read `/auth/me` and update the cached user.
   *
   * Needed because `must_change_password` changes server-side without any
   * navigation: completing a password change clears it, and the app has to
   * notice in order to stop rendering the forced-change screen. Without this
   * the user would hold a perfectly good new session while the UI still
   * insisted they owed a change.
   */
  refresh: () => Promise<void>;
  /**
   * Whether the signed-in role holds a capability.
   *
   * Used to hide controls the user cannot use. This is COSMETIC: the server
   * checks every call independently, because a hidden button is not a security
   * boundary. Removing a check here would make the UI tidy and change nothing
   * about what the API permits.
   */
  can: (capability: string) => boolean;
}

/**
 * Exported so tests can supply a session directly.
 *
 * The alternative is mounting `AuthProvider` and mocking the API calls it
 * makes on start-up, which couples every component test to the shape of
 * session restoration. Providing the context value states the precondition the
 * test actually cares about - "a signed-in it_admin who owes a password
 * change" - in one line.
 *
 * Application code should use `useAuth`, not this.
 */
export const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<MeResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      const restored = await api.restoreSession();
      if (!cancelled) {
        setUser(restored);
        setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // When the client gives up refreshing, drop straight back to the login page
  // rather than leaving a shell of an app that 401s on every action.
  useEffect(() => {
    setSessionLostHandler(() => setUser(null));
    return () => setSessionLostHandler(null);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    setUser(await api.login(email, password));
  }, []);

  const logout = useCallback(async () => {
    await api.logout();
    setUser(null);
  }, []);

  const refresh = useCallback(async () => {
    // `me()` rather than `restoreSession()`: the caller already holds a valid
    // access token - it was just reissued by the password change - and
    // restoring would spend the refresh cookie for no reason. A failure here
    // leaves the cached user alone rather than signing them out, because the
    // operation that prompted it has already succeeded on the server.
    try {
      setUser(await api.me());
    } catch {
      // Intentionally swallowed; the client's own 401 handling covers a session
      // that has genuinely gone.
    }
  }, []);

  const capabilities = useMemo(() => new Set(user?.capabilities ?? []), [user]);
  const can = useCallback(
    (capability: string) => capabilities.has(capability),
    [capabilities],
  );

  const value = useMemo<AuthState>(
    () => ({ user, loading, login, logout, refresh, can }),
    [user, loading, login, logout, refresh, can],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider");
  return context;
}
