import { Navigate, Route, Routes, useLocation } from "react-router-dom";

import Layout from "./components/Layout";
import { useAuth } from "./auth";
import AuditLogPage from "./pages/AuditLogPage";
import ChangePasswordPage from "./pages/ChangePasswordPage";
import DeviceDetailPage from "./pages/DeviceDetailPage";
import AlertsPage from "./pages/AlertsPage";
import DevicesPage from "./pages/DevicesPage";
import EmployeesPage from "./pages/EmployeesPage";
import EnrollPage from "./pages/EnrollPage";
import EnrollmentTokensPage from "./pages/EnrollmentTokensPage";
import LoginPage from "./pages/LoginPage";
import UsersPage from "./pages/UsersPage";

/**
 * Routes that need no account, and are not part of the admin console.
 *
 * Exactly one today: the employee enrollment page. Kept as a list so adding a
 * second is a deliberate edit to a named constant rather than another branch
 * somewhere in the tree.
 */
const PUBLIC_PATHS = ["/enroll"];

export default function App() {
  const { user, loading } = useAuth();
  const { pathname } = useLocation();

  /*
   * Checked BEFORE the loading gate and before the signed-out gate, and the
   * order is the whole point.
   *
   * `AuthProvider` attempts a session restore on mount, so for an employee -
   * who has no session and no account - the component would otherwise render
   * "Restoring session…" and then the administrator login form. Neither is
   * anything they should be shown, and a login form in front of an employee is
   * an invitation to try credentials they do not have.
   *
   * This also keeps the employee page genuinely independent of the admin
   * console: it renders outside `Layout`, so it has no navigation, no sign-out
   * button and no capability-filtered tabs, and it calls only the one public
   * endpoint.
   */
  if (PUBLIC_PATHS.includes(pathname)) {
    return (
      <Routes>
        <Route path="/enroll" element={<EnrollPage />} />
      </Routes>
    );
  }

  if (loading) {
    return (
      <div className="centred">
        <p className="muted">Restoring session…</p>
      </div>
    );
  }

  if (!user) return <LoginPage />;

  /*
   * An administrator has reset this account's password, so the server is
   * refusing every capability-guarded route with `password_change_required`.
   * Rendering the console would mean a page of controls that all 403.
   *
   * This is NOT the enforcement. The server gate in `require_capability` is,
   * and a user who bypassed this screen with curl gets the same refusal. What
   * this does is replace a wall of broken buttons with the one action that
   * resolves the state - which is also why it renders outside `Layout`, with
   * no navigation to pages that would not work.
   */
  if (user.must_change_password) {
    return <ChangePasswordPage forced />;
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/devices" replace />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/devices/:deviceId" element={<DeviceDetailPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/employees" element={<EmployeesPage />} />
        <Route path="/enrollment" element={<EnrollmentTokensPage />} />
        <Route path="/audit" element={<AuditLogPage />} />
        <Route path="/users" element={<UsersPage />} />
        {/* Self-service, available to every role: no capability guards it. */}
        <Route path="/account/password" element={<ChangePasswordPage />} />
        <Route
          path="*"
          element={
            <div className="card">
              <h2>Not found</h2>
              <p className="muted">That page does not exist.</p>
            </div>
          }
        />
      </Routes>
    </Layout>
  );
}
