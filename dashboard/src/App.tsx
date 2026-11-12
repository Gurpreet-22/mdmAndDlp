import { Navigate, Route, Routes } from "react-router-dom";

import Layout from "./components/Layout";
import { useAuth } from "./auth";
import AuditLogPage from "./pages/AuditLogPage";
import DeviceDetailPage from "./pages/DeviceDetailPage";
import DevicesPage from "./pages/DevicesPage";
import EnrollmentTokensPage from "./pages/EnrollmentTokensPage";
import LoginPage from "./pages/LoginPage";
import UsersPage from "./pages/UsersPage";

export default function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="centred">
        <p className="muted">Restoring session…</p>
      </div>
    );
  }

  if (!user) return <LoginPage />;

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/devices" replace />} />
        <Route path="/devices" element={<DevicesPage />} />
        <Route path="/devices/:deviceId" element={<DeviceDetailPage />} />
        <Route path="/enrollment" element={<EnrollmentTokensPage />} />
        <Route path="/audit" element={<AuditLogPage />} />
        <Route path="/users" element={<UsersPage />} />
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
