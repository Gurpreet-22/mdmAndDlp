import { NavLink } from "react-router-dom";
import type { ReactNode } from "react";

import { useAuth } from "../auth";

/**
 * Navigation is filtered by capability, so an auditor does not see an
 * "Enrollment" tab they would be refused at. Cosmetic only: the server checks
 * every request regardless.
 */
export default function Layout({ children }: { children: ReactNode }) {
  const { user, logout, can } = useAuth();

  const links: { to: string; label: string; visible: boolean }[] = [
    { to: "/devices", label: "Devices", visible: can("device_read") },
    { to: "/enrollment", label: "Enrollment", visible: can("enrollment_token_manage") },
    { to: "/audit", label: "Audit log", visible: can("audit_read") },
    { to: "/users", label: "Administrators", visible: can("manage_users") },
  ];

  return (
    <div className="shell">
      <header className="topbar">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span>UbuntuGuard</span>
        </div>

        <nav className="nav" aria-label="Main">
          {links
            .filter((link) => link.visible)
            .map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
              >
                {link.label}
              </NavLink>
            ))}
        </nav>

        <div className="session">
          <span className="who">
            {user?.email}
            <span className="role-badge">{user?.role.replace(/_/g, " ")}</span>
          </span>
          <button type="button" className="ghost" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      </header>

      <main className="content">{children}</main>

      <footer className="footer">
        <span>
          Prototype. No USB enforcement yet — detection and response, not a guarantee.
        </span>
      </footer>
    </div>
  );
}
