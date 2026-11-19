import { NavLink } from "react-router-dom";
import type { ReactNode } from "react";

import { useAuth } from "../auth";
import Brand from "./Brand";
import Icon, { type IconName } from "./Icon";

/**
 * Navigation is filtered by capability, so an auditor does not see an
 * "Enrollment" tab they would be refused at. Cosmetic only: the server checks
 * every request regardless.
 */
export default function Layout({ children }: { children: ReactNode }) {
  const { user, logout, can } = useAuth();

  const links: { to: string; label: string; icon: IconName; visible: boolean }[] = [
    { to: "/devices", label: "Devices", icon: "devices", visible: can("device_read") },
    { to: "/employees", label: "Employees", icon: "employees", visible: can("device_read") },
    {
      to: "/enrollment",
      label: "Enrollment",
      icon: "enrollment",
      visible: can("enrollment_token_manage"),
    },
    { to: "/audit", label: "Audit log", icon: "audit", visible: can("audit_read") },
    { to: "/users", label: "Administrators", icon: "admins", visible: can("manage_users") },
  ];

  return (
    <div className="shell">
      <header className="topbar">
        <Brand />

        <nav className="nav" aria-label="Main">
          {links
            .filter((link) => link.visible)
            .map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
              >
                <Icon name={link.icon} size={17} />
                {link.label}
              </NavLink>
            ))}
        </nav>

        <div className="session">
          <span className="who">
            {user?.email}
            <span className="role-badge">{user?.role.replace(/_/g, " ")}</span>
          </span>
          {/*
            Not in the capability-filtered nav above, because no capability
            guards it: every role can change its own password, and an account
            that could not would have no way to rotate a credential it believed
            was compromised.
          */}
          <NavLink to="/account/password" className="nav-link">
            <Icon name="lock" size={16} />
            Password
          </NavLink>
          <a href="/enroll" target="_blank" rel="noreferrer" className="nav-link">
            <Icon name="external" size={16} />
            Enroll portal
          </a>
          <button type="button" className="ghost" onClick={() => void logout()}>
            <Icon name="logout" size={16} />
            Sign out
          </button>
        </div>
      </header>

      <main className="content">{children}</main>

      <footer className="footer">
        {/*
          Updated when USB enforcement started actually working on real
          hardware. It had said "no USB enforcement yet" since before the
          enforcer existed, which by then understated the product -- and a
          footer that is wrong about the thing it disclaims is worse than no
          footer. What is still true is named instead.
        */}
        <span>
          USB storage control is enforced. Screen lock, disk encryption and firewall
          policies are not implemented yet.
        </span>
      </footer>
    </div>
  );
}
