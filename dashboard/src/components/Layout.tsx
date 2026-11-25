import { NavLink } from "react-router-dom";
import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { api } from "../api/client";
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
  const [openAlerts, setOpenAlerts] = useState(0);

  /**
   * Poll the open alert count.
   *
   * On the shell rather than the Alerts page, because the point of a badge is
   * to be seen while you are somewhere else. One `COUNT(*)` a minute, and
   * failures are swallowed: a missing badge is a small loss, whereas an error
   * banner on every page because one count failed is a large one.
   */
  useEffect(() => {
    if (!can("incident_read")) return;
    let cancelled = false;
    const poll = () =>
      void api
        .incidentCounts()
        .then((counts) => {
          if (!cancelled) setOpenAlerts(counts.open);
        })
        .catch(() => undefined);
    poll();
    const timer = window.setInterval(poll, 60_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [can]);

  const links: {
    to: string;
    label: string;
    icon: IconName;
    visible: boolean;
    badge?: number;
  }[] = [
    { to: "/devices", label: "Devices", icon: "devices", visible: can("device_read") },
    {
      to: "/alerts",
      label: "Alerts",
      icon: "alert",
      visible: can("incident_read"),
      // The count is why this link earns a badge: an alert nobody has looked
      // at is the one thing on this bar that is actively waiting for someone.
      badge: openAlerts || undefined,
    },
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
                {link.badge ? <span className="nav-badge">{link.badge}</span> : null}
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
