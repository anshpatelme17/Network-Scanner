import { Fragment } from "react";
import { NavLink } from "react-router-dom";

interface NavEntry {
  to: string;
  label: string;
  end?: boolean;
}

/**
 * Phase 3, Step 33: the sidebar is grouped into SOC workspaces. This is a
 * navigation/UX organization only — every route, API call and safety
 * boundary is untouched. Group labels are plain text (spans), never links,
 * so they cannot be mistaken for destinations.
 */
const GROUPS: Array<{ title: string; links: NavEntry[] }> = [
  {
    title: "Monitor",
    links: [
      { to: "/", label: "Dashboard", end: true },
      { to: "/events", label: "Events" },
      { to: "/triage", label: "Triage" },
    ],
  },
  {
    title: "Investigate",
    links: [
      { to: "/incidents", label: "Incidents" },
      { to: "/correlations", label: "Correlations" },
      { to: "/assets", label: "Assets" },
    ],
  },
  {
    title: "Assess",
    links: [
      { to: "/risk", label: "Risk" },
      { to: "/risk-prioritization", label: "Prioritization" },
      { to: "/vulnerabilities", label: "Vulnerabilities" },
    ],
  },
  {
    title: "Operate",
    links: [
      { to: "/network", label: "Network" },
      { to: "/response", label: "Response" },
      { to: "/response-center", label: "Response Center" },
    ],
  },
  {
    title: "Administration",
    links: [{ to: "/settings", label: "Settings" }],
  },
];

export function Sidebar() {
  return (
    <aside className="sidebar" aria-label="Primary navigation">
      <div className="brand">
        <h1>Security Platform</h1>
        <p>SOC Console · v0.1.0</p>
      </div>
      <nav className="nav">
        {GROUPS.map((group) => (
          <Fragment key={group.title}>
            <span className="nav-note">{group.title}</span>
            {group.links.map((link) => (
              <NavLink
                key={link.to}
                to={link.to}
                end={link.end}
                className={({ isActive }) => (isActive ? "active" : "")}
              >
                {link.label}
              </NavLink>
            ))}
          </Fragment>
        ))}
        <hr className="nav-divider" />
        <NavLink to="/login" className={({ isActive }) => (isActive ? "active" : "")}>
          Login
        </NavLink>
      </nav>
    </aside>
  );
}
