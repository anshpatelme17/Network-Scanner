import { NavLink } from "react-router-dom";

const LINKS = [
  { to: "/", label: "Dashboard" },
  { to: "/assets", label: "Assets" },
  { to: "/events", label: "Events" },
  { to: "/correlations", label: "Correlations" },
  { to: "/risk", label: "Risk" },
  { to: "/incidents", label: "Incidents" },
  { to: "/network", label: "Network" },
  { to: "/vulnerabilities", label: "Vulnerabilities" },
  { to: "/response", label: "Response" },
  { to: "/settings", label: "Settings" },
  { to: "/login", label: "Login" },
];

export function Sidebar() {
  return (
    <aside className="sidebar" aria-label="Primary navigation">
      <div className="brand">
        <h1>Security Platform</h1>
        <p>SOC Console · v0.1.0</p>
      </div>
      <nav className="nav">
        <span className="nav-note">Operate</span>
        {LINKS.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            end={link.to === "/"}
            className={({ isActive }) => (isActive ? "active" : "")}
          >
            {link.label}
          </NavLink>
        ))}
      </nav>
    </aside>
  );
}
