import { useLocation } from "react-router-dom";
import type { SystemState } from "../../types";
import { StatusBadge } from "./StatusBadge";

const TITLES: Record<string, string> = {
  "/": "Dashboard",
  "/assets": "Assets",
  "/events": "Events",
  "/incidents": "Incidents",
  "/network": "Network",
  "/vulnerabilities": "Vulnerabilities",
  "/response": "Response",
  "/settings": "Settings",
};

export function Header({
  environment,
  state,
}: {
  environment: string;
  state: SystemState;
}) {
  const location = useLocation();
  const title = TITLES[location.pathname] ?? "Security Platform";
  return (
    <header className="topbar">
      <h2>{title}</h2>
      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
        <StatusBadge state={state} />
        <span className="env-pill" title="Deployment environment">
          {environment}
        </span>
      </div>
    </header>
  );
}
