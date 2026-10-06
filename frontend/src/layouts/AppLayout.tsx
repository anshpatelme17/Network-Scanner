import { Outlet } from "react-router-dom";
import { useSystemStatus } from "../hooks/useSystemStatus";
import { Header } from "../components/layout/Header";
import { Sidebar } from "../components/layout/Sidebar";

export function AppLayout() {
  // Single live status source shared by header + dashboard.
  const { state, environment } = useSystemStatus();
  return (
    <div className="app-shell">
      <Sidebar />
      <div className="main">
        <Header environment={environment} state={state} />
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
