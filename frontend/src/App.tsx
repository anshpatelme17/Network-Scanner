import { BrowserRouter, Route, Routes } from "react-router-dom";
import { SessionProvider } from "./context/SessionContext";
import { AppLayout } from "./layouts/AppLayout";
import { AssetWorkspace } from "./pages/AssetWorkspace";
import { Assets } from "./pages/Assets";
import { Correlations } from "./pages/Correlations";
import { Dashboard } from "./pages/Dashboard";
import { Events } from "./pages/Events";
import { Incidents } from "./pages/Incidents";
import { Login } from "./pages/Login";
import { Network } from "./pages/Network";
import { Response } from "./pages/Response";
import { Risk } from "./pages/Risk";
import { Vulnerabilities } from "./pages/Vulnerabilities";
import { Settings } from "./pages/placeholders";

export function App() {
  return (
    <BrowserRouter>
      {/*
        Step 31: the session context is advisory only. It lets a page
        explain which governed actions the current account may attempt; it
        never grants access, and every endpoint still authorizes
        server-side.
      */}
      <SessionProvider>
        <Routes>
          <Route element={<AppLayout />}>
            <Route index element={<Dashboard />} />
            <Route path="assets" element={<Assets />} />
            <Route path="assets/:assetId" element={<AssetWorkspace />} />
            <Route path="events" element={<Events />} />
            <Route path="correlations" element={<Correlations />} />
            <Route path="risk" element={<Risk />} />
            <Route path="incidents" element={<Incidents />} />
            <Route path="network" element={<Network />} />
            <Route path="vulnerabilities" element={<Vulnerabilities />} />
            <Route path="response" element={<Response />} />
            <Route path="settings" element={<Settings />} />
            <Route path="login" element={<Login />} />
            <Route path="*" element={<Dashboard />} />
          </Route>
        </Routes>
      </SessionProvider>
    </BrowserRouter>
  );
}
