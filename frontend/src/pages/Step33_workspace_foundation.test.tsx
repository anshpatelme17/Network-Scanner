import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SessionProvider } from "../context/SessionContext";
import { AppLayout } from "../layouts/AppLayout";
import { Dashboard } from "./Dashboard";

const READINESS = {
  status: "ready",
  app: "Security Platform",
  version: "0.1.0",
  environment: "test",
  checks: { database: "up" },
};

const OVERVIEW = {
  generated_at: "2026-10-06T12:00:00",
  version: "soc-overview:1.0.0",
  disclaimer:
    "Read-only roll-up of stored state. Related events are not proof of compromise, and nothing on this screen performs an action.",
  limits: { max_items: 50, requested_items: 10 },
  counts: {
    assets_total: 11,
    assets_active: 2,
    services_total: 42,
    events_total: 305,
    correlations_total: 6,
    incidents_total: 4,
    incidents_open: 3,
    risk_assessments_total: 7,
    vulnerabilities_open: 9,
    response_actions_total: 2,
    response_actions_pending_approval: 1,
  },
  incidents_by_severity: { CRITICAL: 1, HIGH: 2, MEDIUM: 0, LOW: 0, INFO: 0 },
  incidents_by_priority: { P1: 1, P2: 0, P3: 0, P4: 0, UNSCORED: 2 },
  top_incidents: [],
  recent_audit: [],
  connectors: [],
};

const NAV_LINKS = [
  "Dashboard",
  "Events",
  "Incidents",
  "Correlations",
  "Assets",
  "Risk",
  "Vulnerabilities",
  "Network",
  "Response",
  "Settings",
  "Login",
];

const GROUPS = ["Monitor", "Investigate", "Assess", "Operate", "Administration"];

function stubFetch(handler: (url: string) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: unknown) => ({
    ok: true,
    status: 200,
    json: async () => handler(String(url)),
  }));
}

function routes(url: string): unknown {
  if (url.includes("/api/v1/ready")) return READINESS;
  if (url.includes("/api/v1/overview")) return OVERVIEW;
  return {};
}

/** Renders the real app shell (AppLayout: Sidebar + Header + content) at a path. */
function renderWorkspace(initialPath: string, element: ReactNode) {
  return render(
    <MemoryRouter initialEntries={[initialPath]} initialIndex={0}>
      <SessionProvider>
        <Routes>
          <Route element={<AppLayout />}>
            <Route index element={element} />
            <Route path="assets" element={element} />
            <Route path="events" element={element} />
            <Route path="correlations" element={element} />
            <Route path="risk" element={element} />
            <Route path="incidents" element={element} />
            <Route path="network" element={element} />
            <Route path="vulnerabilities" element={element} />
            <Route path="response" element={element} />
            <Route path="settings" element={element} />
            <Route path="login" element={element} />
          </Route>
        </Routes>
      </SessionProvider>
    </MemoryRouter>,
  );
}

describe("SOC workspace foundation (Phase 3, Step 33)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("keeps every navigation link, including Login", () => {
    stubFetch(routes);
    renderWorkspace("/", <div data-testid="page-stub" />);
    for (const label of NAV_LINKS) {
      expect(screen.getByRole("link", { name: label })).toBeInTheDocument();
    }
  });

  it("renders the SOC workspace group labels as plain text, not links", () => {
    stubFetch(routes);
    renderWorkspace("/", <div data-testid="page-stub" />);
    for (const group of GROUPS) {
      const label = screen.getByText(group);
      expect(label.tagName).toBe("SPAN");
      expect(label.className).toContain("nav-note");
      expect(screen.queryByRole("link", { name: group })).toBeNull();
    }
  });

  it("marks the active route in the navigation", () => {
    stubFetch(routes);
    renderWorkspace("/events", <div data-testid="page-stub" />);
    const events = screen.getByRole("link", { name: "Events" });
    expect(events).toHaveClass("active");
    expect(events).toHaveAttribute("aria-current", "page");
    expect(screen.getByRole("link", { name: "Dashboard" })).not.toHaveClass("active");
  });

  it("activates only the exact root route for Dashboard", () => {
    stubFetch(routes);
    renderWorkspace("/", <div data-testid="page-stub" />);
    expect(screen.getByRole("link", { name: "Dashboard" })).toHaveClass("active");
    expect(screen.getByRole("link", { name: "Dashboard" })).toHaveAttribute("aria-current", "page");
  });

  it.each(["/correlations", "/risk"])(
    "shows the mapped page title in the header on %s",
    (path) => {
      stubFetch(routes);
      const title = path === "/correlations" ? "Correlations" : "Risk";
      renderWorkspace(path, <div data-testid="page-stub" />);
      expect(screen.getByText(title, { selector: "h2" })).toBeInTheDocument();
    },
  );

  it("preserves the Dashboard header title on the root route", () => {
    stubFetch(routes);
    renderWorkspace("/", <div data-testid="page-stub" />);
    expect(screen.getByText("Dashboard", { selector: "h2" })).toBeInTheDocument();
  });

  it("still renders the Dashboard route", async () => {
    stubFetch(routes);
    renderWorkspace("/", <Dashboard />);
    await waitFor(() => expect(screen.getByText("SOC summary")).toBeInTheDocument());
    expect(screen.getByText("System status")).toBeInTheDocument();
  });

  it("keeps the system status badge and environment indicator in the header", async () => {
    stubFetch(routes);
    renderWorkspace("/", <div data-testid="page-stub" />);
    await waitFor(() => expect(screen.getByRole("status")).toBeInTheDocument());
    expect(screen.getByText("test")).toBeInTheDocument();
  });

  it("keeps Login reachable and renders the brand without mojibake", () => {
    stubFetch(routes);
    renderWorkspace("/", <div data-testid="page-stub" />);
    const login = screen.getByRole("link", { name: "Login" });
    expect(login).toHaveAttribute("href", "/login");
    fireEvent.click(login);
    expect(login).toHaveAttribute("aria-current", "page");
    expect(screen.getByText("SOC Console · v0.1.0")).toBeInTheDocument();
    expect(screen.queryByText(/SOC Console Â· v0\.1\.0/)).toBeNull();
  });

  it("introduces no operational action controls", async () => {
    stubFetch(routes);
    renderWorkspace("/", <Dashboard />);
    await waitFor(() => expect(screen.getByText("SOC summary")).toBeInTheDocument());
    const buttonTexts = screen
      .getAllByRole("button")
      .map((button) => (button.textContent ?? "").toLowerCase());
    for (const verb of [
      "approve",
      "execute",
      "block",
      "isolate",
      "delete",
      "reject",
      "rollback",
      "trigger",
    ]) {
      expect(buttonTexts.some((text) => text.includes(verb))).toBe(false);
    }
  });
});