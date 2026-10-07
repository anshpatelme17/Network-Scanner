import { render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Dashboard } from "./Dashboard";
import { api } from "../services/api";

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
  top_incidents: [
    {
      id: "inc-1",
      incident_key: "INC-2026-0001",
      title: "Correlated security event on 198.51.100.23",
      status: "OPEN",
      severity: "HIGH",
      confidence: 80,
      risk_score: 72,
      priority: "P2",
      primary_asset_id: "asset-1",
      primary_ip: "198.51.100.23",
      hostname: "web-01",
      correlation_id: "corr-1",
      first_seen: "2026-10-06T09:00:00",
      last_seen: "2026-10-06T09:30:00",
    },
  ],
  recent_audit: [
    {
      id: "audit-1",
      action: "events.ingested",
      actor: "operator",
      event_id: "evt-1",
      detail: "Ingested 50 events from suricata.",
      created_at: "2026-10-06T09:31:00",
    },
  ],
  connectors: [
    {
      source: "SURICATA",
      mode: "live",
      state: "OK",
      connector_state: "configured",
      last_check_at: "2026-10-06T11:00:00",
      last_poll_at: "2026-10-06T11:01:00",
      last_error_category: null,
      events_retrieved: 120,
    },
  ],
};

const READINESS = {
  status: "ready",
  app: "Security Platform",
  version: "0.1.0",
  environment: "test",
  checks: { database: "up" },
};

function emptyOverview() {
  return {
    ...OVERVIEW,
    counts: {
      assets_total: 0,
      assets_active: 0,
      services_total: 0,
      events_total: 0,
      correlations_total: 0,
      incidents_total: 0,
      incidents_open: 0,
      risk_assessments_total: 0,
      vulnerabilities_open: 0,
      response_actions_total: 0,
      response_actions_pending_approval: 0,
    },
    incidents_by_severity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 },
    incidents_by_priority: { P1: 0, P2: 0, P3: 0, P4: 0, UNSCORED: 0 },
    top_incidents: [],
    recent_audit: [],
    connectors: [],
  };
}

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: unknown, init?: RequestInit) => {
    const payload = handler(String(url), init);
    return {
      ok: true,
      status: 200,
      json: async () => payload,
    };
  });
}

function mockFetchResult(_url: string, status: number, payload: unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (requestUrl: unknown) => {
    if (String(requestUrl).includes("/api/v1/overview")) {
      return { ok: status >= 200 && status < 300, status, json: async () => payload };
    }
    return { ok: true, status: 200, json: async () => READINESS };
  });
}

function routes(url: string): unknown {
  if (url.includes("/api/v1/overview")) return OVERVIEW;
  return READINESS;
}

function expectStat(card: HTMLElement, label: string, value: string) {
  const labelEl = within(card).getByText(label);
  const stat = labelEl.closest(".stat");
  expect(stat).not.toBeNull();
  expect(within(stat as HTMLElement).getByText(value)).toBeInTheDocument();
}

describe("SOC dashboard (Phase 2, Step 9)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders counts, buckets, incidents, connectors, audit, disclaimer and metadata", async () => {
    mockFetch(routes);
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByText("SOC summary")).toBeInTheDocument());

    const summary = screen.getByText("SOC summary").closest(".card") as HTMLElement;
    expectStat(summary, "Assets", "11");
    expectStat(summary, "Active assets", "2");
    expectStat(summary, "Services", "42");
    expectStat(summary, "Events", "305");
    expectStat(summary, "Correlations", "6");
    expectStat(summary, "Incidents", "4");
    expectStat(summary, "Open incidents", "3");
    expectStat(summary, "Risk assessments", "7");
    expectStat(summary, "Open vulnerabilities", "9");
    expectStat(summary, "Response actions", "2");
    expectStat(summary, "Pending approvals", "1");

    const severity = screen.getByText("Incidents by severity").closest(".card") as HTMLElement;
    expectStat(severity, "CRITICAL", "1");
    expectStat(severity, "HIGH", "2");
    expectStat(severity, "MEDIUM", "0");
    expectStat(severity, "LOW", "0");
    expectStat(severity, "INFO", "0");

    const priority = screen.getByText("Incidents by priority").closest(".card") as HTMLElement;
    expectStat(priority, "P1", "1");
    expectStat(priority, "P2", "0");
    expectStat(priority, "P3", "0");
    expectStat(priority, "P4", "0");
    expectStat(priority, "UNSCORED", "2");

    expect(screen.getByText("Correlated security event on 198.51.100.23")).toBeInTheDocument();
    expect(screen.getByText("web-01")).toBeInTheDocument();
    expect(screen.getByText("198.51.100.23")).toBeInTheDocument();
    expect(screen.getByText("72")).toBeInTheDocument();
    const incidentsCard = screen.getByText("Top open incidents").closest(".card") as HTMLElement;
    expect(within(incidentsCard).getByText("P2")).toBeInTheDocument();

    expect(screen.getByText("SURICATA")).toBeInTheDocument();
    expect(screen.getByText("120")).toBeInTheDocument();

    expect(screen.getByText("events.ingested")).toBeInTheDocument();
    expect(screen.getByText("operator")).toBeInTheDocument();
    expect(screen.getByText("Ingested 50 events from suricata.")).toBeInTheDocument();

    expect(screen.getByText(`${OVERVIEW.disclaimer}`)).toBeInTheDocument();
    expect(screen.getByText(/soc-overview:1\.0\.0/)).toBeInTheDocument();
    expect(screen.getByText(/lists bounded to 10 of 50/)).toBeInTheDocument();
  });

  it("renders a valid all-zero empty platform without crashing", async () => {
    mockFetch((url) => (url.includes("/api/v1/overview") ? emptyOverview() : READINESS));
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );

    await waitFor(() => expect(screen.getByText("SOC summary")).toBeInTheDocument());
    expect(screen.getByText("No open incidents.")).toBeInTheDocument();
    expect(screen.getByText("No connectors configured.")).toBeInTheDocument();
    expect(screen.getByText("No ingestion audit entries yet.")).toBeInTheDocument();
    expect(screen.getByText(OVERVIEW.disclaimer)).toBeInTheDocument();
  });

  it("shows a permission state on 401 / PERMISSION_DENIED without fabricating data", async () => {
    mockFetchResult("/api/v1/overview", 401, { error: { code: "PERMISSION_DENIED" } });
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(screen.getByText("SOC overview unavailable")).toBeInTheDocument(),
    );
    expect(screen.getByText("Your account is not permitted to perform this action.")).toBeInTheDocument();
    expect(screen.queryByText("SOC summary")).not.toBeInTheDocument();
    expect(screen.queryByText("Correlated security event on 198.51.100.23")).not.toBeInTheDocument();
  });

  it("shows an honest offline state on network failure", async () => {
    (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async () => {
      throw new Error("Network error");
    });
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );

    await waitFor(() =>
      expect(screen.getByText("SOC overview unavailable")).toBeInTheDocument(),
    );
    expect(screen.getByText("The SOC overview could not be loaded.")).toBeInTheDocument();
    expect(screen.queryByText("SOC summary")).not.toBeInTheDocument();
  });

  it("forwards the limit query parameter when supplied", async () => {
    const fetchMock = vi.fn(async (_url: unknown) => {
      return { ok: true, status: 200, json: async () => OVERVIEW };
    });
    (globalThis as unknown as { fetch: unknown }).fetch = fetchMock;

    await api.getSocOverview(25);
    expect(String(fetchMock.mock.calls[0][0])).toContain("/api/v1/overview?limit=25");

    await api.getSocOverview();
    expect(String(fetchMock.mock.calls[1][0])).toBe("/api/v1/overview");
  });

  it("is read-only: no approve/execute/block/isolate/delete/action controls appear", async () => {
    mockFetch(routes);
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("SOC summary")).toBeInTheDocument());

    const buttonText = screen
      .getAllByRole("button")
      .map((button) => (button.textContent ?? "").toLowerCase());
    for (const verb of ["approve", "execute", "block", "isolate", "delete", "reject", "rollback", "action"]) {
      expect(buttonText.some((text) => text.includes(verb))).toBe(false);
    }
  });
});