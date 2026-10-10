import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Sidebar } from "../components/layout/Sidebar";
import { RiskPrioritization } from "./RiskPrioritization";
import type { IncidentSummary, RiskAssessment } from "../types";

function makeIncident(
  overrides: Partial<IncidentSummary> & { id: string; incident_key: string },
): IncidentSummary {
  return {
    title: `Incident ${overrides.incident_key}`,
    status: "OPEN",
    severity: "MEDIUM",
    confidence: 50,
    primary_asset_id: null,
    primary_ip: "10.0.0.1",
    hostname: null,
    correlation_id: "corr-x",
    risk_assessment_id: null,
    first_seen: "2026-10-01T00:00:00",
    last_seen: "2026-10-01T00:00:00",
    resolved_at: null,
    created_at: "2026-10-01T00:00:00",
    updated_at: "2026-10-01T00:00:00",
    version: "1.0.0",
    incident_type: "CORRELATED_SECURITY_EVENT",
    risk_score: null,
    detection_reason: null,
    ...overrides,
  };
}

function makeRisk(
  overrides: Partial<RiskAssessment> & { id: string; entity_type: string; entity_id: string },
): RiskAssessment {
  return {
    score: 50,
    severity: "MEDIUM",
    priority: "P3",
    factors: {},
    explanation: "Deterministic assessment.",
    calculated_at: "2026-10-01T00:30:00",
    scoring_version: "1.0.0",
    ...overrides,
  };
}

// -- Incidents ---------------------------------------------------------------

const INC_P1 = makeIncident({
  id: "inc-p1",
  incident_key: "INC-P1",
  status: "OPEN",
  severity: "CRITICAL",
  last_seen: "2026-10-01T10:00:00",
  risk_score: 90,
});
const INC_P2_HI = makeIncident({
  id: "inc-p2-hi",
  incident_key: "INC-P2-HI",
  status: "ACKNOWLEDGED",
  severity: "HIGH",
  last_seen: "2026-10-01T07:00:00",
  risk_score: 74,
});
const INC_P2_LO = makeIncident({
  id: "inc-p2-lo",
  incident_key: "INC-P2-LO",
  status: "INVESTIGATING",
  severity: "HIGH",
  last_seen: "2026-10-01T12:00:00",
  risk_score: 65,
});
// Same priority and score as TB, but seen more recently -> sorts first.
const INC_P2_TA = makeIncident({
  id: "inc-p2-ta",
  incident_key: "INC-P2-TA",
  status: "OPEN",
  severity: "MEDIUM",
  last_seen: "2026-10-01T13:00:00",
  risk_score: 60,
});
const INC_P2_TB = makeIncident({
  id: "inc-p2-tb",
  incident_key: "INC-P2-TB",
  status: "OPEN",
  severity: "MEDIUM",
  last_seen: "2026-10-01T06:00:00",
  risk_score: 60,
});
const INC_UNSCORED = makeIncident({
  id: "inc-unscored",
  incident_key: "INC-UNSCORED",
  status: "OPEN",
  severity: "LOW",
  last_seen: "2026-10-01T05:00:00",
  risk_score: 88, // stale snapshot must NOT be treated as a current assessment
});
const INC_RES = makeIncident({
  id: "inc-res",
  incident_key: "INC-RES",
  status: "RESOLVED",
  severity: "HIGH",
  last_seen: "2026-09-30T10:00:00",
  resolved_at: "2026-09-30T11:00:00",
  risk_score: 55,
});
const INC_CLOSED = makeIncident({
  id: "inc-closed",
  incident_key: "INC-CLOSED",
  status: "CLOSED",
  severity: "LOW",
  last_seen: "2026-09-29T10:00:00",
  resolved_at: "2026-09-29T11:00:00",
});

const INCIDENTS_BASE = {
  items: [
    INC_P2_TB,
    INC_CLOSED,
    INC_P1,
    INC_UNSCORED,
    INC_P2_LO,
    INC_P2_TA,
    INC_RES,
    INC_P2_HI,
  ],
  total: 8,
  limit: 200,
  offset: 0,
};

// -- Risk assessments --------------------------------------------------------

const RISK_P1 = makeRisk({
  id: "risk-inc-p1",
  entity_type: "incident",
  entity_id: "inc-p1",
  score: 90,
  severity: "CRITICAL",
  priority: "P1",
  factors: { severity_pts: 55, observation_count: 3, confidence: 70 },
  explanation: "Risk score 90 (CRITICAL, priority P1). Incident severity contributes 55 points.",
});
const RISK_P2_HI = makeRisk({
  id: "risk-inc-p2-hi",
  entity_type: "incident",
  entity_id: "inc-p2-hi",
  score: 74,
  severity: "HIGH",
  priority: "P2",
});
const RISK_P2_LO = makeRisk({
  id: "risk-inc-p2-lo",
  entity_type: "incident",
  entity_id: "inc-p2-lo",
  score: 65,
  severity: "HIGH",
  priority: "P2",
});
const RISK_P2_TA = makeRisk({
  id: "risk-inc-p2-ta",
  entity_type: "incident",
  entity_id: "inc-p2-ta",
  score: 60,
  severity: "MEDIUM",
  priority: "P2",
});
const RISK_P2_TB = makeRisk({
  id: "risk-inc-p2-tb",
  entity_type: "incident",
  entity_id: "inc-p2-tb",
  score: 60,
  severity: "MEDIUM",
  priority: "P2",
});
const RISK_RES = makeRisk({
  id: "risk-inc-res",
  entity_type: "incident",
  entity_id: "inc-res",
  score: 55,
  severity: "HIGH",
  priority: "P3",
});
// Non-incident assessments deliberately reuse incident ids to prove that only
// `entity_type === "incident"` rows ever join to an incident.
const RISK_ASSET_COLLISION = makeRisk({
  id: "risk-asset",
  entity_type: "asset",
  entity_id: "inc-p2-hi",
  score: 99,
  severity: "CRITICAL",
  priority: "P1",
});
const RISK_VULN_COLLISION = makeRisk({
  id: "risk-vuln",
  entity_type: "vuln_finding",
  entity_id: "inc-unscored",
  score: 88,
  severity: "CRITICAL",
  priority: "P1",
});

const RISK_BASE = {
  items: [
    RISK_VULN_COLLISION,
    RISK_P2_TB,
    RISK_ASSET_COLLISION,
    RISK_P1,
    RISK_P2_LO,
    RISK_RES,
    RISK_P2_HI,
    RISK_P2_TA,
  ],
  total: 8,
  limit: 200,
  offset: 0,
};

type Handler = (url: string, init?: RequestInit) => unknown;
type Fail = { __fail: true; code: string; status: number };

function fail(code: string, status: number): Fail {
  return { __fail: true, code, status };
}

const calls: string[] = [];

function mockFetch(handler: Handler) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => {
      calls.push(`${init?.method ?? "GET"} ${String(url)}`);
      const value = handler(String(url), init);
      const marker = value as Fail | null;
      if (marker && marker.__fail) {
        return {
          ok: false,
          status: marker.status,
          json: async () => ({ error: { code: marker.code } }),
        };
      }
      return { ok: true, status: 200, json: async () => value };
    },
  );
}

const baseRoute: Handler = (url, init) => {
  if ((init?.method ?? "GET") !== "GET") throw new Error("unexpected write");
  if (url.includes("/api/v1/risk?")) return RISK_BASE;
  if (url.includes("/api/v1/incidents?")) return INCIDENTS_BASE;
  return {};
};

function routeWith(...overrides: Handler[]): Handler {
  return (url, init) => {
    for (const override of overrides) {
      const value = override(url, init);
      if (value !== undefined) return value;
    }
    return baseRoute(url, init);
  };
}

function renderPage(initialEntry = "/risk-prioritization") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/risk-prioritization" element={<RiskPrioritization />} />
        <Route path="*" element={<p>Unknown route</p>} />
      </Routes>
    </MemoryRouter>,
  );
}

async function queueRows() {
  const queue = await screen.findByLabelText("Risk priority queue");
  await waitFor(() => expect(within(queue).getAllByRole("row").length).toBeGreaterThan(1));
  return { queue, rows: within(queue).getAllByRole("row") };
}

const originalFetch = globalThis.fetch;

describe("Risk prioritization (Phase 3, Step 39)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    calls.length = 0;
  });

  afterEach(() => {
    (globalThis as unknown as { fetch: unknown }).fetch = originalFetch;
  });

  it("orders active scored incidents by priority band, then score, then recency", async () => {
    mockFetch(baseRoute);
    renderPage();

    const { rows } = await queueRows();
    // Row 0 is the header; five active incidents carry an assessment.
    expect(rows).toHaveLength(6);
    expect(within(rows[1]).getByText("INC-P1")).toBeInTheDocument();
    expect(within(rows[1]).getByText("P1")).toBeInTheDocument();
    expect(within(rows[1]).getByText("90")).toBeInTheDocument();
    expect(within(rows[2]).getByText("INC-P2-HI")).toBeInTheDocument();
    expect(within(rows[2]).getByText("74")).toBeInTheDocument();
    expect(within(rows[3]).getByText("INC-P2-LO")).toBeInTheDocument();
    expect(within(rows[3]).getByText("65")).toBeInTheDocument();
    // Same P2 band and score 60: the more recently seen incident wins.
    expect(within(rows[4]).getByText("INC-P2-TA")).toBeInTheDocument();
    expect(within(rows[5]).getByText("INC-P2-TB")).toBeInTheDocument();
  });

  it("uses a deterministic id tie-breaker when priority, score and last_seen all match", async () => {
    const sameSeen = "2026-10-01T09:00:00";
    const incidentZ = makeIncident({ id: "inc-z", incident_key: "INC-Z", last_seen: sameSeen });
    const incidentA = makeIncident({ id: "inc-a", incident_key: "INC-A", last_seen: sameSeen });
    const incidents: Handler = (url) => {
      if (url.includes("/api/v1/incidents?")) {
        return { items: [incidentZ, incidentA], total: 2, limit: 200, offset: 0 };
      }
      return undefined;
    };
    const risk: Handler = (url) => {
      if (url.includes("/api/v1/risk?")) {
        return {
          items: [
            makeRisk({ id: "r-z", entity_type: "incident", entity_id: "inc-z", score: 60, priority: "P2" }),
            makeRisk({ id: "r-a", entity_type: "incident", entity_id: "inc-a", score: 60, priority: "P2" }),
          ],
          total: 2,
          limit: 200,
          offset: 0,
        };
      }
      return undefined;
    };
    mockFetch(routeWith(incidents, risk));
    renderPage();

    const { rows } = await queueRows();
    expect(rows).toHaveLength(3);
    expect(within(rows[1]).getByText("INC-A")).toBeInTheDocument();
    expect(within(rows[2]).getByText("INC-Z")).toBeInTheDocument();
  });

  it("excludes resolved and closed incidents from the active view", async () => {
    mockFetch(baseRoute);
    renderPage();

    const { queue } = await queueRows();
    expect(within(queue).queryByText("INC-RES")).toBeNull();
    expect(within(queue).queryByText("INC-CLOSED")).toBeNull();
  });

  it("shows resolved and closed incidents in the separate view", async () => {
    mockFetch(baseRoute);
    renderPage();
    await queueRows();

    fireEvent.click(screen.getByRole("button", { name: "Resolved & closed" }));

    const queue = screen.getByLabelText("Risk priority queue");
    await waitFor(() => expect(within(queue).getByText("INC-RES")).toBeInTheDocument());
    expect(within(queue).queryByText("INC-P1")).toBeNull();
    expect(within(queue).getByText("P3")).toBeInTheDocument();

    const unscored = screen.getByLabelText("Unscored incidents");
    expect(within(unscored).getByText("INC-CLOSED")).toBeInTheDocument();
  });

  it("only joins incident-typed assessments and never a colliding asset/vuln id", async () => {
    mockFetch(baseRoute);
    renderPage();

    const { rows } = await queueRows();
    const hiRow = rows.find((row) => within(row).queryByText("INC-P2-HI") !== null);
    expect(hiRow).toBeDefined();
    // The asset assessment shares the id but scores 99/P1; it must be ignored.
    expect(within(hiRow as HTMLElement).getByText("74")).toBeInTheDocument();
    expect(within(hiRow as HTMLElement).getByText("P2")).toBeInTheDocument();
    expect(within(hiRow as HTMLElement).queryByText("99")).toBeNull();
    expect(within(hiRow as HTMLElement).queryByText("P1")).toBeNull();

    // The vuln assessment shares the unscored incident id and must be ignored.
    const unscored = screen.getByLabelText("Unscored incidents");
    expect(within(unscored).getByText("INC-UNSCORED")).toBeInTheDocument();
  });

  it("lists incidents without an assessment in UNSCORED with no fabricated score or priority", async () => {
    mockFetch(baseRoute);
    renderPage();
    await queueRows();

    const unscored = screen.getByLabelText("Unscored incidents");
    const row = within(unscored).getByText("INC-UNSCORED").closest("tr") as HTMLElement;
    expect(within(row).getByText("LOW")).toBeInTheDocument();
    // No priority badge and no score from the stale snapshot (88) or the
    // colliding vuln assessment (88).
    expect(within(row).queryByText(/^P[1-4]$/)).toBeNull();
    expect(within(row).queryByText("88")).toBeNull();
    expect(
      within(unscored).getByText(/no stored risk assessment/i),
    ).toBeInTheDocument();
  });

  it("reveals explanation, factors, calculation time and scoring version", async () => {
    mockFetch(baseRoute);
    renderPage();

    const { rows } = await queueRows();
    fireEvent.click(within(rows[1]).getByRole("button", { name: "Details" }));

    const detail = await screen.findByLabelText("Risk prioritization detail");
    expect(within(detail).getByText(/Risk score 90 \(CRITICAL, priority P1\)/)).toBeInTheDocument();
    expect(within(detail).getByText(/Scoring version 1.0.0/)).toBeInTheDocument();
    expect(within(detail).getByText(/severity_pts: 55/)).toBeInTheDocument();
    expect(within(detail).getByText("priority P1")).toBeInTheDocument();
  });

  it("requests incident-specific risk assessments and is GET-only", async () => {
    mockFetch(baseRoute);
    renderPage();
    await queueRows();

    expect(
      calls.some(
        (entry) => entry.includes("/api/v1/risk?") && entry.includes("entity_type=incident"),
      ),
    ).toBe(true);
    expect(calls.some((entry) => entry.includes("/api/v1/incidents?"))).toBe(true);
    expect(calls.every((entry) => entry.startsWith("GET "))).toBe(true);
  });

  it("reports the bounded-result limitation honestly", async () => {
    const truncated: Handler = (url) => {
      if (url.includes("/api/v1/risk?")) return { ...RISK_BASE, total: 500 };
      return undefined;
    };
    mockFetch(routeWith(truncated));
    renderPage();

    await screen.findByLabelText("Risk priority queue");
    expect(
      screen.getByText(/may be incomplete/),
    ).toBeInTheDocument();
    expect(screen.getByText(/500 incident assessments exist/)).toBeInTheDocument();
  });

  it("shows the loading state before data resolves", async () => {
    mockFetch(baseRoute);
    renderPage();
    expect(screen.getByText("Loading risk prioritization…")).toBeInTheDocument();
    // Let the in-flight requests settle so no state update escapes the test.
    await queueRows();
  });

  it("shows honest empty states", async () => {
    const empty: Handler = (url) => {
      if (url.includes("/api/v1/risk?")) return { items: [], total: 0, limit: 200, offset: 0 };
      if (url.includes("/api/v1/incidents?")) return { items: [], total: 0, limit: 200, offset: 0 };
      return undefined;
    };
    mockFetch(routeWith(empty));
    renderPage();

    expect(await screen.findByText("No assessed incidents in this view.")).toBeInTheDocument();
    expect(screen.getByText("No unscored incidents in this view.")).toBeInTheDocument();
  });

  it("isolates an API error and recovers through Retry", async () => {
    let broken = true;
    const flaky: Handler = (url) => {
      if (broken && url.includes("/api/v1/risk?")) return fail("INTERNAL_ERROR", 500);
      return undefined;
    };
    mockFetch(routeWith(flaky));
    renderPage();

    await waitFor(() =>
      expect(screen.getByText("Risk prioritization unavailable")).toBeInTheDocument(),
    );
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument();

    broken = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    const { rows } = await queueRows();
    expect(rows).toHaveLength(6);
  });

  it("reports a restricted account honestly without retry controls", async () => {
    const restricted: Handler = (url) => {
      if (url.includes("/api/v1/risk?")) return fail("PERMISSION_DENIED", 403);
      return undefined;
    };
    mockFetch(routeWith(restricted));
    renderPage();

    await waitFor(() =>
      expect(screen.getByText("Risk prioritization restricted")).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  });

  it("navigates onward to existing workspaces without write traffic", async () => {
    mockFetch(baseRoute);
    renderPage();
    await queueRows();

    const navigation = screen.getByLabelText("Risk prioritization navigation");
    expect(within(navigation).getByRole("link", { name: "Risk assessments" })).toHaveAttribute(
      "href",
      "/risk",
    );
    expect(within(navigation).getByRole("link", { name: "Incidents" })).toHaveAttribute(
      "href",
      "/incidents",
    );
    expect(within(navigation).getByRole("link", { name: "Alert triage" })).toHaveAttribute(
      "href",
      "/triage",
    );
    expect(
      calls.some((entry) => /(recompute|detect|\/status|\/calculate)/.test(entry)),
    ).toBe(false);
  });

  it("adds the Prioritization navigation entry to the sidebar", () => {
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Prioritization" })).toHaveAttribute(
      "href",
      "/risk-prioritization",
    );
  });
});
