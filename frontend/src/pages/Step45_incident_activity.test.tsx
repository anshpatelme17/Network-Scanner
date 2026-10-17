import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Incidents } from "./Incidents";

const ITEM = {
  id: "inc-1",
  incident_key: "INC-INTEL1234567",
  title: "Incident: auth chain against 192.0.2.77",
  description: "Correlated authentication sequence.",
  status: "OPEN",
  severity: "HIGH",
  confidence: 75,
  primary_asset_id: "asset-1",
  primary_ip: "192.0.2.77",
  hostname: null,
  correlation_id: "corr-1",
  risk_assessment_id: "ris-1",
  first_seen: "2026-09-27T07:00:00",
  last_seen: "2026-09-27T07:10:00",
  resolved_at: null,
  created_at: "2026-09-27T07:11:00",
  updated_at: "2026-09-27T07:11:00",
  version: "1.0.0",
  incident_type: "AUTHENTICATION_ANOMALY",
  risk_score: 74,
  detection_reason: "Correlation corr-1 groups 3 related events.",
};

const PAGE = { items: [ITEM], total: 1, limit: 100, offset: 0 };
const DETAIL = { ...ITEM, evidence_event_ids: [] };

const EVIDENCE = {
  incident_id: "inc-1",
  incident_type: "AUTHENTICATION_ANOMALY",
  detection_reason: null,
  correlation: null,
  events: [],
  vulnerabilities: [],
};

const RELATIONSHIPS = { incident_id: "inc-1", items: [], total: 0, limit: 50, offset: 0 };
const AUDIT = { incident_id: "inc-1", entries: [] };
const TIMELINE = { incident_id: "inc-1", truncated: false, entries: [] };
const RESPONSES = { items: [], total: 0, limit: 100, offset: 0 };
const RECOMMENDATIONS = {
  incident_id: "inc-1",
  incident_key: "INC-INTEL1234567",
  severity: "HIGH",
  risk_score: 74,
  risk_priority: "P2",
  items: [],
  total: 0,
  truncated: false,
  policy_version: "1.0.0",
  governance_version: "1.0.0",
};
const RISK = {
  id: "ris-1",
  entity_type: "incident",
  entity_id: "inc-1",
  score: 74,
  severity: "HIGH",
  priority: "P2",
  factors: { severity_impact: 0.75 },
  explanation: "Stored evidence implies elevated risk.",
  calculated_at: "2026-09-27T07:11:00",
  scoring_version: "1.0.0",
};

const ACTIVITY_ROWS = [
  {
    id: "a-1",
    action_id: "act-1",
    action_type: "BLOCK_INDICATOR",
    event: "RESPONSE_REQUESTED",
    actor: "analyst-1",
    previous_status: null,
    new_status: "PENDING_APPROVAL",
    policy_version: "1.0.0",
    created_at: "2026-09-27T07:20:00",
    detail: null,
  },
  {
    id: "a-2",
    action_id: "act-1",
    action_type: "BLOCK_INDICATOR",
    event: "RESPONSE_APPROVED",
    actor: "operator-1",
    previous_status: "PENDING_APPROVAL",
    new_status: "APPROVED",
    policy_version: "1.0.0",
    created_at: "2026-09-27T07:30:00",
    detail: null,
  },
];

function activityPage(url: string, forcedLimit?: number) {
  const params = new URL(url, "http://localhost").searchParams;
  const event = params.get("event");
  const actor = params.get("actor");
  let rows = ACTIVITY_ROWS;
  if (event) rows = rows.filter((row) => row.event === event);
  if (actor) rows = rows.filter((row) => row.actor === actor);
  const limit = forcedLimit ?? Number(params.get("limit") ?? 50);
  const offset = Number(params.get("offset") ?? 0);
  const total = rows.length;
  const items = rows.slice(offset, offset + limit);
  return {
    incident_id: "inc-1",
    incident_key: "INC-INTEL1234567",
    items,
    total,
    limit,
    offset,
    truncated: offset + items.length < total,
    filters: { event: event ?? null, actor: actor ?? null },
  };
}

type Handler = (url: string, init?: RequestInit) => unknown;

function baseRoute(limit?: number): Handler {
  return (url, init) => {
    if (url.includes("/activity?")) return activityPage(url, limit);
    if (url.includes("/response-recommendations")) return RECOMMENDATIONS;
    if (url.endsWith("/responses?limit=100")) return RESPONSES;
    if (url.endsWith("/evidence")) return EVIDENCE;
    if (url.endsWith("/audit")) return AUDIT;
    if (url.includes("/relationships?")) return RELATIONSHIPS;
    if (url.endsWith("/timeline")) return TIMELINE;
    if (url.includes("/api/v1/risk/incidents/") && url.includes("/calculate")) return RISK;
    if (url.includes("/api/v1/risk/incident/")) return RISK;
    if (url.includes("/api/v1/incidents/inc-1")) return DETAIL;
    if ((init?.method ?? "GET") !== "GET") throw new Error("unexpected write");
    if (url.includes("/api/v1/incidents?")) return PAGE;
    return {};
  };
}

function mockFetch(handler: Handler, activityStatus?: number) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => {
      const value = String(url);
      if (activityStatus && value.includes("/activity?")) {
        return {
          ok: false,
          status: activityStatus,
          json: async () => ({ error: { code: "PERMISSION_DENIED" } }),
        };
      }
      return { ok: true, status: 200, json: async () => handler(value, init) };
    },
  );
}

async function openIncidentDetail() {
  await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Open"));
  await waitFor(() =>
    expect(
      screen.getByRole("heading", { level: 5, name: /Accountability activity/ }),
    ).toBeInTheDocument(),
  );
}

// Event names also appear as filter <option> labels, so assert on the badge.
const eventBadges = (name: string) => screen.queryAllByText(name, { selector: "span.badge" });

describe("Incident accountability activity (Phase 4, Step 45)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("renders the stored lifecycle rows with event, actor, action and transition", async () => {
    mockFetch(baseRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();

    expect(
      screen.getByRole("heading", { level: 5, name: "Accountability activity (2)" }),
    ).toBeInTheDocument();
    expect(eventBadges("RESPONSE_REQUESTED")).toHaveLength(1);
    expect(eventBadges("RESPONSE_REQUESTED")[0].className).toContain("badge info");
    expect(screen.getByText("analyst-1")).toBeInTheDocument();
    expect(screen.getAllByText(/BLOCK_INDICATOR/)).toHaveLength(2);
    expect(screen.getAllByText("act-1")).toHaveLength(2);
    expect(screen.getByText(/PENDING_APPROVAL → APPROVED/)).toBeInTheDocument();
  });

  it("applies an event filter through the server query", async () => {
    mockFetch(baseRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();

    fireEvent.change(screen.getByLabelText("Filter activity by event"), {
      target: { value: "RESPONSE_APPROVED" },
    });
    fireEvent.click(screen.getByText("Apply filters"));

    await waitFor(() =>
      expect(
        screen.getByRole("heading", { level: 5, name: "Accountability activity (1)" }),
      ).toBeInTheDocument(),
    );
    expect(eventBadges("RESPONSE_APPROVED")).toHaveLength(1);
    expect(eventBadges("RESPONSE_REQUESTED")).toHaveLength(0);

    const called = (globalThis.fetch as unknown as { mock: { calls: [string][] } }).mock.calls.map(
      (call) => call[0],
    );
    expect(called.some((url) => url.includes("activity?") && url.includes("event=RESPONSE_APPROVED"))).toBe(true);
  });

  it("resets filters back to the full feed", async () => {
    mockFetch(baseRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();

    fireEvent.change(screen.getByLabelText("Filter activity by actor"), {
      target: { value: "operator-1" },
    });
    fireEvent.click(screen.getByText("Apply filters"));
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { level: 5, name: "Accountability activity (1)" }),
      ).toBeInTheDocument(),
    );

    fireEvent.click(screen.getByText("Reset filters"));
    await waitFor(() =>
      expect(
        screen.getByRole("heading", { level: 5, name: "Accountability activity (2)" }),
      ).toBeInTheDocument(),
    );
  });

  it("paginates through the bounded server window", async () => {
    mockFetch(baseRoute(1));
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();

    expect(screen.getByText(/Showing 1–1 of 2/)).toBeInTheDocument();
    expect(eventBadges("RESPONSE_REQUESTED")).toHaveLength(1);
    expect(eventBadges("RESPONSE_APPROVED")).toHaveLength(0);

    fireEvent.click(screen.getByText("Next page"));
    await waitFor(() => expect(screen.getByText(/Showing 2–2 of 2/)).toBeInTheDocument());
    expect(eventBadges("RESPONSE_APPROVED")).toHaveLength(1);
    expect(eventBadges("RESPONSE_REQUESTED")).toHaveLength(0);
  });

  it("labels the table and reports a truncated server window", async () => {
    mockFetch(baseRoute(1));
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();

    expect(
      screen.getByRole("table", { name: "Incident accountability activity" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/More activity exists/)).toBeInTheDocument();
  });

  it("shows an honest empty state when nothing matches", async () => {
    const emptyRoute: Handler = (url, init) => {
      if (url.includes("/activity?")) {
        return {
          incident_id: "inc-1",
          incident_key: "INC-INTEL1234567",
          items: [],
          total: 0,
          limit: 50,
          offset: 0,
          truncated: false,
          filters: {},
        };
      }
      return baseRoute()(url, init);
    };
    mockFetch(emptyRoute);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();

    expect(
      screen.getByRole("heading", { level: 5, name: "Accountability activity (0)" }),
    ).toBeInTheDocument();
    expect(screen.getByText("No controlled-response activity matches.")).toBeInTheDocument();
  });

  it("reports a restricted feed without leaking server detail", async () => {
    mockFetch(baseRoute(), 403);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));

    await waitFor(() =>
      expect(screen.getByText("Activity is restricted for your account.")).toBeInTheDocument(),
    );
    expect(screen.queryByText(/PERMISSION_DENIED/)).toBeNull();
  });
});
