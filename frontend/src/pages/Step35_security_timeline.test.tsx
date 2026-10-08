import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
  detection_reason: "Correlation corr-1 groups 3 related events against 203.0.113.9.",
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

const RELATIONSHIPS = {
  incident_id: "inc-1",
  items: [],
  total: 0,
  limit: 50,
  offset: 0,
};

const AUDIT = { incident_id: "inc-1", entries: [] };

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

const TIMELINE_FULL = {
  incident_id: "inc-1",
  truncated: false,
  entries: [
    {
      at: "2026-09-27T07:00:00",
      kind: "observation",
      label: "First observed activity",
      detail: "Correlation window opened.",
    },
    {
      at: "2026-09-27T07:05:00",
      kind: "event",
      label: "Authentication succeeded",
      detail: "WAZUH: WAZUH_AUTH (HIGH)",
      event_id: "evt-2",
      event_type: "WAZUH_AUTH",
      source: "WAZUH",
      severity: "HIGH",
      entity: "192.0.2.77",
      explanation: null,
    },
    {
      at: "2026-09-27T07:11:00",
      kind: "opened",
      label: "Opened",
      detail: "detection: opened from correlation corr-1.",
    },
    {
      at: "2026-09-28T08:00:00",
      kind: "status",
      label: "Marked ACKNOWLEDGED",
      detail: "operator: status OPEN -> ACKNOWLEDGED.",
    },
    {
      at: "2026-09-28T08:05:00",
      kind: "event",
      label: "Additional observation",
      detail: "WAZUH: WAZUH_AUTH (LOW)",
      event_id: "evt-3",
      event_type: "WAZUH_AUTH",
      source: "WAZUH",
      severity: "LOW",
      entity: "203.0.113.9",
      explanation: "Later activity seen.",
    },
    {
      at: "2026-09-28T09:00:00",
      kind: "resolution",
      label: "Resolved and closed",
      detail: "analyst closed the record.",
    },
  ],
};

type Handler = (url: string, init?: RequestInit) => unknown;
type Fail = { __fail: true; code: string; status: number };

function fail(code: string, status: number): Fail {
  return { __fail: true, code, status };
}

function mockFetch(handler: Handler) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => {
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
  if (url.includes("/response-recommendations")) return RECOMMENDATIONS;
  if (url.endsWith("/responses?limit=100")) return RESPONSES;
  if (url.endsWith("/evidence")) return EVIDENCE;
  if (url.endsWith("/audit")) return AUDIT;
  if (url.includes("/relationships?")) return RELATIONSHIPS;
  if (url.endsWith("/timeline")) return TIMELINE_FULL;
  if (url.includes("/api/v1/risk/incidents/") && url.includes("/calculate")) return RISK;
  if (url.includes("/api/v1/risk/incident/")) return RISK;
  if (url.includes("/api/v1/incidents/inc-1")) return DETAIL;
  if ((init?.method ?? "GET") !== "GET") throw new Error("unexpected write");
  if (url.includes("/api/v1/incidents?")) return PAGE;
  return {};
};

function routeWithTimeline(timelineValue: unknown): Handler {
  return (url, init) => {
    if (url.endsWith("/timeline")) return timelineValue;
    return baseRoute(url, init);
  };
}

async function openIncidentDetail() {
  await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Open"));
  await waitFor(() =>
    expect(screen.getByText("Relationship analysis (0)")).toBeInTheDocument(),
  );
}

function following(prev: Element, next: Element): boolean {
  return (prev.compareDocumentPosition(next) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
}

describe("Security timeline (Phase 3, Step 35)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("orders entries chronologically with day groups, tones and event deep links", async () => {
    mockFetch(baseRoute);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    await waitFor(() => expect(screen.getByText("Timeline (6)")).toBeInTheDocument());

    const list = screen.getByRole("list");
    expect(within(list).getAllByRole("listitem")).toHaveLength(8);

    const firstDay = new Date("2026-09-27T07:00:00").toLocaleDateString();
    const secondDay = new Date("2026-09-28T08:00:00").toLocaleDateString();
    expect(within(list).getByText(firstDay)).toBeInTheDocument();
    expect(within(list).getByText(secondDay)).toBeInTheDocument();

    expect(
      following(
        screen.getByText("First observed activity"),
        screen.getByText("Resolved and closed"),
      ),
    ).toBe(true);

    const links = screen.getAllByRole("link").map((link) => link.getAttribute("href"));
    expect(links).toEqual(["/events?event=evt-2", "/events?event=evt-3"]);

    const eventRow = screen.getByText("Additional observation").closest("li") as HTMLElement;
    expect(within(eventRow).getByText("event").className).toContain("badge warn");
    expect(within(eventRow).getByText(/entity 203\.0\.113\.9/)).toBeInTheDocument();
    expect(within(eventRow).getByText(/Later activity seen\./)).toBeInTheDocument();

    const observationRow = screen.getByText("First observed activity").closest("li") as HTMLElement;
    expect(within(observationRow).getByText("observation").className).toContain("badge neutral");

    const resolutionRow = screen.getByText("Resolved and closed").closest("li") as HTMLElement;
    expect(within(resolutionRow).getByText("resolution").className).toContain("badge ok");
  });

  it("shows a loading state while the timeline fetch is in flight", async () => {
    const delayedTimeline = new Promise((resolve) =>
      setTimeout(() => resolve(TIMELINE_FULL), 120),
    );
    mockFetch(
      (url, init) => {
        if (url.endsWith("/timeline")) return delayedTimeline;
        return baseRoute(url, init);
      },
    );
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("Loading timeline…")).toBeInTheDocument(), {
      timeout: 1000,
    });
    await waitFor(() => expect(screen.getByText("Timeline (6)")).toBeInTheDocument(), {
      timeout: 2000,
    });
  });

  it("shows an error state and reloads the timeline on demand", async () => {
    let failTimeline = true;
    mockFetch((url, init) => {
      if (url.endsWith("/timeline") && failTimeline) return fail("INTERNAL_ERROR", 500);
      return baseRoute(url, init);
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    await waitFor(() =>
      expect(screen.getByText("Timeline could not be loaded.")).toBeInTheDocument(),
    );
    expect(screen.queryByText("Timeline (6)")).toBeNull();
    expect(screen.getByText("Relationship analysis (0)")).toBeInTheDocument();

    failTimeline = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry timeline" }));
    await waitFor(() => expect(screen.getByText("Timeline (6)")).toBeInTheDocument(), {
      timeout: 2000,
    });
  });

  it("keeps timeline reads restricted when permission is denied", async () => {
    mockFetch(routeWithTimeline(fail("PERMISSION_DENIED", 403)));
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    await waitFor(() =>
      expect(screen.getByText("Timeline is restricted for your account.")).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: "Retry timeline" })).toBeNull();
    expect(screen.queryByText("Timeline (6)")).toBeNull();
    expect(screen.getByText("Relationship analysis (0)")).toBeInTheDocument();
  });

  it("renders the honest empty state when no entries are stored", async () => {
    mockFetch(routeWithTimeline({ incident_id: "inc-1", truncated: false, entries: [] }));
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    await waitFor(() =>
      expect(screen.getByText("No timeline entries are stored yet.")).toBeInTheDocument(),
    );
    expect(screen.queryByText("Timeline (0)")).toBeNull();
    expect(screen.queryByLabelText("Filter timeline by type")).toBeNull();
  });

  it("filters by kind, reports no matches and labels server truncation", async () => {
    mockFetch(routeWithTimeline({ ...TIMELINE_FULL, truncated: true }));
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    await waitFor(() => expect(screen.getByText("Timeline (6)")).toBeInTheDocument());
    expect(
      screen.getByText("Timeline truncated at the server bound — earlier entries are omitted."),
    ).toBeInTheDocument();

    const filterSelect = screen.getByLabelText("Filter timeline by type") as HTMLSelectElement;
    fireEvent.change(filterSelect, { target: { value: "event" } });
    await waitFor(() => expect(screen.getByText("Timeline (2)")).toBeInTheDocument());
    expect(screen.getByText("Authentication succeeded")).toBeInTheDocument();
    expect(screen.getByText("Additional observation")).toBeInTheDocument();
    expect(screen.queryByText("Resolved and closed")).toBeNull();

    fireEvent.change(filterSelect, { target: { value: "evidence" } });
    await waitFor(() => expect(screen.getByText("Timeline (0)")).toBeInTheDocument());
    expect(screen.getByText("No timeline entries match this filter.")).toBeInTheDocument();
    expect(screen.queryByText("Authentication succeeded")).toBeNull();
  });
});