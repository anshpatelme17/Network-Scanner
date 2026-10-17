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

const TIMELINE = {
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
      at: "2026-09-27T07:20:00",
      kind: "response",
      label: "Response Requested",
      detail: "analyst-1: — -> PENDING_APPROVAL",
      action_id: "act-1",
      action_type: "BLOCK_INDICATOR",
      event: "RESPONSE_REQUESTED",
      actor: "analyst-1",
      previous_status: null,
      new_status: "PENDING_APPROVAL",
    },
    {
      at: "2026-09-27T07:30:00",
      kind: "response",
      label: "Response Approved",
      detail: "operator-1: PENDING_APPROVAL -> APPROVED",
      action_id: "act-1",
      action_type: "BLOCK_INDICATOR",
      event: "RESPONSE_APPROVED",
      actor: "operator-1",
      previous_status: "PENDING_APPROVAL",
      new_status: "APPROVED",
    },
  ],
};

type Handler = (url: string, init?: RequestInit) => unknown;

function mockFetch(handler: Handler) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => {
      const value = handler(String(url), init);
      return { ok: true, status: 200, json: async () => value };
    },
  );
}

const route: Handler = (url, init) => {
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

async function openIncidentDetail() {
  await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Open"));
  await waitFor(() => expect(screen.getByText("Timeline (4)")).toBeInTheDocument());
}

describe("Security timeline response lifecycle (Phase 4, Step 44)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("renders controlled-response lifecycle entries with a distinct tone", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();

    const requestedRow = screen.getByText("Response Requested").closest("li") as HTMLElement;
    const approvedRow = screen.getByText("Response Approved").closest("li") as HTMLElement;

    expect(within(requestedRow).getByText("response").className).toContain("badge info");
    expect(within(approvedRow).getByText("response").className).toContain("badge info");

    // The action type and action id are shown; the id is plain code, no link.
    expect(within(approvedRow).getByText(/BLOCK_INDICATOR/)).toBeInTheDocument();
    expect(within(approvedRow).getByText("act-1")).toBeInTheDocument();
    expect(within(approvedRow).getByText(/PENDING_APPROVAL -> APPROVED/)).toBeInTheDocument();
  });

  it("adds no deep links for response entries", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();

    const links = screen.getAllByRole("link").map((link) => link.getAttribute("href"));
    expect(links).toEqual(["/events?event=evt-2"]);
  });

  it("filters the timeline down to response entries", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();

    const filterSelect = screen.getByLabelText("Filter timeline by type") as HTMLSelectElement;
    fireEvent.change(filterSelect, { target: { value: "response" } });
    await waitFor(() => expect(screen.getByText("Timeline (2)")).toBeInTheDocument());
    expect(screen.getByText("Response Requested")).toBeInTheDocument();
    expect(screen.getByText("Response Approved")).toBeInTheDocument();
    expect(screen.queryByText("Authentication succeeded")).toBeNull();
    expect(screen.queryByText("First observed activity")).toBeNull();
  });
});
