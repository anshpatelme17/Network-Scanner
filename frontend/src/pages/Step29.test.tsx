import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { Events } from "./Events";
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
  risk_assessment_id: null,
  first_seen: "2026-09-27T07:00:00",
  last_seen: "2026-09-27T07:10:00",
  resolved_at: null,
  created_at: "2026-09-27T07:11:00",
  updated_at: "2026-09-27T07:11:00",
  version: "1.0.0",
  incident_type: "AUTHENTICATION_ANOMALY",
  risk_score: null,
  detection_reason:
    "Correlation corr-1 groups 3 related events against 203.0.113.9 under rule 'repeated-source' (bar: 3).",
};

const PAGE = { items: [ITEM], total: 1, limit: 100, offset: 0 };
const DETAIL = { ...ITEM, evidence_event_ids: ["evt-1", "evt-2"] };

const EVIDENCE = {
  incident_id: "inc-1",
  incident_type: "AUTHENTICATION_ANOMALY",
  detection_reason: ITEM.detection_reason,
  correlation: {
    id: "corr-1",
    rule_id: "repeated-source",
    rule_name: "Repeated activity from one source",
    severity: "HIGH",
    confidence: 75,
    explanation:
      "3 events from source 203.0.113.9 observed within 15 minutes against 198.51.100.23.",
  },
  events: [
    {
      id: "evt-1",
      event_type: "WAZUH_AUTH",
      severity: "MEDIUM",
      source_type: "WAZUH",
      title: "Authentication failed",
      event_time: "2026-09-27T07:00:00",
      role: "related",
      reason: "Evidence event.",
    },
    {
      id: "evt-2",
      event_type: "WAZUH_AUTH",
      severity: "HIGH",
      source_type: "WAZUH",
      title: "Authentication succeeded",
      event_time: "2026-09-27T07:05:00",
      role: "related",
      reason: "Evidence event.",
    },
  ],
  vulnerabilities: [],
  evidence_count: 3,
  truncated: false,
  primary_event: { id: "evt-1", role: "related", title: "Authentication failed" },
  source_distribution: { WAZUH: 3 },
  entities: {
    source_ips: ["203.0.113.9"],
    destination_ips: ["192.0.2.77"],
    hostnames: [],
    usernames: ["alice"],
  },
  assets: [{ id: "asset-1", ip_address: "192.0.2.77", hostname: "workstation-77" }],
  first_observed: "2026-09-27T07:00:00",
  last_observed: "2026-09-27T07:10:00",
  correlation_rules: [
    {
      rule_id: "repeated-source",
      rule_name: "Repeated activity from one source",
      confidence: 75,
      confidence_label: "STRONG",
      relationship_count: 0,
    },
    {
      rule_id: "entity-event-indicator",
      rule_name: "Event observed against a network indicator",
      confidence: 80,
      confidence_label: "STRONG",
      relationship_count: 6,
    },
  ],
};

const TEMPORAL_RELATIONSHIP = {
  id: "r".repeat(64),
  incident_id: "inc-1",
  rule_id: "temporal-auth-sequence",
  rule_name: "Auth failure then success then suspicious observation",
  relation: "followed_by",
  source_kind: "event",
  source_id: "evt-1",
  source_label: "Authentication failed",
  target_kind: "event",
  target_id: "evt-2",
  target_label: "Authentication succeeded",
  confidence: 75,
  confidence_label: "STRONG",
  explanation:
    "Authentication failure then successful authentication then suspicious observation " +
    "for user 'alice' within the configured 60-minute correlation window (ordered by " +
    "timestamp; chain evt-1 -> evt-2 -> evt-3).",
  evidence_event_ids: ["evt-1", "evt-2", "evt-3"],
  first_seen: "2026-09-27T07:00:00",
  last_seen: "2026-09-27T07:10:00",
};

const ASSET_RELATIONSHIP = {
  id: "s".repeat(64),
  incident_id: "inc-1",
  rule_id: "entity-event-asset",
  rule_name: "Event observed on an inventoried asset",
  relation: "observed_on",
  source_kind: "event",
  source_id: "evt-1",
  source_label: "Authentication failed",
  target_kind: "asset",
  target_id: "asset-1",
  target_label: "192.0.2.77",
  confidence: 90,
  confidence_label: "DIRECT",
  explanation:
    "Event evt-1 reports destination_ip=192.0.2.77, which equals stored asset asset-1 " +
    "— direct field match, no inference and no manufactured asset.",
  evidence_event_ids: ["evt-1"],
  first_seen: "2026-09-27T07:00:00",
  last_seen: "2026-09-27T07:00:00",
};

const RELATIONSHIPS = {
  incident_id: "inc-1",
  items: [TEMPORAL_RELATIONSHIP, ASSET_RELATIONSHIP],
  total: 2,
  limit: 50,
  offset: 0,
};

const RECALC = {
  incident_id: "inc-1",
  analysis_version: "1.0.0",
  rules_evaluated: 8,
  events_considered: 3,
  relationships_created: 1,
  relationships_refreshed: 1,
  relationships_total: 2,
  truncated: false,
  bounds: { max_events: 200, max_relationships: 200 },
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
      at: "2026-09-27T07:11:00",
      kind: "opened",
      label: "Opened",
      detail: "detection: opened from correlation corr-1.",
    },
  ],
};

const AUDIT = {
  incident_id: "inc-1",
  entries: [
    {
      action: "OPENED",
      actor: "detection",
      detail: "Opened from correlation corr-1.",
      created_at: "2026-09-27T07:11:00",
    },
  ],
};

type Handler = (url: string, init?: RequestInit) => unknown;

function mockFetch(handler: Handler) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => ({
      ok: true,
      status: 200,
      json: async () => handler(String(url), init),
    }),
  );
}

function incidentRoute(failFor?: string): Handler {
  return (url: string, init?: RequestInit) => {
    if (failFor && url.includes(failFor)) throw new Error("refused");
    if (url.includes("/recalculate")) return RECALC;
    if (url.includes("/relationships")) return RELATIONSHIPS;
    if (url.endsWith("/evidence")) return EVIDENCE;
    if (url.endsWith("/timeline")) return TIMELINE;
    if (url.endsWith("/audit")) return AUDIT;
    if (url.endsWith("/responses?limit=100")) return { items: [], total: 0, limit: 100, offset: 0 };
    if (url.includes("/api/v1/incidents/inc-1")) return DETAIL;
    if (init?.method === "POST") throw new Error("unexpected post");
    return PAGE;
  };
}

const EVENT_DETAIL = {
  id: "evt-9",
  event_time: "2026-09-27T07:10:00",
  received_at: "2026-09-27T07:10:05",
  source_type: "WAZUH",
  source_name: "step29-wazuh",
  event_type: "WAZUH_SUSPICIOUS",
  severity: "HIGH",
  title: "Suspicious process observed",
  description: null,
  source_ip: "203.0.113.9",
  destination_ip: "192.0.2.77",
  source_port: null,
  destination_port: null,
  protocol: null,
  asset_id: null,
  hostname: null,
  username: "alice",
  process_name: null,
  action: null,
  status: null,
  confidence: null,
  occurrence_count: 1,
  last_seen_at: null,
  ingest_mode: "FIXTURE",
  raw_event: null,
  normalized_data: {},
  correlation_key: null,
  fingerprint: "fp-step29",
  external_event_id: "s29-3",
  created_at: "2026-09-27T07:10:06",
};

function eventsRoute(): Handler {
  return (url: string) => {
    if (url.includes("/events/connectors")) return { items: [] };
    if (url.includes("/events/ingestion")) return {};
    if (url.includes("/events/evt-9")) return EVENT_DETAIL;
    if (url.includes("/api/v1/events?")) return { items: [], total: 0, limit: 100, offset: 0 };
    return {};
  };
}

async function openIncidentDetail() {
  await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Open"));
  await waitFor(() => expect(screen.getByText("Relationship analysis (2)")).toBeInTheDocument());
}

describe("Incident intelligence UI (Step 29)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("shows stored relationships with rule, confidence label and explanation", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    expect(screen.getByText("temporal-auth-sequence")).toBeInTheDocument();
    expect(screen.getAllByText("STRONG").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("entity-event-asset")).toBeInTheDocument();
    expect(screen.getAllByText("DIRECT").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/60-minute correlation window/)).toBeInTheDocument();
    expect(screen.getByText(/followed_by · confidence 75/)).toBeInTheDocument();
    expect(screen.getByText(/no inference and no manufactured asset/)).toBeInTheDocument();
    // Neutral, deterministic language — no AI certainty claims.
    expect(screen.getByText(/not a machine-learning prediction/)).toBeInTheDocument();
    expect(screen.queryByText(/AI-driven/)).toBeNull();
  });

  it("links relationship evidence back to the original event", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    const links = screen.getAllByRole("link");
    const hrefs = links.map((link) => link.getAttribute("href"));
    expect(hrefs).toContain("/events?event=evt-1");
    expect(hrefs).toContain("/events?event=evt-2");
    expect(hrefs).toContain("/events?event=evt-3");
    // Evidence list deep-links too (Incident → Evidence → Original Event).
    expect(hrefs.filter((href) => href === "/events?event=evt-1").length).toBeGreaterThanOrEqual(2);
  });

  it("recalculates with a bodyless POST and reports bounded results", async () => {
    const fetchMock = incidentRoute();
    mockFetch(fetchMock);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    fireEvent.click(screen.getByText("Recalculate analysis"));
    await waitFor(() =>
      expect(
        screen.getByText("Analysis v1.0.0: 1 created, 1 refreshed, 2 stored."),
      ).toBeInTheDocument(),
    );
    const calls = (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls as [
      string,
      RequestInit | undefined,
    ][];
    const recalcCall = calls.find(([url]) => url.includes("/recalculate"));
    expect(recalcCall).toBeTruthy();
    expect(recalcCall?.[1]?.method).toBe("POST");
    expect(recalcCall?.[1]?.body).toBeUndefined(); // rules are server-side only
  });

  it("renders the evidence overview: entities, assets, bounds and contributing rules", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    expect(screen.getByText(/Evidence count 3/)).toBeInTheDocument();
    expect(screen.getByText(/source IPs 203\.0\.113\.9/)).toBeInTheDocument();
    expect(screen.getByText(/Affected assets \(stored inventory only\): workstation-77/))
      .toBeInTheDocument();
    expect(screen.getByText("Correlation rules (2)")).toBeInTheDocument();
    expect(screen.getByText("entity-event-indicator")).toBeInTheDocument();
    expect(screen.getByText(/6 stored relationship\(s\)/)).toBeInTheDocument();
  });

  it("renders timeline event entries with entity and original-event link", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    await waitFor(() => expect(screen.getByText("Timeline (3)")).toBeInTheDocument());
    expect(screen.getByText(/entity 192\.0\.2\.77/)).toBeInTheDocument();
    const hrefs = screen
      .getAllByRole("link")
      .map((link) => link.getAttribute("href"));
    expect(hrefs).toContain("/events?event=evt-2");
  });

  it("keeps an honest empty state when no relationships are stored", async () => {
    mockFetch((url, init) => incidentRoute()(url, init) === RELATIONSHIPS
      ? { ...RELATIONSHIPS, items: [], total: 0 }
      : incidentRoute()(url, init));
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() =>
      expect(screen.getByText("Relationship analysis (0)")).toBeInTheDocument(),
    );
    expect(screen.getByText(/No deterministic relationships are stored/)).toBeInTheDocument();
    expect(screen.getByText(/a vulnerability finding alone never creates a relationship/))
      .toBeInTheDocument();
  });

  it("hides relationship analysis when the read fails", async () => {
    mockFetch(incidentRoute("/relationships"));
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("Correlation explanation")).toBeInTheDocument());
    expect(screen.queryByText(/Relationship analysis/)).toBeNull();
    expect(screen.queryByText("Recalculate analysis")).toBeNull();
  });

  it("opens the original event from an ?event= deep link", async () => {
    window.history.replaceState({}, "", "/events?event=evt-9");
    mockFetch(eventsRoute());
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Suspicious process observed" })).toBeInTheDocument(),
    );
    expect(screen.getByText(/fp-step29/)).toBeInTheDocument();
  });

  it("leaves the detail closed when the deep-linked event is unknown", async () => {
    window.history.replaceState({}, "", "/events?event=missing");
    mockFetch((url) => {
      if (url.includes("/events/missing")) throw new Error("404");
      return eventsRoute()(url);
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Security events (0)")).toBeInTheDocument());
    expect(screen.queryByRole("heading", { name: "Suspicious process observed" })).toBeNull();
  });
});
