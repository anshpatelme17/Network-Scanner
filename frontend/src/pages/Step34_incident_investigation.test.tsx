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
  detection_reason:
    "Correlation corr-1 groups 3 related events against 203.0.113.9 under rule 'repeated-source' (bar: 3).",
};

const PAGE = { items: [ITEM], total: 1, limit: 100, offset: 0 };
const DETAIL = { ...ITEM, evidence_event_ids: ["evt-1", "evt-2"] };
const DETAIL_EMPTY = { ...ITEM, evidence_event_ids: [] };

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
  vulnerabilities: [
    {
      id: "vuln-1",
      title: "Outdated component",
      severity: "HIGH",
      status: "OPEN",
      cve_id: "CVE-2026-1234",
      reason: "matched stored inventory.",
    },
  ],
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

const EVIDENCE_EMPTY = {
  incident_id: "inc-1",
  incident_type: "AUTHENTICATION_ANOMALY",
  detection_reason: null,
  correlation: null,
  events: [],
  vulnerabilities: [],
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
    {
      action: "STATUS_CHANGED",
      actor: "operator@example.com",
      detail: "Status OPEN -> ACKNOWLEDGED.",
      created_at: "2026-09-27T08:00:00",
    },
  ],
};

const RESPONSE_PROPOSED = {
  id: "act-1",
  incident_id: "inc-1",
  action_type: "REVIEW",
  target_type: "incident",
  target_reference: "inc-1",
  reason: "Confirm no other correlated observations.",
  requested_by: "operator",
  status: "PROPOSED",
  dry_run: true,
  policy_version: "1.0.0",
  execution_status: null,
  created_at: "2026-09-27T07:20:00",
  approved_at: null,
  expires_at: null,
  approved_by: null,
  started_at: null,
  completed_at: null,
  failure_reason: null,
  result_summary: null,
  provider: "manual",
  policy_decision: "DRY_RUN_ONLY",
  approval_required: true,
  rollback_supported: false,
  rollback_state: null,
  rollback_reference: null,
  target_evidence: ["evt-1"],
};

const RESPONSE_APPROVED = {
  ...RESPONSE_PROPOSED,
  id: "act-2",
  action_type: "ACKNOWLEDGE",
  status: "APPROVED",
  execution_status: "READY_FOR_EXECUTION",
  approved_at: "2026-09-27T07:30:00",
  approved_by: "senior@example.com",
  result_summary: "Ready to run in the next controlled window.",
  policy_decision: "APPROVAL_REQUIRED",
};

const RESPONSES = { items: [RESPONSE_PROPOSED, RESPONSE_APPROVED], total: 2, limit: 100, offset: 0 };

const RECOMMENDATIONS = {
  incident_id: "inc-1",
  incident_key: "INC-INTEL1234567",
  severity: "HIGH",
  risk_score: 74,
  risk_priority: "P2",
  items: [
    {
      action_type: "BLOCK_INDICATOR",
      target_type: "indicator",
      target_reference: "203.0.113.9",
      incident_id: "inc-1",
      incident_key: "INC-INTEL1234567",
      severity: "HIGH",
      risk_priority: "P2",
      available: true,
      provider: "fixture-dns",
      evidence_event_ids: ["evt-1"],
      reason: "Event evt-1 referenced this indicator and no approval was needed to draft it.",
      requires_approval: true,
      automatic: false,
    },
  ],
  total: 1,
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
  factors: { severity_impact: 0.75, evidence_count: 3, exposure: "single" },
  explanation: "Stored evidence implies elevated risk for the target asset.",
  calculated_at: "2026-09-27T07:11:00",
  scoring_version: "1.0.0",
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

function incidentRoute(failFor?: string): Handler {
  return (url: string, init?: RequestInit) => {
    if (failFor && url.includes(failFor)) throw new Error(`refused: ${failFor}`);
    if (url.endsWith("/responses?limit=100")) return RESPONSES;
    if (url.includes("/response-recommendations")) return RECOMMENDATIONS;
    if (url.includes("/recalculate")) return {};
    if (url.includes("/relationships?")) return RELATIONSHIPS;
    if (url.endsWith("/evidence")) return EVIDENCE;
    if (url.endsWith("/timeline")) return TIMELINE;
    if (url.endsWith("/audit")) return AUDIT;
    if (url.includes("/api/v1/risk/incidents/") && url.includes("/calculate")) return RISK;
    if (url.includes("/api/v1/risk/incident/")) return RISK;
    if (url.includes("/api/v1/incidents/inc-1")) return DETAIL;
    if ((init?.method ?? "GET") !== "GET") throw new Error("unexpected write");
    if (url.includes("/api/v1/incidents?")) return PAGE;
    return {};
  };
}

async function openIncidentDetail() {
  await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Open"));
  await waitFor(() => expect(screen.getByText("Relationship analysis (2)")).toBeInTheDocument());
}

function follows(prev: Element, next: Element): boolean {
  return (prev.compareDocumentPosition(next) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;
}

describe("Incident investigation workspace (Phase 3, Step 34)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("renders the incident summary header with real record data", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    expect(screen.getByRole("heading", { name: /INC-INTEL1234567/ })).toBeInTheDocument();
    expect(screen.getByText("Correlated authentication sequence.")).toBeInTheDocument();
    expect(screen.getByText(/Why this incident exists/)).toBeInTheDocument();
    expect(screen.getByText("confidence 75")).toBeInTheDocument();
    expect(screen.getByText(/risk 74/)).toBeInTheDocument();
    expect(screen.getByText(/Correlation: corr-1/)).toBeInTheDocument();
    expect(screen.getByText(/Asset: 192\.0\.2\.77/)).toBeInTheDocument();
    expect(screen.getAllByText("HIGH").length).toBeGreaterThanOrEqual(2);
  });

  it("orders the investigation sections in analyst order without inventing steps", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    const title = screen.getByRole("heading", { name: /INC-INTEL1234567/ });
    const happened = screen.getByRole("heading", { level: 4, name: "What happened?" });
    const evidence = screen.getByRole("heading", { level: 4, name: "What evidence supports it?" });
    const relationships = screen.getByRole("heading", { level: 4, name: "What relationships exist?" });
    const when = screen.getByRole("heading", { level: 4, name: "When did it happen?" });
    const assessment = screen.getByRole("heading", { level: 4, name: "What is the current assessment?" });
    const record = screen.getByRole("heading", { level: 4, name: "What happened to the record?" });
    const next = screen.getByRole("heading", { level: 4, name: "What can happen next?" });
    const chain = [title, happened, evidence, relationships, when, assessment, record, next];
    for (let index = 1; index < chain.length; index += 1) {
      expect(follows(chain[index - 1], chain[index])).toBe(true);
    }
  });

  it("renders stored evidence: events, findings, assets, correlation and rules", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    expect(screen.getByText(/Correlated observations: 2 event\(s\)/)).toBeInTheDocument();
    expect(screen.getByText(/Evidence count 3/)).toBeInTheDocument();
    expect(screen.getByText(/source IPs 203\.0\.113\.9/)).toBeInTheDocument();
    expect(screen.getByText(/Affected assets \(stored inventory only\): workstation-77/))
      .toBeInTheDocument();
    expect(screen.getAllByText(/Authentication failed/).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("Related vulnerability findings (1)")).toBeInTheDocument();
    expect(screen.getByText("Outdated component")).toBeInTheDocument();
    expect(screen.getByText("CVE-2026-1234 · OPEN")).toBeInTheDocument();
    expect(screen.getByText("Correlation explanation")).toBeInTheDocument();
    expect(screen.getByText("Correlation rules (2)")).toBeInTheDocument();
    expect(screen.getByText(/6 stored relationship\(s\)/)).toBeInTheDocument();
    expect(screen.getByText(/references only, never payload copies/)).toBeInTheDocument();
  });

  it("keeps an honest empty state when no evidence is stored", async () => {
    mockFetch((url, init) => {
      if (url.endsWith("/evidence")) return EVIDENCE_EMPTY;
      if (url.includes("/api/v1/incidents/inc-1")) return DETAIL_EMPTY;
      return incidentRoute()(url, init);
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() =>
      expect(screen.getByText(/No supporting evidence is stored for this incident yet\./))
        .toBeInTheDocument(),
    );
    expect(screen.getByText("No evidence references.")).toBeInTheDocument();
    expect(screen.queryByText("Correlation explanation")).toBeNull();
  });

  it("renders the stored timeline without fabricated entries", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    await waitFor(() => expect(screen.getByText("Timeline (3)")).toBeInTheDocument());
    expect(screen.getByText(/First observed activity/)).toBeInTheDocument();
    expect(screen.getByText(/Correlation window opened\./)).toBeInTheDocument();
    expect(screen.getByText(/entity 192\.0\.2\.77/)).toBeInTheDocument();
    expect(screen.queryByText(/No timeline entries are stored yet\./)).toBeNull();
    expect(screen.getAllByText("opened").length).toBeGreaterThanOrEqual(1);
  });

  it("keeps advisory risk distinct from severity", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    expect(screen.getByText(/74 \(HIGH\)/)).toBeInTheDocument();
    expect(screen.getByText("priority P2")).toBeInTheDocument();
    expect(screen.getByText(/scoring v1\.0\.0/)).toBeInTheDocument();
    expect(screen.getByText("Advisory risk")).toBeInTheDocument();
    expect(screen.getByText(/CALCULATED RISK/)).toBeInTheDocument();
    expect(screen.getByText(/the two are distinct/)).toBeInTheDocument();
    expect(screen.getByText(/evidence_count=3/)).toBeInTheDocument();
  });

  it("degrades to the unscored state when the risk lookup fails", async () => {
    mockFetch((url, init) => {
      if (url.includes("/api/v1/risk/incident/")) return fail("INTERNAL_ERROR", 500);
      return incidentRoute()(url, init);
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    await waitFor(() =>
      expect(screen.getByText(/No incident risk calculated yet\./)).toBeInTheDocument(),
    );
    expect(screen.getByRole("button", { name: "Calculate risk" })).toBeInTheDocument();
    expect(screen.queryByText(/74 \(HIGH\)/)).toBeNull();
    expect(screen.getByText("Correlation explanation")).toBeInTheDocument();
  });

  it("keeps other sections when the audit trail denies permission", async () => {
    mockFetch((url, init) => {
      if (url.endsWith("/audit")) return fail("PERMISSION_DENIED", 403);
      return incidentRoute()(url, init);
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    await waitFor(() =>
      expect(screen.getByText("Audit history is restricted for your account.")).toBeInTheDocument(),
    );
    expect(screen.queryByText("Audit history (2)")).toBeNull();
    expect(screen.getByText("What happened to the record?")).toBeInTheDocument();
    expect(screen.getByText("Correlation explanation")).toBeInTheDocument();
    expect(screen.getByText("Relationship analysis (2)")).toBeInTheDocument();
    expect(screen.getByText("Timeline (3)")).toBeInTheDocument();
    expect(screen.getByText(/74 \(HIGH\)/)).toBeInTheDocument();
  });

  it("isolates a failed section without erasing successful ones", async () => {
    mockFetch((url, init) => {
      if (url.endsWith("/timeline")) return fail("INTERNAL_ERROR", 500);
      return incidentRoute()(url, init);
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    await waitFor(() => expect(screen.getByText("Timeline could not be loaded.")).toBeInTheDocument());
    expect(screen.queryByText("Timeline (3)")).toBeNull();
    expect(screen.getByText("Correlation explanation")).toBeInTheDocument();
    expect(screen.getByText("Relationship analysis (2)")).toBeInTheDocument();
    expect(screen.getByText("Audit history (2)")).toBeInTheDocument();
    expect(screen.getByText("Controlled responses (2)")).toBeInTheDocument();
    expect(screen.getByText(/74 \(HIGH\)/)).toBeInTheDocument();
  });

  it("keeps response approval governance and never executes automatically on view", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    expect(screen.getByText("Controlled responses (2)")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reject" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Execute" })).toBeInTheDocument();
    expect(screen.getAllByRole("button", { name: "Cancel" })).toHaveLength(2);
    expect(screen.getByText(/needs approval before it can run/)).toBeInTheDocument();
    expect(screen.getByText(/nothing here executes automatically/)).toBeInTheDocument();
    expect(screen.getByText("Recommended defensive responses (1)")).toBeInTheDocument();
  });

  it("performs no write calls while opening and reading an incident", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    const calls = (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls as [
      string,
      RequestInit | undefined,
    ][];
    expect(calls.length).toBeGreaterThan(0);
    const writes = calls.filter(([, init]) => (init?.method ?? "GET") !== "GET");
    expect(writes).toHaveLength(0);
    const urls = calls.map(([url]) => url);
    expect(
      urls.some(
        (url) =>
          url.includes("/execute") ||
          url.includes("/controlled") ||
          url.includes("/approve") ||
          url.includes("/reject") ||
          url.includes("/cancel") ||
          url.includes("/detect"),
      ),
    ).toBe(false);
  });

  it("keeps the status lifecycle controls", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    expect(screen.getByRole("button", { name: "Mark Acknowledged" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Mark Closed" })).toBeInTheDocument();
  });

  it("keeps evidence, relationship and timeline event deep-links", async () => {
    mockFetch(incidentRoute());
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openIncidentDetail();
    await waitFor(() => expect(screen.getByText("Timeline (3)")).toBeInTheDocument());
    const hrefs = screen.getAllByRole("link").map((link) => link.getAttribute("href"));
    expect(hrefs).toContain("/events?event=evt-1");
    expect(hrefs).toContain("/events?event=evt-2");
    expect(hrefs).toContain("/events?event=evt-3");
  });

  it("introduces no destructive actions in the workspace", async () => {
    mockFetch((url, init) => {
      const value = incidentRoute()(url, init);
      if (url.endsWith("/responses?limit=100")) return { items: [], total: 0, limit: 100, offset: 0 };
      if (url.includes("/response-recommendations")) {
        return { ...RECOMMENDATIONS, items: [], total: 0, truncated: false };
      }
      return value;
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() =>
      expect(screen.getByText("Controlled responses (0)")).toBeInTheDocument(),
    );
    expect(screen.getByText("No responses proposed for this incident.")).toBeInTheDocument();
    expect(screen.getByText("No defensive responses are available for this incident."))
      .toBeInTheDocument();
    expect(screen.queryByText(/Block|Isolate|Delete|Rollback/i)).toBeNull();
    expect(screen.queryByText("Threat neutralized")).toBeNull();
  });
});