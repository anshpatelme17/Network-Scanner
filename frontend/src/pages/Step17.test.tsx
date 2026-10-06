import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Incidents } from "./Incidents";

const ITEM = {
  id: "inc-1",
  incident_key: "INC-ABC123DEF456",
  title: "Incident: Activity on a host with a known finding",
  description: "Security incident opened for review.",
  status: "OPEN",
  severity: "HIGH",
  confidence: 70,
  primary_asset_id: null,
  primary_ip: "192.0.2.50",
  hostname: null,
  correlation_id: "corr-1",
  risk_assessment_id: null,
  first_seen: "2026-09-27T06:00:00",
  last_seen: "2026-09-27T06:20:00",
  resolved_at: null,
  created_at: "2026-09-27T06:21:00",
  updated_at: "2026-09-27T06:21:00",
  version: "1.0.0",
  incident_type: "VULNERABILITY_ACTIVITY",
  risk_score: null,
  detection_reason: "A recorded vulnerability finding combined with 1 observed event(s).",
};

const PAGE = { items: [ITEM], total: 1, limit: 100, offset: 0 };
const DETAIL = { ...ITEM, evidence_event_ids: ["evt-1", "evt-2"] };
const EVIDENCE = {
  incident_id: "inc-1",
  incident_type: "VULNERABILITY_ACTIVITY",
  detection_reason: ITEM.detection_reason,
  correlation: {
    id: "corr-1",
    rule_id: "vuln-exposure",
    rule_name: "Activity on a host with a known finding",
    severity: "HIGH",
    confidence: 70,
    explanation: "Host 192.0.2.50 has a recorded finding and related activity.",
  },
  events: [
    {
      id: "evt-1",
      event_type: "VULNERABILITY_FINDING",
      severity: "HIGH",
      source_type: "VULNERABILITY_SCANNER",
      title: "Test finding",
      event_time: "2026-09-27T06:00:00",
      role: "vulnerability",
      reason: "Evidence event in role 'vulnerability'.",
    },
    {
      id: "evt-2",
      event_type: "NETWORK",
      severity: "MEDIUM",
      source_type: "SURICATA",
      title: "Observed activity",
      event_time: "2026-09-27T06:20:00",
      role: "activity",
      reason: "Evidence event in role 'activity'.",
    },
  ],
  vulnerabilities: [],
};
const TIMELINE = {
  incident_id: "inc-1",
  entries: [
    {
      at: "2026-09-27T06:00:00",
      kind: "observation",
      label: "First observed activity",
      detail: "Correlation window opened.",
    },
    {
      at: "2026-09-27T06:21:00",
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
      created_at: "2026-09-27T06:21:00",
    },
  ],
};
const DETECT_RESULT = {
  evaluated: 1,
  created: 1,
  updated: 0,
  skipped: 0,
  detector_version: "1.0.0",
  outcomes: [{ correlation_id: "corr-1", incident_id: "inc-1", created: true, reason: "ok" }],
};

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => ({
      ok: true,
      status: 200,
      json: async () => handler(String(url), init),
    }),
  );
}

function route(url: string, init?: RequestInit): unknown {
  const method = init?.method ?? "GET";
  if (url.endsWith("/evidence")) return EVIDENCE;
  if (url.endsWith("/timeline")) return TIMELINE;
  if (url.endsWith("/audit")) return AUDIT;
  if (url.endsWith("/detect") && method === "POST") return DETECT_RESULT;
  if (url.endsWith("/status")) return { ...DETAIL, status: "ACKNOWLEDGED" };
  if (url.includes("/api/v1/incidents/inc-1")) return DETAIL;
  return PAGE;
}

describe("Incidents page (Step 17)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders type and risk columns and filters by type through the API", async () => {
    const seen: string[] = [];
    mockFetch((url) => {
      seen.push(url);
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("VULNERABILITY_ACTIVITY")).toBeInTheDocument());
    expect(screen.getByText("Type")).toBeInTheDocument();
    expect(screen.getByText("Risk")).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Filter by type"), {
      target: { value: "VULNERABILITY_ACTIVITY" },
    });
    await waitFor(() =>
      expect(seen.some((url) => url.includes("incident_type=VULNERABILITY_ACTIVITY"))).toBe(true),
    );
  });

  it("shows risk distinct from severity plus evidence, timeline and audit", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText(/Why this incident exists/)).toBeInTheDocument());
    // Severity badge vs risk score are visibly distinct values.
    expect(screen.getAllByText("HIGH").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/risk —/)).toBeInTheDocument();
    expect(screen.getByText(/distinct/)).toBeInTheDocument();
    expect(screen.getByText(/not proof of compromise/)).toBeInTheDocument();
    // Rich evidence roles from the evidence endpoint.
    expect(screen.getByText(/\(vulnerability\)/)).toBeInTheDocument();
    expect(screen.getByText(/\(activity\)/)).toBeInTheDocument();
    // Correlation explanation, timeline and audit history.
    expect(screen.getByText("Correlation explanation")).toBeInTheDocument();
    expect(screen.getByText("Timeline (2)")).toBeInTheDocument();
    expect(screen.getByText("Audit history (1)")).toBeInTheDocument();
    expect(screen.getByText("OPENED")).toBeInTheDocument();
  });

  it("runs detection and reports the summary", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      return route(url, init);
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Run detection")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Run detection"));
    await waitFor(() =>
      expect(
        seen.some((entry) => entry.startsWith("POST") && entry.endsWith("/detect")),
      ).toBe(true),
    );
    await waitFor(() =>
      expect(screen.getByText(/1 opened, 0 updated, 0 skipped/)).toBeInTheDocument(),
    );
  });

  it("keeps an honest empty state when nothing is recorded", async () => {
    mockFetch(() => ({ items: [], total: 0, limit: 100, offset: 0 }));
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("No incidents recorded.")).toBeInTheDocument(),
    );
    expect(screen.getByText(/proves a host is compromised/)).toBeInTheDocument();
  });
});
