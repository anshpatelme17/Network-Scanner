import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Incidents } from "./Incidents";

const ITEM = {
  id: "inc-1",
  incident_key: "INC-CORR12345678",
  title: "Incident: Same target, multiple sources: 198.51.100.23",
  description: "Correlated security observations detected for review.",
  status: "OPEN",
  severity: "HIGH",
  confidence: 75,
  primary_asset_id: null,
  primary_ip: "198.51.100.23",
  hostname: null,
  correlation_id: "corr-1",
  risk_assessment_id: null,
  first_seen: "2026-09-27T06:00:00",
  last_seen: "2026-09-27T06:10:00",
  resolved_at: null,
  created_at: "2026-09-27T06:11:00",
  updated_at: "2026-09-27T06:11:00",
  version: "1.0.0",
  incident_type: "CORRELATED_SECURITY_EVENT",
  risk_score: null,
  detection_reason:
    "Correlation corr-1 groups 2 related events against 198.51.100.23 under rule 'multi-source-target' (bar: 3).",
};

const PAGE = { items: [ITEM], total: 1, limit: 100, offset: 0 };
const DETAIL = { ...ITEM, evidence_event_ids: ["evt-1", "evt-2"] };
const EVIDENCE = {
  incident_id: "inc-1",
  incident_type: "CORRELATED_SECURITY_EVENT",
  detection_reason: ITEM.detection_reason,
  correlation: {
    id: "corr-1",
    rule_id: "multi-source-target",
    rule_name: "Same target, multiple sources",
    severity: "HIGH",
    confidence: 75,
    explanation:
      "2 events from 2 distinct sources (SURICATA, ZEEK) observed the same destination 198.51.100.23 within 60 minutes.",
  },
  events: [
    {
      id: "evt-1",
      event_type: "SURICATA_ALERT",
      severity: "HIGH",
      source_type: "SURICATA",
      title: "First observation",
      event_time: "2026-09-27T06:00:00",
      role: "related",
      reason: "Evidence event.",
    },
    {
      id: "evt-2",
      event_type: "ZEEK_CONN",
      severity: "INFO",
      source_type: "ZEEK",
      title: "Second observation",
      event_time: "2026-09-27T06:10:00",
      role: "related",
      reason: "Evidence event.",
    },
  ],
  vulnerabilities: [
    {
      id: "vuln-1",
      title: "Test finding on the same asset",
      severity: "MEDIUM",
      status: "OPEN",
      cve_id: null,
      reason: "Finding shares asset identifiers with the incident host.",
    },
  ],
};
const SECOND_VULN = {
  id: "vuln-2",
  title: "Second bounded finding",
  severity: "LOW",
  status: "OPEN",
  cve_id: "CVE-2026-0002",
  reason: "Finding shares asset identifiers with the incident host.",
};
const EVIDENCE_TRUNCATED = {
  ...EVIDENCE,
  vulnerabilities: [EVIDENCE.vulnerabilities[0], SECOND_VULN],
  vulnerability_count: 7,
  vulnerabilities_truncated: true,
};
const EVIDENCE_EVENT_TRUNCATED = {
  ...EVIDENCE,
  evidence_count: 250,
  truncated: true,
  vulnerability_count: 1,
  vulnerabilities_truncated: false,
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
      at: "2026-09-27T06:10:00",
      kind: "observation",
      label: "Latest observed activity",
      detail: "Correlation window extends.",
    },
    {
      at: "2026-09-27T06:11:00",
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
      created_at: "2026-09-27T06:11:00",
    },
  ],
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

function route(url: string): unknown {
  if (url.endsWith("/evidence")) return EVIDENCE;
  if (url.endsWith("/timeline")) return TIMELINE;
  if (url.endsWith("/audit")) return AUDIT;
  if (url.endsWith("/responses?limit=100")) return { items: [], total: 0, limit: 100, offset: 0 };
  if (url.includes("/api/v1/incidents/inc-1")) return DETAIL;
  return PAGE;
}

function routeWithEvidence(evidencePayload: unknown) {
  return (url: string): unknown => {
    if (url.endsWith("/evidence")) return evidencePayload;
    return route(url);
  };
}

async function openIncident(evidencePayload: unknown) {
  mockFetch(routeWithEvidence(evidencePayload));
  render(
    <MemoryRouter>
      <Incidents />
    </MemoryRouter>,
  );
  await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Open"));
  await waitFor(() =>
    expect(screen.getByText(/Correlated observations:/)).toBeInTheDocument(),
  );
}

describe("Incidents page (Step 24 correlation)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("lists incidents with severity, confidence, and status", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("INC-CORR12345678")).toBeInTheDocument());
    expect(screen.getAllByText("HIGH").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("OPEN").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("198.51.100.23")).toBeInTheDocument();
  });

  it("shows correlated observations, explanation, timeline, and related findings", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() =>
      expect(screen.getByText(/Correlated observations:/)).toBeInTheDocument(),
    );
    expect(screen.getByText(/2 event\(s\)/)).toBeInTheDocument();
    expect(screen.getByText(/1 vulnerability finding\(s\)/)).toBeInTheDocument();
    expect(screen.getByText(/1 correlation/)).toBeInTheDocument();
    expect(screen.getByText("Correlation explanation")).toBeInTheDocument();
    expect(screen.getByText(/198\.51\.100\.23 within 60 minutes/)).toBeInTheDocument();
    expect(screen.getByText("Timeline (3)")).toBeInTheDocument();
    expect(screen.getByText("Test finding on the same asset")).toBeInTheDocument();
    expect(screen.getByText(/references only, never/)).toBeInTheDocument();
  });

  it("reports the true vulnerability total when the bounded list is complete", async () => {
    await openIncident({ ...EVIDENCE, vulnerability_count: 1, vulnerabilities_truncated: false });
    expect(screen.getByText(/1 vulnerability finding\(s\)/)).toBeInTheDocument();
    expect(screen.getByText("Related vulnerability findings (1)")).toBeInTheDocument();
    expect(screen.queryByText("incomplete")).toBeNull();
    expect(screen.queryByText(/Showing .* of .* vulnerability findings/)).toBeNull();
  });

  it("marks a capped vulnerability list incomplete and shows total vs displayed", async () => {
    await openIncident(EVIDENCE_TRUNCATED);
    expect(
      screen.getByText(/7 vulnerability finding\(s\) \(showing 2\)/),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Related vulnerability findings (7 total, showing 2)"),
    ).toBeInTheDocument();
    expect(screen.getByText("incomplete")).toBeInTheDocument();
    expect(screen.getByText(/Showing 2 of 7 vulnerability findings/)).toBeInTheDocument();
    expect(screen.getByText("Second bounded finding")).toBeInTheDocument();
  });

  it("falls back to the list length when the total fields are absent", async () => {
    await openIncident(EVIDENCE);
    expect(screen.getByText(/1 vulnerability finding\(s\)/)).toBeInTheDocument();
    expect(screen.getByText("Related vulnerability findings (1)")).toBeInTheDocument();
    expect(screen.queryByText("incomplete")).toBeNull();
  });

  it("does not treat event truncation as vulnerability truncation", async () => {
    await openIncident(EVIDENCE_EVENT_TRUNCATED);
    expect(
      screen.getByText(/Evidence count 250 \(truncated at the configured bound\)/),
    ).toBeInTheDocument();
    expect(screen.getByText("Related vulnerability findings (1)")).toBeInTheDocument();
    expect(screen.queryByText("incomplete")).toBeNull();
    expect(screen.queryByText(/Showing .* of .* vulnerability findings/)).toBeNull();
  });

  it("uses neutral language and offers no response/remediation controls", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() =>
      expect(screen.getByText(/Correlated observations:/)).toBeInTheDocument(),
    );
    expect(screen.queryByText("Threat neutralized")).toBeNull();
    expect(screen.queryByText("Attack successfully stopped")).toBeNull();
    expect(screen.queryByText("Host compromised")).toBeNull();
    expect(screen.queryByText("Block")).toBeNull();
    expect(screen.queryByText("Isolate")).toBeNull();
    expect(screen.queryByText("Kill process")).toBeNull();
    expect(screen.queryByText("Remediate")).toBeNull();
  });

  it("shows honest empty and error states", async () => {
    mockFetch(() => ({ items: [], total: 0, limit: 100, offset: 0 }));
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("No incidents recorded.")).toBeInTheDocument(),
    );
    mockFetch(() => {
      throw new Error("down");
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Incidents unavailable")).toBeInTheDocument());
  });
});
