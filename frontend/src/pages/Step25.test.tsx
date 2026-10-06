import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Incidents } from "./Incidents";

const ITEM = {
  id: "inc-1",
  incident_key: "INC-RISK12345678",
  title: "Incident: repeated activity from 192.0.2.9",
  description: "Correlated security observations detected.",
  status: "OPEN",
  severity: "HIGH",
  confidence: 60,
  primary_asset_id: null,
  primary_ip: "192.0.2.9",
  hostname: null,
  correlation_id: "corr-1",
  risk_assessment_id: null,
  first_seen: "2026-09-28T06:00:00",
  last_seen: "2026-09-28T06:10:00",
  resolved_at: null,
  created_at: "2026-09-28T06:11:00",
  updated_at: "2026-09-28T06:11:00",
  version: "1.0.0",
  incident_type: "CORRELATED_SECURITY_EVENT",
  risk_score: null,
  detection_reason: "Correlation corr-1 carries severity HIGH against 192.0.2.9.",
};

const PAGE = { items: [ITEM], total: 1, limit: 100, offset: 0 };
const DETAIL = { ...ITEM, evidence_event_ids: ["evt-1"] };
const EVIDENCE = {
  incident_id: "inc-1",
  incident_type: "CORRELATED_SECURITY_EVENT",
  detection_reason: ITEM.detection_reason,
  correlation: null,
  events: [
    {
      id: "evt-1",
      event_type: "GENERIC",
      severity: "HIGH",
      source_type: "GENERIC",
      title: "Observed",
      event_time: "2026-09-28T06:00:00",
      role: "related",
      reason: "Evidence event.",
    },
  ],
  vulnerabilities: [],
};
const RISK = {
  id: "risk-1",
  entity_type: "incident",
  entity_id: "inc-1",
  score: 74,
  severity: "HIGH",
  priority: "P2",
  factors: {
    severity: "HIGH",
    severity_pts: 40,
    observation_count: 2,
    vulnerability_count: 1,
    confidence: 70,
    signal_pts: 14,
    recency_days: 0,
    recency_pts: 10,
  },
  explanation: "Risk score 74 (HIGH, priority P2). Incident severity contributes 40 points.",
  calculated_at: "2026-09-28T07:00:00",
  scoring_version: "1.0.0",
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

describe("Incident risk panel (Step 25)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("shows the unscored empty state then calculates on demand", async () => {
    let calculated = false;
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      if (url.endsWith("/calculate") && (init?.method ?? "GET") === "POST") {
        calculated = true;
        return RISK;
      }
      if (url.includes("/api/v1/risk/incident/")) {
        if (!calculated) throw new Error("RISK_NOT_FOUND");
        return RISK;
      }
      if (url.endsWith("/evidence")) return EVIDENCE;
      if (url.endsWith("/timeline")) return { incident_id: "inc-1", entries: [] };
      if (url.endsWith("/audit")) return { incident_id: "inc-1", entries: [] };
      if (url.includes("/responses")) return { items: [], total: 0, limit: 100, offset: 0 };
      if (url.includes("/api/v1/incidents/inc-1")) return DETAIL;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("Advisory risk")).toBeInTheDocument());
    expect(screen.getByText(/No incident risk calculated yet/)).toBeInTheDocument();
    fireEvent.click(screen.getByText("Calculate risk"));
    await waitFor(() => expect(screen.getByText(/74 \(HIGH\)/)).toBeInTheDocument());
    expect(screen.getByText("priority P2")).toBeInTheDocument();
    expect(screen.getByText(/scoring v1\.0\.0/)).toBeInTheDocument();
    expect(screen.getByText(/observation_count=2/)).toBeInTheDocument();
    expect(screen.getByText(/CALCULATED RISK/)).toBeInTheDocument();
    expect(
      seen.some(
        (entry) => entry.startsWith("POST") && entry.includes("/risk/incidents/inc-1/calculate"),
      ),
    ).toBe(true);
  });

  it("renders a stored assessment without recalculating", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/risk/incident/")) return RISK;
      if (url.endsWith("/evidence")) return EVIDENCE;
      if (url.endsWith("/timeline")) return { incident_id: "inc-1", entries: [] };
      if (url.endsWith("/audit")) return { incident_id: "inc-1", entries: [] };
      if (url.includes("/responses")) return { items: [], total: 0, limit: 100, offset: 0 };
      if (url.includes("/api/v1/incidents/inc-1")) return DETAIL;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("Recalculate risk")).toBeInTheDocument());
    expect(screen.queryByText("Threat neutralized")).toBeNull();
    expect(screen.queryByText("Block IP")).toBeNull();
    expect(screen.queryByText("Isolate Host")).toBeNull();
  });
});
