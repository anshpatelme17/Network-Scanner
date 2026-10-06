import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Vulnerabilities } from "./Vulnerabilities";

const FINDING_PAGE = {
  items: [
    {
      id: "vuln-1",
      asset_id: "asset-1",
      service_id: "svc-1",
      scanner: "fixture-scanner",
      scanner_finding_id: "FIX-SSH-LEGACY",
      title: "TEST SSH legacy configuration",
      severity: "MEDIUM",
      cvss_score: 5.4,
      cve_id: null,
      hostname: "192.0.2.10",
      destination_ip: "192.0.2.10",
      destination_port: 22,
      status: "OPEN",
      first_seen: "2026-09-27T00:00:00",
      last_seen: "2026-09-27T01:00:00",
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

const FINDING_DETAIL = {
  ...FINDING_PAGE.items[0],
  description: "Synthetic fixture finding.",
  cwe_id: null,
  affected_component: null,
  evidence: "evidence",
  remediation_reference: null,
  created_at: "2026-09-27T00:00:00",
  updated_at: "2026-09-27T01:00:00",
  audit: [],
};

const FINDING_RISK = {
  id: "risk-1",
  entity_type: "vuln_finding",
  entity_id: "vuln-1",
  score: 59,
  severity: "MEDIUM",
  factors: { severity_pts: 25 },
  explanation: "Risk score 59 (MEDIUM).",
  calculated_at: "2026-09-27T02:00:00",
  scoring_version: "1.0.0",
};

const FINDING_LINKS = {
  vulnerability_id: "vuln-1",
  asset_id: "asset-1",
  service_id: "svc-1",
  related_events: [
    {
      id: "evt-1",
      event_type: "probe",
      source_type: "GENERIC",
      severity: "MEDIUM",
      title: "Activity on assessed asset",
      event_time: "2026-09-27T06:00:00",
    },
  ],
  related_incidents: [],
  reasons: ["shares asset IP 192.0.2.10"],
};

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: unknown, init?: RequestInit) => ({
    ok: true,
    status: 200,
    json: () => Promise.resolve(handler(String(url), init)),
  }));
}

function route(url: string) {
  if (url.includes("/risk")) return FINDING_RISK;
  if (url.includes("/correlations")) return FINDING_LINKS;
  if (url.includes("/api/v1/vulnerabilities/vuln-1")) return FINDING_DETAIL;
  return FINDING_PAGE;
}

describe("Vulnerabilities risk display (Step 16)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("shows risk score distinct from finding severity with explanation", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Vulnerabilities />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Details")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Details"));
    await waitFor(() => expect(screen.getByText("59 (MEDIUM)")).toBeInTheDocument());
    expect(screen.getByText("Risk score 59 (MEDIUM).")).toBeInTheDocument();
  });

  it("shows correlated records with reasons", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Vulnerabilities />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Details")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Details"));
    await waitFor(() =>
      expect(screen.getByText("Activity on assessed asset")).toBeInTheDocument(),
    );
    expect(screen.getByText("shares asset IP 192.0.2.10")).toBeInTheDocument();
  });

  it("shows the unscored empty risk state when no assessment exists", async () => {
    mockFetch((url) => {
      if (url.includes("/risk")) {
        throw new Error("RISK_NOT_FOUND");
      }
      if (url.includes("/correlations")) {
        return { ...FINDING_LINKS, related_events: [], related_incidents: [], reasons: [] };
      }
      if (url.includes("/api/v1/vulnerabilities/vuln-1")) return FINDING_DETAIL;
      return FINDING_PAGE;
    });
    render(
      <MemoryRouter>
        <Vulnerabilities />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Details")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Details"));
    await waitFor(() => expect(screen.getByText(/Not scored yet/)).toBeInTheDocument());
    expect(screen.getByText(/insufficient shared evidence/)).toBeInTheDocument();
  });
});
