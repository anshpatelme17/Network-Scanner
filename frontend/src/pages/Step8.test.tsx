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
  cwe_id: "CWE-326",
  affected_component: null,
  evidence: "Synthetic fixture evidence.",
  remediation_reference: "Synthetic fixture solution.",
  created_at: "2026-09-27T00:00:00",
  updated_at: "2026-09-27T01:00:00",
  audit: [
    {
      event: "VULNERABILITY_OPENED",
      actor: "operator",
      previous_status: null,
      new_status: "OPEN",
      created_at: "2026-09-27T00:00:00",
      detail: null,
    },
  ],
};

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: unknown, init?: RequestInit) => ({
    ok: true,
    status: 200,
    json: () => Promise.resolve(handler(String(url), init)),
  }));
}

describe("Vulnerabilities page (Step 15 findings)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders finding rows with severity, CVE, CVSS and scanner", async () => {
    mockFetch(() => FINDING_PAGE);
    render(
      <MemoryRouter>
        <Vulnerabilities />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("TEST SSH legacy configuration")).toBeInTheDocument(),
    );
    expect(screen.getByText("5.4")).toBeInTheDocument();
    expect(screen.getByText("fixture-scanner")).toBeInTheDocument();
    expect(screen.getByText("22")).toBeInTheDocument();
  });

  it("shows an honest empty state when nothing was assessed", async () => {
    mockFetch(() => ({ items: [], total: 0, limit: 50, offset: 0 }));
    render(
      <MemoryRouter>
        <Vulnerabilities />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("No vulnerability findings received.")).toBeInTheDocument(),
    );
  });

  it("filters by severity and opens detail with audit and status controls", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      if (url.includes("/risk")) {
        return {
          id: "risk-1",
          entity_type: "vuln_finding",
          entity_id: "vuln-1",
          score: 40,
          severity: "MEDIUM",
          factors: {},
          explanation: "Risk score 40 (MEDIUM).",
          calculated_at: "2026-09-27T02:00:00",
          scoring_version: "1.0.0",
        };
      }
      if (url.includes("/correlations")) {
        return {
          vulnerability_id: "vuln-1",
          asset_id: "asset-1",
          service_id: null,
          related_events: [],
          related_incidents: [],
          reasons: [],
        };
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
    fireEvent.change(screen.getByLabelText("Filter by severity"), {
      target: { value: "HIGH" },
    });
    await waitFor(() =>
      expect(seen.some((url) => url.includes("severity=HIGH"))).toBe(true),
    );
    fireEvent.click(screen.getByText("Details"));
    await waitFor(() => expect(screen.getByText("VULNERABILITY_OPENED")).toBeInTheDocument());
    expect(screen.getByText("Synthetic fixture solution.")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Mark Accepted risk"));
    await waitFor(() =>
      expect(
        seen.some((entry) => entry.startsWith("POST") && entry.includes("/status")),
      ).toBe(true),
    );
  });
});
