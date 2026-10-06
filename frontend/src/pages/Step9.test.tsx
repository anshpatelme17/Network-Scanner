import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Correlations } from "./Correlations";

const CORR_PAGE = {
  items: [
    {
      id: "corr-1",
      rule_id: "multi-source-target",
      rule_name: "Same target, multiple sources",
      title: "Same target, multiple sources: 198.51.100.23",
      status: "open",
      severity: "HIGH",
      confidence: 75,
      primary_ip: "198.51.100.23",
      hostname: null,
      event_count: 2,
      window_start: "2026-09-27T06:00:00",
      window_end: "2026-09-27T06:10:00",
      created_at: "2026-09-27T06:11:00",
      updated_at: "2026-09-27T06:11:00",
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

const CORR_DETAIL = {
  ...CORR_PAGE.items[0],
  description: "Correlated activity grouped for review.",
  explanation: "2 events from 2 distinct sources",
  evidence: [
    {
      event_id: "evt-1",
      role: "related",
      position: 0,
      event_type: "SURICATA_ALERT",
      source_type: "SURICATA",
      severity: "HIGH",
      title: "Chain A suricata alert",
      event_time: "2026-09-27T06:00:00",
      source_ip: "192.0.2.10",
      destination_ip: "198.51.100.23",
    },
  ],
};

const CHAIN = {
  correlation_id: "corr-1",
  nodes: [
    { id: "correlation:corr-1", kind: "correlation", label: "Same target", detail: {} },
    { id: "asset:198.51.100.23", kind: "asset", label: "198.51.100.23", detail: {} },
    { id: "event:evt-1", kind: "event", label: "2026-09-27 — Chain A suricata alert", detail: {} },
  ],
  edges: [{ source: "correlation:corr-1", target: "event:evt-1", relation: "supported by" }],
};

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: unknown, init?: RequestInit) => ({
    ok: true,
    status: 200,
    json: async () => handler(String(url), init),
  }));
}

describe("Correlations page (Step 9)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders correlated activity with rule and explanation", async () => {
    mockFetch((url) => {
      if (url.includes("/attack-chain")) return CHAIN;
      if (url.includes("/api/v1/correlations/corr-1")) return CORR_DETAIL;
      return CORR_PAGE;
    });
    render(
      <MemoryRouter>
        <Correlations />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("Same target, multiple sources: 198.51.100.23")).toBeInTheDocument(),
    );
    expect(screen.getByText("not proof of compromise")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Evidence"));
    await waitFor(() =>
      expect(screen.getByText("Why correlated:")).toBeInTheDocument(),
    );
    expect(screen.getByText("Chain A suricata alert")).toBeInTheDocument();
    expect(screen.getByText("Potential attack chain")).toBeInTheDocument();
  });

  it("shows an honest empty state and recomputes", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      if (url.includes("/recompute")) {
        return { events_scanned: 3, rules_evaluated: 3, created: 0, refreshed: 0, correlation_ids: [] };
      }
      return { items: [], total: 0, limit: 50, offset: 0 };
    });
    render(
      <MemoryRouter>
        <Correlations />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("No correlated activity found.")).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Recompute" }));
    await waitFor(() =>
      expect(seen.some((entry) => entry.startsWith("POST") && entry.includes("/recompute"))).toBe(true),
    );
    await waitFor(() => expect(screen.getByText(/Recompute finished/)).toBeInTheDocument());
  });
});
