import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Incidents } from "./Incidents";

const INCIDENT_PAGE = {
  items: [
    {
      id: "inc-1",
      incident_key: "INC-ABC123DEF456",
      title: "Incident: Same target, multiple sources: 198.51.100.23",
      description: "Security incident opened for review.",
      status: "OPEN",
      severity: "HIGH",
      confidence: 75,
      primary_asset_id: null,
      primary_ip: "198.51.100.23",
      hostname: null,
      correlation_id: "corr-1",
      risk_assessment_id: null,
      first_seen: "2026-09-27T06:00:00",
      last_seen: "2026-09-27T06:20:00",
      created_at: "2026-09-27T06:21:00",
      updated_at: "2026-09-27T06:21:00",
      version: "1.0.0",
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

const INCIDENT_DETAIL = { ...INCIDENT_PAGE.items[0], evidence_event_ids: ["evt-1", "evt-2"] };

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: unknown, init?: RequestInit) => ({
    ok: true,
    status: 200,
    json: async () => handler(String(url), init),
  }));
}

describe("Incidents page (Step 11)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders incident rows with key, severity and status", async () => {
    mockFetch(() => INCIDENT_PAGE);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("INC-ABC123DEF456")).toBeInTheDocument());
    expect(screen.getAllByText("OPEN").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("198.51.100.23")).toBeInTheDocument();
  });

  it("shows an honest empty state when no incidents exist", async () => {
    mockFetch(() => ({ items: [], total: 0, limit: 50, offset: 0 }));
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("No incidents recorded.")).toBeInTheDocument(),
    );
  });

  it("opens detail with evidence and performs a status update", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      if (url.includes("/api/v1/incidents/inc-1") && (init?.method ?? "GET") === "GET") {
        return INCIDENT_DETAIL;
      }
      if (url.includes("/status")) {
        return { ...INCIDENT_DETAIL, status: "ACKNOWLEDGED" };
      }
      return INCIDENT_PAGE;
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("evt-1")).toBeInTheDocument());
    expect(screen.getByText("evt-2")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Mark Acknowledged"));
    await waitFor(() =>
      expect(
        seen.some((entry) => entry.startsWith("PATCH") && entry.includes("/status")),
      ).toBe(true),
    );
  });

  it("filters by status through the API", async () => {
    const seen: string[] = [];
    mockFetch((url) => {
      seen.push(url);
      return INCIDENT_PAGE;
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByLabelText("Filter by status")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Filter by status"), {
      target: { value: "OPEN" },
    });
    await waitFor(() =>
      expect(seen.some((url) => url.includes("status=OPEN"))).toBe(true),
    );
  });
});
