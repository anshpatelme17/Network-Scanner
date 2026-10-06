import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Events } from "./Events";

const ITEM = {
  id: "evt-1",
  event_time: "2026-09-28T10:00:00",
  received_at: "2026-09-28T10:00:01",
  source_type: "SURICATA",
  source_name: "lab-sensor",
  event_type: "SURICATA_ALERT",
  severity: "HIGH",
  title: "TEST signature fired",
  description: "Fixture alert for testing.",
  source_ip: "10.0.0.5",
  destination_ip: "10.0.0.9",
  source_port: 4444,
  destination_port: 80,
  protocol: "tcp",
  asset_id: null,
  hostname: null,
  username: null,
  process_name: null,
  action: null,
  status: null,
  confidence: null,
  occurrence_count: 2,
  last_seen_at: "2026-09-28T10:05:00",
  ingest_mode: "FIXTURE",
  raw_event: { event_type: "alert" },
  normalized_data: {},
  correlation_key: "k",
  fingerprint: "f",
  external_event_id: "suricata:abc",
  created_at: "2026-09-28T10:00:01",
};

const PAGE = { items: [ITEM], total: 1, limit: 100, offset: 0 };

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => ({
      ok: true,
      status: 200,
      json: async () => handler(String(url), init),
    }),
  );
}

describe("Events page (Step 23)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("marks fixture sources and unresolved assets", async () => {
    mockFetch(() => PAGE);
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("TEST signature fired")).toBeInTheDocument());
    expect(screen.getAllByText("FIXTURE").length).toBeGreaterThanOrEqual(2);
    expect(screen.getByText("unresolved")).toBeInTheDocument();
    expect(screen.getByText(/never means a threat was contained/)).toBeInTheDocument();
  });

  it("shows occurrences, confidence, and raw evidence in detail", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/events/evt-1")) return ITEM;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Details")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Details"));
    await waitFor(() => expect(screen.getByText(/occurrences: 2/)).toBeInTheDocument());
    expect(screen.getByText(/confidence: unknown/)).toBeInTheDocument();
    expect(screen.getByText(/"event_type"/)).toBeInTheDocument();
  });

  it("shows an honest empty state and error state", async () => {
    mockFetch(() => ({ items: [], total: 0, limit: 100, offset: 0 }));
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("No security events received.")).toBeInTheDocument(),
    );
    mockFetch(() => {
      throw new Error("down");
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Events unavailable")).toBeInTheDocument());
  });
});
