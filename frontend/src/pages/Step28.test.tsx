import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Events } from "./Events";

const CONNECTORS = {
  items: [
    {
      source: "suricata",
      mode: "LIVE",
      state: "CONNECTED",
      detail: "EVE path readable; bounded poll available.",
      configured: { path: true },
      last_success_at: null,
      connector_state: "CONNECTED",
      last_check_at: null,
      last_poll_at: null,
      last_error_category: null,
      events_retrieved: 0,
      latency_ms: null,
    },
    {
      source: "zeek",
      mode: "FIXTURE",
      state: "UNAVAILABLE",
      detail: "No log path configured; fixture ingestion remains available.",
      configured: { path: false },
      last_success_at: null,
      connector_state: "NOT_CONFIGURED",
      last_check_at: null,
      last_poll_at: null,
      last_error_category: null,
      events_retrieved: 0,
      latency_ms: null,
    },
    {
      source: "wazuh",
      mode: "LIVE",
      state: "UNAVAILABLE",
      detail: "Credentials configured; live connection not attempted yet.",
      configured: { url: true, username: true, password: true },
      last_success_at: null,
      connector_state: "CONFIGURED",
      last_check_at: null,
      last_poll_at: null,
      last_error_category: null,
      events_retrieved: 0,
      latency_ms: null,
    },
    {
      source: "defender",
      mode: "LIVE",
      state: "UNAVAILABLE",
      detail: "No credentials configured; live connection not attempted.",
      configured: { tenant_id: false, client_id: false, client_secret: false },
      last_success_at: null,
      connector_state: "NOT_CONFIGURED",
      last_check_at: null,
      last_poll_at: null,
      last_error_category: null,
      events_retrieved: 0,
      latency_ms: null,
    },
  ],
};

const INGESTION = {
  generated_at: "2026-09-30T08:00:00",
  pipeline: [
    "SOURCE",
    "CONNECTOR",
    "FETCH",
    "VALIDATE",
    "NORMALIZE",
    "DEDUPLICATE",
    "CORRELATE",
    "STORE",
    "AUDIT",
  ],
  limits: {
    max_pages: 3,
    max_events: 100,
    max_poll_lines: 100,
    batch_size: 50,
    queue_max: 500,
    retry_max: 1,
    timeout_seconds: 10,
    file_resume: false,
  },
  queue: {
    max: 500,
    depth: 0,
    enqueued_total: 120,
    dequeued_total: 120,
    dropped_total: 5,
    overflow: "REJECT_NEW",
  },
  streaming: {
    enabled: false,
    mode: "MANUAL",
    detail: "Manual, operator-initiated polls only.",
  },
  totals: {
    fetched: 120,
    accepted: 115,
    deduplicated: 5,
    rejected: 0,
    failed: 1,
    dropped: 5,
    retries: 2,
    batches: 6,
  },
  sources: [
    {
      source: "suricata",
      mode: "LIVE",
      state: "CONNECTED",
      connector_state: "CONNECTED",
      last_poll_at: "2026-09-30T07:55:00",
      last_success_at: "2026-09-30T07:55:00",
      last_failure_at: null,
      last_failure_reason: null,
      events_fetched: 100,
      events_accepted: 95,
      events_deduplicated: 5,
      events_rejected: 0,
      events_failed: 0,
      events_dropped: 0,
      retries: 0,
      batches: 2,
      queue_depth: 0,
      checkpoint: {
        source: "suricata",
        cursor: { v: 1, kind: "file", offset: 4096, file_size: 4096 },
        last_event_time: "2026-09-30T07:54:00",
        last_external_event_id: "suricata:abc",
        advance_count: 3,
        last_rejected_at: null,
        updated_at: "2026-09-30T07:55:00",
        created_at: "2026-09-30T07:00:00",
      },
    },
    {
      source: "zeek",
      mode: "FIXTURE",
      state: "UNAVAILABLE",
      connector_state: "NOT_CONFIGURED",
      last_poll_at: null,
      last_success_at: null,
      last_failure_at: null,
      last_failure_reason: null,
      events_fetched: 0,
      events_accepted: 0,
      events_deduplicated: 0,
      events_rejected: 0,
      events_failed: 0,
      events_dropped: 0,
      retries: 0,
      batches: 0,
      queue_depth: 0,
      checkpoint: null,
    },
    {
      source: "wazuh",
      mode: "LIVE",
      state: "UNAVAILABLE",
      connector_state: "CONFIGURED",
      last_poll_at: null,
      last_success_at: null,
      last_failure_at: "2026-09-30T07:40:00",
      last_failure_reason: "connector unavailable",
      events_fetched: 0,
      events_accepted: 0,
      events_deduplicated: 0,
      events_rejected: 0,
      events_failed: 1,
      events_dropped: 5,
      retries: 2,
      batches: 4,
      queue_depth: 0,
      checkpoint: null,
    },
    {
      source: "defender",
      mode: "LIVE",
      state: "UNAVAILABLE",
      connector_state: "NOT_CONFIGURED",
      last_poll_at: null,
      last_success_at: null,
      last_failure_at: null,
      last_failure_reason: null,
      events_fetched: 0,
      events_accepted: 0,
      events_deduplicated: 0,
      events_rejected: 0,
      events_failed: 0,
      events_dropped: 0,
      retries: 0,
      batches: 0,
      queue_depth: 0,
      checkpoint: null,
    },
  ],
};

const PAGE = { items: [], total: 0, limit: 100, offset: 0 };

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => ({
      ok: true,
      status: 200,
      json: async () => handler(String(url), init),
    }),
  );
}

describe("Events ingestion pipeline panel (Step 28)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders bounds, manual streaming, and per-source counters", async () => {
    mockFetch((url) => {
      if (url.includes("/events/ingestion/status")) return INGESTION;
      if (url.includes("/events/connectors")) return CONNECTORS;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("Ingestion pipeline (Step 28)")).toBeInTheDocument(),
    );
    expect(screen.getByText("run: suricata")).toBeInTheDocument();
    expect(screen.getByText("state: CONNECTED")).toBeInTheDocument();
    expect(screen.getByText("state: CONFIGURED")).toBeInTheDocument();
    expect(screen.getAllByText("state: NOT_CONFIGURED")).toHaveLength(2);
    // Checkpoint provenance in operator language (cursor stays server-side).
    expect(screen.getByText("3 advance(s)")).toBeInTheDocument();
    expect(screen.getAllByText("no successful run yet")).toHaveLength(3);
    // Configured bounds, deterministic overflow policy, manual streaming.
    expect(screen.getByText(/50 record\(s\) per batch/)).toBeInTheDocument();
    expect(screen.getByText(/queue 500 capped \(REJECT_NEW\)/)).toBeInTheDocument();
    expect(screen.getByText(/1 bounded retry\(ies\)/)).toBeInTheDocument();
    expect(screen.getByText(/5 dropped in total/)).toBeInTheDocument();
    expect(screen.getAllByText(/MANUAL/).length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText(/enabled: true/)).toBeNull();
    // Read-only observability: the panel adds no run actions of its own.
    expect(screen.getAllByText("Check now")).toHaveLength(4);
    expect(screen.getAllByText("Poll now")).toHaveLength(3);
    // No secret material anywhere in the rendered panel.
    const text = document.body.textContent ?? "";
    expect(text).not.toContain("password");
    expect(text.toLowerCase()).not.toContain("token");
    expect(text.toLowerCase()).not.toContain("secret");
  });

  it("keeps unverified sources honest instead of claiming connectivity", async () => {
    mockFetch((url) => {
      if (url.includes("/events/ingestion/status")) return INGESTION;
      if (url.includes("/events/connectors")) return CONNECTORS;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("run: wazuh")).toBeInTheDocument());
    // Configuration is reported as configuration, never as a live link.
    expect(screen.getByText("state: CONFIGURED")).toBeInTheDocument();
    expect(screen.queryByText("state: CONNECTING")).toBeNull();
    expect(screen.getByText(/connector unavailable/)).toBeInTheDocument();
  });

  it("reports absence when the payload is not an ingestion status", async () => {
    mockFetch((url) => {
      if (url.includes("/events/ingestion/status")) return PAGE;
      if (url.includes("/events/connectors")) return CONNECTORS;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(
        screen.getByText("Ingestion telemetry not reported by the server."),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByText("run: suricata")).toBeNull();
    expect(screen.getByText("Event sources / connectors")).toBeInTheDocument();
  });

  it("survives a refused status read without an unhandled rejection", async () => {
    mockFetch((url) => {
      if (url.includes("/events/ingestion/status")) throw new Error("PERMISSION_DENIED");
      if (url.includes("/events/connectors")) return CONNECTORS;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(
        screen.getByText("Ingestion telemetry not reported by the server."),
      ).toBeInTheDocument(),
    );
    expect(screen.getAllByText("Check now")).toHaveLength(4);
    expect(screen.getByText("Event sources / connectors")).toBeInTheDocument();
  });

  it("reports backpressure and a held checkpoint truthfully", async () => {
    mockFetch((url, init) => {
      if (init?.method === "POST" && url.endsWith("/zeek/poll")) {
        return {
          source: "zeek",
          accepted: 5,
          duplicates: 0,
          rejected: 0,
          truncated: false,
          errors: [],
          pages: 1,
          retrieved: 5,
          termination: null,
          batches: 1,
          queue_dropped: 2,
          checkpoint_advanced: false,
        };
      }
      if (url.includes("/events/ingestion/status")) return INGESTION;
      if (url.includes("/events/connectors")) return CONNECTORS;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getAllByText("Poll now")).toHaveLength(3));
    fireEvent.click(screen.getAllByText("Poll now")[1]);
    await waitFor(() =>
      expect(
        screen.getByText(
          /zeek: 5 accepted, 0 duplicates, 0 rejected.*1 batch\(es\).*2 queue drop\(s\).*checkpoint held/,
        ),
      ).toBeInTheDocument(),
    );
  });

  it("appends pipeline provenance only when the server reports it", async () => {
    mockFetch((url, init) => {
      if (init?.method === "POST" && url.endsWith("/wazuh/poll")) {
        return {
          source: "wazuh",
          accepted: 12,
          duplicates: 0,
          rejected: 0,
          truncated: false,
          errors: [],
          pages: 2,
          retrieved: 12,
          termination: "COMPLETED",
          batches: 3,
          queue_dropped: 0,
          checkpoint_advanced: true,
        };
      }
      if (url.includes("/events/ingestion/status")) return INGESTION;
      if (url.includes("/events/connectors")) return CONNECTORS;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getAllByText("Poll now")).toHaveLength(3));
    fireEvent.click(screen.getAllByText("Poll now")[2]);
    await waitFor(() =>
      expect(
        screen.getByText(
          /wazuh: 12 accepted, 0 duplicates, 0 rejected · termination COMPLETED · 3 batch\(es\) · checkpoint advanced/,
        ),
      ).toBeInTheDocument(),
    );
  });
});
