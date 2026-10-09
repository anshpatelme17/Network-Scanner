import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Sidebar } from "../components/layout/Sidebar";
import { AlertTriage } from "./AlertTriage";

const CORR_CRITICAL = {
  id: "corr-1",
  rule_id: "multi-source-target",
  rule_name: "Same target, multiple sources",
  title: "Multi-source target: 10.0.0.9",
  status: "open",
  severity: "CRITICAL",
  confidence: 75,
  confidence_label: "STRONG",
  primary_ip: "10.0.0.9",
  hostname: null,
  event_count: 2,
  window_start: "2026-10-01T09:00:00",
  window_end: "2026-10-01T09:40:00",
  created_at: "2026-10-01T09:41:00",
  updated_at: "2026-10-01T09:41:00",
};

const CORR_HIGH = {
  id: "corr-2",
  rule_id: "repeated-source",
  rule_name: "Repeated activity from one source",
  title: "Repeated source: 203.0.113.9",
  status: "open",
  severity: "HIGH",
  confidence: 60,
  confidence_label: "MODERATE",
  primary_ip: "203.0.113.9",
  hostname: null,
  event_count: 3,
  window_start: "2026-10-01T08:00:00",
  window_end: "2026-10-01T08:12:00",
  created_at: "2026-10-01T08:13:00",
  updated_at: "2026-10-01T08:13:00",
};

// Deliberately unsorted: the page must prioritize CRITICAL ahead of HIGH.
const CORR_PAGE = { items: [CORR_HIGH, CORR_CRITICAL], total: 2, limit: 100, offset: 0 };
const CORR_PAGE_EMPTY = { items: [], total: 0, limit: 100, offset: 0 };

const DETAIL = {
  ...CORR_CRITICAL,
  description: "Grouped for review.",
  explanation:
    "2 events from 2 distinct sources observed the same address 10.0.0.9 within 60 minutes.",
  evidence: [
    {
      event_id: "evt-1",
      role: "related",
      position: 0,
      event_type: "NETWORK",
      source_type: "SURICATA",
      severity: "HIGH",
      title: "First related event",
      event_time: "2026-10-01T09:00:00",
      source_ip: "198.51.100.1",
      destination_ip: "10.0.0.9",
    },
    {
      event_id: "evt-2",
      role: "related",
      position: 1,
      event_type: "NETWORK",
      source_type: "ZEEK",
      severity: "MEDIUM",
      title: "Second related event",
      event_time: "2026-10-01T09:05:00",
      source_ip: "198.51.100.2",
      destination_ip: "10.0.0.9",
    },
  ],
};

const CHAIN = {
  correlation_id: "corr-1",
  nodes: [
    {
      id: "correlation:corr-1",
      kind: "correlation",
      label: "Multi-source target: 10.0.0.9",
      detail: { rule: "multi-source-target", severity: "CRITICAL" },
    },
    { id: "asset:10.0.0.9", kind: "asset", label: "10.0.0.9", detail: {} },
    {
      id: "event:evt-1",
      kind: "event",
      label: "2026-10-01T09:00:00 — First related event",
      detail: { source: "SURICATA" },
    },
  ],
  edges: [],
};

const INCIDENT = {
  id: "inc-1",
  incident_key: "INC-ABC12345",
  title: "Incident: Multi-source target: 10.0.0.9",
  status: "OPEN",
  severity: "CRITICAL",
  confidence: 75,
  primary_asset_id: null,
  primary_ip: "10.0.0.9",
  hostname: null,
  correlation_id: "corr-1",
  risk_assessment_id: null,
  first_seen: "2026-10-01T09:00:00",
  last_seen: "2026-10-01T09:40:00",
  resolved_at: null,
  created_at: "2026-10-01T09:42:00",
  updated_at: "2026-10-01T09:42:00",
  version: "1.0.0",
  incident_type: "CORRELATED_SECURITY_EVENT",
  risk_score: null,
  detection_reason: null,
};

const INCIDENTS = { items: [INCIDENT], total: 1, limit: 100, offset: 0 };

type Handler = (url: string, init?: RequestInit) => unknown;
type Fail = { __fail: true; code: string; status: number };

function fail(code: string, status: number): Fail {
  return { __fail: true, code, status };
}

const calls: string[] = [];

function mockFetch(handler: Handler) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => {
      calls.push(`${init?.method ?? "GET"} ${String(url)}`);
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

const baseRoute: Handler = (url, init) => {
  if ((init?.method ?? "GET") !== "GET") throw new Error("unexpected write");
  if (url.includes("/api/v1/correlations/corr-1/attack-chain")) return CHAIN;
  if (url.includes("/api/v1/correlations/corr-1")) return DETAIL;
  if (url.includes("/api/v1/correlations?")) return CORR_PAGE;
  if (url.includes("/api/v1/incidents?")) return INCIDENTS;
  return {};
};

function routeWith(...overrides: Handler[]): Handler {
  return (url, init) => {
    for (const override of overrides) {
      const value = override(url, init);
      if (value !== undefined) return value;
    }
    return baseRoute(url, init);
  };
}

function renderTriage(initialEntry = "/triage") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/triage" element={<AlertTriage />} />
        <Route path="*" element={<p>Unknown route</p>} />
      </Routes>
    </MemoryRouter>,
  );
}

const originalFetch = globalThis.fetch;

describe("Alert triage queue (Phase 3, Step 37)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    calls.length = 0;
  });

  afterEach(() => {
    (globalThis as unknown as { fetch: unknown }).fetch = originalFetch;
  });

  it("renders the queue prioritized by severity with incident association", async () => {
    mockFetch(baseRoute);
    renderTriage();

    const queue = await screen.findByLabelText("Alert queue");
    await waitFor(() =>
      expect(within(queue).getAllByRole("row")).toHaveLength(3),
    );

    const rows = within(queue).getAllByRole("row");
    // Row 0 is the header; CRITICAL must sort ahead of HIGH.
    expect(within(rows[1]).getByText("Multi-source target: 10.0.0.9")).toBeInTheDocument();
    expect(within(rows[1]).getByText("CRITICAL")).toBeInTheDocument();
    expect(within(rows[1]).getByText(/confidence 75 \(STRONG\)/)).toBeInTheDocument();
    expect(
      within(rows[1]).getByText(/Incident INC-ABC12345/),
    ).toBeInTheDocument();

    expect(within(rows[2]).getByText("Repeated source: 203.0.113.9")).toBeInTheDocument();
    expect(within(rows[2]).getByText("No incident")).toBeInTheDocument();
  });

  it("filters the queue by severity through the API", async () => {
    mockFetch(baseRoute);
    renderTriage();
    await screen.findByLabelText("Alert queue");
    await waitFor(() =>
      expect(within(screen.getByLabelText("Alert queue")).getAllByRole("row")).toHaveLength(3),
    );

    fireEvent.change(screen.getByLabelText("Filter by severity"), {
      target: { value: "HIGH" },
    });

    await waitFor(() =>
      expect(
        calls.some(
          (entry) => entry.includes("/api/v1/correlations?") && entry.includes("severity=HIGH"),
        ),
      ).toBe(true),
    );
    expect(within(screen.getByLabelText("Alert queue")).getAllByRole("row")).toHaveLength(3);
  });

  it("reveals explanation, ordered evidence, attack chain, and incident link on Review", async () => {
    mockFetch(baseRoute);
    renderTriage();

    await waitFor(() =>
      expect(
        within(screen.getByLabelText("Alert queue")).getAllByRole("row"),
      ).toHaveLength(3),
    );
    fireEvent.click(screen.getAllByRole("button", { name: "Review" })[0]);

    const detail = await screen.findByLabelText("Alert detail");
    await waitFor(() =>
      expect(
        within(detail).getByText(/2 events from 2 distinct sources/),
      ).toBeInTheDocument(),
    );
    expect(within(detail).getByText("Why correlated:")).toBeInTheDocument();
    expect(within(detail).getByText("Grouped for review.")).toBeInTheDocument();

    const evidenceLinks = within(detail).getAllByRole("link", { name: /related event/ });
    expect(evidenceLinks[0]).toHaveTextContent("First related event");
    expect(evidenceLinks[1]).toHaveTextContent("Second related event");
    expect(evidenceLinks[0]).toHaveAttribute("href", "/events?event=evt-1");
    expect(evidenceLinks[1]).toHaveAttribute("href", "/events?event=evt-2");

    await waitFor(() =>
      expect(within(detail).getByText("asset")).toBeInTheDocument(),
    );
    expect(within(detail).getByText("correlation")).toBeInTheDocument();

    expect(within(detail).getByText(/INC-ABC12345/)).toBeInTheDocument();
    expect(within(detail).getByRole("link", { name: "View incidents" })).toHaveAttribute(
      "href",
      "/incidents",
    );
  });

  it("supports an unlinked-only filter once incident association is known", async () => {
    mockFetch(baseRoute);
    renderTriage();

    const queue = await screen.findByLabelText("Alert queue");
    await waitFor(() =>
      expect(within(queue).getAllByRole("row")).toHaveLength(3),
    );

    const toggle = screen.getByRole("checkbox", {
      name: "Only groups without an incident",
    });
    expect(toggle).toBeEnabled();
    fireEvent.click(toggle);

    await waitFor(() =>
      expect(within(queue).queryByText("Multi-source target: 10.0.0.9")).toBeNull(),
    );
    expect(within(queue).getByText("Repeated source: 203.0.113.9")).toBeInTheDocument();
  });

  it("shows an honest empty state", async () => {
    const empty: Handler = (url) => {
      if (url.includes("/api/v1/correlations?")) return CORR_PAGE_EMPTY;
      return undefined;
    };
    mockFetch(routeWith(empty));
    renderTriage();

    expect(
      await screen.findByText("No correlated activity to triage."),
    ).toBeInTheDocument();
  });

  it("keeps the queue when incident association fails", async () => {
    const noIncidents: Handler = (url) => {
      if (url.includes("/api/v1/incidents?")) return fail("INTERNAL_ERROR", 500);
      return undefined;
    };
    mockFetch(routeWith(noIncidents));
    renderTriage();

    const queue = await screen.findByLabelText("Alert queue");
    await waitFor(() =>
      expect(within(queue).getAllByRole("row")).toHaveLength(3),
    );
    expect(within(queue).queryByText("No incident")).toBeNull();
    expect(
      within(queue).getAllByText("association unavailable").length,
    ).toBeGreaterThanOrEqual(2);
    expect(
      screen.getByText(/Incident association is unavailable/),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("checkbox", { name: "Only groups without an incident" }),
    ).toBeDisabled();
  });

  it("reports a restricted account honestly without retry controls", async () => {
    const restricted: Handler = (url) => {
      if (url.includes("/api/v1/correlations?")) return fail("PERMISSION_DENIED", 403);
      if (url.includes("/api/v1/incidents?")) return fail("PERMISSION_DENIED", 403);
      return undefined;
    };
    mockFetch(routeWith(restricted));
    renderTriage();

    await waitFor(() =>
      expect(
        screen.getByText("Correlated activity is restricted for your account."),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: "Retry queue" })).toBeNull();
    expect(
      screen.getByText(/Incident association is unavailable/),
    ).toBeInTheDocument();
  });

  it("isolates a queue failure and recovers through its retry control", async () => {
    let broken = true;
    const flaky: Handler = (url) => {
      if (broken && url.includes("/api/v1/correlations?")) {
        return fail("INTERNAL_ERROR", 500);
      }
      return undefined;
    };
    mockFetch(routeWith(flaky));
    renderTriage();

    await waitFor(() =>
      expect(screen.getByText("Alert queue could not be loaded.")).toBeInTheDocument(),
    );
    expect(screen.getByRole("button", { name: "Retry queue" })).toBeInTheDocument();

    broken = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry queue" }));
    await waitFor(() =>
      expect(
        within(screen.getByLabelText("Alert queue")).getAllByRole("row"),
      ).toHaveLength(3),
    );
  });

  it("is read-only GET traffic and links onward to existing workspaces", async () => {
    mockFetch(baseRoute);
    renderTriage();

    await waitFor(() =>
      expect(
        within(screen.getByLabelText("Alert queue")).getAllByRole("row"),
      ).toHaveLength(3),
    );
    fireEvent.click(screen.getAllByRole("button", { name: "Review" })[0]);
    await screen.findByLabelText("Alert detail");
    await waitFor(() =>
      expect(screen.getByText(/2 events from 2 distinct sources/)).toBeInTheDocument(),
    );

    const navigation = screen.getByLabelText("Alert triage navigation");
    expect(within(navigation).getByRole("link", { name: "Correlated activity" })).toHaveAttribute(
      "href",
      "/correlations",
    );
    expect(within(navigation).getByRole("link", { name: "Incidents" })).toHaveAttribute(
      "href",
      "/incidents",
    );
    expect(within(navigation).getByRole("link", { name: "Security events" })).toHaveAttribute(
      "href",
      "/events",
    );

    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every((entry) => entry.startsWith("GET "))).toBe(true);
    expect(
      calls.some((entry) => /(recompute|detect|\/status|responses)/.test(entry)),
    ).toBe(false);
  });

  it("adds the Triage navigation entry to the sidebar", () => {
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: "Triage" })).toHaveAttribute(
      "href",
      "/triage",
    );
  });
});
