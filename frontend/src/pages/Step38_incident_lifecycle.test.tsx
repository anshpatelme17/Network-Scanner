import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Incidents } from "./Incidents";

/**
 * Phase 3, Step 38: incident lifecycle hardening.
 *
 * These tests pin the existing five-status / eight-transition contract and
 * the hardened changeStatus workflow: distinct failure messages, in-flight
 * control disabling, duplicate-submission prevention and stale-UI
 * resynchronization. No new status or transition may appear here.
 */

const BASE_ITEM = {
  id: "inc-1",
  incident_key: "INC-INTEL1234567",
  title: "Incident: auth chain against 192.0.2.77",
  description: "Correlated authentication sequence.",
  status: "OPEN",
  severity: "HIGH",
  confidence: 75,
  primary_asset_id: "asset-1",
  primary_ip: "192.0.2.77",
  hostname: null,
  correlation_id: "corr-1",
  risk_assessment_id: "ris-1",
  first_seen: "2026-09-27T07:00:00",
  last_seen: "2026-09-27T07:10:00",
  resolved_at: null,
  created_at: "2026-09-27T07:11:00",
  updated_at: "2026-09-27T07:11:00",
  version: "1.0.0",
  incident_type: "AUTHENTICATION_ANOMALY",
  risk_score: 74,
  detection_reason: "Correlation corr-1 groups 3 related events.",
};

function detailFor(status: string) {
  return { ...BASE_ITEM, status, evidence_event_ids: ["evt-1", "evt-2"] };
}

const EVIDENCE = {
  incident_id: "inc-1",
  incident_type: "AUTHENTICATION_ANOMALY",
  detection_reason: BASE_ITEM.detection_reason,
  correlation: {
    id: "corr-1",
    rule_id: "repeated-source",
    rule_name: "Repeated activity from one source",
    severity: "HIGH",
    confidence: 75,
    explanation: "3 events from source 203.0.113.9.",
  },
  events: [
    {
      id: "evt-1",
      event_type: "WAZUH_AUTH",
      severity: "MEDIUM",
      source_type: "WAZUH",
      title: "Authentication failed",
      event_time: "2026-09-27T07:00:00",
      role: "related",
      reason: "Evidence event.",
    },
    {
      id: "evt-2",
      event_type: "WAZUH_AUTH",
      severity: "HIGH",
      source_type: "WAZUH",
      title: "Authentication succeeded",
      event_time: "2026-09-27T07:05:00",
      role: "related",
      reason: "Evidence event.",
    },
  ],
  vulnerabilities: [],
};

const RELATIONSHIPS = {
  incident_id: "inc-1",
  items: [
    {
      id: "r".repeat(64),
      incident_id: "inc-1",
      rule_id: "temporal-auth-sequence",
      rule_name: "Auth sequence",
      relation: "followed_by",
      source_kind: "event",
      source_id: "evt-1",
      source_label: "Authentication failed",
      target_kind: "event",
      target_id: "evt-2",
      target_label: "Authentication succeeded",
      confidence: 75,
      confidence_label: "STRONG",
      explanation: "Ordered by timestamp.",
      evidence_event_ids: ["evt-1", "evt-2"],
      first_seen: "2026-09-27T07:00:00",
      last_seen: "2026-09-27T07:10:00",
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

const TIMELINE = {
  incident_id: "inc-1",
  truncated: false,
  entries: [
    {
      at: "2026-09-27T07:00:00",
      kind: "observation",
      label: "First observed activity",
      detail: "Correlation window opened.",
    },
    {
      at: "2026-09-27T07:05:00",
      kind: "event",
      label: "Authentication succeeded",
      detail: "WAZUH: WAZUH_AUTH (HIGH)",
      event_id: "evt-2",
      event_type: "WAZUH_AUTH",
      source: "WAZUH",
      severity: "HIGH",
      entity: "192.0.2.77",
      explanation: null,
    },
    {
      at: "2026-09-27T07:11:00",
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
      created_at: "2026-09-27T07:11:00",
    },
    {
      action: "STATUS_CHANGED",
      actor: "operator@example.com",
      detail: "Status OPEN -> ACKNOWLEDGED.",
      created_at: "2026-09-27T08:00:00",
    },
  ],
};

const RESPONSES = { items: [], total: 0, limit: 100, offset: 0 };

const RECOMMENDATIONS = {
  incident_id: "inc-1",
  incident_key: BASE_ITEM.incident_key,
  severity: "HIGH",
  risk_score: 74,
  risk_priority: "P2",
  items: [],
  total: 0,
  truncated: false,
  policy_version: "1.0.0",
  governance_version: "1.0.0",
};

const RISK = {
  id: "ris-1",
  entity_type: "incident",
  entity_id: "inc-1",
  score: 74,
  severity: "HIGH",
  priority: "P2",
  factors: { severity_impact: 0.75 },
  explanation: "Stored evidence implies elevated risk.",
  calculated_at: "2026-09-27T07:11:00",
  scoring_version: "1.0.0",
};

type Handler = (url: string, init?: RequestInit) => unknown;
type Fail = { __fail: true; code: string; status: number };

function fail(code: string, status: number): Fail {
  return { __fail: true, code, status };
}

function mockFetch(handler: Handler) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => {
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

function fetchCalls() {
  return (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls as [
    string,
    RequestInit | undefined,
  ][];
}

/**
 * Route builder. `patch` receives the mutable server state so a test can
 * simulate a competing writer; the default success advances to ACKNOWLEDGED.
 */
function makeRoute(
  patch?: (state: { status: string }, detail: () => unknown) => unknown,
  initialStatus = "OPEN",
) {
  const state = { status: initialStatus };
  const detail = () => detailFor(state.status);
  const handler: Handler = (url, init) => {
    const method = init?.method ?? "GET";
    if (url.endsWith("/status") && method === "PATCH") {
      if (patch) return patch(state, detail);
      state.status = "ACKNOWLEDGED";
      return detail();
    }
    if (url.endsWith("/responses?limit=100")) return RESPONSES;
    if (url.includes("/response-recommendations")) return RECOMMENDATIONS;
    if (url.includes("/recalculate")) return {};
    if (url.includes("/relationships?")) return RELATIONSHIPS;
    if (url.endsWith("/evidence")) return EVIDENCE;
    if (url.endsWith("/timeline")) return TIMELINE;
    if (url.endsWith("/audit")) return AUDIT;
    if (url.includes("/api/v1/risk/incidents/") && url.includes("/calculate")) return RISK;
    if (url.includes("/api/v1/risk/incident/")) return RISK;
    if (url.includes("/api/v1/incidents?") && method === "GET") {
      return { items: [detail()], total: 1, limit: 100, offset: 0 };
    }
    if (url.includes("/api/v1/incidents/") && method === "GET") return detail();
    return {};
  };
  return { handler, state, detail };
}

async function openDetail() {
  await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Open"));
  await waitFor(() =>
    expect(screen.getByRole("heading", { name: /INC-INTEL1234567/ })).toBeInTheDocument(),
  );
}

const TRANSITION_CASES = [
  { status: "OPEN", expected: ["Mark Acknowledged", "Mark Closed"] },
  { status: "ACKNOWLEDGED", expected: ["Mark Investigating", "Mark Closed"] },
  { status: "INVESTIGATING", expected: ["Mark Resolved", "Mark Closed"] },
  { status: "RESOLVED", expected: ["Mark Closed"] },
  { status: "CLOSED", expected: [] as string[] },
];

const ALL_TRANSITION_LABELS = [
  "Mark Acknowledged",
  "Mark Investigating",
  "Mark Resolved",
  "Mark Closed",
];

describe("Incident lifecycle hardening (Phase 3, Step 38)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it.each(TRANSITION_CASES)(
    "shows exactly the permitted transitions for $status",
    async ({ status, expected }) => {
      const route = makeRoute(undefined, status);
      mockFetch(route.handler);
      render(
        <MemoryRouter>
          <Incidents />
        </MemoryRouter>,
      );
      await openDetail();
      for (const label of ALL_TRANSITION_LABELS) {
        if (expected.includes(label)) {
          expect(screen.getByRole("button", { name: label })).toBeInTheDocument();
        } else {
          expect(screen.queryByRole("button", { name: label })).toBeNull();
        }
      }
      if (expected.length === 0) {
        expect(screen.queryByRole("button", { name: /^Mark / })).toBeNull();
      }
    },
  );

  it("applies a successful transition from the server response and refreshes the list", async () => {
    const route = makeRoute();
    mockFetch(route.handler);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Mark Acknowledged" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Mark Investigating" })).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: "Mark Acknowledged" })).toBeNull();

    const calls = fetchCalls();
    const patch = calls.find(([url, init]) => url.endsWith("/status") && init?.method === "PATCH");
    expect(patch).toBeDefined();
    expect(JSON.parse(String(patch?.[1]?.body))).toEqual({ status: "ACKNOWLEDGED" });
    expect(
      calls.some(
        ([url, init]) => url.includes("/api/v1/incidents?") && (init?.method ?? "GET") === "GET",
      ),
    ).toBe(true);
  });

  it("reports an invalid transition distinctly and resynchronizes stale UI", async () => {
    // A competing writer moved the incident to ACKNOWLEDGED, so Mark Closed is stale.
    const route = makeRoute((state) => {
      state.status = "ACKNOWLEDGED";
      return fail("INVALID_TRANSITION", 422);
    });
    mockFetch(route.handler);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Mark Closed" }));
    await waitFor(() =>
      expect(
        screen.getByText(/not allowed from the incident's current state/),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByText(/INVALID_TRANSITION/)).toBeNull();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Mark Investigating" })).toBeInTheDocument(),
    );
  });

  it("reports a permission denial for PERMISSION_DENIED and for HTTP 403", async () => {
    mockFetch(makeRoute(() => fail("PERMISSION_DENIED", 403)).handler);
    const first = render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Mark Acknowledged" }));
    await waitFor(() =>
      expect(screen.getByText(/not permitted to change this incident's status/)).toBeInTheDocument(),
    );
    first.unmount();

    mockFetch(makeRoute(() => fail("HTTP_403", 403)).handler);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Mark Acknowledged" }));
    await waitFor(() =>
      expect(screen.getByText(/not permitted to change this incident's status/)).toBeInTheDocument(),
    );
  });

  it("reports an incident-not-found failure for INCIDENT_NOT_FOUND and for HTTP 404", async () => {
    mockFetch(makeRoute(() => fail("INCIDENT_NOT_FOUND", 404)).handler);
    const first = render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Mark Acknowledged" }));
    await waitFor(() =>
      expect(screen.getByText(/could not be found\. It may have been removed/)).toBeInTheDocument(),
    );
    first.unmount();

    mockFetch(makeRoute(() => fail("HTTP_404", 404)).handler);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Mark Acknowledged" }));
    await waitFor(() =>
      expect(screen.getByText(/could not be found\. It may have been removed/)).toBeInTheDocument(),
    );
  });

  it("reports an honest network/server failure for other errors without leaking detail", async () => {
    mockFetch((url, init) => {
      if (url.endsWith("/status") && (init?.method ?? "GET") === "PATCH") {
        throw new Error("socket hang up: internal detail that must never render");
      }
      return makeRoute().handler(url, init);
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Mark Acknowledged" }));
    await waitFor(() =>
      expect(screen.getByText(/network or server error/)).toBeInTheDocument(),
    );
    expect(screen.queryByText(/socket hang up/)).toBeNull();
    expect(screen.queryByText(/internal detail/)).toBeNull();
  });

  it("disables status controls while a request is in flight", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const route = makeRoute();
    (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
      async (url: unknown, init?: RequestInit) => {
        if (String(url).endsWith("/status") && init?.method === "PATCH") {
          await gate;
          return { ok: true, status: 200, json: async () => detailFor("ACKNOWLEDGED") };
        }
        return { ok: true, status: 200, json: async () => route.handler(String(url), init) };
      },
    );
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Mark Acknowledged" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Mark Acknowledged" })).toBeDisabled(),
    );
    expect(screen.getByRole("button", { name: "Mark Closed" })).toBeDisabled();
    release();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Mark Investigating" })).toBeInTheDocument(),
    );
  });

  it("prevents duplicate submissions of the same transition", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let patchCount = 0;
    const route = makeRoute();
    (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
      async (url: unknown, init?: RequestInit) => {
        if (String(url).endsWith("/status") && init?.method === "PATCH") {
          patchCount += 1;
          await gate;
          return { ok: true, status: 200, json: async () => detailFor("ACKNOWLEDGED") };
        }
        return { ok: true, status: 200, json: async () => route.handler(String(url), init) };
      },
    );
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openDetail();
    const button = screen.getByRole("button", { name: "Mark Acknowledged" });
    fireEvent.click(button);
    fireEvent.click(button);
    fireEvent.click(button);
    await waitFor(() => expect(patchCount).toBe(1));
    release();
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Mark Investigating" })).toBeInTheDocument(),
    );
    expect(patchCount).toBe(1);
  });

  it("keeps honest messaging when resynchronization itself fails", async () => {
    const route = makeRoute();
    let patchAttempted = false;
    (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
      async (url: unknown, init?: RequestInit) => {
        const target = String(url);
        const method = init?.method ?? "GET";
        if (target.endsWith("/status") && method === "PATCH") {
          patchAttempted = true;
          return {
            ok: false,
            status: 422,
            json: async () => ({ error: { code: "INVALID_TRANSITION" } }),
          };
        }
        if (patchAttempted && target.includes("/api/v1/incidents")) {
          return {
            ok: false,
            status: 500,
            json: async () => ({ error: { code: "INTERNAL_ERROR" } }),
          };
        }
        return { ok: true, status: 200, json: async () => route.handler(target, init) };
      },
    );
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openDetail();
    fireEvent.click(screen.getByRole("button", { name: "Mark Closed" }));
    await waitFor(() => expect(screen.getByText(/could not be reloaded/)).toBeInTheDocument());
    expect(
      screen.getByText(/not allowed from the incident's current state/),
    ).toBeInTheDocument();
  });

  it("preserves the existing timeline and audit history behavior", async () => {
    mockFetch(makeRoute().handler);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await openDetail();
    await waitFor(() => expect(screen.getByText("Timeline (3)")).toBeInTheDocument());
    expect(screen.getByText("Audit history (2)")).toBeInTheDocument();
    expect(screen.getByText(/Status OPEN -> ACKNOWLEDGED/)).toBeInTheDocument();
    expect(screen.getAllByText("STATUS_CHANGED").length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText(/No timeline entries are stored yet\./)).toBeNull();
  });
});
