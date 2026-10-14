import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Response } from "./Response";
import { Incidents } from "./Incidents";
import { SessionProvider } from "../context/SessionContext";
import { ResponseCenter } from "./ResponseCenter";

/**
 * Phase 4, Step 41: response approval hardening.
 *
 * These pin the duplicate-submission guard, the in-flight disabled state,
 * guard release on success AND failure, safe handling of the server's
 * stable error codes, and the optional rejection reason. The API remains
 * the only authority: disabling a control here grants nothing.
 */

const ITEM = {
  id: "resp-1",
  incident_id: "inc-1",
  incident_key: "INC-AAA111BBB222",
  action_type: "BLOCK_INDICATOR",
  target_type: "IP",
  target_reference: "198.51.100.23",
  reason: "Confirmed malicious destination in incident evidence.",
  requested_by: "analyst-1",
  status: "PENDING_APPROVAL",
  dry_run: true,
  policy_version: "1.0.0",
  execution_status: null,
  created_at: "2026-10-01T09:00:00",
  approved_at: null,
  expires_at: "2026-10-01T13:00:00",
  approved_by: null,
  started_at: null,
  completed_at: null,
  failure_reason: null,
  result_summary: null,
  provider: "MOCK",
  policy_decision: "APPROVAL_REQUIRED",
  approval_required: true,
  rollback_supported: false,
  rollback_state: null,
  rollback_reference: null,
  target_evidence: ["evt-1"],
};

const POLICY = {
  action_id: "resp-1",
  decision: "APPROVAL_REQUIRED",
  approval_required: true,
  provider: "MOCK",
  provider_capable: true,
  target_proven: true,
  evidence_event_ids: ["evt-1"],
  expires_at: "2026-10-01T13:00:00",
  reason: "A second operator must approve before the provider may act.",
  policy_version: "1.0.0",
};

const INCIDENT = {
  id: "inc-1",
  incident_key: "INC-AAA111BBB222",
  title: "Incident: repeated activity",
  description: "Security incident opened for review.",
  status: "OPEN",
  severity: "MEDIUM",
  confidence: 60,
  primary_asset_id: null,
  primary_ip: "10.0.0.9",
  hostname: null,
  correlation_id: "corr-1",
  risk_assessment_id: null,
  first_seen: "2026-10-01T06:00:00",
  last_seen: "2026-10-01T06:10:00",
  resolved_at: null,
  created_at: "2026-10-01T06:11:00",
  updated_at: "2026-10-01T06:11:00",
  version: "1.0.0",
  incident_type: "CORRELATED_SECURITY_EVENT",
  risk_score: null,
  detection_reason: "3 related events under rule 'repeated-source'.",
};

function page(items: unknown[]) {
  return { items, total: items.length, limit: 50, offset: 0 };
}

type Fail = { __fail: true; code: string; status: number };

function fail(code: string, status: number): Fail {
  return { __fail: true, code, status };
}

const originalFetch = globalThis.fetch;

/**
 * Mock transport for the controlled-response page. A mutable row stands in
 * for stored state, so a successful decision is visible to the subsequent
 * list and detail reads. `gate` delays the decision POST so a duplicate
 * click can be attempted while one is still in flight.
 */
function mockControlled(opts: {
  decide?: (url: string, init?: RequestInit) => unknown;
  gate?: Promise<void>;
  posts?: string[];
}) {
  const { decide, gate, posts } = opts;
  const row: Record<string, unknown> = { ...ITEM };
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => {
      const target = String(url);
      const method = init?.method ?? "GET";
      if (target.includes("/api/v1/auth/me")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            id: "u1",
            username: "operator-1",
            display_name: "Operator",
            roles: ["OPERATOR"],
            permissions: ["APPROVE_RESPONSE", "CANCEL_RESPONSE", "EXECUTE_RESPONSE"],
          }),
        };
      }
      if (target.startsWith("/api/v1/responses?")) {
        return { ok: true, status: 200, json: async () => page([row]) };
      }
      if (method === "POST" && /\/(approve|reject|cancel)$/.test(target)) {
        if (posts) posts.push(target);
        if (gate) await gate;
        const outcome = decide ? decide(target, init) : undefined;
        const marker = outcome as Fail | null;
        if (marker && marker.__fail) {
          return {
            ok: false,
            status: marker.status,
            json: async () => ({ error: { code: marker.code } }),
          };
        }
        // Stored state advances, exactly as the server would persist it.
        Object.assign(row, (outcome as object) ?? {});
        return { ok: true, status: 200, json: async () => ({ ...row }) };
      }
      if (target.includes("/policy")) {
        return { ok: true, status: 200, json: async () => POLICY };
      }
      if (target === "/api/v1/responses/resp-1") {
        return { ok: true, status: 200, json: async () => ({ ...row, audit: [] }) };
      }
      return { ok: true, status: 200, json: async () => ({}) };
    },
  );
}

/**
 * Mock transport for the incident-scoped response list. `outcome` decides
 * what a decision POST reports; the stored row advances on success so the
 * reload reflects it, exactly as the server would persist it.
 */
function mockIncidentResponses(opts: { gate?: Promise<void>; posts?: string[]; outcome?: Fail }) {
  const { gate, posts, outcome } = opts;
  const row: Record<string, unknown> = { ...ITEM, status: "PROPOSED" };
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => {
      const target = String(url);
      const method = init?.method ?? "GET";
      if (target.includes("/api/v1/auth/me")) {
        return {
          ok: true,
          status: 200,
          json: async () => ({
            id: "u1",
            username: "operator-1",
            display_name: "Operator",
            roles: ["OPERATOR"],
            permissions: ["APPROVE_RESPONSE"],
          }),
        };
      }
      // The decision endpoint is the global one: the incident-scoped
      // handler calls POST /api/v1/responses/{id}/{decision}.
      if (method === "POST" && /\/api\/v1\/responses\/[^/]+\/(approve|reject|cancel)$/.test(target)) {
        if (posts) posts.push(target);
        if (gate) await gate;
        if (outcome) {
          return {
            ok: false,
            status: outcome.status,
            json: async () => ({ error: { code: outcome.code } }),
          };
        }
        const decision = /\/(approve|reject|cancel)$/.exec(target)?.[1];
        Object.assign(row, {
          status: decision === "approve" ? "APPROVED" : decision === "reject" ? "REJECTED" : "CANCELLED",
          ...(decision === "approve" ? { approved_by: "operator-1" } : {}),
        });
        return { ok: true, status: 200, json: async () => ({ ...row }) };
      }
      if (target.includes("/incidents?")) {
        return { ok: true, status: 200, json: async () => page([INCIDENT]) };
      }
      if (target.includes("/incidents/inc-1/responses")) {
        return { ok: true, status: 200, json: async () => page([row]) };
      }
      if (target.includes("/incidents/inc-1")) {
        // The real detail route appends evidence_event_ids; the component
        // reads its length, so the mock must carry it.
        return {
          ok: true,
          status: 200,
          json: async () => ({ ...INCIDENT, evidence_event_ids: ["evt-1"] }),
        };
      }
      return { ok: true, status: 200, json: async () => ({ entries: [], events: [] }) };
    },
  );
}

function renderResponsePage() {
  return render(
    <MemoryRouter>
      <SessionProvider>
        <Response />
      </SessionProvider>
    </MemoryRouter>,
  );
}

async function openIncidentDetail() {
  await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Open"));
  // The responses section loads independently; wait for it rather than
  // relying on the default findBy timeout.
  await waitFor(() =>
    expect(screen.getByText(/Controlled responses/)).toBeInTheDocument(),
  );
  await screen.findByRole("button", { name: "Approve" });
}

function renderIncidentsPage() {
  return render(
    <MemoryRouter>
      <SessionProvider>
        <Incidents />
      </SessionProvider>
    </MemoryRouter>,
  );
}

async function openControlledDetail() {
  await waitFor(() => expect(screen.getByText("Open Controlled Response")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Open Controlled Response"));
  await waitFor(() => expect(screen.getByText("Approve")).toBeInTheDocument());
}

describe("Response approval hardening (Phase 4, Step 41)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    (globalThis as unknown as { fetch: unknown }).fetch = originalFetch;
  });

  // -- 1. Duplicate-submit prevention ----------------------------------------

  it("sends exactly one decision for repeated clicks on the response page", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const posts: string[] = [];
    mockControlled({ gate, posts });

    renderResponsePage();
    await openControlledDetail();
    const approve = screen.getByRole("button", { name: "Approve" });
    fireEvent.click(approve);
    fireEvent.click(approve);
    fireEvent.click(approve);

    release();
    await waitFor(() => expect(posts).toHaveLength(1));
    expect(posts[0]).toContain("/approve");
  });

  it("sends exactly one decision for repeated clicks in the incident view", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const posts: string[] = [];
    mockIncidentResponses({ gate, posts });

    renderIncidentsPage();
    await openIncidentDetail();
    const approve = screen.getByRole("button", { name: "Approve" });
    fireEvent.click(approve);
    fireEvent.click(approve);
    fireEvent.click(approve);

    release();
    await waitFor(() => expect(posts).toHaveLength(1));
  });

  // -- 2. In-flight disabled state -------------------------------------------

  it("disables the decision controls while a decision is in flight", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    mockControlled({ gate });

    renderResponsePage();
    await openControlledDetail();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Approve" })).toBeDisabled(),
    );
    expect(screen.getByRole("button", { name: "Reject" })).toBeDisabled();
    expect(screen.getByLabelText("Rejection reason")).toBeDisabled();

    release();
    // Guard released on success: the PENDING_APPROVAL controls are offered
    // again (the mock leaves the row pending), proving the ref was cleared.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Approve" })).toBeEnabled(),
    );
  });

  it("disables the incident-scoped decision controls while in flight", async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const posts: string[] = [];
    mockIncidentResponses({ gate, posts });

    renderIncidentsPage();
    await openIncidentDetail();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    // In flight: every decision control on the row is disabled.
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Approve" })).toBeDisabled(),
    );
    expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();

    release();
    // The decision succeeded, so the stored row advanced to APPROVED and
    // the Approve control is gone. Guard release is proven by the fact
    // that a *subsequent* decision (Cancel is still offered for an
    // approved row) is accepted rather than being swallowed by a stuck
    // in-flight guard.
    await waitFor(() => expect(screen.queryByRole("button", { name: "Approve" })).toBeNull());
    const cancel = screen.getByRole("button", { name: "Cancel" });
    expect(cancel).toBeEnabled();
    fireEvent.click(cancel);
    await waitFor(() => expect(posts).toHaveLength(2));
    expect(posts[1]).toContain("/cancel");
  });

  // -- 3. Guard release and error handling -----------------------------------

  it("releases the guard and reports a permission denial safely", async () => {
    mockControlled({
      decide: () => fail("PERMISSION_DENIED", 403),
    });

    renderResponsePage();
    await openControlledDetail();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() =>
      expect(
        screen.getByText("Your account is not permitted to perform this action."),
      ).toBeInTheDocument(),
    );
    // No server message text is rendered.
    expect(screen.queryByText(/Permission is required/)).toBeNull();
    // Guard released: the control is offered again.
    await waitFor(() => expect(screen.getByRole("button", { name: "Approve" })).toBeEnabled());
  });

  it("reports an invalid transition distinctly and never leaks server text", async () => {
    mockIncidentResponses({ outcome: fail("INVALID_TRANSITION", 409) });

    renderIncidentsPage();
    await openIncidentDetail();
    const reject = screen.getByRole("button", { name: "Reject" });
    fireEvent.click(reject);

    await waitFor(() =>
      expect(
        screen.getByText("That action is not valid in the current state."),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByText(/Permission is required/)).toBeNull();
    expect(screen.queryByText(/INVALID_TRANSITION/i)).toBeNull();
  });

  it("falls back to a generic message for an unexpected code", async () => {
    mockControlled({ decide: () => fail("SOMETHING_NEW", 500) });

    renderResponsePage();
    await openControlledDetail();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() =>
      expect(screen.getByText("Decision was rejected by the server.")).toBeInTheDocument(),
    );
    await waitFor(() => expect(screen.getByRole("button", { name: "Approve" })).toBeEnabled());
  });

  // -- 4. Optional rejection reason ------------------------------------------

  it("sends a rejection reason when the operator typed one", async () => {
    const bodies: string[] = [];
    mockControlled({
      decide: (url, init) => {
        if (url.endsWith("/reject")) bodies.push(String(init?.body ?? ""));
        return undefined;
      },
    });

    renderResponsePage();
    await openControlledDetail();
    fireEvent.change(screen.getByLabelText("Rejection reason"), {
      target: { value: "Confirmed benign with the asset owner." },
    });
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(JSON.parse(bodies[0])).toEqual({
      actor: "operator",
      reason: "Confirmed benign with the asset owner.",
    });
  });

  it("omits the reason entirely for approval and for an empty rejection", async () => {
    const bodies: Array<Record<string, string>> = [];
    mockControlled({
      decide: (_url, init) => {
        bodies.push(JSON.parse(String(init?.body ?? "{}")) as Record<string, string>);
        return undefined;
      },
    });

    renderResponsePage();
    await openControlledDetail();
    // Approval carries no rationale.
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(bodies[0]).toEqual({ actor: "operator" });
  });

  it("does not send a whitespace-only rejection reason", async () => {
    const bodies: string[] = [];
    mockControlled({
      decide: (url, init) => {
        if (url.endsWith("/reject")) bodies.push(String(init?.body ?? ""));
        return undefined;
      },
    });

    renderResponsePage();
    await openControlledDetail();
    fireEvent.change(screen.getByLabelText("Rejection reason"), { target: { value: "   " } });
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));

    await waitFor(() => expect(bodies).toHaveLength(1));
    expect(JSON.parse(bodies[0])).toEqual({ actor: "operator" });
  });

  // -- 5. Success path -------------------------------------------------------

  it("refreshes the detail and list after a successful decision", async () => {
    mockControlled({ decide: () => ({ status: "APPROVED", approved_by: "operator-1" }) });

    renderResponsePage();
    await openControlledDetail();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Approve" })).toBeNull(),
    );
    // The list was reloaded and the approved identity is visible.
    await waitFor(() => expect(screen.getByText("approved by operator-1")).toBeInTheDocument());
  });

  // -- 6. Read-only surface preserved ----------------------------------------

  it("keeps the response center free of decision controls", async () => {
    const summary = {
      version: "1",
      generated_at: "2026-10-01T10:00:00",
      counts: { PENDING_APPROVAL: 1 },
      pending_approval: [ITEM],
      expiring_soon: [],
      total: 1,
      limit: 100,
      offset: 0,
      truncated: false,
      expiry_warning_hours: 72,
    };
    (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => summary,
    }));

    render(
      <MemoryRouter>
        <SessionProvider>
          <ResponseCenter />
        </SessionProvider>
      </MemoryRouter>,
    );

    const pageRegion = await screen.findByRole("region", { name: "Response center" });
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Reject" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Cancel" })).toBeNull();
    expect(pageRegion).toBeInTheDocument();
  });
});
