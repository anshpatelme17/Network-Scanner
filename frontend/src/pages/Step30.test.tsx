import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { SessionProvider } from "../context/SessionContext";
import { Response } from "./Response";

/**
 * Step 30 UI contract.
 *
 * The point of these tests is that the interface never overstates what
 * the platform did: a pending request is visibly pending, a dry run says
 * nothing external happened, an execution result is only ever shown when
 * the server returned one, and no control appears for a state that does
 * not allow it.
 */

const PENDING = {
  id: "ctl-1",
  incident_id: "inc-1",
  action_type: "BLOCK_INDICATOR",
  target_type: "IP",
  target_reference: "198.51.100.23",
  reason: "Confirmed malicious destination in incident evidence.",
  requested_by: "analyst-1",
  status: "PENDING_APPROVAL",
  dry_run: true,
  policy_version: "1.0.0",
  execution_status: null,
  created_at: "2026-09-30T06:00:00",
  approved_at: null,
  expires_at: "2026-09-30T07:00:00",
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
  target_evidence: ["evt-1", "evt-2"],
};

const APPROVED = {
  ...PENDING,
  status: "APPROVED",
  approved_at: "2026-09-30T06:05:00",
  approved_by: "operator-2",
};

const COMPLETED = {
  ...APPROVED,
  status: "COMPLETED",
  execution_status: "COMPLETED",
  started_at: "2026-09-30T06:06:00",
  completed_at: "2026-09-30T06:06:01",
  rollback_supported: true,
  rollback_reference: "abc123",
  result_summary: "Mock provider recorded BLOCK_INDICATOR against IP:198.51.100.23.",
};

const FAILED = {
  ...APPROVED,
  status: "FAILED",
  execution_status: "FAILED",
  failure_reason: "Mock provider reported a controlled failure.",
  rollback_supported: false,
};

const POLICY = {
  action_id: "ctl-1",
  decision: "APPROVAL_REQUIRED",
  approval_required: true,
  provider: "MOCK",
  provider_capable: true,
  target_proven: true,
  evidence_event_ids: ["evt-1", "evt-2"],
  expires_at: "2026-09-30T07:00:00",
  reason:
    "BLOCK_INDICATOR is available because the incident contains a stored IP indicator supported by 2 event(s) and policy requires human approval before the provider MOCK may act.",
  policy_version: "1.0.0",
};

const DRY_RUN = {
  action_id: "ctl-1",
  incident_id: "inc-1",
  action_type: "BLOCK_INDICATOR",
  target: "IP:198.51.100.23",
  provider: "MOCK",
  dry_run: true,
  would_execute: true,
  executed: false,
  result: "SIMULATED",
  explanation:
    "Dry run: BLOCK_INDICATOR against IP:198.51.100.23 would be recorded by the mock provider only. Mock provider: the defensive step was recorded inside the platform only. No firewall, endpoint, account, or cloud system was contacted or changed.",
  changes: [],
  evidence_event_ids: ["evt-1"],
  policy_decision: "APPROVAL_REQUIRED",
  policy_reason: POLICY.reason,
  expires_at: "2026-09-30T07:00:00",
  policy_version: "1.0.0",
  governance_version: "1.0.0",
};

const ROLLBACK = {
  id: "rb-1",
  action_id: "ctl-1",
  incident_id: "inc-1",
  provider: "MOCK",
  result: "COMPLETED",
  explanation: "Mock provider rolled back BLOCK_INDICATOR to recorded prior state.",
  policy_version: "1.0.0",
  created_at: "2026-09-30T06:07:00",
};

function executionRecord(over: Record<string, unknown> = {}) {
  return {
    id: "exec-1",
    action_id: "ctl-1",
    incident_id: "inc-1",
    adapter: "MOCK",
    dry_run: false,
    would_execute: true,
    result: "COMPLETED",
    explanation: "Mock provider recorded BLOCK_INDICATOR against IP:198.51.100.23.",
    policy_version: "1.0.0",
    simulated_at: "2026-09-30T06:06:01",
    ...over,
  };
}

function detail(over: Record<string, unknown> = {}) {
  const merged = { ...PENDING, ...over };
  const hasRun = ["COMPLETED", "FAILED"].includes(merged.status as string);
  return {
    ...merged,
    audit: [
      {
        id: "a1",
        event: "RESPONSE_REQUESTED",
        previous_status: null,
        new_status: "PENDING_APPROVAL",
        actor: "analyst-1",
        policy_version: "1.0.0",
        created_at: "2026-09-30T06:00:00",
      },
    ],
    execution: hasRun
      ? executionRecord(
          merged.status === "FAILED"
            ? {
                result: "FAILED",
                explanation: "Mock provider reported a controlled failure.",
              }
            : {},
        )
      : null,
    rollback: null,
  };
}

function okBody(value: unknown) {
  return { ok: true, status: 200, json: async () => value };
}

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => okBody(handler(String(url), init)),
  );
}

/** An identity holding every governed-response permission. */
const OPERATOR = {
  id: "u-1",
  username: "operator-1",
  display_name: "Operator",
  roles: ["OPERATOR"],
  permissions: [
    "READ_RESPONSES",
    "REQUEST_RESPONSE",
    "CANCEL_RESPONSE",
    "APPROVE_RESPONSE",
    "EXECUTE_RESPONSE",
    "ROLLBACK_RESPONSE",
  ],
};

/** A viewer: may read responses, may govern nothing. */
const VIEWER = {
  id: "u-2",
  username: "viewer-1",
  display_name: "Viewer",
  roles: ["VIEWER"],
  permissions: ["READ_RESPONSES"],
};

/**
 * Render the page as `identity`.
 *
 * The identity is authoritative only through the mocked `/auth/me`
 * response; the parameter exists so each test states up front which
 * account it is acting as, and is reflected in the wrapper's test id so a
 * failure message shows it.
 */
function renderPage(identity: typeof OPERATOR | typeof VIEWER | null = OPERATOR) {
  return render(
    <div data-testid={`session-${identity?.roles[0] ?? "anonymous"}`}>
      <MemoryRouter>
        <SessionProvider>
          <Response />
        </SessionProvider>
      </MemoryRouter>
    </div>,
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe("Controlled defensive responses (Step 30)", () => {
  it("renders a controlled request as pending approval, never as executed", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/responses/ctl-1/policy")) return POLICY;
      if (url.includes("/api/v1/responses/ctl-1")) return detail();
      return { items: [PENDING], total: 1, limit: 100, offset: 0 };
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Controlled defensive responses (1)")).toBeTruthy());
    expect(screen.getAllByText("PENDING_APPROVAL").length).toBeGreaterThan(0);
    expect(screen.getByText("DRY RUN — NO EXTERNAL ACTION PERFORMED")).toBeTruthy();
    // Evidence supporting the target is shown, and the provider is named.
    expect(screen.getByText(/2 evidence event\(s\)/)).toBeTruthy();
    expect(screen.getAllByText("MOCK").length).toBeGreaterThan(0);
    // No success state is claimed anywhere.
    expect(screen.queryByText("Threat neutralized")).toBeNull();
    expect(screen.queryByText("Indicator blocked")).toBeNull();
  });

  it("shows no execute control while approval is still pending", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/responses/ctl-1/policy")) return POLICY;
      if (url.includes("/api/v1/responses/ctl-1")) return detail();
      return { items: [PENDING], total: 1, limit: 100, offset: 0 };
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Controlled defensive responses (1)")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Open Controlled Response" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Approve" })).toBeTruthy());
    // Pending: approve/reject/cancel and a preview, but never execute.
    expect(screen.getByRole("button", { name: "Reject" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Preview Controlled Action" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Execute Controlled Action" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Roll Back" })).toBeNull();
  });

  it("states the policy decision and its deterministic reason", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/responses/ctl-1/policy")) return POLICY;
      if (url.includes("/api/v1/responses/ctl-1")) return detail();
      return { items: [PENDING], total: 1, limit: 100, offset: 0 };
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Controlled defensive responses (1)")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Open Controlled Response" }));
    await waitFor(() => expect(screen.getByLabelText("Response policy")).toBeTruthy());
    expect(screen.getByText("APPROVAL_REQUIRED")).toBeTruthy();
    expect(screen.getByText(POLICY.reason)).toBeTruthy();
    expect(screen.getByText(/target proven: true/)).toBeTruthy();
  });

  it("renders a dry run without claiming anything was performed", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/responses/ctl-1/policy")) return POLICY;
      if (url.includes("/api/v1/responses/ctl-1/provider-preview")) return DRY_RUN;
      if (url.includes("/api/v1/responses/ctl-1")) return detail();
      return { items: [PENDING], total: 1, limit: 100, offset: 0 };
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Controlled defensive responses (1)")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Open Controlled Response" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Preview Controlled Action" })).toBeTruthy(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Preview Controlled Action" }));
    await waitFor(() => expect(screen.getByLabelText("Provider dry run")).toBeTruthy());
    expect(screen.getByText(DRY_RUN.explanation)).toBeTruthy();
    expect(screen.getByText(/executed: false/)).toBeTruthy();
    expect(screen.getByText(/result: SIMULATED/)).toBeTruthy();
    // A dry run must not read as a completed block.
    expect(screen.queryByText(/Indicator blocked/)).toBeNull();
  });

  it("offers execution only once approved and labels the mock provider honestly", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/responses/ctl-1/policy")) return {
        ...POLICY,
        decision: "ALLOWED_WITH_APPROVAL",
      };
      if (url.includes("/api/v1/responses/ctl-1")) return detail(APPROVED);
      return { items: [APPROVED], total: 1, limit: 100, offset: 0 };
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Controlled defensive responses (1)")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Open Controlled Response" }));
    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Execute Controlled Action" })).toBeTruthy(),
    );
    // Approved: execute appears; approve/reject no longer do.
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.getByText(/approved by operator-2/)).toBeTruthy();
  });

  it("shows the real execution result and a rollback control when complete", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/auth/me")) return OPERATOR;
      if (url.includes("/api/v1/responses/ctl-1/policy")) return {
        ...POLICY,
        decision: "ALLOWED_WITH_APPROVAL",
      };
      if (url.includes("/api/v1/responses/ctl-1/rollback")) return ROLLBACK;
      if (url.includes("/api/v1/responses/ctl-1")) return detail(COMPLETED);
      return { items: [COMPLETED], total: 1, limit: 100, offset: 0 };
    });
    renderPage(OPERATOR);
    await waitFor(() => expect(screen.getByText("Controlled defensive responses (1)")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Open Controlled Response" }));
    await waitFor(() => expect(screen.getByLabelText("Execution result")).toBeTruthy());
    expect(
      screen.getByText("MOCK PROVIDER — PLATFORM RECORD ONLY, NO EXTERNAL SYSTEM CHANGED"),
    ).toBeTruthy();
    expect(screen.getAllByText(COMPLETED.result_summary as string).length).toBeGreaterThan(0);
    // Rollback is offered only because the provider recorded prior state.
    const rollbackButton = screen.getByRole("button", { name: "Roll Back" }) as HTMLButtonElement;
    await waitFor(() => expect(rollbackButton.disabled).toBe(false));
    fireEvent.click(rollbackButton);
    await waitFor(() => expect(screen.getByLabelText("Rollback record")).toBeTruthy());
    expect(screen.getByText(ROLLBACK.explanation)).toBeTruthy();
  });

  it("does not offer governed controls the signed-in account cannot use", async () => {
    // Step 31: permission reflection. The buttons are present but disabled,
    // and clicking one performs no request. This is a usability affordance
    // only — the server rejects the call regardless.
    const calls: string[] = [];
    (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
      async (url: unknown, init?: RequestInit) => {
        calls.push(`${init?.method ?? "GET"} ${String(url)}`);
        if (String(url).includes("/api/v1/auth/me")) return okBody(VIEWER);
        if (String(url).includes("/api/v1/responses/ctl-1/policy")) return okBody(POLICY);
        if (String(url).includes("/api/v1/responses/ctl-1")) return okBody(detail(COMPLETED));
        return okBody({ items: [COMPLETED], total: 1, limit: 100, offset: 0 });
      },
    );
    renderPage(VIEWER);
    await waitFor(() => expect(screen.getByText("Controlled defensive responses (1)")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Open Controlled Response" }));
    const rollbackButton = await screen.findByRole("button", { name: "Roll Back" });
    await waitFor(() => expect((rollbackButton as HTMLButtonElement).disabled).toBe(true));
    calls.length = 0;
    fireEvent.click(rollbackButton);
    // No rollback request was issued.
    expect(calls.filter((entry) => entry.includes("/rollback"))).toHaveLength(0);
    // And the reason is stated rather than left mysterious.
    expect(rollbackButton.getAttribute("title") ?? "").toContain("ROLLBACK_RESPONSE");
  });

  it("treats an unknown identity as not permitted", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/responses/ctl-1/policy")) return {
        ...POLICY,
        decision: "ALLOWED_WITH_APPROVAL",
      };
      if (url.includes("/api/v1/responses/ctl-1")) return detail(APPROVED);
      // /auth/me is unmocked and fails: the identity stays unknown.
      return { items: [APPROVED], total: 1, limit: 100, offset: 0 };
    });
    renderPage(null);
    await waitFor(() => expect(screen.getByText("Controlled defensive responses (1)")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Open Controlled Response" }));
    const execute = await screen.findByRole("button", { name: "Execute Controlled Action" });
    await waitFor(() => expect((execute as HTMLButtonElement).disabled).toBe(true));
  });

  it("offers no rollback and shows the failure reason when execution failed", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/responses/ctl-1/policy")) return {
        ...POLICY,
        decision: "ALLOWED_WITH_APPROVAL",
      };
      if (url.includes("/api/v1/responses/ctl-1")) return detail(FAILED);
      return { items: [FAILED], total: 1, limit: 100, offset: 0 };
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Controlled defensive responses (1)")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Open Controlled Response" }));
    await waitFor(() => expect(screen.getByText(/Failure reason:/)).toBeTruthy());
    expect(screen.getAllByText(FAILED.failure_reason as string).length).toBeGreaterThan(0);
    // A failed action must not offer a rollback it cannot perform.
    expect(screen.queryByRole("button", { name: "Roll Back" })).toBeNull();
  });

  it("displays the expiration bound rather than implying a permanent block", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/responses/ctl-1/policy")) return POLICY;
      if (url.includes("/api/v1/responses/ctl-1")) return detail();
      return { items: [PENDING], total: 1, limit: 100, offset: 0 };
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Controlled defensive responses (1)")).toBeTruthy());
    // The Expires column renders the bounded TTL, not a dash.
    expect(screen.getByText("Expires")).toBeTruthy();
    expect(screen.queryByText("permanent")).toBeNull();
  });

  it("keeps legacy proposals out of the controlled section", async () => {
    const legacy = {
      ...PENDING,
      id: "resp-1",
      action_type: "REVIEW",
      target_type: "INCIDENT",
      status: "PROPOSED",
      provider: "MOCK",
      policy_decision: "DRY_RUN_ONLY",
      target_evidence: [],
    };
    mockFetch((url) => {
      if (url.includes("/api/v1/responses/res")) return { ...detail(legacy), ...legacy };
      return { items: [legacy], total: 1, limit: 100, offset: 0 };
    });
    renderPage();
    await waitFor(() => expect(screen.getByText("Response proposals (1)")).toBeTruthy());
    expect(screen.getByText("Controlled defensive responses (0)")).toBeTruthy();
    expect(screen.getByText("No controlled defensive responses.")).toBeTruthy();
    // A Step 12 proposal still reports the dry-run-only default decision.
    expect(screen.queryByText("No response proposals.")).toBeNull();
    expect(screen.getByText("DRY RUN — NO ACTION EXECUTED")).toBeTruthy();
  });
});
