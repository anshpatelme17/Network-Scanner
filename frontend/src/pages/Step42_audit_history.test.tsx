import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Response } from "./Response";
import { SessionProvider } from "../context/SessionContext";

/**
 * Phase 5, Step 42A: read-only audit history.
 *
 * The audit section loads from the v2 endpoint and is display-only. These
 * tests pin the truthful states (loading/empty/populated/denied/error),
 * the pagination contract, the rejection rationale appearing only where
 * the server recorded it, and the absence of any mutation control in the
 * audit view. The API remains the only authority.
 */

const ITEM = {
  id: "resp-1",
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

function entry(id: string, event: string, extra: Record<string, unknown> = {}) {
  return {
    id,
    event,
    previous_status: null,
    new_status: null,
    actor: "analyst-1",
    policy_version: "1.0.0",
    created_at: "2026-10-01T09:00:00",
    detail: null,
    ...extra,
  };
}

function auditPage(entries: unknown[], overrides: Record<string, unknown> = {}) {
  return {
    action_id: "resp-1",
    incident_id: "inc-1",
    entries,
    total: entries.length,
    limit: 50,
    offset: 0,
    truncated: false,
    ...overrides,
  };
}

type Fail = { __fail: true; code: string; status: number };
function fail(code: string, status: number): Fail {
  return { __fail: true, code, status };
}
function isFail(value: unknown): value is Fail {
  return typeof value === "object" && value !== null && "__fail" in value;
}

function ok(body: unknown) {
  return { ok: true, status: 200, json: async () => body };
}

const originalFetch = globalThis.fetch;

/**
 * Mock transport. `audit` receives the raw v2 audit URL so a test can
 * branch on `offset` for pagination, and can return a `Fail` sentinel.
 */
function mockApi(opts: { audit: (url: string) => unknown; gate?: Promise<void> }) {
  const { audit, gate } = opts;
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown) => {
      const target = String(url);
      if (target.includes("/api/v1/auth/me")) {
        return ok({
          id: "u1",
          username: "operator-1",
          display_name: "Operator",
          roles: ["OPERATOR"],
          permissions: ["APPROVE_RESPONSE", "CANCEL_RESPONSE", "EXECUTE_RESPONSE"],
        });
      }
      if (target.startsWith("/api/v1/responses?")) {
        return ok({ items: [ITEM], total: 1, limit: 100, offset: 0 });
      }
      if (target.includes("/api/v2/responses/") && target.includes("/audit")) {
        if (gate) await gate;
        const outcome = audit(target);
        if (isFail(outcome)) {
          return {
            ok: false,
            status: outcome.status,
            json: async () => ({ error: { code: outcome.code } }),
          };
        }
        return ok(outcome);
      }
      if (target.includes("/policy")) return ok(POLICY);
      if (target === "/api/v1/responses/resp-1") return ok({ ...ITEM, audit: [] });
      return ok({});
    },
  );
}

async function openDetail() {
  await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Open"));
}

function renderPage() {
  render(
    <MemoryRouter>
      <SessionProvider>
        <Response />
      </SessionProvider>
    </MemoryRouter>,
  );
}

describe("Response audit history (Step 42A)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    (globalThis as unknown as { fetch: unknown }).fetch = originalFetch;
  });

  it("shows a loading state, then the populated history", async () => {
    let release = () => {};
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    mockApi({
      gate,
      audit: () =>
        auditPage([
          entry("a1", "RESPONSE_REQUESTED", { new_status: "PENDING_APPROVAL" }),
          entry("a2", "RESPONSE_APPROVED", {
            previous_status: "PENDING_APPROVAL",
            new_status: "APPROVED",
            actor: "operator-2",
          }),
        ]),
    });
    renderPage();
    await openDetail();

    await waitFor(() => expect(screen.getByText("Loading audit history…")).toBeInTheDocument());
    release();

    await waitFor(() => expect(screen.getByText("RESPONSE_REQUESTED")).toBeInTheDocument());
    const region = screen.getByRole("region", { name: "Audit history" });
    expect(within(region).getByText("RESPONSE_APPROVED")).toBeInTheDocument();
    expect(within(region).getByText(/analyst-1/)).toBeInTheDocument();
    expect(within(region).getByText(/operator-2/)).toBeInTheDocument();
  });

  it("shows an honest empty state", async () => {
    mockApi({ audit: () => auditPage([]) });
    renderPage();
    await openDetail();
    await waitFor(() => expect(screen.getByText("No audit entries.")).toBeInTheDocument());
  });

  it("shows rejection detail only on the rejected entry", async () => {
    mockApi({
      audit: () =>
        auditPage([
          entry("a1", "RESPONSE_REQUESTED", { new_status: "PENDING_APPROVAL" }),
          entry("a2", "RESPONSE_REJECTED", {
            previous_status: "PENDING_APPROVAL",
            new_status: "REJECTED",
            actor: "operator-2",
            detail: "Needs the asset owner's sign-off.",
          }),
          entry("a3", "RESPONSE_EXECUTION_COMPLETED", {
            previous_status: "APPROVED",
            new_status: "COMPLETED",
            detail: null,
          }),
        ]),
    });
    renderPage();
    await openDetail();

    await waitFor(() => expect(screen.getByText("RESPONSE_REJECTED")).toBeInTheDocument());
    const region = screen.getByRole("region", { name: "Audit history" });
    expect(within(region).getByText(/Needs the asset owner's sign-off\./)).toBeInTheDocument();
    // Exactly one entry carries a rationale: the rejection.
    expect(within(region).getAllByText(/^Reason:/)).toHaveLength(1);
    // The execute entry is shown but never claims a reason.
    expect(within(region).getByText("RESPONSE_EXECUTION_COMPLETED")).toBeInTheDocument();
  });

  it("paginates using the backend contract", async () => {
    const seen: string[] = [];
    const firstPage = Array.from({ length: 50 }, (_, index) =>
      entry(`p0-${index}`, "RESPONSE_REQUESTED"),
    );
    mockApi({
      audit: (url) => {
        seen.push(url);
        if (url.includes("offset=50")) {
          return auditPage([entry("p1-0", "RESPONSE_EXECUTION_COMPLETED")], {
            total: 51,
            offset: 50,
            truncated: false,
          });
        }
        return auditPage(firstPage, { total: 51, offset: 0, truncated: true });
      },
    });
    renderPage();
    await openDetail();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Next" })).toBeInTheDocument(),
    );
    const previous = screen.getByRole("button", { name: "Previous" });
    expect(previous).toBeDisabled();
    fireEvent.click(screen.getByRole("button", { name: "Next" }));

    await waitFor(() =>
      expect(screen.getByText("RESPONSE_EXECUTION_COMPLETED")).toBeInTheDocument(),
    );
    expect(seen.some((url) => url.includes("offset=50"))).toBe(true);
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Previous" })).not.toBeDisabled();
  });

  it("shows a denied state on 403 without hiding the rest of the page", async () => {
    mockApi({ audit: () => fail("PERMISSION_DENIED", 403) });
    renderPage();
    await openDetail();

    await waitFor(() =>
      expect(
        screen.getByText("Your account is not permitted to view audit history."),
      ).toBeInTheDocument(),
    );
    // The detail section itself is unaffected.
    expect(screen.getByText("BLOCK_INDICATOR → IP:198.51.100.23")).toBeInTheDocument();
  });

  it("renders a safe message for a server error", async () => {
    mockApi({ audit: () => fail("INTERNAL_ERROR", 500) });
    renderPage();
    await openDetail();

    await waitFor(() =>
      expect(screen.getByText("The server could not complete the request.")).toBeInTheDocument(),
    );
    // No raw exception text reaches the DOM.
    expect(screen.queryByText(/Internal server error/i)).toBeNull();
  });

  it("exposes no mutation control inside the audit view", async () => {
    mockApi({
      audit: () => auditPage([entry("a1", "RESPONSE_REQUESTED", { new_status: "PENDING_APPROVAL" })]),
    });
    renderPage();
    await openDetail();

    await waitFor(() => expect(screen.getByText("RESPONSE_REQUESTED")).toBeInTheDocument());

    const region = screen.getByRole("region", { name: "Audit history" });
    // The audit view offers no approve/reject/cancel/execute/delete control.
    for (const name of ["Approve", "Reject", "Cancel", "Execute", "Delete"]) {
      expect(within(region).queryByRole("button", { name })).toBeNull();
    }
    // Only pagination (and none is needed for a single page).
    expect(within(region).queryAllByRole("button")).toHaveLength(0);

    // The detail page still offers its decision controls — proving the
    // assertion above is about the audit view, not the whole card.
    expect(screen.getByRole("button", { name: "Approve" })).toBeInTheDocument();
  });
});
