import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Sidebar } from "../components/layout/Sidebar";
import { ResponseCenter } from "./ResponseCenter";
import type { ResponseCenterSummary, ResponseProposal } from "../types";

/**
 * Phase 4, Step 40: response center. Read-only by construction.
 *
 * These tests pin the guarantees the page claims: it makes one GET and
 * nothing else, it offers no approve/execute/rollback/creation control of
 * its own, it links to /response for every interaction, and it never
 * presents a mock-provider record as a real defensive action.
 */

function makeProposal(overrides: Partial<ResponseProposal> & { id: string }): ResponseProposal {
  return {
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
    target_evidence: ["evt-1", "evt-2"],
    ...overrides,
  };
}

function makeSummary(overrides: Partial<ResponseCenterSummary> = {}): ResponseCenterSummary {
  return {
    version: "1",
    generated_at: "2026-10-01T10:00:00",
    counts: {
      PENDING_APPROVAL: 2,
      APPROVED: 1,
      COMPLETED: 1,
      FAILED: 1,
      ROLLED_BACK: 0,
      REJECTED: 1,
      CANCELLED: 0,
      EXPIRED: 1,
      RUNNING: 1,
      DRY_RUN_COMPLETED: 0,
    },
    pending_approval: [
      makeProposal({ id: "act-pending-1" }),
      makeProposal({
        id: "act-pending-2",
        action_type: "DISABLE_ACCOUNT",
        target_type: "ACCOUNT",
        target_reference: "chain-user",
        expires_at: "2026-10-03T09:00:00",
      }),
    ],
    expiring_soon: [
      makeProposal({ id: "act-soon-1", status: "APPROVED", expires_at: "2026-10-01T16:00:00" }),
    ],
    total: 8,
    limit: 100,
    offset: 0,
    truncated: false,
    expiry_warning_hours: 72,
    ...overrides,
  };
}

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
      const marker = handler(String(url), init) as Fail | null;
      if (marker && marker.__fail) {
        return {
          ok: false,
          status: marker.status,
          json: async () => ({ error: { code: marker.code } }),
        };
      }
      return { ok: true, status: 200, json: async () => handler(String(url), init) };
    },
  );
}

function routeWith(summary: ResponseCenterSummary | Fail = makeSummary()): Handler {
  return (url) => {
    if (url.includes("/api/v1/responses/summary")) return summary;
    return {};
  };
}

function renderPage(initialEntry = "/response-center") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/response-center" element={<ResponseCenter />} />
        <Route path="/response" element={<p>Response page</p>} />
        <Route path="*" element={<p>Unknown route</p>} />
      </Routes>
    </MemoryRouter>,
  );
}

const originalFetch = globalThis.fetch;

describe("Response center (Phase 4, Step 40)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    calls.length = 0;
  });

  afterEach(() => {
    (globalThis as unknown as { fetch: unknown }).fetch = originalFetch;
  });

  // -- 1. Content ------------------------------------------------------------

  it("renders the exact controlled-status counts from the server", async () => {
    mockFetch(routeWith());
    renderPage();

    const counts = await screen.findByLabelText("Controlled response counts");
    expect(within(counts).getByText("Controlled responses (8)")).toBeInTheDocument();
    for (const status of [
      "PENDING_APPROVAL",
      "APPROVED",
      "RUNNING",
      "COMPLETED",
      "FAILED",
      "ROLLED_BACK",
    ]) {
      expect(within(counts).getByText(status)).toBeInTheDocument();
    }
    // Exact figures, not rounded or bucketed.
    const pending = within(counts).getByText("PENDING_APPROVAL").closest("li") as HTMLElement;
    expect(within(pending).getByText("2")).toBeInTheDocument();
  });

  it("renders the pending-approval queue", async () => {
    mockFetch(routeWith());
    renderPage();

    const queue = await screen.findByLabelText("Awaiting approval");
    expect(within(queue).getByText("Awaiting approval (2)")).toBeInTheDocument();
    expect(within(queue).getByText("BLOCK_INDICATOR")).toBeInTheDocument();
    expect(within(queue).getByText("DISABLE_ACCOUNT")).toBeInTheDocument();
    expect(within(queue).getByText("IP:198.51.100.23")).toBeInTheDocument();
    expect(within(queue).getByText("ACCOUNT:chain-user")).toBeInTheDocument();
    // Both rows carry a requester and both state their evidence basis.
    expect(within(queue).getAllByText("analyst-1")).toHaveLength(2);
    expect(within(queue).getAllByText(/2 event\(s\)/)).toHaveLength(2);
  });

  it("renders the upcoming-expiration list with its timestamps and window", async () => {
    mockFetch(routeWith());
    renderPage();

    const panel = await screen.findByLabelText("Expiring soon");
    expect(within(panel).getByText("Expiring within 72 hours (1)")).toBeInTheDocument();
    // The warning window is described, and it is described as a warning.
    expect(within(panel).getByText(/never extends, shortens, or otherwise changes/i)).toBeInTheDocument();
    // Expiry timestamps are rendered.
    expect(within(panel).getByText(/2026/)).toBeInTheDocument();
    expect(within(panel).getByText("APPROVED")).toBeInTheDocument();
  });

  it("reuses the server-reported warning window rather than a hardcoded one", async () => {
    mockFetch(routeWith(makeSummary({ expiry_warning_hours: 24 })));
    renderPage();

    const panel = await screen.findByLabelText("Expiring soon");
    expect(within(panel).getByText("Expiring within 24 hours (1)")).toBeInTheDocument();
    expect(screen.queryByText(/Expiring within 72 hours/)).toBeNull();
  });

  // -- 2. Read-only ----------------------------------------------------------

  it("uses GET requests only", async () => {
    mockFetch(routeWith());
    renderPage();
    await screen.findByLabelText("Controlled response counts");

    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every((entry) => entry.startsWith("GET "))).toBe(true);
    expect(
      calls.some((entry) => entry.includes("/api/v1/responses/summary")),
    ).toBe(true);
  });

  it("offers no approval, execution, rollback, or creation control", async () => {
    mockFetch(routeWith());
    renderPage();
    await screen.findByLabelText("Controlled response counts");

    const page = screen.getByRole("region", { name: "Response center" });
    for (const label of [
      /^Approve$/i,
      /^Reject$/i,
      /^Cancel$/i,
      /^Execute/i,
      /^Roll back$/i,
      /^Propose/i,
      /^Request/i,
      /^Preview/i,
      /^Dry run$/i,
    ]) {
      expect(within(page).queryByRole("button", { name: label })).toBeNull();
    }
    // A retry control only appears in the error state, never on success.
    expect(within(page).queryByRole("button", { name: "Retry" })).toBeNull();
  });

  it("links to /response for every interaction that needs a decision", async () => {
    mockFetch(routeWith());
    renderPage();
    await screen.findByLabelText("Controlled response counts");

    const links = screen.getAllByRole("link", { name: "Response" });
    expect(links.length).toBeGreaterThan(0);
    for (const link of links) {
      expect(link).toHaveAttribute("href", "/response");
    }
  });

  it("never calls a mutating response endpoint after render", async () => {
    mockFetch(routeWith());
    renderPage();
    await screen.findByLabelText("Controlled response counts");

    for (const forbidden of [
      "/approve",
      "/reject",
      "/cancel",
      "/execute",
      "/rollback",
      "/controlled",
      "/dry-run",
      "/provider-preview",
      "/preview",
    ]) {
      expect(calls.some((entry) => entry.includes(forbidden))).toBe(false);
    }
  });

  // -- 5-6. States -----------------------------------------------------------

  it("shows the loading state before data resolves", async () => {
    mockFetch(routeWith());
    renderPage();
    expect(screen.getByText("Loading response center…")).toBeInTheDocument();
    await screen.findByLabelText("Controlled response counts");
  });

  it("shows honest empty states", async () => {
    mockFetch(
      routeWith(
        makeSummary({
          counts: {},
          pending_approval: [],
          expiring_soon: [],
          total: 0,
        }),
      ),
    );
    renderPage();

    expect(await screen.findByText("Nothing to show here.")).toBeInTheDocument();
    expect(
      screen.getByText("No controlled action expires within 72 hours."),
    ).toBeInTheDocument();
    expect(screen.getByText("Controlled responses (0)")).toBeInTheDocument();
  });

  it("shows a distinct denied state without a retry control", async () => {
    mockFetch(routeWith(fail("PERMISSION_DENIED", 403)));
    renderPage();

    await waitFor(() =>
      expect(screen.getByText("Response center restricted")).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: "Retry" })).toBeNull();
  });

  it("shows an error state that recovers through Retry", async () => {
    let broken = true;
    const flaky: Handler = (url) => {
      if (broken && url.includes("/api/v1/responses/summary")) {
        return fail("INTERNAL_ERROR", 500);
      }
      return {};
    };
    mockFetch(flaky);
    renderPage();

    await waitFor(() =>
      expect(screen.getByText("Response center unavailable")).toBeInTheDocument(),
    );
    const retry = screen.getByRole("button", { name: "Retry" });

    broken = false;
    mockFetch(routeWith());
    fireEvent.click(retry);

    expect(await screen.findByLabelText("Controlled response counts")).toBeInTheDocument();
  });

  it("discloses bounded output when the server reports truncation", async () => {
    mockFetch(routeWith(makeSummary({ truncated: true, limit: 2 })));
    renderPage();

    const notice = await screen.findByLabelText("Response center notice");
    expect(within(notice).getByText("Results are incomplete")).toBeInTheDocument();
    // The aggregate is still described as complete; only the lists are not.
    expect(within(notice).getByText(/counts above are\s+complete/)).toBeInTheDocument();
  });

  // -- 7-8. Honesty ----------------------------------------------------------

  it("labels every controlled row as a platform record, not an external change", async () => {
    mockFetch(routeWith());
    renderPage();
    await screen.findByLabelText("Controlled response counts");

    const page = screen.getByRole("region", { name: "Response center" });
    const notices = within(page).getAllByText(
      "MOCK PROVIDER — PLATFORM RECORD ONLY, NO EXTERNAL SYSTEM CHANGED",
    );
    // Counts, pending queue and expiry list each carry the notice.
    expect(notices.length).toBeGreaterThanOrEqual(3);
    // And it is never claimed that a real integration performed anything.
    expect(within(page).queryByText(/Microsoft Defender/)).toBeNull();
    expect(within(page).queryByText(/firewall was contacted/i)).toBeNull();
  });

  it("states that legacy dry-run proposals are excluded", async () => {
    mockFetch(routeWith());
    renderPage();
    await screen.findByLabelText("Controlled response counts");
    expect(screen.getByText(/Legacy dry-run proposals/)).toBeInTheDocument();
  });

  // -- 9. Navigation ---------------------------------------------------------

  it("adds the Response Center route and sidebar entry", async () => {
    render(
      <MemoryRouter>
        <Sidebar />
      </MemoryRouter>,
    );
    const link = screen.getByRole("link", { name: "Response Center" });
    expect(link).toHaveAttribute("href", "/response-center");
    // The existing Response entry is untouched by the addition.
    expect(screen.getByRole("link", { name: "Response" })).toHaveAttribute("href", "/response");
  });

  it("renders at /response-center and keeps /response reachable", () => {
    mockFetch(routeWith());
    renderPage("/response-center");
    expect(screen.getByRole("region", { name: "Response center" })).toBeInTheDocument();
  });
});
