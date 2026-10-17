import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Response } from "./Response";

const PROPOSAL_PAGE = {
  items: [
    {
      id: "resp-1",
      incident_id: "inc-1",
      action_type: "BLOCK_IP",
      target_type: "IP",
      target_reference: "203.0.113.9",
      reason: "Repeat offender.",
      requested_by: "analyst-1",
      status: "PROPOSED",
      dry_run: true,
      policy_version: "1.0.0",
      created_at: "2026-09-27T06:00:00",
      approved_at: null,
      expires_at: null,
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

const PROPOSAL_DETAIL = {
  ...PROPOSAL_PAGE.items[0],
  execution_status: null,
  audit: [
    {
      id: "audit-1",
      event: "ACTION_PROPOSED",
      previous_status: null,
      new_status: "PROPOSED",
      actor: "analyst-1",
      policy_version: "1.0.0",
      created_at: "2026-09-27T06:00:00",
    },
  ],
  execution: null,
};

const DRY_RUN = {
  action_id: "resp-1",
  action_type: "BLOCK_IP",
  target: "IP:203.0.113.9",
  dry_run: true,
  would_execute: false,
  result: "SIMULATED",
  explanation: "Action would request blocking the specified IP. No action was executed.",
  policy_version: "1.0.0",
};

// Step 42A: the workspace now loads audit history from the read-only v2 feed.
const AUDIT_PAGE = {
  action_id: "resp-1",
  incident_id: "inc-1",
  entries: PROPOSAL_DETAIL.audit,
  total: PROPOSAL_DETAIL.audit.length,
  limit: 50,
  offset: 0,
  truncated: false,
};

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => ({
      ok: true,
      status: 200,
      json: () => Promise.resolve(handler(String(url), init)),
    }),
  );
}

describe("Response page (Step 12 dry-run foundation)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders proposals with dry-run banner and statuses", async () => {
    mockFetch(() => PROPOSAL_PAGE);
    render(
      <MemoryRouter>
        <Response />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("BLOCK_IP")).toBeInTheDocument());
    expect(screen.getAllByText("DRY RUN — NO ACTION EXECUTED").length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText("PROPOSED").length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText("Execute")).toBeNull();
    expect(screen.queryByText("Block now")).toBeNull();
  });

  it("shows an honest empty state when no proposals exist", async () => {
    mockFetch(() => ({ items: [], total: 0, limit: 50, offset: 0 }));
    render(
      <MemoryRouter>
        <Response />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("No response proposals.")).toBeInTheDocument(),
    );
  });

  it("opens detail with audit history and dry-run preview", async () => {
    mockFetch((url) => {
      if (url.includes("/dry-run")) return DRY_RUN;
      if (url.includes("/api/v2/responses/resp-1/audit")) return AUDIT_PAGE;
      if (url.includes("/api/v1/responses/resp-1")) return PROPOSAL_DETAIL;
      return PROPOSAL_PAGE;
    });
    render(
      <MemoryRouter>
        <Response />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("ACTION_PROPOSED")).toBeInTheDocument());
    expect(screen.getByText("analyst-1")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Dry Run"));
    await waitFor(() => expect(screen.getByText("Dry-run preview")).toBeInTheDocument());
    expect(screen.getByText(/No action was executed/)).toBeInTheDocument();
  });

  it("sends approve decisions and filters by status", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      if (url.includes("/approve")) return { ...PROPOSAL_DETAIL, status: "APPROVED" };
      if (url.includes("/api/v1/responses/resp-1")) return PROPOSAL_DETAIL;
      return PROPOSAL_PAGE;
    });
    render(
      <MemoryRouter>
        <Response />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("Approve")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Approve"));
    await waitFor(() =>
      expect(seen.some((entry) => entry.startsWith("POST") && entry.includes("/approve"))).toBe(true),
    );
    fireEvent.change(screen.getByLabelText("Filter by status"), {
      target: { value: "APPROVED" },
    });
    await waitFor(() =>
      expect(seen.some((url) => url.includes("status=APPROVED"))).toBe(true),
    );
  });
});
