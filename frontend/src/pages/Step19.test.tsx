import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Response } from "./Response";

const PROPOSAL = {
  id: "resp-1",
  incident_id: "inc-1",
  action_type: "BLOCK_IP",
  target_type: "IP",
  target_reference: "203.0.113.9",
  reason: "Repeat offender observed in correlated activity.",
  requested_by: "analyst-1",
  status: "DRY_RUN_COMPLETED",
  dry_run: true,
  policy_version: "1.0.0",
  execution_status: null,
  created_at: "2026-09-28T06:00:00",
  approved_at: "2026-09-28T06:01:00",
  expires_at: null,
  approved_by: "lead",
  started_at: null,
  completed_at: null,
  failure_reason: null,
  result_summary: null,
};

const PAGE = { items: [PROPOSAL], total: 1, limit: 100, offset: 0 };
const DETAIL = {
  ...PROPOSAL,
  audit: [
    {
      id: "a1",
      event: "ACTION_PROPOSED",
      previous_status: null,
      new_status: "PROPOSED",
      actor: "analyst-1",
      policy_version: "1.0.0",
      created_at: "2026-09-28T06:00:00",
    },
  ],
  execution: null,
};
const PREVIEW = {
  action_id: "resp-1",
  incident_id: "inc-1",
  adapter_type: "FIREWALL_SIMULATION",
  accepted: true,
  executed: false,
  simulated: true,
  would_execute: true,
  status: "SIMULATED",
  result_summary:
    "A firewall rule change would be previewed here in a future stage. Simulation completed; no external system was modified.",
  evidence: [],
  policy_decision: "ALLOW_SIMULATION",
  policy_version: "1.0.0",
};

// Step 42A: the workspace loads audit history from the read-only v2 feed.
const AUDIT_PAGE = {
  action_id: "resp-1",
  incident_id: "inc-1",
  entries: DETAIL.audit,
  total: DETAIL.audit.length,
  limit: 50,
  offset: 0,
  truncated: false,
};

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => ({
      ok: true,
      status: 200,
      json: async () => handler(String(url), init),
    }),
  );
}

function route(url: string): unknown {
  if (url.endsWith("/preview")) return PREVIEW;
  if (url.includes("/api/v2/responses/resp-1/audit")) return AUDIT_PAGE;
  if (url.includes("/api/v1/responses/resp-1")) return DETAIL;
  return PAGE;
}

describe("Response adapters (Step 19)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("shows the simulation-only badge and adapter preview flow", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      return route(url);
    });
    render(
      <MemoryRouter>
        <Response />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("Preview Response")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Preview Response"));
    await waitFor(() =>
      expect(
        screen.getByText("SIMULATION ONLY — NO EXTERNAL SYSTEM MODIFIED"),
      ).toBeInTheDocument(),
    );
    expect(screen.getByText(/FIREWALL_SIMULATION/)).toBeInTheDocument();
    expect(screen.getByText(/would_execute: true/)).toBeInTheDocument();
    expect(screen.getByText(/no external system was modified/)).toBeInTheDocument();
    expect(
      seen.some((entry) => entry.startsWith("POST") && entry.endsWith("/preview")),
    ).toBe(true);
  });

  it("renders audit history and never claims neutralized threats", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Response />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("ACTION_PROPOSED")).toBeInTheDocument());
    expect(screen.getByText("analyst-1")).toBeInTheDocument();
    expect(screen.queryByText("Threat neutralized")).toBeNull();
    expect(screen.queryByText("Block IP")).toBeNull();
    expect(screen.queryByText("Isolate Host")).toBeNull();
    expect(screen.queryByText("Kill Process")).toBeNull();
    expect(screen.queryByText("Disable Account")).toBeNull();
  });

  it("reports preview refusal honestly", async () => {
    mockFetch((url) => {
      if (url.endsWith("/preview")) {
        throw new Error("forbidden");
      }
      return route(url);
    });
    render(
      <MemoryRouter>
        <Response />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("Preview Response")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Preview Response"));
    await waitFor(() =>
      expect(screen.getByText("Adapter preview was refused by policy.")).toBeInTheDocument(),
    );
  });
});
