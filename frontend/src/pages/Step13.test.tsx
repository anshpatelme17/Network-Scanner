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
      status: "DRY_RUN_COMPLETED",
      dry_run: true,
      policy_version: "1.0.0",
      execution_status: null,
      created_at: "2026-09-27T06:00:00",
      approved_at: null,
      expires_at: null,
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

const DETAIL_NO_AUDIT = { ...PROPOSAL_PAGE.items[0], audit: [], execution: null };

const EXECUTED_DETAIL = {
  ...PROPOSAL_PAGE.items[0],
  status: "READY_FOR_EXECUTION",
  execution_status: "SIMULATED",
  audit: [
    {
      id: "audit-3",
      event: "EXECUTION_COMPLETED",
      previous_status: "DRY_RUN_COMPLETED",
      new_status: "READY_FOR_EXECUTION",
      actor: "operator",
      policy_version: "1.0.0",
      created_at: "2026-09-27T06:02:00",
    },
  ],
  execution: {
    id: "exec-1",
    action_id: "resp-1",
    incident_id: "inc-1",
    adapter: "simulation",
    dry_run: true,
    would_execute: false,
    result: "SIMULATED",
    explanation: "Action would request blocking the specified IP. No real action was executed.",
    policy_version: "1.0.0",
    simulated_at: "2026-09-27T06:02:00",
  },
};

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: unknown, init?: RequestInit) => ({
    ok: true,
    status: 200,
    json: () => Promise.resolve(handler(String(url), init)),
  }));
}

describe("Response execution UI (Step 13 simulation only)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("shows the Execute Simulation control only for previewed proposals", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/responses/resp-1")) return DETAIL_NO_AUDIT;
      return PROPOSAL_PAGE;
    });
    render(
      <MemoryRouter>
        <Response />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("Execute Simulation")).toBeInTheDocument());
    expect(screen.queryByText("Execute", { exact: true })).toBeNull();
  });

  it("runs the simulation and displays the non-execution record", async () => {
    const seen: string[] = [];
    let executed = false;
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      if (url.includes("/execute")) {
        executed = true;
        return EXECUTED_DETAIL.execution;
      }
      if (url.includes("/api/v1/responses/resp-1")) {
        return executed ? EXECUTED_DETAIL : { ...EXECUTED_DETAIL, status: "DRY_RUN_COMPLETED", execution: null };
      }
      return PROPOSAL_PAGE;
    });
    render(
      <MemoryRouter>
        <Response />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("Execute Simulation")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Execute Simulation"));
    await waitFor(() =>
      expect(
        seen.some((entry) => entry.startsWith("POST") && entry.includes("/execute")),
      ).toBe(true),
    );
    await waitFor(() => expect(screen.getByText("Simulation execution record")).toBeInTheDocument());
    expect(screen.getAllByText("SIMULATION ONLY — NO REAL ACTION EXECUTED").length).toBeGreaterThanOrEqual(1);
    expect(screen.queryByText("Firewall updated")).toBeNull();
    expect(screen.queryByText("Blocked")).toBeNull();
  });
});
