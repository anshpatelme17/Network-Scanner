import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Incidents } from "./Incidents";

const ITEM = {
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
  first_seen: "2026-09-28T06:00:00",
  last_seen: "2026-09-28T06:10:00",
  resolved_at: null,
  created_at: "2026-09-28T06:11:00",
  updated_at: "2026-09-28T06:11:00",
  version: "1.0.0",
  incident_type: "CORRELATED_SECURITY_EVENT",
  risk_score: null,
  detection_reason: "3 related events under rule 'repeated-source'.",
};

const PAGE = { items: [ITEM], total: 1, limit: 100, offset: 0 };
const DETAIL = { ...ITEM, evidence_event_ids: ["evt-1"] };

let proposals: Array<Record<string, unknown>>;

function resetProposals() {
  proposals = [
    {
      id: "resp-1",
      incident_id: "inc-1",
      action_type: "REVIEW",
      target_type: "INCIDENT",
      target_reference: "inc-1",
      reason: "take a look",
      requested_by: "analyst",
      status: "COMPLETED",
      dry_run: true,
      policy_version: "1.0.0",
      execution_status: "COMPLETED",
      created_at: "2026-09-28T06:12:00",
      approved_at: "2026-09-28T06:13:00",
      expires_at: null,
      approved_by: "lead",
      started_at: "2026-09-28T06:14:00",
      completed_at: "2026-09-28T06:14:01",
      failure_reason: null,
      result_summary: "Incident INC-AAA111BBB222 reviewed by lead. No external change.",
    },
  ];
}

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => ({
      ok: true,
      status: 200,
      json: async () => handler(String(url), init),
    }),
  );
}

function route(url: string, init?: RequestInit): unknown {
  const method = init?.method ?? "GET";
  // Return copies: the component (like React with real APIs) must see a
  // fresh array reference to re-render after mutations.
  const snapshot = () => ({
    items: proposals.map((item) => ({ ...item })),
    total: proposals.length,
    limit: 100,
    offset: 0,
  });
  if (url.includes("/incidents/inc-1/responses") && method === "GET") {
    return snapshot();
  }
  if (url.includes("/incidents/inc-1/responses") && method === "POST") {
    const body = JSON.parse(String(init?.body ?? "{}")) as Record<string, string>;
    const created = {
      id: `resp-${proposals.length + 1}`,
      incident_id: "inc-1",
      action_type: body.action_type,
      target_type: "INCIDENT",
      target_reference: "inc-1",
      reason: body.reason,
      requested_by: body.requested_by,
      status: "PROPOSED",
      dry_run: true,
      policy_version: "1.0.0",
      execution_status: null,
      created_at: "2026-09-28T07:00:00",
      approved_at: null,
      expires_at: null,
      approved_by: null,
      started_at: null,
      completed_at: null,
      failure_reason: null,
      result_summary: null,
    };
    proposals.push(created);
    return created;
  }
  const decision = ["/approve", "/reject", "/cancel"].find((suffix) => url.endsWith(suffix));
  if (decision && url.includes("/api/v1/responses/")) {
    const id = url.split("/api/v1/responses/")[1].split("/")[0];
    const row = proposals.find((item) => item.id === id);
    if (row) {
      row.status =
        decision === "/approve" ? "APPROVED" : decision === "/reject" ? "REJECTED" : "CANCELLED";
      if (decision === "/approve") row.approved_by = "lead";
      return { ...row };
    }
    return row;
  }
  if (url.endsWith("/execute") && method === "POST") {
    const id = url.split("/api/v1/responses/")[1].split("/")[0];
    const row = proposals.find((item) => item.id === id);
    if (row) {
      row.status = "COMPLETED";
      row.result_summary = "Incident INC-AAA111BBB222 reviewed. No external change.";
    }
    return {
      id: "exec-1",
      action_id: id,
      incident_id: "inc-1",
      adapter: "safe-record",
      dry_run: true,
      would_execute: true,
      result: "COMPLETED",
      explanation: "done",
      policy_version: "1.0.0",
      simulated_at: "2026-09-28T07:01:00",
    };
  }
  if (url.includes("/evidence") || url.includes("/timeline") || url.includes("/audit")) {
    return { incident_id: "inc-1", entries: [], events: [], vulnerabilities: [] };
  }
  if (url.includes("/api/v1/incidents/inc-1")) return DETAIL;
  return PAGE;
}

describe("Incident responses (Step 18)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    resetProposals();
  });

  it("lists responses with distinct statuses and offers safe actions only", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() =>
      expect(screen.getByText("Controlled responses (1)")).toBeInTheDocument(),
    );
    expect(screen.getByText("COMPLETED")).toBeInTheDocument();
    expect(screen.getByText(/No external change/)).toBeInTheDocument();
    expect(screen.queryByText("Threat neutralized")).toBeNull();
    const options = Array.from(
      (screen.getByLabelText("Response action type") as HTMLSelectElement).options,
    ).map((option) => option.value);
    expect(options).toEqual([
      "REVIEW",
      "COLLECT_EVIDENCE",
      "MARK_FOR_INVESTIGATION",
      "ACKNOWLEDGE",
      "CLOSE",
    ]);
    expect(options).not.toContain("BLOCK_IP");
  });

  it("proposes, approves and executes a safe action", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      return route(url, init);
    });
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() =>
      expect(screen.getByText("Controlled responses (1)")).toBeInTheDocument(),
    );
    fireEvent.change(screen.getByLabelText("Response reason"), {
      target: { value: "second look" },
    });
    fireEvent.click(screen.getByText("Propose response"));
    await waitFor(() =>
      expect(screen.getByText("Controlled responses (2)")).toBeInTheDocument(),
    );
    expect(
      seen.some((entry) => entry.startsWith("POST") && entry.includes("/inc-1/responses")),
    ).toBe(true);
    const approveButtons = screen.getAllByText("Approve");
    fireEvent.click(approveButtons[0]);
    await waitFor(() => expect(screen.getAllByText("APPROVED").length).toBeGreaterThanOrEqual(1));
    fireEvent.click(screen.getByText("Execute"));
    await waitFor(() =>
      expect(screen.getAllByText("COMPLETED").length).toBeGreaterThanOrEqual(2),
    );
  });

  it("shows failure reasons honestly", async () => {
    proposals = [];
    resetProposals();
    (proposals[0] as Record<string, unknown>).status = "FAILED";
    (proposals[0] as Record<string, unknown>).failure_reason =
      "Cannot move incident from ACKNOWLEDGED to ACKNOWLEDGED.";
    (proposals[0] as Record<string, unknown>).result_summary = null;
    mockFetch(route);
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Open")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Open"));
    await waitFor(() => expect(screen.getByText("FAILED")).toBeInTheDocument());
    expect(screen.getByText(/Cannot move incident/)).toBeInTheDocument();
  });
});
