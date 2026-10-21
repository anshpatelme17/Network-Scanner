import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Vulnerabilities } from "./Vulnerabilities";

const ITEM = {
  id: "vuln-1",
  asset_id: "asset-1",
  service_id: "svc-1",
  scanner: "nmap-vuln",
  scanner_version: "nmap 7.94",
  scanner_finding_id: "http-vuln-test:80/tcp",
  title: "[nmap] http-vuln-test on port 80/tcp",
  severity: "UNKNOWN",
  cvss_score: null,
  cve_id: "CVE-2014-6271",
  hostname: "test-host",
  destination_ip: "127.0.0.1",
  destination_port: 80,
  status: "OPEN",
  first_seen: "2026-09-28T06:00:00",
  last_seen: "2026-09-28T06:10:00",
};

const DETAIL = {
  ...ITEM,
  description: "Nmap NSE script reported CVE identifier(s).",
  cwe_id: null,
  affected_component: "TestHTTP",
  detected_version: "1.0",
  fixed_version: null,
  evidence: "VULNERABLE:\n  CVE-2014-6271",
  remediation_reference: null,
  extra_data: { cves: ["CVE-2014-6271"], references: [], extra: {}, scanner_severity: "UNKNOWN" },
  created_at: "2026-09-28T06:00:00",
  updated_at: "2026-09-28T06:10:00",
  audit: [
    {
      event: "VULNERABILITY_OPENED",
      actor: "operator",
      previous_status: null,
      new_status: "OPEN",
      created_at: "2026-09-28T06:00:00",
      detail: null,
    },
  ],
};

const PAGE = { items: [ITEM], total: 1, limit: 100, offset: 0 };
const JOB = {
  id: "job-1",
  target: "127.0.0.1",
  profile: "BASIC",
  scanner: "nmap-vuln",
  status: "queued",
  result_summary: null,
  error: null,
  completed_at: null,
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

function route(url: string, init?: RequestInit): unknown {
  const method = init?.method ?? "GET";
  if (url.endsWith("/vulnerability-scans") && method === "POST") return JOB;
  if (url.includes("/risk") || url.includes("/correlations")) {
    throw new Error("not scored");
  }
  if (url.includes("/api/v1/vulnerabilities/vuln-1")) return DETAIL;
  return PAGE;
}

function auditEntry(index: number) {
  return {
    event: `AUDIT_ENTRY_${index}`,
    actor: "operator",
    previous_status: null,
    new_status: "OPEN",
    created_at: "2026-09-28T06:00:00",
    detail: null,
  };
}

function pagedHandler(total: number) {
  let status = "OPEN";
  const seen: string[] = [];
  const handler = (url: string, init?: RequestInit): unknown => {
    const method = init?.method ?? "GET";
    seen.push(`${method} ${url}`);
    if (method === "POST" && url.endsWith("/status")) {
      const finding: Record<string, unknown> = { ...DETAIL };
      delete finding.audit;
      delete finding.audit_total;
      delete finding.audit_limit;
      delete finding.audit_offset;
      delete finding.audit_truncated;
      status = "RESOLVED";
      return { ...finding, status };
    }
    if (url.includes("/risk") || url.includes("/correlations")) {
      throw new Error("not scored");
    }
    if (url.includes("/api/v1/vulnerabilities/vuln-1")) {
      const params = new URL(url, "http://localhost").searchParams;
      const offset = Number(params.get("offset") ?? "0");
      const limit = Number(params.get("limit") ?? "50");
      const all = Array.from({ length: total }, (_, index) => auditEntry(index));
      return {
        ...DETAIL,
        status,
        audit: all.slice(offset, offset + limit),
        audit_total: total,
        audit_limit: limit,
        audit_offset: offset,
        audit_truncated: offset + limit < total,
      };
    }
    return PAGE;
  };
  return { handler, seen };
}

async function openFirstFinding() {
  render(
    <MemoryRouter>
      <Vulnerabilities />
    </MemoryRouter>,
  );
  await waitFor(() => expect(screen.getByText("Details")).toBeInTheDocument());
  fireEvent.click(screen.getByText("Details"));
  await waitFor(() =>
    expect(screen.getByRole("heading", { name: /Audit history/ })).toBeInTheDocument(),
  );
}

describe("Vulnerabilities assessment flow (Step 22)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("starts an assessment with a fixed profile and reports the job", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url} ${String(init?.body ?? "")}`);
      return route(url, init);
    });
    render(
      <MemoryRouter>
        <Vulnerabilities />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByLabelText("Assessment profile")).toBeInTheDocument());
    const options = Array.from(
      (screen.getByLabelText("Assessment profile") as HTMLSelectElement).options,
    ).map((option) => option.value);
    expect(options).toContain("BASIC");
    expect(options).toContain("STANDARD");
    fireEvent.change(screen.getByLabelText("Assessment target"), { target: { value: "127.0.0.1" } });
    fireEvent.change(screen.getByLabelText("Assessment profile"), { target: { value: "BASIC" } });
    fireEvent.click(screen.getByText("Start assessment"));
    await waitFor(() => expect(screen.getByText(/queued for 127.0.0.1/)).toBeInTheDocument());
    const posted = seen.find((entry) => entry.includes("/vulnerability-scans"));
    expect(posted).toContain('"profile":"BASIC"');
    expect(posted).not.toContain("command");
    expect(posted).not.toContain("--script");
  });

  it("distinguishes LIVE from MOCK results and shows versions", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Vulnerabilities />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Details")).toBeInTheDocument());
    expect(screen.getAllByText("LIVE result").length).toBeGreaterThanOrEqual(1);
    fireEvent.click(screen.getByText("Details"));
    await waitFor(() => expect(screen.getByText(/nmap 7.94/)).toBeInTheDocument());
    expect(screen.getByText(/detected version: 1.0/)).toBeInTheDocument();
    expect(screen.getByText(/fixed version: —/)).toBeInTheDocument();
    expect(screen.getByText(/not proof of exploitation/)).toBeInTheDocument();
  });

  it("exposes no scanner command inputs", async () => {
    mockFetch(route);
    render(
      <MemoryRouter>
        <Vulnerabilities />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Start assessment")).toBeInTheDocument());
    expect(screen.queryByLabelText(/command/i)).toBeNull();
    expect(screen.queryByLabelText(/flag/i)).toBeNull();
    expect(screen.queryByLabelText(/script/i)).toBeNull();
  });

  it("reports the visible and total audit counts when metadata is present", async () => {
    mockFetch((url) => {
      if (url.includes("/risk") || url.includes("/correlations")) {
        throw new Error("not scored");
      }
      if (url.includes("/api/v1/vulnerabilities/vuln-1")) {
        return {
          ...DETAIL,
          audit: [0, 1, 2].map(auditEntry),
          audit_total: 3,
          audit_limit: 50,
          audit_offset: 0,
          audit_truncated: false,
        };
      }
      return PAGE;
    });

    await openFirstFinding();

    expect(screen.getByRole("heading", { name: "Audit history (3 of 3)" })).toBeInTheDocument();
    expect(screen.queryByText(/Showing 3 of 3 audit entries/)).toBeNull();
    expect(screen.queryByLabelText("Previous audit page")).toBeNull();
    expect(screen.queryByLabelText("Next audit page")).toBeNull();
  });

  it("pages audit history with bounded offsets and boundary states", async () => {
    const { handler, seen } = pagedHandler(205);
    mockFetch(handler);

    await openFirstFinding();

    expect(screen.getByRole("heading", { name: "Audit history (50 of 205)" })).toBeInTheDocument();
    expect(screen.getByText(/Showing 50 of 205 audit entries/)).toBeInTheDocument();
    expect(screen.getByText("AUDIT_ENTRY_0")).toBeInTheDocument();
    expect(screen.getByLabelText("Previous audit page")).toBeDisabled();
    expect(screen.getByLabelText("Next audit page")).toBeEnabled();

    fireEvent.click(screen.getByLabelText("Next audit page"));
    await waitFor(() => expect(screen.getByText("AUDIT_ENTRY_50")).toBeInTheDocument());
    expect(screen.getByRole("heading", { name: "Audit history (50 of 205)" })).toBeInTheDocument();
    expect(screen.getByText(/Showing 50 of 205 audit entries/)).toBeInTheDocument();
    expect(screen.getByText(/More entries exist beyond this page/)).toBeInTheDocument();
    expect(screen.getByLabelText("Previous audit page")).toBeEnabled();
    expect(screen.getByLabelText("Next audit page")).toBeEnabled();

    fireEvent.click(screen.getByLabelText("Next audit page"));
    await waitFor(() => expect(screen.getByText("AUDIT_ENTRY_100")).toBeInTheDocument());
    fireEvent.click(screen.getByLabelText("Next audit page"));
    await waitFor(() => expect(screen.getByText("AUDIT_ENTRY_150")).toBeInTheDocument());
    fireEvent.click(screen.getByLabelText("Next audit page"));
    await waitFor(() => expect(screen.getByText("AUDIT_ENTRY_200")).toBeInTheDocument());

    expect(screen.getByRole("heading", { name: "Audit history (5 of 205)" })).toBeInTheDocument();
    expect(screen.getAllByText(/^AUDIT_ENTRY_/)).toHaveLength(5);
    expect(screen.queryByText(/More entries exist beyond this page/)).toBeNull();
    expect(screen.getByLabelText("Previous audit page")).toBeEnabled();
    expect(screen.getByLabelText("Next audit page")).toBeDisabled();

    const detailCalls = seen.filter(
      (entry) => entry.startsWith("GET ") && entry.includes("/api/v1/vulnerabilities/vuln-1?"),
    );
    expect(
      detailCalls.some((entry) => entry.includes("limit=50") && entry.includes("offset=0")),
    ).toBe(true);
    expect(detailCalls.some((entry) => entry.includes("offset=50"))).toBe(true);
    expect(detailCalls.some((entry) => entry.includes("offset=200"))).toBe(true);
  });

  it("keeps legacy audit payloads without metadata working", async () => {
    mockFetch((url) => {
      if (url.includes("/risk") || url.includes("/correlations")) {
        throw new Error("not scored");
      }
      return url.includes("/api/v1/vulnerabilities/vuln-1") ? DETAIL : PAGE;
    });

    await openFirstFinding();

    expect(screen.getByRole("heading", { name: "Audit history (1)" })).toBeInTheDocument();
    expect(screen.getByText("VULNERABILITY_OPENED")).toBeInTheDocument();
    expect(screen.queryByLabelText("Previous audit page")).toBeNull();
    expect(screen.queryByLabelText("Next audit page")).toBeNull();
  });

  it("clears the audit loading state before risk and correlation requests finish", async () => {
    let resolveRisk!: (value: unknown) => void;
    let resolveLinks!: (value: unknown) => void;
    const riskResponse = new Promise<unknown>((resolve) => {
      resolveRisk = resolve;
    });
    const linksResponse = new Promise<unknown>((resolve) => {
      resolveLinks = resolve;
    });

    mockFetch((url) => {
      if (url.includes("/risk")) return riskResponse;
      if (url.includes("/correlations")) return linksResponse;
      if (url.includes("/api/v1/vulnerabilities/vuln-1")) {
        return {
          ...DETAIL,
          audit_total: 1,
          audit_limit: 50,
          audit_offset: 0,
          audit_truncated: false,
        };
      }
      return PAGE;
    });

    await openFirstFinding();

    expect(screen.getByText("VULNERABILITY_OPENED")).toBeInTheDocument();
    expect(screen.queryByText(/Loading audit page/)).toBeNull();

    await act(async () => {
      resolveRisk({
        id: "risk-1",
        entity_type: "vuln_finding",
        entity_id: "vuln-1",
        score: 40,
        severity: "MEDIUM",
        factors: {},
        explanation: "Risk score 40 (MEDIUM).",
        calculated_at: "2026-09-27T02:00:00",
        scoring_version: "1.0.0",
      });
      resolveLinks({
        vulnerability_id: "vuln-1",
        asset_id: "asset-1",
        service_id: "svc-1",
        related_events: [],
        related_incidents: [],
        reasons: [],
      });
    });

    await waitFor(() => expect(screen.getByText("40 (MEDIUM)")).toBeInTheDocument());
  });

  it("preserves the audit page and metadata after a status change", async () => {
    const { handler, seen } = pagedHandler(120);
    mockFetch(handler);

    await openFirstFinding();
    fireEvent.click(screen.getByLabelText("Next audit page"));
    await waitFor(() => expect(screen.getByText("AUDIT_ENTRY_50")).toBeInTheDocument());

    fireEvent.click(screen.getByText("Mark Resolved"));

    await waitFor(() =>
      expect(screen.getByRole("heading", { name: "Audit history (50 of 120)" })).toBeInTheDocument(),
    );
    expect(screen.getByText("AUDIT_ENTRY_50")).toBeInTheDocument();
    expect(screen.getByText(/Showing 50 of 120 audit entries/)).toBeInTheDocument();
    expect(screen.getByLabelText("Next audit page")).toBeEnabled();

    await waitFor(() => {
      const detailCalls = seen.filter(
        (entry) => entry.startsWith("GET ") && entry.includes("/api/v1/vulnerabilities/vuln-1?"),
      );
      expect(detailCalls.filter((entry) => entry.includes("offset=50")).length).toBeGreaterThanOrEqual(
        2,
      );
    });
    expect(seen.some((entry) => entry.startsWith("POST ") && entry.includes("/status"))).toBe(true);
  });

  it("disables audit paging while a status change is pending", async () => {
    const { handler, seen } = pagedHandler(120);
    let releaseStatus!: () => void;
    const statusGate = new Promise<void>((resolve) => {
      releaseStatus = resolve;
    });
    mockFetch(async (url, init) => {
      if ((init?.method ?? "GET") === "POST" && url.endsWith("/status")) {
        await statusGate;
      }
      return handler(url, init);
    });

    await openFirstFinding();
    fireEvent.click(screen.getByLabelText("Next audit page"));
    await waitFor(() => expect(screen.getByText("AUDIT_ENTRY_50")).toBeInTheDocument());
    expect(screen.getByText("Mark Resolved")).toBeEnabled();

    fireEvent.click(screen.getByText("Mark Resolved"));

    await waitFor(() => expect(screen.getByLabelText("Next audit page")).toBeDisabled());
    expect(screen.getByLabelText("Previous audit page")).toBeDisabled();
    expect(screen.getByText("Mark Resolved")).toBeDisabled();

    await act(async () => {
      releaseStatus();
    });

    await waitFor(() => expect(screen.getByLabelText("Next audit page")).toBeEnabled());
    expect(screen.getByLabelText("Previous audit page")).toBeEnabled();
    expect(screen.getByText("AUDIT_ENTRY_50")).toBeInTheDocument();
    expect(seen.some((entry) => entry.startsWith("POST ") && entry.includes("/status"))).toBe(true);
  });
});
