import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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
});
