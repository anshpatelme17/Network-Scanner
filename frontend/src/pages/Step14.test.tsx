import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Assets } from "./Assets";
import { Network } from "./Network";

const ASSET_PAGE = {
  items: [
    {
      id: "asset-1",
      ip_address: "127.0.0.1",
      hostname: "localhost",
      mac_address: null,
      operating_system: null,
      state: "up",
      asset_type: "UNKNOWN",
      discovery_source: "nmap",
      service_count: 1,
      first_seen: "2026-09-27T00:00:00",
      last_seen: "2026-09-27T01:00:00",
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

const SCANS = [
  {
    id: "scan-1",
    target: "127.0.0.1",
    profile: "quick",
    scan_type: "nmap",
    requested_by: "tester-1",
    status: "queued",
    created_at: "2026-09-27T00:00:00",
    started_at: null,
    completed_at: null,
    error: null,
    assets_found: 0,
    services_found: 0,
    result_summary: null,
    nmap_version: null,
    audit: [{ event: "SCAN_REQUESTED", actor: "tester-1", detail: null, created_at: "2026-09-27T00:00:00" }],
  },
];

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: unknown, init?: RequestInit) => ({
    ok: true,
    status: 200,
    json: () => Promise.resolve(handler(String(url), init)),
  }));
}

describe("Step 14 hardening UI", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("Assets table shows type and discovery source", async () => {
    mockFetch((url) => (url.includes("/api/v1/assets") ? ASSET_PAGE : {}));
    render(
      <MemoryRouter>
        <Assets />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("127.0.0.1")).toBeInTheDocument());
    expect(screen.getByText("UNKNOWN")).toBeInTheDocument();
    expect(screen.getByText("nmap")).toBeInTheDocument();
  });

  it("Network page states the authorization scope and offers cancel for queued scans", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      if (url.includes("/network/scans")) return SCANS;
      return { available: true, version: "7.95", profiles: ["quick", "standard"] };
    });
    render(
      <MemoryRouter>
        <Network />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("tester-1")).toBeInTheDocument());
    expect(
      screen.getByText(/inside the[\s\S]*server-configured authorization scope/),
    ).toBeInTheDocument();
    expect(screen.getByLabelText("Requested by")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Cancel"));
    await waitFor(() =>
      expect(seen.some((entry) => entry.startsWith("POST") && entry.includes("/cancel"))).toBe(true),
    );
  });
});
