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
      operating_system: "Linux 6.X",
      state: "up",
      service_count: 1,
      first_seen: "2026-09-27T00:00:00",
      last_seen: "2026-09-27T01:00:00",
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

const ASSET_DETAIL = {
  ...ASSET_PAGE.items[0],
  services: [
    {
      id: "svc-1",
      port: 8000,
      protocol: "tcp",
      state: "open",
      service_name: "http",
      product: "TestServer",
      version: "1.0",
      extra_info: null,
      discovered_at: "2026-09-27T00:00:00",
      last_seen: "2026-09-27T01:00:00",
    },
  ],
};

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: unknown, init?: RequestInit) => ({
    ok: true,
    status: 200,
    json: async () => handler(String(url), init),
  }));
}

const API_ROUTES = (url: string) => {
  if (url.includes("/api/v1/assets/summary"))
    return { total_assets: 1, active_assets: 1, total_services: 1, last_scan_at: null, last_scan_status: "completed" };
  if (url.includes("/api/v1/assets/asset-1")) return ASSET_DETAIL;
  if (url.includes("/api/v1/assets")) return ASSET_PAGE;
  if (url.includes("/api/v1/network/nmap/status"))
    return { available: true, version: "7.94", profiles: ["quick", "standard"] };
  if (url.includes("/api/v1/network/scans"))
    return [
      {
        id: "scan-1",
        target: "127.0.0.1",
        profile: "quick",
        status: "completed",
        created_at: "2026-09-27T00:00:00",
        started_at: "2026-09-27T00:00:01",
        completed_at: "2026-09-27T00:01:00",
        error: null,
        assets_found: 1,
        services_found: 1,
        nmap_version: "7.94",
      },
    ];
  return { status: "ready", app: "x", version: "0.1.0", environment: "test", checks: { database: "up" } };
};

describe("Assets page (Step 2 inventory)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders the asset table from the API", async () => {
    mockFetch(API_ROUTES);
    render(
      <MemoryRouter>
        <Assets />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("127.0.0.1")).toBeInTheDocument());
    expect(screen.getByText("localhost")).toBeInTheDocument();
    expect(screen.getByText("Assets (1)")).toBeInTheDocument();
  });

  it("opens asset details with discovered services", async () => {
    mockFetch(API_ROUTES);
    render(
      <MemoryRouter>
        <Assets />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Details")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Details"));
    await waitFor(() => expect(screen.getByText("TestServer")).toBeInTheDocument());
    expect(screen.getByText("8000")).toBeInTheDocument();
  });
});

describe("Network page (Step 2 scans)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("shows Nmap availability and recent scans", async () => {
    mockFetch(API_ROUTES);
    render(
      <MemoryRouter>
        <Network />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Available")).toBeInTheDocument());
    expect(screen.getByText("Nmap 7.94")).toBeInTheDocument();
    // Recent scans table shows the completed job's target.
    await waitFor(() => expect(screen.getByText("completed")).toBeInTheDocument());
  });

  it("requires a target, authorization, and blocks empty submits", async () => {
    mockFetch(API_ROUTES);
    render(
      <MemoryRouter>
        <Network />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Start scan")).toBeInTheDocument());
    // Submit without ticking the authorization checkbox.
    fireEvent.click(screen.getByText("Start scan"));
    await waitFor(() =>
      expect(screen.getByText("Confirm you are authorized to scan this target.")).toBeInTheDocument(),
    );
    // Empty target is rejected client-side even with authorization ticked.
    fireEvent.click(screen.getByLabelText("Authorization confirmation"));
    fireEvent.change(screen.getByLabelText("Scan target"), { target: { value: "   " } });
    fireEvent.click(screen.getByText("Start scan"));
    await waitFor(() =>
      expect(screen.getByText("Enter a target IP address or CIDR network.")).toBeInTheDocument(),
    );
  });
});
