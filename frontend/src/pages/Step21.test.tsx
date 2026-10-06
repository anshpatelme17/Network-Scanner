import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Network } from "./Network";

const PREVIEW = {
  target: "127.0.0.1",
  profile: "DISCOVERY_PING",
  profile_description: "Host discovery only: ping sweep, no port probing.",
  probes_ports: false,
  address_count: 1,
  scope_authorized: true,
  nmap_available: true,
  timeout_seconds: 120,
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

describe("Network discovery (Step 21)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("offers discovery profiles and previews without scanning", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      if (url.includes("/scans/preview")) return PREVIEW;
      if (url.includes("nmap/status")) {
        return { available: true, version: "7.94", profiles: ["DISCOVERY_PING"] };
      }
      return [];
    });
    render(
      <MemoryRouter>
        <Network />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByLabelText("Scan profile")).toBeInTheDocument());
    const options = Array.from(
      (screen.getByLabelText("Scan profile") as HTMLSelectElement).options,
    ).map((option) => option.value);
    expect(options).toContain("DISCOVERY_PING");
    expect(options).toContain("DISCOVERY_TCP_COMMON");
    fireEvent.change(screen.getByLabelText("Scan profile"), { target: { value: "DISCOVERY_PING" } });
    fireEvent.click(screen.getByText("Preview discovery"));
    await waitFor(() =>
      expect(screen.getByText("Discovery preview — no scan performed")).toBeInTheDocument(),
    );
    expect(screen.getByText(/Host discovery only/)).toBeInTheDocument();
    expect(screen.getByText(/probes ports: false/)).toBeInTheDocument();
    expect(screen.getByText(/does not mean the target is safe/)).toBeInTheDocument();
    expect(
      seen.some((entry) => entry.startsWith("POST") && entry.includes("/scans/preview")),
    ).toBe(true);
    // No scan job was created by the preview.
    expect(seen.some((entry) => entry.includes("/api/v1/network/scans") && !entry.includes("preview") && entry.startsWith("POST"))).toBe(false);
  });

  it("requires authorization confirmation and surfaces validation errors", async () => {
    mockFetch((url) => {
      if (url.includes("nmap/status")) return { available: true, version: "7.94", profiles: [] };
      return [];
    });
    render(
      <MemoryRouter>
        <Network />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Start scan")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Start scan"));
    await waitFor(() =>
      expect(screen.getByText("Confirm you are authorized to scan this target.")).toBeInTheDocument(),
    );
    expect(screen.queryByText("Discovery preview — no scan performed")).toBeNull();
  });

  it("exposes no command or flag inputs", async () => {
    mockFetch((url) => {
      if (url.includes("nmap/status")) return { available: true, version: "7.94", profiles: [] };
      return [];
    });
    render(
      <MemoryRouter>
        <Network />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("New authorized scan")).toBeInTheDocument());
    expect(screen.queryByLabelText(/command/i)).toBeNull();
    expect(screen.queryByLabelText(/flag/i)).toBeNull();
    expect(screen.queryByLabelText(/script/i)).toBeNull();
    expect(screen.getByText(/there are no/)).toBeInTheDocument();
  });
});
