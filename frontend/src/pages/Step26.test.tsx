import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Events } from "./Events";

const CONNECTORS = {
  items: [
    {
      source: "suricata",
      mode: "LIVE",
      state: "CONNECTED",
      detail: "EVE path readable; bounded poll available.",
      configured: { path: true },
      last_success_at: null,
    },
    {
      source: "zeek",
      mode: "FIXTURE",
      state: "UNAVAILABLE",
      detail: "No log path configured; fixture ingestion remains available.",
      configured: { path: false },
      last_success_at: null,
    },
    {
      source: "wazuh",
      mode: "LIVE",
      state: "INVALID_CONFIGURATION",
      detail: "Incomplete configuration; missing: password.",
      configured: { url: true, username: true, password: false },
      last_success_at: null,
    },
    {
      source: "defender",
      mode: "LIVE",
      state: "UNAVAILABLE",
      detail: "No credentials configured; live connection not attempted.",
      configured: { tenant_id: false, client_id: false, client_secret: false },
      last_success_at: null,
    },
  ],
};

const PAGE = { items: [], total: 0, limit: 100, offset: 0 };

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => ({
      ok: true,
      status: 200,
      json: async () => handler(String(url), init),
    }),
  );
}

describe("Events connectors panel (Step 26)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders all four sources with truthful states", async () => {
    mockFetch((url) => {
      if (url.includes("/events/connectors")) return CONNECTORS;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Event sources / connectors")).toBeInTheDocument());
    for (const source of ["suricata", "zeek", "wazuh", "defender"]) {
      expect(screen.getByText(source)).toBeInTheDocument();
    }
    expect(screen.getByText("CONNECTED")).toBeInTheDocument();
    expect(screen.getByText("INVALID_CONFIGURATION")).toBeInTheDocument();
    expect(screen.getAllByText("UNAVAILABLE").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText(/No credentials configured/)).toBeInTheDocument();
  });

  it("polls a file connector and reports the summary", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      if (url.endsWith("/suricata/poll")) {
        return { source: "suricata", accepted: 2, duplicates: 1, rejected: 0, truncated: false, errors: [] };
      }
      if (url.includes("/events/connectors")) return CONNECTORS;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getAllByText("Poll now").length).toBe(2));
    fireEvent.click(screen.getAllByText("Poll now")[0]);
    await waitFor(() =>
      expect(screen.getByText(/suricata: 2 accepted, 1 duplicates, 0 rejected/)).toBeInTheDocument(),
    );
    expect(
      seen.some((entry) => entry.startsWith("POST") && entry.endsWith("/suricata/poll")),
    ).toBe(true);
  });

  it("degrades gracefully when connector status is unavailable", async () => {
    mockFetch((url) => {
      if (url.includes("/events/connectors")) throw new Error("down");
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("Connector status unavailable.")).toBeInTheDocument(),
    );
    expect(screen.getByText("No security events received.")).toBeInTheDocument();
  });
});
