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
      detail: "Verified 2026-09-29T09:00:00 in 4 ms.",
      configured: { path: true },
      last_success_at: null,
      connector_state: "CONNECTED",
      last_check_at: "2026-09-29T09:00:00",
      last_poll_at: null,
      last_error_category: null,
      events_retrieved: 0,
      latency_ms: 4,
    },
    {
      source: "zeek",
      mode: "FIXTURE",
      state: "UNAVAILABLE",
      detail: "No log path configured; fixture ingestion remains available.",
      configured: { path: false },
      last_success_at: null,
      connector_state: "NOT_CONFIGURED",
      last_check_at: null,
      last_poll_at: null,
      last_error_category: null,
      events_retrieved: 0,
      latency_ms: null,
    },
    {
      source: "wazuh",
      mode: "LIVE",
      state: "UNAVAILABLE",
      detail: "Authentication rejected by the endpoint on the last check.",
      configured: { url: true, username: true, password: true },
      last_success_at: null,
      connector_state: "AUTH_FAILED",
      last_check_at: "2026-09-29T09:05:00",
      last_poll_at: null,
      last_error_category: "AUTH_FAILED",
      events_retrieved: 0,
      latency_ms: null,
    },
    {
      source: "defender",
      mode: "LIVE",
      state: "UNAVAILABLE",
      detail: "Credentials configured; live connection not attempted yet.",
      configured: { tenant_id: false, client_id: false, client_secret: false },
      last_success_at: null,
      connector_state: "CONFIGURED",
      last_check_at: null,
      last_poll_at: null,
      last_error_category: null,
      events_retrieved: 0,
      latency_ms: null,
    },
  ],
};

const CONNECTED_WAZUH = {
  items: CONNECTORS.items.map((item) =>
    item.source === "wazuh"
      ? {
          ...item,
          state: "CONNECTED",
          connector_state: "CONNECTED",
          detail: "Verified 2026-09-29T09:10:00 in 12 ms",
          last_error_category: null,
          last_check_at: "2026-09-29T09:10:00",
        }
      : item,
  ),
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

describe("Events connectors panel (Step 27)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders the connector_state vocabulary with health metadata", async () => {
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

    // Step 27 vocabulary is what the operator sees.
    expect(screen.getByText("CONNECTED")).toBeInTheDocument();
    expect(screen.getByText("AUTH_FAILED")).toBeInTheDocument();
    expect(screen.getByText("CONFIGURED")).toBeInTheDocument();
    // NOT_CONFIGURED appears both as a row state and in the legend copy.
    expect(screen.getAllByText("NOT_CONFIGURED").length).toBeGreaterThanOrEqual(2);
    // Health metadata: last-check timestamp + error category.
    expect(screen.getByText("Last check")).toBeInTheDocument();
    expect(
      screen.getByText(/last error: AUTH_FAILED/, { selector: "span" }),
    ).toBeInTheDocument();
    expect(screen.getAllByText("—").length).toBeGreaterThanOrEqual(1);
    // Every source can be checked; polls follow configuration truth:
    // 2 file sources + fully configured wazuh; unconfigured defender has none.
    expect(screen.getAllByText("Check now").length).toBe(4);
    expect(screen.getAllByText("Poll now").length).toBe(3);
  });

  it("runs a check and reports the state the server returns", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      if (init?.method === "POST" && url.includes("/wazuh/check")) {
        return CONNECTED_WAZUH.items[2];
      }
      if (url.includes("/events/connectors")) return CONNECTED_WAZUH;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getAllByText("Check now").length).toBe(4));
    fireEvent.click(screen.getAllByText("Check now")[2]);
    await waitFor(() =>
      expect(screen.getByText(/wazuh: CONNECTED — Verified/)).toBeInTheDocument(),
    );
    expect(
      seen.some((entry) => entry.startsWith("POST") && entry.endsWith("/wazuh/check")),
    ).toBe(true);
    await waitFor(() => expect(screen.queryByText("AUTH_FAILED")).not.toBeInTheDocument());
  });

  it("offers Poll now to a fully configured API source and reports termination", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      if (init?.method === "POST" && url.endsWith("/wazuh/poll")) {
        return {
          source: "wazuh",
          accepted: 2,
          duplicates: 0,
          rejected: 0,
          truncated: true,
          errors: [],
          pages: 1,
          retrieved: 10,
          termination: "MAX_PAGES",
        };
      }
      if (url.includes("/events/connectors")) return CONNECTORS;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    // File sources (2) + fully configured wazuh (1); unconfigured defender: no.
    await waitFor(() => expect(screen.getAllByText("Poll now").length).toBe(3));
    const buttons = screen.getAllByText("Poll now");
    fireEvent.click(buttons[2]);
    await waitFor(() =>
      expect(
        screen.getByText(/wazuh: 2 accepted, 0 duplicates, 0 rejected · termination MAX_PAGES/),
      ).toBeInTheDocument(),
    );
    expect(
      seen.some((entry) => entry.startsWith("POST") && entry.endsWith("/wazuh/poll")),
    ).toBe(true);
  });

  it("degrades gracefully when a check is refused by the server", async () => {
    mockFetch((url, init) => {
      if (init?.method === "POST" && url.includes("/check")) {
        throw new Error("PERMISSION_DENIED");
      }
      if (url.includes("/events/connectors")) return CONNECTORS;
      return PAGE;
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getAllByText("Check now").length).toBe(4));
    fireEvent.click(screen.getAllByText("Check now")[0]);
    await waitFor(() =>
      expect(screen.getByText(/suricata: check refused by the server\./)).toBeInTheDocument(),
    );
  });
});
