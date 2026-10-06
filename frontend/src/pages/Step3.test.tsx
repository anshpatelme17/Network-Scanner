import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Events } from "./Events";

const EVENT_PAGE = {
  items: [
    {
      id: "evt-1",
      event_time: "2026-09-27T00:00:00",
      received_at: "2026-09-27T00:00:01",
      source_type: "GENERIC",
      source_name: "lab-sensor",
      event_type: "test.event",
      severity: "HIGH",
      title: "Something happened",
      description: null,
      source_ip: "10.0.0.5",
      destination_ip: "10.0.0.9",
      source_port: null,
      destination_port: 443,
      protocol: "tcp",
      asset_id: null,
      hostname: null,
      username: null,
      process_name: null,
      action: null,
      status: null,
      raw_event: { vendor: "acme" },
      normalized_data: {},
      correlation_key: "abc",
      fingerprint: "def",
      external_event_id: null,
      created_at: "2026-09-27T00:00:01",
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

function mockFetch(handler: (url: string) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: unknown) => ({
    ok: true,
    status: 200,
    json: async () => handler(String(url)),
  }));
}

describe("Events page (Step 3 ingestion)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders the event table from the API", async () => {
    mockFetch((url) => (url.includes("/api/v1/events") ? EVENT_PAGE : {}));
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Something happened")).toBeInTheDocument());
    // Badge text duplicates the <select> option text, so count instead of getByText.
    expect(screen.getAllByText("HIGH").length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText("10.0.0.5")).toBeInTheDocument();
  });

  it("shows an honest empty state when nothing was ingested", async () => {
    mockFetch(() => ({ items: [], total: 0, limit: 50, offset: 0 }));
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("No security events received.")).toBeInTheDocument(),
    );
  });

  it("opens event details with the raw payload as inert text", async () => {
    mockFetch((url) =>
      url.includes("/api/v1/events/evt-1") ? EVENT_PAGE.items[0] : EVENT_PAGE,
    );
    const { container } = render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Details")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Details"));
    await waitFor(() => expect(screen.getByText("Fingerprint: def")).toBeInTheDocument());
    // Raw payload is rendered as text (React-escaped), never as markup.
    const pre = container.querySelector("pre");
    expect(pre?.textContent).toContain('"vendor"');
    expect(container.querySelector("script")).toBeNull();
  });

  it("filters by severity through the API", async () => {
    const seen: string[] = [];
    mockFetch((url) => {
      seen.push(url);
      return { items: [], total: 0, limit: 50, offset: 0 };
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Refresh")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Filter by severity"), {
      target: { value: "CRITICAL" },
    });
    await waitFor(() =>
      expect(seen.some((url) => url.includes("severity=CRITICAL"))).toBe(true),
    );
  });

  it("filters by source and shows the Suricata empty state", async () => {
    const seen: string[] = [];
    mockFetch((url) => {
      seen.push(url);
      return { items: [], total: 0, limit: 50, offset: 0 };
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByLabelText("Filter by source")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Filter by source"), {
      target: { value: "SURICATA" },
    });
    await waitFor(() =>
      expect(seen.some((url) => url.includes("source_type=SURICATA"))).toBe(true),
    );
    await waitFor(() =>
      expect(screen.getByText("No Suricata events received.")).toBeInTheDocument(),
    );
  });

  it("filters by source and shows the Zeek empty state", async () => {
    const seen: string[] = [];
    mockFetch((url) => {
      seen.push(url);
      return { items: [], total: 0, limit: 50, offset: 0 };
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByLabelText("Filter by source")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Filter by source"), {
      target: { value: "ZEEK" },
    });
    await waitFor(() =>
      expect(seen.some((url) => url.includes("source_type=ZEEK"))).toBe(true),
    );
    await waitFor(() =>
      expect(screen.getByText("No Zeek events received.")).toBeInTheDocument(),
    );
  });

  it("filters by source and shows the Wazuh empty state", async () => {
    const seen: string[] = [];
    mockFetch((url) => {
      seen.push(url);
      return { items: [], total: 0, limit: 50, offset: 0 };
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByLabelText("Filter by source")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Filter by source"), {
      target: { value: "WAZUH" },
    });
    await waitFor(() =>
      expect(seen.some((url) => url.includes("source_type=WAZUH"))).toBe(true),
    );
    await waitFor(() =>
      expect(screen.getByText("No Wazuh events received.")).toBeInTheDocument(),
    );
  });

  it("filters by source and shows the Defender empty state", async () => {
    const seen: string[] = [];
    mockFetch((url) => {
      seen.push(url);
      return { items: [], total: 0, limit: 50, offset: 0 };
    });
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByLabelText("Filter by source")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Filter by source"), {
      target: { value: "DEFENDER" },
    });
    await waitFor(() =>
      expect(seen.some((url) => url.includes("source_type=DEFENDER"))).toBe(true),
    );
    await waitFor(() =>
      expect(screen.getByText("No Defender events received.")).toBeInTheDocument(),
    );
  });
});
