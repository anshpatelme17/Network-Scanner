import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AssetWorkspace } from "./AssetWorkspace";
import { Assets } from "./Assets";

const ASSET_SUMMARY = {
  id: "asset-1",
  ip_address: "192.0.2.77",
  hostname: "workstation-77",
  mac_address: "00:1A:2B:3C:4D:5E",
  operating_system: "Linux 6.8",
  state: "up",
  asset_type: "WORKSTATION",
  discovery_source: "nmap",
  service_count: 1,
  first_seen: "2026-09-01T08:00:00",
  last_seen: "2026-10-01T09:30:00",
};

const ASSET = {
  ...ASSET_SUMMARY,
  services: [
    {
      id: "svc-1",
      asset_id: "asset-1",
      port: 443,
      protocol: "tcp",
      state: "open",
      service_name: "https",
      product: "nginx",
      version: "1.24.0",
      extra_info: null,
      discovered_at: "2026-09-01T08:00:00",
      last_seen: "2026-10-01T09:30:00",
    },
  ],
};

const ASSET_NO_SERVICES = { ...ASSET, services: [], service_count: 0 };

const ASSET_PAGE = { items: [ASSET_SUMMARY], total: 1, limit: 100, offset: 0 };

const VULN_RISK = {
  asset_id: "asset-1",
  finding_count: 2,
  highest_severity: "CRITICAL",
  highest_cvss: 9.8,
  critical_count: 1,
  high_count: 1,
  aggregate_risk: 87,
  risk_level: "HIGH",
  calculated_at: "2026-10-01T10:00:00",
};

const VULN_PAGE = {
  items: [
    {
      id: "vuln-1",
      asset_id: "asset-1",
      service_id: "svc-1",
      scanner: "NVD_SYNC",
      scanner_version: null,
      scanner_finding_id: "f-1",
      title: "Outdated TLS library",
      severity: "CRITICAL",
      cvss_score: 9.8,
      cve_id: "CVE-2026-1234",
      hostname: "workstation-77",
      destination_ip: "192.0.2.77",
      destination_port: 443,
      status: "OPEN",
      first_seen: "2026-09-20T00:00:00",
      last_seen: "2026-10-01T00:00:00",
    },
    {
      id: "vuln-2",
      asset_id: "asset-1",
      service_id: "svc-1",
      scanner: "NVD_SYNC",
      scanner_version: null,
      scanner_finding_id: "f-2",
      title: "Weak cipher suite",
      severity: "HIGH",
      cvss_score: 7.5,
      cve_id: null,
      hostname: "workstation-77",
      destination_ip: "192.0.2.77",
      destination_port: 443,
      status: "ACCEPTED_RISK",
      first_seen: "2026-09-20T00:00:00",
      last_seen: "2026-10-01T00:00:00",
    },
  ],
  total: 2,
  limit: 100,
  offset: 0,
};

const EVENT = {
  id: "evt-1",
  event_time: "2026-10-01T06:00:00",
  received_at: "2026-10-01T06:00:05",
  source_type: "AUTH",
  source_name: "sshd",
  event_type: "AUTH_FAILURE",
  severity: "HIGH",
  title: "Repeated authentication failures",
  description: "Multiple failed logins for user root.",
  source_ip: "203.0.113.9",
  destination_ip: "192.0.2.77",
  source_port: 51234,
  destination_port: 22,
  protocol: "tcp",
  asset_id: "asset-1",
  hostname: "workstation-77",
  username: "root",
  process_name: "sshd",
  action: "login",
  status: "failed",
  confidence: 80,
  occurrence_count: 5,
  last_seen_at: "2026-10-01T06:04:00",
  ingest_mode: "NORMAL",
  raw_event: null,
  normalized_data: {},
  correlation_key: null,
  fingerprint: "fp-evt-1",
  external_event_id: null,
  created_at: "2026-10-01T06:00:06",
};

const EVENTS_PAGE = { items: [EVENT], total: 1, limit: 50, offset: 0 };
const EVENTS_PAGE_EMPTY = { items: [], total: 0, limit: 50, offset: 0 };

const ASSET_RISK = {
  id: "ris-asset-1",
  entity_type: "asset",
  entity_id: "asset-1",
  score: 64,
  severity: "HIGH",
  priority: "P2",
  factors: { open_ports: 1, critical_findings: 1 },
  explanation: "Open service linked to a critical finding.",
  calculated_at: "2026-10-01T10:05:00",
  scoring_version: "1.0.0",
};

type Handler = (url: string, init?: RequestInit) => unknown;
type Fail = { __fail: true; code: string; status: number };

function fail(code: string, status: number): Fail {
  return { __fail: true, code, status };
}

const calls: string[] = [];

function mockFetch(handler: Handler) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => {
      calls.push(`${init?.method ?? "GET"} ${String(url)}`);
      const value = handler(String(url), init);
      const marker = value as Fail | null;
      if (marker && marker.__fail) {
        return {
          ok: false,
          status: marker.status,
          json: async () => ({ error: { code: marker.code } }),
        };
      }
      return { ok: true, status: 200, json: async () => value };
    },
  );
}

const baseRoute: Handler = (url, init) => {
  if ((init?.method ?? "GET") !== "GET") throw new Error("unexpected write");
  if (url.includes("/api/v1/assets/asset-1/vuln-risk")) return VULN_RISK;
  if (url.includes("/api/v1/assets/asset-404")) return fail("ASSET_NOT_FOUND", 404);
  if (url.includes("/api/v1/assets/asset-1")) return ASSET;
  if (url.includes("/api/v1/assets?")) return ASSET_PAGE;
  if (url.includes("/api/v1/vulnerabilities?")) return VULN_PAGE;
  if (url.includes("/api/v1/events?")) return EVENTS_PAGE;
  if (url.includes("/api/v1/risk/asset/asset-1")) return ASSET_RISK;
  if (url.includes("/api/v1/risk/asset/")) return fail("RISK_NOT_FOUND", 404);
  return {};
};

function routeWith(...overrides: Handler[]): Handler {
  return (url, init) => {
    for (const override of overrides) {
      const value = override(url, init);
      if (value !== undefined) return value;
    }
    return baseRoute(url, init);
  };
}

function renderWorkspace(initialEntry = "/assets/asset-1") {
  return render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <Routes>
        <Route path="/assets" element={<Assets />} />
        <Route path="/assets/:assetId" element={<AssetWorkspace />} />
        <Route path="*" element={<p>Unknown route</p>} />
      </Routes>
    </MemoryRouter>,
  );
}

const originalFetch = globalThis.fetch;

describe("Asset investigation workspace (Phase 3, Step 36)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    calls.length = 0;
  });

  afterEach(() => {
    (globalThis as unknown as { fetch: unknown }).fetch = originalFetch;
  });

  it("renders identity, availability state, services, and the honest navigation note", async () => {
    mockFetch(baseRoute);
    renderWorkspace();

    const identity = await screen.findByLabelText("Asset identity");
    await waitFor(() =>
      expect(within(identity).getByText("192.0.2.77")).toBeInTheDocument(),
    );
    expect(within(identity).getByText("workstation-77")).toBeInTheDocument();
    expect(within(identity).getByText("WORKSTATION")).toBeInTheDocument();
    expect(within(identity).getByText("nmap")).toBeInTheDocument();

    const stateBadge = within(identity).getByText("up");
    expect(stateBadge).toHaveClass("badge", "ok");
    expect(within(identity).getByText(/host availability only/)).toBeInTheDocument();

    const services = screen.getByLabelText("Asset services");
    await waitFor(() =>
      expect(within(services).getByText("nginx")).toBeInTheDocument(),
    );
    expect(within(services).getByText("443")).toBeInTheDocument();
    expect(within(services).getByText("https")).toBeInTheDocument();

    expect(screen.getByText("Asset investigation")).toBeInTheDocument();
    expect(
      screen.getByText(
        "Related incidents are not available from the current asset API.",
      ),
    ).toBeInTheDocument();
  });

  it("states honestly when the latest scan found no open services", async () => {
    const noServices: Handler = (url) => {
      if (url.includes("/api/v1/assets/asset-1") && !url.includes("vuln-risk")) {
        return ASSET_NO_SERVICES;
      }
      return undefined;
    };
    mockFetch(routeWith(noServices));
    renderWorkspace();

    const services = await screen.findByLabelText("Asset services");
    await waitFor(() =>
      expect(
        within(services).getByText("No open services in the latest scan."),
      ).toBeInTheDocument(),
    );
    expect(within(services).queryByRole("table")).toBeNull();
  });

  it("shows aggregate exposure and the asset's stored findings", async () => {
    mockFetch(baseRoute);
    renderWorkspace();

    const exposure = await screen.findByLabelText("Vulnerability exposure");
    await waitFor(() =>
      expect(within(exposure).getByText("Outdated TLS library")).toBeInTheDocument(),
    );
    expect(within(exposure).getByText("2 stored findings")).toBeInTheDocument();
    expect(within(exposure).getAllByText("CRITICAL")).toHaveLength(2);
    expect(within(exposure).getByText(/aggregate 87/)).toBeInTheDocument();
    expect(within(exposure).getByText("CVE-2026-1234")).toBeInTheDocument();
    expect(within(exposure).getByText("Weak cipher suite")).toBeInTheDocument();
    expect(within(exposure).getByText("ACCEPTED_RISK")).toBeInTheDocument();
  });

  it("keeps identity and events when vulnerability and risk sections are restricted", async () => {
    const restricted: Handler = (url) => {
      if (url.includes("/vuln-risk")) return fail("PERMISSION_DENIED", 403);
      if (url.includes("/api/v1/vulnerabilities?")) {
        return fail("PERMISSION_DENIED", 403);
      }
      if (url.includes("/api/v1/risk/asset/")) return fail("PERMISSION_DENIED", 403);
      return undefined;
    };
    mockFetch(routeWith(restricted));
    renderWorkspace();

    await waitFor(() =>
      expect(
        screen.getByText("Vulnerability findings are restricted for your account."),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText("Risk assessments are restricted for your account."),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Retry vulnerability exposure" }),
    ).toBeNull();
    expect(screen.queryByRole("button", { name: "Retry risk" })).toBeNull();

    expect(screen.getByText("192.0.2.77")).toBeInTheDocument();
    const eventCard = screen.getByLabelText("Linked security events");
    await waitFor(() =>
      expect(
        within(eventCard).getByText("Repeated authentication failures"),
      ).toBeInTheDocument(),
    );
  });

  it("loads events by exact asset id with a deep link per event", async () => {
    mockFetch(baseRoute);
    renderWorkspace();

    const eventCard = await screen.findByLabelText("Linked security events");
    await waitFor(() =>
      expect(
        within(eventCard).getByText("Repeated authentication failures"),
      ).toBeInTheDocument(),
    );
    expect(
      calls.some(
        (entry) =>
          entry.includes("/api/v1/events?") && entry.includes("asset_id=asset-1"),
      ),
    ).toBe(true);
    const link = within(eventCard).getByRole("link", {
      name: "Repeated authentication failures",
    });
    expect(link).toHaveAttribute("href", "/events?event=evt-1");
    expect(
      within(eventCard).getByText("Linked events (1 total, showing 1)"),
    ).toBeInTheDocument();
  });

  it("shows honest restricted messages for identity, services, and events together", async () => {
    const restricted: Handler = (url) => {
      if (url.includes("/api/v1/assets/asset-1") && !url.includes("vuln-risk")) {
        return fail("PERMISSION_DENIED", 403);
      }
      if (url.includes("/api/v1/events?")) return fail("PERMISSION_DENIED", 403);
      return undefined;
    };
    mockFetch(routeWith(restricted));
    renderWorkspace();

    await waitFor(() =>
      expect(
        screen.getByText("Asset details are restricted for your account."),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByText("Services are restricted for your account."),
    ).toBeInTheDocument();
    expect(
      screen.getByText("Event history is restricted for your account."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry asset details" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Retry events" })).toBeNull();

    await waitFor(() => {
      expect(screen.getByText("Outdated TLS library")).toBeInTheDocument();
      expect(screen.getByText("Score 64")).toBeInTheDocument();
    });
  });

  it("keeps stored risk separate from availability state and finding severity", async () => {
    mockFetch(baseRoute);
    renderWorkspace();

    const riskCard = await screen.findByLabelText("Stored asset risk");
    await waitFor(() =>
      expect(within(riskCard).getByText("Score 64")).toBeInTheDocument(),
    );
    expect(within(riskCard).getByText("HIGH")).toBeInTheDocument();
    expect(within(riskCard).getByText("priority P2")).toBeInTheDocument();
    expect(
      within(riskCard).getByText("Open service linked to a critical finding."),
    ).toBeInTheDocument();
    expect(within(riskCard).queryByText("up")).toBeNull();
    expect(
      within(riskCard).getByText(/not asset state, not finding severity/),
    ).toBeInTheDocument();
    expect(
      within(riskCard).getByText(/never recalculated here/),
    ).toBeInTheDocument();
  });

  it("states honestly when no stored risk assessment exists yet", async () => {
    const riskMissing: Handler = (url) => {
      if (url.includes("/api/v1/risk/asset/asset-1")) {
        return fail("RISK_NOT_FOUND", 404);
      }
      return undefined;
    };
    mockFetch(routeWith(riskMissing));
    renderWorkspace();

    const riskCard = await screen.findByLabelText("Stored asset risk");
    await waitFor(() =>
      expect(
        within(riskCard).getByText("No stored risk assessment for this asset yet."),
      ).toBeInTheDocument(),
    );
    expect(within(riskCard).queryByRole("button")).toBeNull();
    expect(screen.getByText("192.0.2.77")).toBeInTheDocument();
  });

  it("stops at an honest not-found state without loading dependent sections", async () => {
    mockFetch(baseRoute);
    renderWorkspace("/assets/asset-404");

    await waitFor(() =>
      expect(screen.getByText("Asset not found.")).toBeInTheDocument(),
    );
    expect(screen.queryByLabelText("Asset services")).toBeNull();
    expect(screen.queryByLabelText("Vulnerability exposure")).toBeNull();
    expect(screen.queryByLabelText("Linked security events")).toBeNull();
    expect(screen.queryByLabelText("Stored asset risk")).toBeNull();
    expect(
      screen.getByText(
        "Related incidents are not available from the current asset API.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Back to asset inventory" }),
    ).toHaveAttribute("href", "/assets");
    expect(calls).toHaveLength(1);
    expect(
      calls.every(
        (entry) =>
          !entry.includes("/vulnerabilities?") &&
          !entry.includes("/events?") &&
          !entry.includes("/risk/"),
      ),
    ).toBe(true);
  });

  it("isolates an events failure and recovers through its retry control", async () => {
    let eventsBroken = true;
    const flakyEvents: Handler = (url) => {
      if (eventsBroken && url.includes("/api/v1/events?")) {
        return fail("INTERNAL_ERROR", 500);
      }
      return undefined;
    };
    mockFetch(routeWith(flakyEvents));
    renderWorkspace();

    const eventCard = await screen.findByLabelText("Linked security events");
    await waitFor(() =>
      expect(
        within(eventCard).getByText("Linked events could not be loaded."),
      ).toBeInTheDocument(),
    );
    expect(
      within(eventCard).getByRole("button", { name: "Retry events" }),
    ).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText("192.0.2.77")).toBeInTheDocument();
      expect(screen.getByText("2 stored findings")).toBeInTheDocument();
      expect(screen.getByText("Score 64")).toBeInTheDocument();
    });

    eventsBroken = false;
    fireEvent.click(within(eventCard).getByRole("button", { name: "Retry events" }));
    await waitFor(() =>
      expect(
        within(eventCard).getByText("Repeated authentication failures"),
      ).toBeInTheDocument(),
    );
  });

  it("isolates an identity failure and recovers through its retry control", async () => {
    let identityBroken = true;
    const flakyIdentity: Handler = (url) => {
      if (
        identityBroken &&
        url.includes("/api/v1/assets/asset-1") &&
        !url.includes("vuln-risk")
      ) {
        return fail("INTERNAL_ERROR", 500);
      }
      return undefined;
    };
    mockFetch(routeWith(flakyIdentity));
    renderWorkspace();

    await waitFor(() =>
      expect(
        screen.getByText("Asset details could not be loaded."),
      ).toBeInTheDocument(),
    );
    expect(
      screen.getByRole("button", { name: "Retry asset details" }),
    ).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText("Outdated TLS library")).toBeInTheDocument();
      expect(screen.getByText("Repeated authentication failures")).toBeInTheDocument();
      expect(screen.getByText("Score 64")).toBeInTheDocument();
    });

    identityBroken = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry asset details" }));
    await waitFor(() => expect(screen.getByText("192.0.2.77")).toBeInTheDocument());
  });

  it("is reachable from asset inventory without disturbing existing details", async () => {
    mockFetch(baseRoute);
    renderWorkspace("/assets");

    await waitFor(() => expect(screen.getByText("Details")).toBeInTheDocument());
    fireEvent.click(screen.getByText("Details"));
    await waitFor(() =>
      expect(screen.getByLabelText("Asset details")).toBeInTheDocument(),
    );
    await waitFor(() => expect(screen.getByText("nginx")).toBeInTheDocument());

    const investigate = screen.getByRole("link", { name: "Investigate" });
    expect(investigate).toHaveAttribute("href", "/assets/asset-1");
    fireEvent.click(investigate);

    await waitFor(() =>
      expect(screen.getByText("Asset investigation")).toBeInTheDocument(),
    );
    await waitFor(() => expect(screen.getByText("workstation-77")).toBeInTheDocument());
    expect(calls.some((entry) => entry.includes("/api/v1/assets?"))).toBe(true);
  });

  it("uses only read-only GETs and states honestly when no events are linked", async () => {
    const emptyEvents: Handler = (url) => {
      if (url.includes("/api/v1/events?")) return EVENTS_PAGE_EMPTY;
      return undefined;
    };
    mockFetch(routeWith(emptyEvents));
    renderWorkspace();

    const eventCard = await screen.findByLabelText("Linked security events");
    await waitFor(() =>
      expect(
        within(eventCard).getByText("No events are linked to this asset."),
      ).toBeInTheDocument(),
    );
    await waitFor(() => {
      expect(screen.getByText("2 stored findings")).toBeInTheDocument();
      expect(screen.getByText("Score 64")).toBeInTheDocument();
    });

    expect(calls.length).toBeGreaterThan(0);
    expect(calls.every((entry) => entry.startsWith("GET "))).toBe(true);
    expect(
      calls.some((entry) =>
        /(recompute|calculate|vulnerability-scans|\/status|\/incidents)/.test(entry),
      ),
    ).toBe(false);
  });
});
