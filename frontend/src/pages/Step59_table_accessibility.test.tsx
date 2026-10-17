import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AlertTriage } from "./AlertTriage";
import { Assets } from "./Assets";
import { AssetWorkspace } from "./AssetWorkspace";
import { Correlations } from "./Correlations";
import { Dashboard } from "./Dashboard";
import { Events } from "./Events";
import { Incidents } from "./Incidents";
import { Network } from "./Network";
import { Response as ResponsePage } from "./Response";
import { ResponseCenter } from "./ResponseCenter";
import { Risk } from "./Risk";
import { RiskPrioritization } from "./RiskPrioritization";
import { Vulnerabilities } from "./Vulnerabilities";

const READINESS = {
  status: "ready",
  app: "Security Platform",
  version: "0.1.0",
  environment: "test",
  checks: { database: "up" },
};

const OVERVIEW = {
  generated_at: "2026-10-06T12:00:00",
  version: "soc-overview:1.0.0",
  disclaimer: "Read-only roll-up of stored state.",
  limits: { max_items: 50, requested_items: 10 },
  counts: {
    assets_total: 1,
    assets_active: 1,
    services_total: 1,
    events_total: 1,
    correlations_total: 1,
    incidents_total: 1,
    incidents_open: 1,
    risk_assessments_total: 1,
    vulnerabilities_open: 1,
    response_actions_total: 1,
    response_actions_pending_approval: 1,
  },
  incidents_by_severity: { CRITICAL: 0, HIGH: 1, MEDIUM: 0, LOW: 0, INFO: 0 },
  incidents_by_priority: { P1: 0, P2: 1, P3: 0, P4: 0, UNSCORED: 0 },
  top_incidents: [
    {
      id: "inc-1",
      incident_key: "INC-1",
      title: "Correlated event",
      status: "OPEN",
      severity: "HIGH",
      confidence: 80,
      risk_score: 72,
      priority: "P2",
      primary_asset_id: "asset-1",
      primary_ip: "192.0.2.1",
      hostname: "host-1",
      correlation_id: "corr-1",
      first_seen: "2026-10-06T09:00:00",
      last_seen: "2026-10-06T09:30:00",
    },
  ],
  recent_audit: [
    {
      id: "audit-1",
      action: "events.ingested",
      actor: "operator",
      event_id: "evt-1",
      detail: "Ingested events.",
      created_at: "2026-10-06T09:31:00",
    },
  ],
  connectors: [
    {
      source: "SURICATA",
      mode: "live",
      state: "OK",
      connector_state: "CONNECTED",
      last_check_at: "2026-10-06T11:00:00",
      last_poll_at: "2026-10-06T11:01:00",
      last_error_category: null,
      events_retrieved: 120,
    },
  ],
};

const ASSET_DETAIL = {
  id: "asset-1",
  ip_address: "127.0.0.1",
  hostname: "localhost",
  operating_system: "linux",
  state: "up",
  asset_type: "SERVER",
  discovery_source: "nmap",
  mac_address: null,
  first_seen: "2026-10-06T08:00:00",
  last_seen: "2026-10-06T09:00:00",
  service_count: 1,
  services: [
    {
      id: "svc-1",
      port: 80,
      protocol: "tcp",
      service_name: "http",
      product: "nginx",
      version: "1.0",
      last_seen: "2026-10-06T09:00:00",
    },
  ],
};

const ASSET_SUMMARY = {
  id: "asset-1",
  ip_address: "127.0.0.1",
  hostname: "localhost",
  operating_system: "linux",
  state: "up",
  asset_type: "SERVER",
  discovery_source: "nmap",
  service_count: 1,
  last_seen: "2026-10-06T09:00:00",
};

const VULN_RISK = {
  finding_count: 1,
  highest_severity: "HIGH",
  risk_level: "elevated",
  aggregate_risk: 55,
  highest_cvss: 7.5,
  critical_count: 0,
  high_count: 1,
};

const FINDING = {
  id: "vuln-1",
  severity: "HIGH",
  title: "Outdated component",
  hostname: "localhost",
  destination_ip: "127.0.0.1",
  destination_port: 80,
  cve_id: "CVE-2026-0001",
  cvss_score: 7.5,
  scanner: "nmap-vuln",
  status: "OPEN",
  last_seen: "2026-10-06T09:00:00",
};

const CORRELATION = {
  id: "corr-1",
  severity: "HIGH",
  title: "Authentication sequence",
  rule_name: "auth-chain",
  event_count: 3,
  window_start: "2026-10-06T09:00:00",
  window_end: "2026-10-06T09:10:00",
  confidence: 80,
};

const INCIDENT = {
  id: "inc-1",
  incident_key: "INC-1",
  title: "Correlated event",
  incident_type: "AUTHENTICATION_ANOMALY",
  severity: "HIGH",
  risk_score: 72,
  confidence: 80,
  status: "OPEN",
  correlation_id: "corr-1",
  primary_ip: "192.0.2.1",
  created_at: "2026-10-06T09:11:00",
  last_seen: "2026-10-06T09:30:00",
};

const INCIDENT_UNSCORED = {
  ...INCIDENT,
  id: "inc-2",
  incident_key: "INC-2",
  title: "Unscored event",
  severity: "LOW",
};

const RISK_ASSESSMENT = {
  id: "ris-1",
  entity_type: "incident",
  entity_id: "inc-1",
  score: 74,
  severity: "HIGH",
  priority: "P2",
  factors: {},
  explanation: "Stored evidence implies elevated risk.",
  calculated_at: "2026-10-06T09:11:00",
  scoring_version: "1.0.0",
};

const CONNECTORS = {
  items: [
    {
      source: "suricata",
      mode: "live",
      state: "OK",
      connector_state: "CONNECTED",
      detail: "ready",
      last_check_at: "2026-10-06T11:00:00",
      last_success_at: "2026-10-06T11:01:00",
      last_error_category: null,
      configured: {},
    },
  ],
};

const INGESTION = {
  pipeline: [{ stage: "jsonl", detail: "parse" }],
  sources: [
    {
      source: "suricata",
      connector_state: "CONNECTED",
      last_failure_reason: null,
      events_accepted: 12,
      events_deduplicated: 1,
      events_dropped: 0,
      batches: 2,
      checkpoint: { advance_count: 1 },
    },
  ],
  limits: { max_pages: 5, max_poll_lines: 1000, batch_size: 100, retry_max: 2 },
  queue: { max: 500, overflow: "reject_newest" },
  streaming: { mode: "MANUAL" },
  totals: { dropped: 0 },
};

const EVENTS = {
  items: [
    {
      id: "evt-1",
      event_time: "2026-10-06T09:00:00",
      severity: "HIGH",
      source_type: "SURICATA",
      source_name: "suricata",
      ingest_mode: "FIXTURE",
      event_type: "alert",
      title: "Security event",
      source_ip: "192.0.2.1",
      destination_ip: "192.0.2.2",
      asset_id: "asset-1",
    },
  ],
  total: 1,
  limit: 100,
  offset: 0,
};

const SCANS = [
  {
    id: "scan-1",
    target: "127.0.0.1",
    profile: "quick",
    status: "completed",
    requested_by: "operator",
    assets_found: 1,
    services_found: 2,
    completed_at: "2026-10-06T09:00:00",
    error: null,
  },
];

const RESPONSE_ITEM = {
  id: "act-1",
  action_type: "ISOLATE_ENDPOINT",
  target_type: "asset",
  target_reference: "asset-1",
  target_evidence: [],
  status: "PENDING_APPROVAL",
  approved_by: null,
  approval_required: true,
  provider: "mock",
  expires_at: null,
  dry_run: false,
  policy_version: "1.0.0",
  requested_by: "operator",
  created_at: "2026-10-06T09:11:00",
};

const RESPONSE_CENTER = {
  total: 1,
  limit: 100,
  offset: 0,
  truncated: false,
  expiry_warning_hours: 24,
  counts: { PENDING_APPROVAL: 1 },
  pending_approval: [RESPONSE_ITEM],
  expiring_soon: [RESPONSE_ITEM],
};

function page<T>(items: T[]): { items: T[]; total: number; limit: number; offset: number } {
  return { items, total: items.length, limit: 100, offset: 0 };
}

function route(url: string): unknown {
  if (url.includes("/api/v1/ready")) return READINESS;
  if (url.includes("/api/v1/overview")) return OVERVIEW;
  if (url.includes("/api/v1/network/nmap/status")) return { available: true, version: "7.94" };
  if (url.includes("/api/v1/network/scans")) return SCANS;
  if (url.includes("/api/v1/events/connectors")) return CONNECTORS;
  if (url.includes("/api/v1/events/ingestion/status")) return INGESTION;
  if (url.includes("/api/v1/events?")) return EVENTS;
  if (url.includes("/api/v1/correlations?")) return page([CORRELATION]);
  if (url.includes("/api/v1/risk/asset/")) return { ...RISK_ASSESSMENT, entity_type: "asset", entity_id: "asset-1" };
  if (url.includes("/api/v1/risk?")) return page([RISK_ASSESSMENT]);
  if (url.includes("/api/v1/incidents?")) return page([INCIDENT, INCIDENT_UNSCORED]);
  if (url.includes("/api/v1/responses/summary")) return RESPONSE_CENTER;
  if (url.includes("/api/v1/responses?")) return page([RESPONSE_ITEM]);
  if (url.includes("/vuln-risk")) return VULN_RISK;
  if (url.includes("/api/v1/vulnerabilities?")) return page([FINDING]);
  if (url.includes("/api/v1/assets/")) return ASSET_DETAIL;
  if (url.includes("/api/v1/assets?")) return page([ASSET_SUMMARY]);
  return {};
}

function mockFetch() {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: unknown) => ({
    ok: true,
    status: 200,
    json: async () => route(String(url)),
  }));
}

async function expectEveryTableNamed() {
  const tables = await screen.findAllByRole("table");
  expect(tables.length).toBeGreaterThan(0);
  for (const table of tables) {
    expect(table).toHaveAccessibleName();
  }
}

describe("Data table accessibility (Phase 5, Step 59)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.history.replaceState({}, "", "/");
  });

  afterEach(() => {
    window.history.replaceState({}, "", "/");
  });

  it("names the alert triage queue", async () => {
    mockFetch();
    render(
      <MemoryRouter>
        <AlertTriage />
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(
      screen.getByRole("table", { name: "Correlated activity to triage" }),
    ).toBeInTheDocument();
  });

  it("names the asset inventory and the asset services tables", async () => {
    mockFetch();
    render(
      <MemoryRouter>
        <Assets />
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(screen.getByRole("table", { name: "Inventoried assets" })).toBeInTheDocument();

    fireEvent.click(screen.getAllByText("Details")[0]);
    expect(await screen.findByRole("table", { name: "Asset services" })).toBeInTheDocument();
    await expectEveryTableNamed();
  });

  it("names every asset workspace table", async () => {
    mockFetch();
    render(
      <MemoryRouter initialEntries={["/assets/asset-1"]}>
        <Routes>
          <Route path="/assets/:assetId" element={<AssetWorkspace />} />
        </Routes>
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(screen.getByRole("table", { name: "Asset identity attributes" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Detected services" })).toBeInTheDocument();
    expect(
      screen.getByRole("table", { name: "Asset vulnerability findings" }),
    ).toBeInTheDocument();
  });

  it("names the correlations table", async () => {
    mockFetch();
    render(
      <MemoryRouter>
        <Correlations />
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(screen.getByRole("table", { name: "Correlations" })).toBeInTheDocument();
  });

  it("names every SOC dashboard table", async () => {
    mockFetch();
    render(
      <MemoryRouter>
        <Dashboard />
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(screen.getByRole("table", { name: "Top open incidents" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Connector health" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Recent ingestion audit" })).toBeInTheDocument();
  });

  it("names every events table", async () => {
    mockFetch();
    render(
      <MemoryRouter>
        <Events />
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(screen.getByRole("table", { name: "Event connector status" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Ingestion status" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Received security events" })).toBeInTheDocument();
  });

  it("names the incidents table", async () => {
    mockFetch();
    render(
      <MemoryRouter>
        <Incidents />
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(screen.getByRole("table", { name: "Incidents" })).toBeInTheDocument();
  });

  it("names the recent scans table", async () => {
    mockFetch();
    render(
      <MemoryRouter>
        <Network />
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(screen.getByRole("table", { name: "Recent scans" })).toBeInTheDocument();
  });

  it("names the response proposals and controlled responses tables", async () => {
    mockFetch();
    render(
      <MemoryRouter>
        <ResponsePage />
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(
      screen.getByRole("table", { name: "Controlled defensive actions" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Response proposal records" })).toBeInTheDocument();
  });

  it("names every response center table", async () => {
    mockFetch();
    render(
      <MemoryRouter>
        <ResponseCenter />
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(screen.getByRole("table", { name: "Awaiting approval records" })).toBeInTheDocument();
    expect(
      screen.getByRole("table", { name: "Controlled actions expiring soon" }),
    ).toBeInTheDocument();
  });

  it("names the risk assessments table", async () => {
    mockFetch();
    render(
      <MemoryRouter>
        <Risk />
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(screen.getByRole("table", { name: "Stored risk assessments" })).toBeInTheDocument();
  });

  it("names the scored and unscored prioritization tables", async () => {
    mockFetch();
    render(
      <MemoryRouter>
        <RiskPrioritization />
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(screen.getByRole("table", { name: "Scored incidents" })).toBeInTheDocument();
    expect(screen.getByRole("table", { name: "Unscored incident records" })).toBeInTheDocument();
  });

  it("names the vulnerability findings table", async () => {
    mockFetch();
    render(
      <MemoryRouter>
        <Vulnerabilities />
      </MemoryRouter>,
    );
    await expectEveryTableNamed();
    expect(screen.getByRole("table", { name: "Assessment findings" })).toBeInTheDocument();
  });
});
