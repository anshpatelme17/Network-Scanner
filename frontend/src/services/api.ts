/**
 * Minimal typed API client.
 * Step 1: readiness probe. Step 2: asset inventory + controlled scans.
 */
import type {
  AdapterPreview,
  AssetDetail,
  AssetPage,
  AssetVulnRisk,
  AttackChain,
  AuthUser,
  ConnectorPage,
  ConnectorStatus,
  ControlledRequest,
  CorrelationDetail,
  CorrelationPage,
  DryRunResult,
  EventPage,
  EventSummary,
  ExecutionRecord,
  FindingLinks,
  FindingRisk,
  IncidentDetail,
  IncidentDetectResult,
  IncidentEvidence,
  IncidentAuditTrail,
  IncidentActivityPage,
  IncidentPage,
  IncidentRecalculateResult,
  IncidentRelationshipsPage,
  IncidentTimeline,
  IngestionCheckpoint,
  IngestionStatus,
  LoginToken,
  PollResult,
  InventorySummary,
  NmapStatus,
  ReadinessStatus,
  ResponseCenterSummary,
  ResponseDetail,
  ResponseAuditPage,
  ResponsePage,
  ResponsePolicy,
  ResponseProposal,
  ResponseRecommendations,
  ProviderDryRun,
  RollbackRecord,
  RiskAssessment,
  RiskPage,
  RiskRecomputeResult,
  ScanJob,
  ScanPreview,
  ScanProfile,
  SecurityEventInfo,
  SocOverview,
  VulnerabilityDetail,
  VulnerabilityPage,
  VulnScanJob,
  VulnScanProfile,
} from "../types";

const API_BASE: string =
  (import.meta.env.VITE_API_URL as string | undefined)?.replace(/\/$/, "") ?? "";

const TOKEN_KEY = "sp.auth.token";

function storedToken(): string | null {
  try {
    return window.localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

function storeToken(token: string | null): void {
  try {
    if (token) window.localStorage.setItem(TOKEN_KEY, token);
    else window.localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage unavailable (tests/private mode): auth simply does not persist */
  }
}

/**
 * A failed API call, reduced to what is safe to show and act on.
 *
 * Step 31: only the server's stable machine-readable `error.code` is
 * retained. The response body, any `detail`/`message` field, headers and
 * the request itself are deliberately discarded, so a backend message can
 * never be rendered verbatim into the DOM or leak into a log. The raw
 * token is never attached to the error either.
 */
export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status: number) {
    super(code);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

/** A short, human-readable sentence for an unknown failure. */
export function safeErrorText(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    // Render the code, never a server message. The mapping is exhaustive
    // so a new server code degrades to the fallback rather than leaking.
    switch (error.code) {
      case "AUTH_REQUIRED":
        return "Your session has expired. Sign in again.";
      case "PERMISSION_DENIED":
        return "Your account is not permitted to perform this action.";
      case "VALIDATION_ERROR":
        return "The request was rejected as invalid.";
      case "RATE_LIMITED":
        return "Too many requests. Wait a moment and try again.";
      case "PAYLOAD_TOO_LARGE":
        return "The request was too large.";
      case "INVALID_TRANSITION":
        return "That action is not valid in the current state.";
      case "TARGET_NOT_SUPPORTED":
        return "That target is not supported by stored evidence.";
      case "ACTION_NOT_PERMITTED":
        return "That action type is not allowed.";
      case "INTERNAL_ERROR":
        return "The server could not complete the request.";
      default:
        return fallback;
    }
  }
  return fallback;
}

async function request<T>(
  path: string,
  init?: RequestInit,
  timeoutMs = 30000,
): Promise<T> {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const token = storedToken();
    const response = await fetch(`${API_BASE}${path}`, {
      signal: controller.signal,
      ...init,
      headers: {
        Accept: "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(init?.headers ?? {}),
      },
    });
    if (!response.ok) {
      // Step 31: only the server's stable machine code survives. The body
      // is parsed solely to read `error.code`; nothing else is kept, so a
      // backend message can never reach the DOM.
      let code = `HTTP_${response.status}`;
      try {
        const body = (await response.json()) as {
          error?: { code?: string };
        };
        if (body?.error?.code) code = String(body.error.code);
      } catch {
        /* non-JSON error body: keep the HTTP-derived code */
      }
      throw new ApiError(code, response.status);
    }
    return (await response.json()) as T;
  } catch (err) {
    if (err instanceof ApiError) throw err;
    // Step 31: an aborted/timed-out request and any transport failure
    // surface as one opaque, non-leaking error rather than whatever the
    // browser produced.
    throw new ApiError("REQUEST_FAILED", 0);
  } finally {
    window.clearTimeout(timer);
  }
}

export const api = {
  getReadiness: () => request<ReadinessStatus>("/api/v1/ready"),
  getAssets: (params?: { ip?: string; limit?: number; offset?: number }) => {
    const query = new URLSearchParams();
    if (params?.ip) query.set("ip", params.ip);
    query.set("limit", String(params?.limit ?? 50));
    query.set("offset", String(params?.offset ?? 0));
    return request<AssetPage>(`/api/v1/assets?${query.toString()}`);
  },
  getAsset: (id: string) => request<AssetDetail>(`/api/v1/assets/${encodeURIComponent(id)}`),
  /** Step 36: aggregate finding risk for one asset (server-capped, read-only). */
  getAssetVulnRisk: (id: string) =>
    request<AssetVulnRisk>(`/api/v1/assets/${encodeURIComponent(id)}/vuln-risk`),
  getInventorySummary: () => request<InventorySummary>("/api/v1/assets/summary"),
  getNmapStatus: () => request<NmapStatus>("/api/v1/network/nmap/status"),
  createScan: (target: string, scan_profile: ScanProfile, requested_by = "operator") =>
    request<ScanJob>("/api/v1/network/scans", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ target, scan_profile, requested_by }),
    }),
  previewScan: (target: string, scan_profile: ScanProfile) =>
    request<ScanPreview>("/api/v1/network/scans/preview", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ target, scan_profile, requested_by: "operator" }),
    }),
  listScans: (limit = 20) => request<ScanJob[]>(`/api/v1/network/scans?limit=${limit}`),
  getScan: (id: string) => request<ScanJob>(`/api/v1/network/scans/${encodeURIComponent(id)}`),
  cancelScan: (id: string) =>
    request<ScanJob>(`/api/v1/network/scans/${encodeURIComponent(id)}/cancel`, {
      method: "POST",
      headers: { Accept: "application/json" },
    }),
  getEvents: (params?: {
    severity?: string;
    source_type?: string;
    /** Step 36: backend matches SecurityEvent.asset_id exactly. */
    asset_id?: string;
    limit?: number;
    offset?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.severity) query.set("severity", params.severity);
    if (params?.source_type) query.set("source_type", params.source_type);
    if (params?.asset_id) query.set("asset_id", params.asset_id);
    query.set("limit", String(params?.limit ?? 50));
    query.set("offset", String(params?.offset ?? 0));
    return request<EventPage>(`/api/v1/events?${query.toString()}`);
  },
  getEvent: (id: string) => request<SecurityEventInfo>(`/api/v1/events/${encodeURIComponent(id)}`),
  getEventSummary: () => request<EventSummary>("/api/v1/events/summary"),
  /** Phase 2, Step 9: read-only SOC overview roll-up. */
  getSocOverview: (limit?: number) =>
    request<SocOverview>(limit === undefined ? "/api/v1/overview" : `/api/v1/overview?limit=${limit}`),
  getConnectors: () => request<ConnectorPage>("/api/v1/events/connectors"),
  /** Step 28: read-only ingestion observability (no polling side effects). */
  getIngestionStatus: () => request<IngestionStatus>("/api/v1/events/ingestion/status"),
  getIngestionCheckpoints: () =>
    request<{ items: IngestionCheckpoint[] }>("/api/v1/events/ingestion/checkpoints"),
  pollConnector: (source: string) =>
    request<PollResult>(`/api/v1/events/connectors/${encodeURIComponent(source)}/poll`, {
      method: "POST",
      headers: { Accept: "application/json" },
    }),
  checkConnector: (source: string) =>
    request<ConnectorStatus>(
      `/api/v1/events/connectors/${encodeURIComponent(source)}/check`,
      {
        method: "POST",
        headers: { Accept: "application/json" },
      },
    ),
  getCorrelations: (params?: { status?: string; severity?: string; limit?: number; offset?: number }) => {
    const query = new URLSearchParams();
    if (params?.status) query.set("status", params.status);
    if (params?.severity) query.set("severity", params.severity);
    query.set("limit", String(params?.limit ?? 50));
    query.set("offset", String(params?.offset ?? 0));
    return request<CorrelationPage>(`/api/v1/correlations?${query.toString()}`);
  },
  getCorrelation: (id: string) =>
    request<CorrelationDetail>(`/api/v1/correlations/${encodeURIComponent(id)}`),
  getAttackChain: (id: string) =>
    request<AttackChain>(`/api/v1/correlations/${encodeURIComponent(id)}/attack-chain`),
  recomputeCorrelations: () =>
    request<{ events_scanned: number; rules_evaluated: number; created: number; refreshed: number; correlation_ids: string[] }>(
      "/api/v1/correlations/recompute",
      { method: "POST", headers: { Accept: "application/json" } },
    ),
  getRisk: (params?: { entity_type?: string; severity?: string; limit?: number; offset?: number }) => {
    const query = new URLSearchParams();
    if (params?.entity_type) query.set("entity_type", params.entity_type);
    if (params?.severity) query.set("severity", params.severity);
    query.set("limit", String(params?.limit ?? 50));
    query.set("offset", String(params?.offset ?? 0));
    return request<RiskPage>(`/api/v1/risk?${query.toString()}`);
  },
  getRiskDetail: (entityType: string, entityId: string) =>
    request<RiskAssessment>(
      `/api/v1/risk/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}`,
    ),
  calculateIncidentRisk: (id: string) =>
    request<RiskAssessment>(`/api/v1/risk/incidents/${encodeURIComponent(id)}/calculate`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }),
  recomputeRisk: () =>
    request<RiskRecomputeResult>(
      "/api/v1/risk/recompute",
      { method: "POST", headers: { Accept: "application/json" } },
    ),
  getIncidents: (params?: {
    status?: string;
    severity?: string;
    incident_type?: string;
    limit?: number;
    offset?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.status) query.set("status", params.status);
    if (params?.severity) query.set("severity", params.severity);
    if (params?.incident_type) query.set("incident_type", params.incident_type);
    query.set("limit", String(params?.limit ?? 50));
    query.set("offset", String(params?.offset ?? 0));
    return request<IncidentPage>(`/api/v1/incidents?${query.toString()}`);
  },
  getIncident: (id: string) => request<IncidentDetail>(`/api/v1/incidents/${encodeURIComponent(id)}`),
  getIncidentEvidence: (id: string) =>
    request<IncidentEvidence>(`/api/v1/incidents/${encodeURIComponent(id)}/evidence`),  getIncidentTimeline: (id: string) =>
    request<IncidentTimeline>(`/api/v1/incidents/${encodeURIComponent(id)}/timeline`),
  getIncidentAudit: (id: string) =>
    request<IncidentAuditTrail>(`/api/v1/incidents/${encodeURIComponent(id)}/audit`),
  /**
   * Step 45: incident-scoped controlled-response activity. Read-only and
   * bounded: filters are applied server-side and the response echoes the
   * filters actually used. No global/cross-incident feed exists.
   */
  getIncidentActivity: (
    id: string,
    params?: {
      event?: string;
      actor?: string;
      since?: string;
      until?: string;
      action_id?: string;
      limit?: number;
      offset?: number;
    },
  ) => {
    const query = new URLSearchParams();
    if (params?.event) query.set("event", params.event);
    if (params?.actor) query.set("actor", params.actor);
    if (params?.since) query.set("since", params.since);
    if (params?.until) query.set("until", params.until);
    if (params?.action_id) query.set("action_id", params.action_id);
    query.set("limit", String(params?.limit ?? 50));
    query.set("offset", String(params?.offset ?? 0));
    return request<IncidentActivityPage>(
      `/api/v1/incidents/${encodeURIComponent(id)}/activity?${query.toString()}`,
    );
  },
  /** Step 29: stored deterministic relationships (bounded, read-only). */
  getIncidentRelationships: (
    id: string,
    params?: { rule_id?: string; limit?: number; offset?: number },
  ) => {
    const query = new URLSearchParams();
    if (params?.rule_id) query.set("rule_id", params.rule_id);
    query.set("limit", String(params?.limit ?? 50));
    query.set("offset", String(params?.offset ?? 0));
    return request<IncidentRelationshipsPage>(
      `/api/v1/incidents/${encodeURIComponent(id)}/relationships?${query.toString()}`,
    );
  },
  /** Step 29: parameter-free recalculate — the server accepts no rules or thresholds. */
  recalculateIncident: (id: string) =>
    request<IncidentRecalculateResult>(
      `/api/v1/incidents/${encodeURIComponent(id)}/recalculate`,
      { method: "POST", headers: { Accept: "application/json" } },
    ),
  login: async (username: string, password: string) => {
    const body = await request<LoginToken>("/api/v1/auth/login", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    storeToken(body.access_token);
    return body;
  },
  logout: async () => {
    try {
      await request<{ logged_out: boolean }>("/api/v1/auth/logout", { method: "POST" });
    } finally {
      storeToken(null);
    }
  },
  me: () => request<AuthUser>("/api/v1/auth/me"),
  getAuthToken: storedToken,
  clearAuthToken: () => storeToken(null),
  getIncidentResponses: (id: string) =>
    request<ResponsePage>(`/api/v1/incidents/${encodeURIComponent(id)}/responses?limit=100`),
  proposeIncidentResponse: (id: string, action_type: string, reason: string) =>
    request<ResponseProposal>(`/api/v1/incidents/${encodeURIComponent(id)}/responses`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ action_type, reason, requested_by: "operator" }),
    }),
  runIncidentDetect: () =>
    request<IncidentDetectResult>("/api/v1/incidents/detect", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({}),
    }),
  updateIncidentStatus: (id: string, status: string) =>
    request<IncidentDetail>(`/api/v1/incidents/${encodeURIComponent(id)}/status`, {
      method: "PATCH",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    }),
  getResponses: (params?: { status?: string; action_type?: string; limit?: number; offset?: number }) => {
    const query = new URLSearchParams();
    if (params?.status) query.set("status", params.status);
    if (params?.action_type) query.set("action_type", params.action_type);
    query.set("limit", String(params?.limit ?? 50));
    query.set("offset", String(params?.offset ?? 0));
    return request<ResponsePage>(`/api/v1/responses?${query.toString()}`);
  },
  getResponse: (id: string) => request<ResponseDetail>(`/api/v1/responses/${encodeURIComponent(id)}`),
  /**
   * Step 42A: read-only audit history for one action (v2). This path is
   * read-only on the server: it transitions nothing and writes no audit
   * row. `detail` is returned only where the server recorded it.
   */
  getResponseAudit: (id: string, params?: { limit?: number; offset?: number }) => {
    const query = new URLSearchParams();
    query.set("limit", String(params?.limit ?? 50));
    query.set("offset", String(params?.offset ?? 0));
    return request<ResponseAuditPage>(
      `/api/v2/responses/${encodeURIComponent(id)}/audit?${query.toString()}`,
    );
  },
  decideResponse: (
    id: string,
    decision: "approve" | "reject" | "cancel",
    actor = "operator",
    reason?: string,
  ) =>
    request<ResponseProposal>(`/api/v1/responses/${encodeURIComponent(id)}/${decision}`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      // Step 41: the rationale is optional and is only meaningful for a
      // rejection. Omitted entirely when absent so older server builds and
      // callers that never send a reason are unaffected.
      body: JSON.stringify(reason ? { actor, reason } : { actor }),
    }),
  dryRunResponse: (id: string) =>
    request<DryRunResult>(`/api/v1/responses/${encodeURIComponent(id)}/dry-run`, {
      method: "POST",
      headers: { Accept: "application/json" },
    }),
  previewResponse: (id: string) =>
    request<AdapterPreview>(`/api/v1/responses/${encodeURIComponent(id)}/preview`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ actor: "operator" }),
    }),
  executeResponse: (id: string) =>
    request<ExecutionRecord>(`/api/v1/responses/${encodeURIComponent(id)}/execute`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ actor: "operator" }),
    }),

  // -- Step 30: controlled defensive responses -------------------------------
  // The client chooses an allow-listed action and an allow-listed target.
  // It never chooses a provider, a policy, an approval, or a state, and
  // there is deliberately no call that takes a command, URL, or script.
  requestControlledResponse: (payload: ControlledRequest) =>
    request<ResponseProposal>("/api/v1/responses/controlled", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }),
  getResponsePolicy: (id: string) =>
    request<ResponsePolicy>(`/api/v1/responses/${encodeURIComponent(id)}/policy`),
  providerPreviewResponse: (id: string) =>
    request<ProviderDryRun>(`/api/v1/responses/${encodeURIComponent(id)}/provider-preview`, {
      method: "POST",
      headers: { Accept: "application/json" },
    }),
  rollbackResponse: (id: string) =>
    request<RollbackRecord>(`/api/v1/responses/${encodeURIComponent(id)}/rollback`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ actor: "operator" }),
    }),
  getIncidentResponseRecommendations: (id: string) =>
    request<ResponseRecommendations>(
      `/api/v1/incidents/${encodeURIComponent(id)}/response-recommendations?limit=50`,
    ),

  // -- Step 40: response center (read-only) ----------------------------------
  // A single aggregated GET. There is deliberately no call here that
  // approves, executes, rolls back, or requests anything: the center only
  // reads stored state and links to /response for every interaction.
  getResponseCenterSummary: (params?: { limit?: number; offset?: number }) => {
    const query = new URLSearchParams();
    query.set("limit", String(params?.limit ?? 100));
    query.set("offset", String(params?.offset ?? 0));
    return request<ResponseCenterSummary>(`/api/v1/responses/summary?${query.toString()}`);
  },
  getVulnerabilities: (params?: {
    severity?: string;
    status?: string;
    asset_id?: string;
    limit?: number;
    offset?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.severity) query.set("severity", params.severity);
    if (params?.status) query.set("status", params.status);
    if (params?.asset_id) query.set("asset_id", params.asset_id);
    query.set("limit", String(params?.limit ?? 50));
    query.set("offset", String(params?.offset ?? 0));
    return request<VulnerabilityPage>(`/api/v1/vulnerabilities?${query.toString()}`);
  },
  getVulnerability: (id: string, params?: { limit?: number; offset?: number }) => {
    const query = new URLSearchParams();
    if (typeof params?.limit === "number") query.set("limit", String(params.limit));
    if (typeof params?.offset === "number") query.set("offset", String(params.offset));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<VulnerabilityDetail>(
      `/api/v1/vulnerabilities/${encodeURIComponent(id)}${suffix}`,
    );
  },
  getVulnerabilityRisk: (id: string) =>
    request<FindingRisk>(`/api/v1/vulnerabilities/${encodeURIComponent(id)}/risk`),
  getVulnerabilityLinks: (id: string) =>
    request<FindingLinks>(`/api/v1/vulnerabilities/${encodeURIComponent(id)}/correlations`),
  updateVulnerabilityStatus: (id: string, status: string) =>
    request<VulnerabilityDetail>(`/api/v1/vulnerabilities/${encodeURIComponent(id)}/status`, {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    }),
  requestVulnScan: (target: string, profile: VulnScanProfile) =>
    request<VulnScanJob>("/api/v1/vulnerability-scans", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      body: JSON.stringify({ target, profile }),
    }),
};
