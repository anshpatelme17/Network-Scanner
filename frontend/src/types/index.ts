/** Shared frontend types: system status (Step 1) + asset inventory (Step 2). */

export interface ReadinessStatus {
  status: "ready" | "not_ready";
  app: string;
  version: string;
  environment: string;
  checks: Record<string, "up" | "down" | string>;
}

export type SystemState = "loading" | "online" | "degraded" | "offline";

export interface DiscoveredServiceInfo {
  id: string;
  port: number;
  protocol: string;
  state: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
  extra_info: string | null;
  discovered_at: string;
  last_seen: string;
}

export interface AssetSummary {
  id: string;
  ip_address: string;
  hostname: string | null;
  mac_address: string | null;
  operating_system: string | null;
  state: string;
  asset_type: string;
  discovery_source: string | null;
  service_count: number;
  first_seen: string;
  last_seen: string;
}

export interface AssetDetail extends AssetSummary {
  services: DiscoveredServiceInfo[];
}

export interface AssetPage {
  items: AssetSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface InventorySummary {
  total_assets: number;
  active_assets: number;
  total_services: number;
  last_scan_at: string | null;
  last_scan_status: string | null;
}

export interface ConnectorStatus {
  source: string;
  mode: string;
  state: string;
  detail: string;
  configured: Record<string, boolean>;
  last_success_at: string | null;
  /** Step 27: NOT_CONFIGURED | CONFIGURED | CONNECTING | CONNECTED |
   *  AUTH_FAILED | UNAVAILABLE | RATE_LIMITED | ERROR (optional so
   *  older payloads keep rendering). */
  connector_state?: string;
  last_check_at?: string | null;
  last_poll_at?: string | null;
  last_error_category?: string | null;
  events_retrieved?: number;
  latency_ms?: number | null;
}

export interface ConnectorPage {
  items: ConnectorStatus[];
}

export interface PollError {
  index: number;
  code: string;
  message: string;
}

export interface PollResult {
  source: string;
  accepted: number;
  duplicates: number;
  rejected: number;
  truncated: boolean;
  errors: PollError[];
  /** Step 27: bounded API-poll provenance. */
  pages?: number;
  retrieved?: number;
  termination?: string | null;
  /** Step 28: bounded pipeline provenance. */
  batches?: number;
  queue_dropped?: number;
  checkpoint_advanced?: boolean;
}

/** Server-written cursor state for one source (Step 28, read-only). */
export interface IngestionCheckpoint {
  source: string;
  cursor: Record<string, string | number | boolean | null> | null;
  last_event_time: string | null;
  last_external_event_id: string | null;
  advance_count: number;
  last_rejected_at: string | null;
  updated_at: string | null;
  created_at: string | null;
}

export interface IngestionSourceStatus {
  source: string;
  mode: string;
  state: string;
  connector_state: string;
  last_poll_at: string | null;
  last_success_at: string | null;
  last_failure_at: string | null;
  last_failure_reason: string | null;
  events_fetched: number;
  events_accepted: number;
  events_deduplicated: number;
  events_rejected: number;
  events_failed: number;
  events_dropped: number;
  retries: number;
  batches: number;
  queue_depth: number;
  checkpoint: IngestionCheckpoint | null;
}

export interface IngestionStatus {
  generated_at: string;
  pipeline: string[];
  limits: {
    max_pages: number;
    max_events: number;
    max_poll_lines: number;
    batch_size: number;
    queue_max: number;
    retry_max: number;
    timeout_seconds: number;
    file_resume: boolean;
  };
  queue: {
    max: number;
    depth: number;
    enqueued_total: number;
    dequeued_total: number;
    dropped_total: number;
    overflow: string;
  };
  streaming: {
    enabled: boolean;
    mode: string;
    detail: string;
  };
  totals: {
    fetched: number;
    accepted: number;
    deduplicated: number;
    rejected: number;
    failed: number;
    dropped: number;
    retries: number;
    batches: number;
  };
  sources: IngestionSourceStatus[];
}

export interface SecurityEventInfo {
  id: string;
  event_time: string;
  received_at: string;
  source_type: string;
  source_name: string;
  event_type: string;
  severity: string;
  title: string;
  description: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  source_port: number | null;
  destination_port: number | null;
  protocol: string | null;
  asset_id: string | null;
  hostname: string | null;
  username: string | null;
  process_name: string | null;
  action: string | null;
  status: string | null;
  confidence: number | null;
  occurrence_count: number;
  last_seen_at: string | null;
  ingest_mode: string;
  raw_event: Record<string, unknown> | null;
  normalized_data: Record<string, unknown>;
  correlation_key: string | null;
  fingerprint: string;
  external_event_id: string | null;
  created_at: string;
}

export interface EventPage {
  items: SecurityEventInfo[];
  total: number;
  limit: number;
  offset: number;
}

export interface EventSummary {
  total_events: number;
  critical_events: number;
  high_events: number;
  last_24h_events: number;
}

export interface CorrelationSummary {
  id: string;
  rule_id: string;
  rule_name: string;
  title: string;
  status: string;
  severity: string;
  confidence: number;
  /** Step 29: deterministic label for the rule confidence (DIRECT/STRONG/MODERATE/WEAK). */
  confidence_label?: string;
  primary_ip: string | null;
  hostname: string | null;
  event_count: number;
  window_start: string;
  window_end: string;
  created_at: string;
  updated_at: string;
}

export interface CorrelationEvidenceItem {
  event_id: string;
  role: string;
  position: number;
  event_type: string;
  source_type: string;
  severity: string;
  title: string;
  event_time: string;
  source_ip: string | null;
  destination_ip: string | null;
}

export interface CorrelationDetail extends CorrelationSummary {
  description: string | null;
  explanation: string;
  evidence: CorrelationEvidenceItem[];
}

export interface CorrelationPage {
  items: CorrelationSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface ChainNode {
  id: string;
  kind: string;
  label: string;
  detail: Record<string, string>;
}

export interface ChainEdge {
  source: string;
  target: string;
  relation: string;
}

export interface AttackChain {
  correlation_id: string;
  nodes: ChainNode[];
  edges: ChainEdge[];
}

export interface RiskAssessment {
  id: string;
  entity_type: string;
  entity_id: string;
  score: number;
  severity: string;
  priority: string;
  factors: Record<string, unknown>;
  explanation: string;
  calculated_at: string;
  scoring_version: string;
}

export interface RiskPage {
  items: RiskAssessment[];
  total: number;
  limit: number;
  offset: number;
}

export interface RiskRecomputeResult {
  assessed: number;
  created: number;
  updated: number;
  scoring_version: string;
}

export interface IncidentSummary {
  id: string;
  incident_key: string;
  title: string;
  status: string;
  severity: string;
  confidence: number;
  primary_asset_id: string | null;
  primary_ip: string | null;
  hostname: string | null;
  correlation_id: string;
  risk_assessment_id: string | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  created_at: string;
  updated_at: string;
  version: string;
  incident_type: string;
  risk_score: number | null;
  detection_reason: string | null;
}

export interface IncidentDetail extends IncidentSummary {
  description: string | null;
  evidence_event_ids: string[];
}

export interface IncidentEvidenceEvent {
  id: string;
  event_type: string;
  severity: string;
  source_type: string;
  title: string;
  event_time: string;
  role: string | null;
  reason: string | null;
}

export interface IncidentEvidenceVulnerability {
  id: string;
  title: string;
  severity: string;
  status: string;
  cve_id: string | null;
  reason: string | null;
}

export interface IncidentEvidenceCorrelation {
  id: string;
  rule_id: string;
  rule_name: string;
  severity: string;
  confidence: number;
  explanation: string;
}

export interface IncidentEvidenceAsset {
  id: string;
  ip_address: string;
  hostname: string | null;
}

/** Step 29: explicitly stored entity values (never inferred, may be empty). */
export interface IncidentEvidenceEntities {
  source_ips: string[];
  destination_ips: string[];
  hostnames: string[];
  usernames: string[];
}

/** Step 29: rule contribution overview for one incident. */
export interface IncidentEvidenceRule {
  rule_id: string;
  rule_name: string;
  confidence: number;
  confidence_label: string;
  relationship_count: number;
}

export interface IncidentEvidence {
  incident_id: string;
  incident_type: string;
  detection_reason: string | null;
  correlation: IncidentEvidenceCorrelation | null;
  events: IncidentEvidenceEvent[];
  vulnerabilities: IncidentEvidenceVulnerability[];
  /** Step 29 additive overview (optional so Step 11/17/24 payloads still render). */
  evidence_count?: number;
  truncated?: boolean;
  primary_event?: { id: string; role: string; title?: string } | null;
  source_distribution?: Record<string, number>;
  entities?: IncidentEvidenceEntities;
  assets?: IncidentEvidenceAsset[];
  first_observed?: string | null;
  last_observed?: string | null;
  correlation_rules?: IncidentEvidenceRule[];
}

export interface IncidentTimelineEntry {
  at: string | null;
  kind: string;
  label: string;
  detail: string | null;
  /** Step 29: present on kind == "event" entries (canonical event reference). */
  event_id?: string;
  event_type?: string;
  source?: string;
  severity?: string;
  entity?: string | null;
  explanation?: string | null;
}

export interface IncidentTimeline {
  incident_id: string;
  entries: IncidentTimelineEntry[];
  truncated?: boolean;
}

/** Step 29: one stored deterministic relationship (evidence references only). */
export interface IncidentRelationshipItem {
  id: string;
  incident_id: string;
  rule_id: string;
  rule_name: string;
  relation: string;
  source_kind: string;
  source_id: string;
  source_label: string | null;
  target_kind: string;
  target_id: string;
  target_label: string | null;
  confidence: number;
  confidence_label: string;
  explanation: string;
  evidence_event_ids: string[];
  first_seen: string;
  last_seen: string;
}

export interface IncidentRelationshipsPage {
  incident_id: string;
  items: IncidentRelationshipItem[];
  total: number;
  limit: number;
  offset: number;
}

/** Step 29: result of the parameter-free, bounded recalculate operation. */
export interface IncidentRecalculateResult {
  incident_id: string;
  analysis_version: string;
  rules_evaluated: number;
  events_considered: number;
  relationships_created: number;
  relationships_refreshed: number;
  relationships_total: number;
  truncated: boolean;
  bounds: Record<string, number>;
}

export interface IncidentAuditEntry {
  action: string;
  actor: string;
  detail: string | null;
  created_at: string;
}

export interface IncidentAuditTrail {
  incident_id: string;
  entries: IncidentAuditEntry[];
}

export interface IncidentDetectOutcome {
  correlation_id: string;
  incident_id: string | null;
  created: boolean;
  reason: string;
}

export interface IncidentDetectResult {
  evaluated: number;
  created: number;
  updated: number;
  skipped: number;
  detector_version: string;
  outcomes: IncidentDetectOutcome[];
}

export interface IncidentPage {
  items: IncidentSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface ResponseAuditEntry {
  id: string;
  event: string;
  previous_status: string | null;
  new_status: string | null;
  actor: string;
  policy_version: string;
  created_at: string;
}

export interface ResponseProposal {
  id: string;
  incident_id: string;
  action_type: string;
  target_type: string;
  target_reference: string;
  reason: string;
  requested_by: string;
  status: string;
  dry_run: boolean;
  policy_version: string;
  execution_status: string | null;
  created_at: string;
  approved_at: string | null;
  expires_at: string | null;
  approved_by: string | null;
  started_at: string | null;
  completed_at: string | null;
  failure_reason: string | null;
  result_summary: string | null;
  // Step 30: controlled-response governance state. Always present so the
  // UI has one shape; a Step 12-19 proposal reports the dry-run-only
  // defaults and therefore never implies a controlled capability.
  provider: string;
  policy_decision: string;
  approval_required: boolean;
  rollback_supported: boolean;
  rollback_state: string | null;
  rollback_reference: string | null;
  target_evidence: string[];
}

export interface ExecutionRecord {
  id: string;
  action_id: string;
  incident_id: string;
  adapter: string;
  dry_run: boolean;
  would_execute: boolean;
  result: string;
  explanation: string;
  policy_version: string;
  simulated_at: string;
}

export interface ResponseDetail extends ResponseProposal {
  audit: ResponseAuditEntry[];
  execution: ExecutionRecord | null;
  rollback: RollbackRecord | null;
}

// ---------------------------------------------------------------------------
// Step 30: controlled defensive responses
// ---------------------------------------------------------------------------

export const CONTROLLED_ACTION_TYPES = [
  "BLOCK_INDICATOR",
  "DISABLE_INDICATOR_BLOCK",
  "ISOLATE_ENDPOINT",
  "RELEASE_ENDPOINT",
  "DISABLE_ACCOUNT",
  "ENABLE_ACCOUNT",
] as const;

export type ControlledActionType = (typeof CONTROLLED_ACTION_TYPES)[number];

export interface ControlledRequest {
  incident_id: string;
  action_type: string;
  target_type: string;
  target_reference: string;
  reason: string;
  requested_by: string;
  ttl_minutes?: number;
}

export interface ResponsePolicy {
  action_id: string;
  decision: "NOT_ALLOWED" | "DRY_RUN_ONLY" | "APPROVAL_REQUIRED" | "ALLOWED_WITH_APPROVAL";
  approval_required: boolean;
  provider: string;
  provider_capable: boolean;
  target_proven: boolean;
  evidence_event_ids: string[];
  expires_at: string | null;
  reason: string;
  policy_version: string;
}

export interface ProviderDryRun {
  action_id: string;
  incident_id: string;
  action_type: string;
  target: string;
  provider: string;
  dry_run: boolean;
  would_execute: boolean;
  executed: boolean;
  result: string;
  explanation: string;
  changes: string[];
  evidence_event_ids: string[];
  policy_decision: string;
  policy_reason: string;
  expires_at: string | null;
  policy_version: string;
  governance_version: string;
}

export interface RollbackRecord {
  id: string;
  action_id: string;
  incident_id: string;
  provider: string;
  result: string;
  explanation: string;
  policy_version: string;
  created_at: string;
}

export interface ResponseRecommendation {
  action_type: string;
  target_type: string;
  target_reference: string;
  incident_id: string;
  incident_key: string;
  severity: string;
  risk_priority: string;
  available: boolean;
  provider: string;
  evidence_event_ids: string[];
  reason: string;
  requires_approval: boolean;
  automatic: boolean;
}

export interface ResponseRecommendations {
  incident_id: string;
  incident_key: string;
  severity: string;
  risk_score: number | null;
  risk_priority: string;
  items: ResponseRecommendation[];
  total: number;
  truncated: boolean;
  policy_version: string;
  governance_version: string;
}

export interface ResponsePage {
  items: ResponseProposal[];
  total: number;
  limit: number;
  offset: number;
}

export interface DryRunResult {
  action_id: string;
  action_type: string;
  target: string;
  dry_run: boolean;
  would_execute: boolean;
  result: string;
  explanation: string;
  policy_version: string;
}

export interface PreviewEvidence {
  kind: string;
  reference: string;
  detail: string | null;
}

export interface AdapterPreview {
  action_id: string;
  incident_id: string;
  adapter_type: string;
  accepted: boolean;
  executed: boolean;
  simulated: boolean;
  would_execute: boolean;
  status: string;
  result_summary: string;
  evidence: PreviewEvidence[];
  policy_decision: string;
  policy_version: string;
}

export interface AuthUser {
  id: string;
  username: string;
  display_name: string;
  is_active: boolean;
  roles: string[];
  permissions: string[];
}

export interface LoginToken {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
}

export interface VulnerabilityAuditEntry {
  event: string;
  actor: string;
  previous_status: string | null;
  new_status: string | null;
  created_at: string;
  detail: string | null;
}

export interface VulnerabilitySummary {
  id: string;
  asset_id: string;
  service_id: string | null;
  scanner: string;
  scanner_version: string | null;
  scanner_finding_id: string;
  title: string;
  severity: string;
  cvss_score: number | null;
  cve_id: string | null;
  hostname: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  status: string;
  first_seen: string;
  last_seen: string;
}

export interface VulnerabilityDetail extends VulnerabilitySummary {
  description: string | null;
  cwe_id: string | null;
  affected_component: string | null;
  detected_version: string | null;
  fixed_version: string | null;
  evidence: string | null;
  remediation_reference: string | null;
  extra_data: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  audit: VulnerabilityAuditEntry[];
}

export type VulnScanProfile =
  | "BASELINE_VULNERABILITY_ASSESSMENT"
  | "SERVICE_VULNERABILITY_ASSESSMENT"
  | "BASIC"
  | "STANDARD";

export interface VulnScanJob {
  id: string;
  target: string;
  profile: string;
  scanner: string | null;
  status: string;
  result_summary: string | null;
  error: string | null;
  completed_at: string | null;
}

export interface VulnerabilityPage {
  items: VulnerabilitySummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface FindingRisk {
  id: string;
  entity_type: string;
  entity_id: string;
  score: number;
  severity: string;
  factors: Record<string, unknown>;
  explanation: string;
  calculated_at: string;
  scoring_version: string;
}

export interface LinkedRecord {
  id: string;
  event_type?: string;
  source_type?: string;
  severity?: string;
  title?: string;
  event_time?: string;
  incident_key?: string;
  status?: string;
}

export interface FindingLinks {
  vulnerability_id: string;
  asset_id: string;
  service_id: string | null;
  related_events: LinkedRecord[];
  related_incidents: LinkedRecord[];
  reasons: string[];
}

export type ScanProfile = "quick" | "standard" | "DISCOVERY_PING" | "DISCOVERY_TCP_COMMON";

export interface ScanPreview {
  target: string;
  profile: string;
  profile_description: string;
  probes_ports: boolean;
  address_count: number;
  scope_authorized: boolean;
  nmap_available: boolean;
  timeout_seconds: number;
}
export type ScanStatus = "queued" | "running" | "completed" | "failed";

export interface ScanJob {
  id: string;
  target: string;
  profile: string;
  scan_type: string;
  requested_by: string;
  status: ScanStatus | string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error: string | null;
  assets_found: number;
  services_found: number;
  result_summary: string | null;
  nmap_version: string | null;
  audit: Array<{ event: string; actor: string; detail: string | null; created_at: string }>;
}

export interface NmapStatus {
  available: boolean;
  version: string | null;
  profiles: string[];
}

/**
 * SOC overview (Phase 2, Step 9) — `GET /api/v1/overview`.
 * Field-for-field mirrors `app/schemas/soc.py`. Counts, bounded integers,
 * stored identifiers, ISO timestamps, scores and fixed enum labels only:
 * the payload carries no event payload, configuration value or credential.
 */
export interface OverviewCounts {
  assets_total: number;
  assets_active: number;
  services_total: number;
  events_total: number;
  correlations_total: number;
  incidents_total: number;
  incidents_open: number;
  risk_assessments_total: number;
  vulnerabilities_open: number;
  response_actions_total: number;
  response_actions_pending_approval: number;
}

export interface OverviewIncident {
  id: string;
  incident_key: string;
  title: string;
  status: string;
  severity: string;
  confidence: number;
  risk_score: number | null;
  priority: string | null;
  primary_asset_id: string | null;
  primary_ip: string | null;
  hostname: string | null;
  correlation_id: string;
  first_seen: string;
  last_seen: string;
}

export interface OverviewAudit {
  id: string;
  action: string;
  actor: string;
  event_id: string | null;
  detail: string;
  created_at: string;
}

export interface OverviewConnector {
  source: string;
  mode: string;
  state: string;
  connector_state: string;
  last_check_at: string | null;
  last_poll_at: string | null;
  last_error_category: string | null;
  events_retrieved: number;
}

export interface OverviewLimits {
  max_items: number;
  requested_items: number;
}

export interface SocOverview {
  generated_at: string;
  version: string;
  counts: OverviewCounts;
  incidents_by_severity: Record<string, number>;
  incidents_by_priority: Record<string, number>;
  top_incidents: OverviewIncident[];
  recent_audit: OverviewAudit[];
  connectors: OverviewConnector[];
  limits: OverviewLimits;
  disclaimer: string;
}
