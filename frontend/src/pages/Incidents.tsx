import { useCallback, useEffect, useState } from "react";
import { IncidentTimeline as IncidentTimelineSection } from "../components/incidents/IncidentTimeline";
import { ApiError, api } from "../services/api";
import type {
  IncidentAuditTrail,
  IncidentDetail,
  IncidentEvidence,
  IncidentRelationshipsPage,
  IncidentSummary,
  IncidentTimeline,
  ResponsePage,
  ResponseProposal,
  ResponseRecommendation,
  ResponseRecommendations,
  RiskAssessment,
} from "../types";

const SAFE_RESPONSE_ACTIONS = [
  "REVIEW",
  "COLLECT_EVIDENCE",
  "MARK_FOR_INVESTIGATION",
  "ACKNOWLEDGE",
  "CLOSE",
];

function responseTone(status: string): string {
  switch (status) {
    case "APPROVED":
    case "COMPLETED":
      return "ok";
    case "REJECTED":
    case "CANCELLED":
    case "FAILED":
      return "bad";
    default:
      return "neutral";
  }
}

const STATUSES = ["", "OPEN", "ACKNOWLEDGED", "INVESTIGATING", "RESOLVED", "CLOSED"];
const TYPES = [
  "",
  "VULNERABILITY_ACTIVITY",
  "SUSPICIOUS_NETWORK_ACTIVITY",
  "AUTHENTICATION_ANOMALY",
  "MALWARE_INDICATOR",
  "POLICY_VIOLATION",
  "CORRELATED_SECURITY_EVENT",
  "OTHER",
];
const NEXT_STATUS: Record<string, string[]> = {
  OPEN: ["ACKNOWLEDGED", "CLOSED"],
  ACKNOWLEDGED: ["INVESTIGATING", "CLOSED"],
  INVESTIGATING: ["RESOLVED", "CLOSED"],
  RESOLVED: ["CLOSED"],
  CLOSED: [],
};

function formatDateTime(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function severityTone(severity: string): string {
  switch (severity) {
    case "CRITICAL":
      return "bad";
    case "HIGH":
    case "MEDIUM":
      return "warn";
    default:
      return "neutral";
  }
}

/**
 * Phase 3, Step 34: the incident detail is organized as an analyst
 * investigation workspace. Every independently loaded section carries its
 * own state, so a failure or a permission denial in one section never
 * erases the unrelated sections that succeeded.
 */
type SectionState = "loading" | "ready" | "error" | "denied";

function isDenied(err: unknown): boolean {
  return (
    err instanceof ApiError &&
    (err.code === "PERMISSION_DENIED" || err.status === 401 || err.status === 403)
  );
}

async function runSection<T>(
  fetcher: () => Promise<T>,
  isValid: (value: unknown) => boolean,
  setState: (state: SectionState) => void,
  setData: (data: T | null) => void,
): Promise<void> {
  setState("loading");
  try {
    const value = await fetcher();
    if (isValid(value)) {
      setData(value);
      setState("ready");
    } else {
      setData(null);
      setState("error");
    }
  } catch (err) {
    setData(null);
    setState(isDenied(err) ? "denied" : "error");
  }
}

function SectionNote({
  state,
  loading,
  error,
  denied,
}: {
  state: SectionState;
  loading: string;
  error: string;
  denied: string;
}) {
  if (state === "loading") return <p className="muted">{loading}</p>;
  if (state === "error") return <p className="muted">{error}</p>;
  if (state === "denied") return <p className="muted">{denied}</p>;
  return null;
}

/** Incident management (Steps 11 + 17 + 29 ...): read + status only, organized as a SOC investigation workspace (Step 34). */
export function Incidents() {
  const [items, setItems] = useState<IncidentSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [selected, setSelected] = useState<IncidentDetail | null>(null);
  const [evidence, setEvidence] = useState<IncidentEvidence | null>(null);
  const [relationships, setRelationships] = useState<IncidentRelationshipsPage | null>(null);
  const [analysisNotice, setAnalysisNotice] = useState<string | null>(null);
  const [timeline, setTimeline] = useState<IncidentTimeline | null>(null);
  const [audit, setAudit] = useState<IncidentAuditTrail | null>(null);
  const [responses, setResponses] = useState<ResponseProposal[]>([]);
  const [recommendations, setRecommendations] = useState<ResponseRecommendation[]>([]);
  const [incidentRisk, setIncidentRisk] = useState<RiskAssessment | null>(null);
  const [proposeType, setProposeType] = useState("REVIEW");
  const [proposeReason, setProposeReason] = useState("");
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [notice, setNotice] = useState<string | null>(null);

  const [evidenceState, setEvidenceState] = useState<SectionState>("loading");
  const [relationshipsState, setRelationshipsState] = useState<SectionState>("loading");
  const [timelineState, setTimelineState] = useState<SectionState>("loading");
  const [auditState, setAuditState] = useState<SectionState>("loading");
  const [responsesState, setResponsesState] = useState<SectionState>("loading");
  const [recommendationsState, setRecommendationsState] = useState<SectionState>("loading");
  const [riskState, setRiskState] = useState<SectionState>("loading");

  const load = useCallback(
    async (statusValue: string, severityValue: string, typeValue: string) => {
      setState("loading");
      try {
        const page = await api.getIncidents({
          status: statusValue || undefined,
          severity: severityValue || undefined,
          incident_type: typeValue || undefined,
          limit: 100,
        });
        setItems(Array.isArray(page.items) ? page.items : []);
        setTotal(typeof page.total === "number" ? page.total : 0);
        setState("ready");
      } catch {
        setState("error");
      }
    },
    [],
  );

  useEffect(() => {
    void load("", "", "");
  }, [load]);

  const openDetail = async (id: string) => {
    try {
      setSelected(await api.getIncident(id));
      setNotice(null);
    } catch {
      setSelected(null);
      return;
    }
    // Every investigation section loads independently underneath. A failure
    // or denial in one never erases the sections that succeeded.
    void runSection(
      () => api.getIncidentEvidence(id),
      (value) =>
        value !== null && typeof value === "object" && Array.isArray((value as IncidentEvidence).events),
      setEvidenceState,
      setEvidence,
    );
    void runSection(
      () => api.getIncidentRelationships(id),
      (value) =>
        value !== null &&
        typeof value === "object" &&
        Array.isArray((value as IncidentRelationshipsPage).items),
      setRelationshipsState,
      setRelationships,
    );
    setAnalysisNotice(null);
    void runSection(
      () => api.getIncidentTimeline(id),
      (value) =>
        value !== null && typeof value === "object" && Array.isArray((value as IncidentTimeline).entries),
      setTimelineState,
      setTimeline,
    );
    void runSection(
      () => api.getIncidentAudit(id),
      (value) =>
        value !== null && typeof value === "object" && Array.isArray((value as IncidentAuditTrail).entries),
      setAuditState,
      setAudit,
    );
    void runSection(
      () => api.getIncidentResponses(id),
      (value) =>
        value !== null && typeof value === "object" && Array.isArray((value as ResponsePage).items),
      setResponsesState,
      (page) => setResponses(page && Array.isArray(page.items) ? page.items : []),
    );
    void runSection(
      () => api.getIncidentResponseRecommendations(id),
      (value) =>
        value !== null &&
        typeof value === "object" &&
        Array.isArray((value as ResponseRecommendations).items),
      setRecommendationsState,
      (page) => setRecommendations(page && Array.isArray(page.items) ? page.items : []),
    );
    // Advisory incident risk: absence and a failed lookup both degrade to
    // the honest unscored state — the analyst can still ask the server to
    // calculate a score, and no number is ever invented here.
    setRiskState("loading");
    try {
      const assessment = await api.getRiskDetail("incident", id);
      setIncidentRisk(assessment && typeof assessment.score === "number" ? assessment : null);
    } catch {
      setIncidentRisk(null);
    } finally {
      setRiskState("ready");
    }
  };

  const changeStatus = async (id: string, next: string) => {
    setNotice(null);
    try {
      const updated = await api.updateIncidentStatus(id, next);
      setSelected({ ...updated, evidence_event_ids: selected?.evidence_event_ids ?? [] });
      await load(statusFilter, severityFilter, typeFilter);
    } catch {
      setNotice("Status change was rejected by the server.");
    }
  };

  const runDetection = async () => {
    setNotice(null);
    try {
      const result = await api.runIncidentDetect();
      setNotice(
        `Detection evaluated ${result.evaluated} correlation(s): ` +
          `${result.created} opened, ${result.updated} updated, ${result.skipped} skipped.`,
      );
      await load(statusFilter, severityFilter, typeFilter);
    } catch {
      setNotice("Detection run was rejected by the server.");
    }
  };

  const calculateRisk = async (id: string) => {
    setNotice(null);
    setRiskState("loading");
    try {
      setIncidentRisk(await api.calculateIncidentRisk(id));
    } catch {
      setNotice("Risk calculation was rejected by the server.");
    } finally {
      setRiskState("ready");
    }
  };

  /** Step 29: bounded, parameter-free server-side analysis (no client rules). */
  const recalculateAnalysis = async (id: string) => {
    setAnalysisNotice(null);
    setRelationshipsState("loading");
    try {
      const result = await api.recalculateIncident(id);
      setAnalysisNotice(
        `Analysis v${result.analysis_version}: ${result.relationships_created} created, ` +
          `${result.relationships_refreshed} refreshed, ${result.relationships_total} stored` +
          `${result.truncated ? " (truncated at the configured bound)" : ""}.`,
      );
      const page = await api.getIncidentRelationships(id);
      setRelationships(page && Array.isArray(page.items) ? page : null);
      setRelationshipsState(page && Array.isArray(page.items) ? "ready" : "error");
    } catch {
      setAnalysisNotice("Recalculation was refused by the server (permission or input).");
      setRelationshipsState("error");
    }
  };

  /** Step 35: reload just the timeline section without touching the others. */
  const reloadTimeline = async () => {
    if (!selected) return;
    await runSection(
      () => api.getIncidentTimeline(selected.id),
      (value) =>
        value !== null && typeof value === "object" && Array.isArray((value as IncidentTimeline).entries),
      setTimelineState,
      setTimeline,
    );
  };

  const requestControlledAction = async (item: ResponseRecommendation) => {
    setNotice(null);
    try {
      await api.requestControlledResponse({
        incident_id: item.incident_id,
        action_type: item.action_type,
        target_type: item.target_type,
        target_reference: item.target_reference,
        reason: item.reason.slice(0, 2000),
        requested_by: "operator",
      });
      setNotice(
        "Defensive response requested. It is now pending approval and has not been executed.",
      );
      await refreshResponses(item.incident_id);
    } catch {
      setNotice("Defensive response request was rejected by the server.");
    }
  };

  const refreshResponses = async (id: string) => {
    try {
      const page = await api.getIncidentResponses(id);
      setResponses(Array.isArray(page.items) ? page.items : []);
      setResponsesState("ready");
    } catch {
      setResponses([]);
      setResponsesState("error");
    }
    // Safe executions can move incident workflow state — refresh it.
    try {
      setSelected(await api.getIncident(id));
    } catch {
      /* keep the current detail on refresh failure */
    }
  };

  const proposeResponse = async () => {
    if (!selected) return;
    setNotice(null);
    try {
      await api.proposeIncidentResponse(selected.id, proposeType, proposeReason || "operator review");
      setProposeReason("");
      await refreshResponses(selected.id);
    } catch {
      setNotice("Response proposal was rejected by the server.");
    }
  };

  const decideResponse = async (actionId: string, decision: "approve" | "reject" | "cancel") => {
    if (!selected) return;
    setNotice(null);
    try {
      await api.decideResponse(actionId, decision);
      await refreshResponses(selected.id);
    } catch {
      setNotice("Response decision was rejected by the server.");
    }
  };

  const executeResponseAction = async (actionId: string) => {
    if (!selected) return;
    setNotice(null);
    try {
      await api.executeResponse(actionId);
      await refreshResponses(selected.id);
    } catch {
      setNotice("Response execution was refused by policy.");
    }
  };

  const closeDetail = () => {
    setSelected(null);
    setEvidence(null);
    setRelationships(null);
    setAnalysisNotice(null);
    setTimeline(null);
    setAudit(null);
    setResponses([]);
    setRecommendations([]);
    setIncidentRisk(null);
    setEvidenceState("loading");
    setRelationshipsState("loading");
    setTimelineState("loading");
    setAuditState("loading");
    setResponsesState("loading");
    setRecommendationsState("loading");
    setRiskState("loading");
  };

  const evidenceEmpty =
    selected?.evidence_event_ids.length === 0 &&
    (evidence?.vulnerabilities.length ?? 0) === 0 &&
    !evidence?.correlation &&
    (evidence?.correlation_rules?.length ?? 0) === 0 &&
    (evidence?.assets?.length ?? 0) === 0;

  return (
    <section aria-label="Incident management">
      <div className="card">
        <h3>Incidents ({total})</h3>
        <p>
          Persistent records opened from correlated activity and risk
          assessments, with an explicit status lifecycle. This page manages
          records only — it performs <strong>no response or remediation
          actions</strong> of any kind.
        </p>
        <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
          <select
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(event) => {
              setStatusFilter(event.target.value);
              void load(event.target.value, severityFilter, typeFilter);
            }}
            style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
          >
            {STATUSES.map((item) => (
              <option key={item} value={item}>
                {item === "" ? "All statuses" : item}
              </option>
            ))}
          </select>
          <select
            aria-label="Filter by severity"
            value={severityFilter}
            onChange={(event) => {
              setSeverityFilter(event.target.value);
              void load(statusFilter, event.target.value, typeFilter);
            }}
            style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
          >
            {["", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].map((level) => (
              <option key={level} value={level}>
                {level === "" ? "All severities" : level}
              </option>
            ))}
          </select>
          <select
            aria-label="Filter by type"
            value={typeFilter}
            onChange={(event) => {
              setTypeFilter(event.target.value);
              void load(statusFilter, severityFilter, event.target.value);
            }}
            style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
          >
            {TYPES.map((item) => (
              <option key={item} value={item}>
                {item === "" ? "All types" : item}
              </option>
            ))}
          </select>
          <button className="button secondary" type="button" onClick={() => void runDetection()}>
            Run detection
          </button>
        </div>
        {notice && <p className="muted">{notice}</p>}
      </div>

      {state === "loading" && <p className="muted">Loading incidents…</p>}
      {state === "error" && (
        <div className="card">
          <h3>Incidents unavailable</h3>
          <p>Could not load incidents from the API.</p>
          <button
            className="button secondary"
            type="button"
            onClick={() => void load(statusFilter, severityFilter, typeFilter)}
          >
            Retry
          </button>
        </div>
      )}
      {state === "ready" && items.length === 0 && (
        <div className="card">
          <h3>No incidents recorded.</h3>
          <p>
            Incidents are opened from existing correlations via{" "}
            <code>POST /api/v1/incidents</code> or the conservative{" "}
            <code>POST /api/v1/incidents/detect</code> detector. A vulnerability
            finding alone never opens one. Nothing here proves a host is
            compromised.
          </p>
        </div>
      )}
      {state === "ready" && items.length > 0 && (
        <div className="card" style={{ padding: 0, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                {[
                  "Key",
                  "Title",
                  "Type",
                  "Severity",
                  "Risk",
                  "Confidence",
                  "Status",
                  "Asset",
                  "Created",
                  "",
                ].map((h) => (
                    <th key={h} style={{ padding: "10px 14px", color: "var(--text-muted)" }}>
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "10px 14px" }}>
                    <strong>{item.incident_key}</strong>
                  </td>
                  <td style={{ padding: "10px 14px" }}>{item.title}</td>
                  <td style={{ padding: "10px 14px" }}>
                    <span className="badge neutral">{item.incident_type ?? "OTHER"}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <span className={`badge ${severityTone(item.severity)}`}>{item.severity}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    {item.risk_score ?? "—"}
                  </td>
                  <td style={{ padding: "10px 14px" }}>{item.confidence}</td>
                  <td style={{ padding: "10px 14px" }}>
                    <span className="badge neutral">{item.status}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>{item.primary_ip ?? "—"}</td>
                  <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                    {formatDateTime(item.created_at)}
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <button
                      className="button secondary"
                      type="button"
                      onClick={() => void openDetail(item.id)}
                    >
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <div className="card" aria-label="Incident detail">
          {/* A. Incident header / summary */}
          <h3>
            {selected.incident_key} — {selected.title}
          </h3>
          <p>
            <span className={`badge ${severityTone(selected.severity)}`}>{selected.severity}</span>{" "}
            <span className="badge neutral">{selected.status}</span>{" "}
            <span className="badge neutral">{selected.incident_type ?? "OTHER"}</span>{" "}
            <span className="muted">confidence {selected.confidence}</span>{" "}
            <span className="muted">
              risk {selected.risk_score ?? "—"}
            </span>
          </p>
          {selected.description && <p>{selected.description}</p>}
          <p className="muted">
            Severity describes the finding; risk is the linked assessment score
            (when present) — the two are distinct. This record is an
            evidence-based investigation lead, not proof of compromise.
          </p>
          <p className="muted">
            Correlation: {selected.correlation_id} · Risk: {selected.risk_assessment_id ?? "—"} ·
            Asset: {selected.primary_ip ?? "—"} · First seen{" "}
            {formatDateTime(selected.first_seen)} · Last seen {formatDateTime(selected.last_seen)} ·
            Resolved: {formatDateTime(selected.resolved_at)}
          </p>

          {/* B. What happened? */}
          <h4>What happened?</h4>
          {selected.detection_reason && (
            <p>
              <strong>Why this incident exists: </strong>
              {selected.detection_reason}
            </p>
          )}
          <p className="muted">
            Severity {selected.severity} · Confidence {selected.confidence} · Status {selected.status}{" "}
            · First seen {formatDateTime(selected.first_seen)} · Last seen{" "}
            {formatDateTime(selected.last_seen)} · Created {formatDateTime(selected.created_at)} ·
            Updated {formatDateTime(selected.updated_at)}
          </p>

          {/* C. What evidence supports it? */}
          <h4>What evidence supports it?</h4>
          <SectionNote
            state={evidenceState}
            loading="Loading supporting evidence…"
            error="Supporting evidence could not be loaded."
            denied="Supporting evidence is restricted for your account."
          />
          {evidenceState === "ready" && evidence && (
            <>
              <p className="muted">
                Correlated observations: {evidence.events.length} event(s) ·{" "}
                {evidence.vulnerabilities.length} vulnerability finding(s) ·{" "}
                {evidence.correlation ? "1 correlation" : "0 correlations"} — references only, never
                payload copies.
              </p>
              {(evidence.evidence_count !== undefined || evidence.entities) && (
                <p className="muted">
                  {typeof evidence.evidence_count === "number" &&
                    `Evidence count ${evidence.evidence_count}${evidence.truncated ? " (truncated at the configured bound)" : ""} · `}
                  {evidence.first_observed && (
                    <>first observed {formatDateTime(evidence.first_observed)} · </>
                  )}
                  {evidence.last_observed && <>last observed {formatDateTime(evidence.last_observed)} · </>}
                  {evidence.entities && (
                    <>
                      entities — source IPs{" "}
                      {evidence.entities.source_ips.length ? evidence.entities.source_ips.join(", ") : "none recorded"}{" "}
                      · destinations{" "}
                      {evidence.entities.destination_ips.length
                        ? evidence.entities.destination_ips.join(", ")
                        : "none recorded"}{" "}
                      · users{" "}
                      {evidence.entities.usernames.length ? evidence.entities.usernames.join(", ") : "none recorded"}
                    </>
                  )}
                </p>
              )}
              {(evidence.assets?.length ?? 0) > 0 && (
                <p className="muted">
                  Affected assets (stored inventory only):{" "}
                  {(evidence.assets ?? [])
                    .map((asset) => asset.hostname ?? asset.ip_address)
                    .join(" · ")}
                </p>
              )}
            </>
          )}
          {selected.evidence_event_ids.length === 0 ? (
            <p className="muted">No evidence references.</p>
          ) : (
            <>
              <h5>Supporting evidence ({selected.evidence_event_ids.length} events)</h5>
              <ul>
                {selected.evidence_event_ids.map((eventId) => {
                  const rich = evidence?.events.find((item) => item.id === eventId);
                  return (
                    <li key={eventId} style={{ marginBottom: 4 }}>
                      <a href={`/events?event=${encodeURIComponent(eventId)}`}>
                        <code>{eventId}</code>
                      </a>
                      {rich && (
                        <span className="muted">
                          {" "}
                          · {rich.event_type} · {rich.severity} · {rich.title}
                          {rich.role ? ` (${rich.role})` : ""}
                        </span>
                      )}
                    </li>
                  );
                })}
              </ul>
            </>
          )}
          {evidenceState === "ready" && (evidence?.vulnerabilities.length ?? 0) > 0 && (
            <>
              <h5>Related vulnerability findings ({evidence?.vulnerabilities.length ?? 0})</h5>
              <ul>
                {(evidence?.vulnerabilities ?? []).map((finding) => (
                  <li key={finding.id} style={{ marginBottom: 4 }}>
                    <strong>{finding.title}</strong>{" "}
                    <span className={`badge ${severityTone(finding.severity)}`}>
                      {finding.severity}
                    </span>{" "}
                    <span className="muted">
                      {finding.cve_id ?? "no CVE"} · {finding.status}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
          {evidenceState === "ready" && evidence?.correlation && (
            <>
              <h5>Correlation explanation</h5>
              <p>
                {evidence.correlation.rule_name} (confidence {evidence.correlation.confidence}):{" "}
                {evidence.correlation.explanation}
              </p>
            </>
          )}
          {evidenceState === "ready" && (evidence?.correlation_rules?.length ?? 0) > 0 && (
            <>
              <h5>Correlation rules ({evidence?.correlation_rules?.length ?? 0})</h5>
              <ul>
                {(evidence?.correlation_rules ?? []).map((rule) => (
                  <li key={rule.rule_id} style={{ marginBottom: 4 }}>
                    <code>{rule.rule_id}</code>{" "}
                    <span className="badge neutral">{rule.confidence_label}</span>{" "}
                    <span className="muted">
                      confidence {rule.confidence} · {rule.relationship_count} stored
                      relationship(s) · {rule.rule_name}
                    </span>
                  </li>
                ))}
              </ul>
            </>
          )}
          {evidenceState === "ready" && evidenceEmpty && (
            <p className="muted">No supporting evidence is stored for this incident yet.</p>
          )}

          {/* D. What relationships exist? */}
          <h4>What relationships exist?</h4>
          <SectionNote
            state={relationshipsState}
            loading="Loading stored relationships…"
            error="Stored relationships could not be loaded."
            denied="Stored relationships are restricted for your account."
          />
          {relationshipsState === "ready" && relationships && (
            <>
              <h5>Relationship analysis ({relationships.items.length})</h5>
              <p className="muted">
                Deterministic field matches over stored evidence — every row names its
                rule, window and reason. Labels describe the rule&apos;s confidence, not a
                machine-learning prediction. Unknown fields stay unknown and no asset,
                user or identity is ever invented.
              </p>
              <button
                className="button secondary"
                type="button"
                onClick={() => void recalculateAnalysis(selected.id)}
              >
                Recalculate analysis
              </button>
              {analysisNotice && <p className="muted">{analysisNotice}</p>}
              {relationships.items.length === 0 ? (
                <p className="muted">
                  No deterministic relationships are stored for this incident yet.
                  Recalculation reconciles stored evidence only — a vulnerability
                  finding alone never creates a relationship.
                </p>
              ) : (
                <ul>
                  {relationships.items.map((rel) => (
                    <li key={rel.id} style={{ marginBottom: 10 }}>
                      <span className="badge neutral">{rel.rule_id}</span>{" "}
                      <span className="badge neutral">{rel.confidence_label}</span>{" "}
                      <strong>
                        {rel.source_kind}: {rel.source_label ?? rel.source_id}
                      </strong>{" "}
                      → <strong>{rel.target_kind}: {rel.target_label ?? rel.target_id}</strong>
                      <div className="muted">
                        {rel.relation} · confidence {rel.confidence} ·{" "}
                        {rel.evidence_event_ids.length} evidence event(s) ·{" "}
                        {formatDateTime(rel.first_seen)}–{formatDateTime(rel.last_seen)}
                      </div>
                      <div>{rel.explanation}</div>
                      <div className="muted">
                        Evidence:{" "}
                        {rel.evidence_event_ids.map((eventId) => (
                          <a
                            key={eventId}
                            href={`/events?event=${encodeURIComponent(eventId)}`}
                            style={{ marginRight: 8 }}
                          >
                            <code>{eventId}</code>
                          </a>
                        ))}
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}

          {/* E. When did it happen? */}
          <h4>When did it happen?</h4>
          <IncidentTimelineSection
            timeline={timeline}
            state={timelineState}
            onReload={() => void reloadTimeline()}
          />

          {/* F. What is the current assessment? */}
          <h4>What is the current assessment?</h4>
          <h5>Advisory risk</h5>
          {riskState === "loading" && <p className="muted">Loading incident risk…</p>}
          {riskState === "ready" && incidentRisk === null && (
            <div>
              <p className="muted">
                No incident risk calculated yet. Calculation scores stored
                evidence only — it is advisory, not an automated response,
                and never proof of compromise.
              </p>
              <button
                className="button secondary"
                type="button"
                onClick={() => void calculateRisk(selected.id)}
              >
                Calculate risk
              </button>
            </div>
          )}
          {riskState === "ready" && incidentRisk && (
            <div>
              <p>
                <strong>
                  {incidentRisk.score} ({incidentRisk.severity})
                </strong>{" "}
                <span className="badge neutral">priority {incidentRisk.priority}</span>{" "}
                <span className="muted">
                  scoring v{incidentRisk.scoring_version} · calculated{" "}
                  {formatDateTime(incidentRisk.calculated_at)}
                </span>
              </p>
              <p>{incidentRisk.explanation}</p>
              <p className="muted">
                Factors:{" "}
                {Object.entries(incidentRisk.factors ?? {})
                  .map(([key, value]) => `${key}=${String(value)}`)
                  .join(" · ")}
              </p>
              <p className="muted">
                CALCULATED RISK — advisory classification only, not an automated response.
              </p>
              <button
                className="button secondary"
                type="button"
                onClick={() => void calculateRisk(selected.id)}
              >
                Recalculate risk
              </button>
            </div>
          )}

          {/* G. What happened to the record? */}
          <h4>What happened to the record?</h4>
          <SectionNote
            state={auditState}
            loading="Loading audit history…"
            error="Audit history could not be loaded."
            denied="Audit history is restricted for your account."
          />
          {auditState === "ready" && audit && audit.entries.length > 0 && (
            <>
              <h5>Audit history ({audit.entries.length})</h5>
              <ul>
                {audit.entries.map((entry, index) => (
                  <li key={`${entry.action}-${index}`} style={{ marginBottom: 4 }}>
                    <code>{entry.action}</code> by {entry.actor}{" "}
                    <span className="muted">{formatDateTime(entry.created_at)}</span>
                    {entry.detail && <span className="muted"> · {entry.detail}</span>}
                  </li>
                ))}
              </ul>
            </>
          )}
          {auditState === "ready" && (audit?.entries.length ?? 0) === 0 && (
            <p className="muted">No audit entries are stored yet.</p>
          )}

          {/* H. What can happen next? */}
          <h4>What can happen next?</h4>
          <SectionNote
            state={responsesState}
            loading="Loading responses…"
            error="Responses could not be loaded."
            denied="Responses are restricted for your account."
          />
          <h5>Controlled responses ({responses.length})</h5>
          <p className="muted">
            Safe foundation actions only — they affect workflow records, never
            external systems. Every proposal needs approval before it can run.
          </p>
          <div style={{ display: "flex", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
            <select
              aria-label="Response action type"
              value={proposeType}
              onChange={(event) => setProposeType(event.target.value)}
              style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
            >
              {SAFE_RESPONSE_ACTIONS.map((item) => (
                <option key={item} value={item}>
                  {item}
                </option>
              ))}
            </select>
            <input
              aria-label="Response reason"
              value={proposeReason}
              onChange={(event) => setProposeReason(event.target.value)}
              placeholder="Reason for this response"
              style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
            />
            <button className="button secondary" type="button" onClick={() => void proposeResponse()}>
              Propose response
            </button>
          </div>
          {responses.length === 0 ? (
            <p className="muted">No responses proposed for this incident.</p>
          ) : (
            <ul>
              {responses.map((item) => (
                <li key={item.id} style={{ marginBottom: 8 }}>
                  <strong>{item.action_type}</strong>{" "}
                  <span className={`badge ${responseTone(item.status)}`}>{item.status}</span>{" "}
                  <span className="muted">
                    requested by {item.requested_by}
                    {item.approved_by ? ` · approved by ${item.approved_by}` : ""} ·
                    dry run {item.dry_run ? "yes" : "no"}
                  </span>
                  {item.result_summary && <span> · {item.result_summary}</span>}
                  {item.failure_reason && (
                    <span className="muted"> · Failed: {item.failure_reason}</span>
                  )}
                  <span style={{ display: "inline-flex", gap: 4, marginLeft: 8 }}>
                    {(item.status === "PROPOSED" || item.status === "DRY_RUN_COMPLETED") && (
                      <>
                        <button
                          className="button secondary"
                          type="button"
                          onClick={() => void decideResponse(item.id, "approve")}
                        >
                          Approve
                        </button>
                        <button
                          className="button secondary"
                          type="button"
                          onClick={() => void decideResponse(item.id, "reject")}
                        >
                          Reject
                        </button>
                      </>
                    )}
                    {item.status === "APPROVED" && (
                      <button
                        className="button secondary"
                        type="button"
                        onClick={() => void executeResponseAction(item.id)}
                      >
                        Execute
                      </button>
                    )}
                    {["PROPOSED", "APPROVED", "DRY_RUN_COMPLETED"].includes(item.status) && (
                      <button
                        className="button secondary"
                        type="button"
                        onClick={() => void decideResponse(item.id, "cancel")}
                      >
                        Cancel
                      </button>
                    )}
                  </span>
                </li>
              ))}
            </ul>
          )}
          {/*
            Step 30: deterministic, evidence-backed suggestions. These are
            derived only from stored event fields and the platform
            inventory, are always labelled as requiring approval, and are
            never executed from this screen. No machine learning is
            involved and no risk score can act on its own.
          */}
          <SectionNote
            state={recommendationsState}
            loading="Loading recommended responses…"
            error="Recommended responses could not be loaded."
            denied="Recommended responses are restricted for your account."
          />
          <h5>Recommended defensive responses ({recommendations.length})</h5>
          <p className="muted">
            Suggestions are computed from this incident&apos;s stored evidence. Requesting one
            only opens a request that still needs a second approver — nothing here executes
            automatically, whatever the risk priority.
          </p>
          {recommendations.length === 0 ? (
            <p className="muted">No defensive responses are available for this incident.</p>
          ) : (
            <ul>
              {recommendations.map((item) => (
                <li key={`${item.action_type}-${item.target_type}-${item.target_reference}`} style={{ marginBottom: 8 }}>
                  <strong>{item.action_type}</strong>{" "}
                  <span className="badge">
                    {item.target_type}:{item.target_reference}
                  </span>{" "}
                  <span className={`badge ${item.available ? "warn" : "bad"}`}>
                    {item.available ? "AVAILABLE AFTER APPROVAL" : "UNAVAILABLE"}
                  </span>
                  <div className="muted" style={{ marginTop: 2 }}>
                    {item.reason}
                  </div>
                  <div className="muted">
                    incident {item.incident_key} · severity {item.severity} · risk priority{" "}
                    {item.risk_priority} · provider {item.provider} ·{" "}
                    {item.evidence_event_ids.length} evidence event(s) · approval required:{" "}
                    {String(item.requires_approval)} · automatic: {String(item.automatic)}
                  </div>
                  {item.available && (
                    <span style={{ display: "inline-flex", gap: 4, marginTop: 4 }}>
                      <button
                        className="button secondary"
                        type="button"
                        onClick={() => void requestControlledAction(item)}
                      >
                        Request approval
                      </button>
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
          {(NEXT_STATUS[selected.status] ?? []).length > 0 && (
            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              {(NEXT_STATUS[selected.status] ?? []).map((next) => (
                <button
                  key={next}
                  className="button secondary"
                  type="button"
                  onClick={() => void changeStatus(selected.id, next)}
                >
                  Mark {next.charAt(0) + next.slice(1).toLowerCase()}
                </button>
              ))}
            </div>
          )}
          <p style={{ marginTop: 12 }}>
            <button className="button secondary" type="button" onClick={closeDetail}>
              Close incident
            </button>
          </p>
        </div>
      )}
    </section>
  );
}