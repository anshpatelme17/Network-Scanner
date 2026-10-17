import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../services/api";
import type { IncidentSummary, RiskAssessment } from "../types";

/**
 * Phase 3, Step 39: a read-only, incident-centric prioritization queue.
 *
 * The queue is built entirely from records the platform already stores: the
 * incident rows provide lifecycle, severity and host context, and the
 * authoritative Step 10/25 risk assessments provide the score, priority,
 * factors and explanation. Nothing is recalculated here, no new score is
 * invented, and the page records no disposition. It is every operation a GET.
 */
type PageState = "loading" | "ready" | "error" | "denied";

const ACTIVE_STATUSES = new Set(["OPEN", "ACKNOWLEDGED", "INVESTIGATING"]);
const CLOSED_STATUSES = new Set(["RESOLVED", "CLOSED"]);

// Existing Step 25 priority bands, reused only as a deterministic sort key.
// The values themselves always come from the risk API.
const PRIORITY_RANK: Record<string, number> = { P1: 0, P2: 1, P3: 2, P4: 3 };

// Both /risk and /incidents accept at most this limit (backend MAX_LIMIT).
const RESULT_LIMIT = 200;

interface QueueRow {
  incident: IncidentSummary;
  assessment: RiskAssessment | null;
}

interface ScoredRow {
  incident: IncidentSummary;
  assessment: RiskAssessment;
}

function isDenied(err: unknown): boolean {
  return (
    err instanceof ApiError &&
    (err.code === "PERMISSION_DENIED" || err.status === 401 || err.status === 403)
  );
}

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

function priorityTone(priority: string): string {
  switch (priority) {
    case "P1":
      return "bad";
    case "P2":
      return "warn";
    default:
      return "neutral";
  }
}

function priorityRank(priority: string): number {
  // Unknown/absent priorities sort last without being given a real band.
  return PRIORITY_RANK[priority] ?? 99;
}

function factorText(factors: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(factors)) {
    if (value === null || value === undefined) continue;
    if (typeof value === "object") continue;
    parts.push(`${key}: ${String(value)}`);
  }
  return parts.join(" · ");
}

function compareScored(a: ScoredRow, b: ScoredRow): number {
  return (
    priorityRank(a.assessment.priority) - priorityRank(b.assessment.priority) ||
    b.assessment.score - a.assessment.score ||
    b.incident.last_seen.localeCompare(a.incident.last_seen) ||
    a.incident.id.localeCompare(b.incident.id)
  );
}

function compareUnscored(a: QueueRow, b: QueueRow): number {
  return (
    b.incident.last_seen.localeCompare(a.incident.last_seen) ||
    a.incident.id.localeCompare(b.incident.id)
  );
}

export function RiskPrioritization() {
  const [view, setView] = useState<"active" | "closed">("active");
  const [state, setState] = useState<PageState>("loading");
  const [assessments, setAssessments] = useState<RiskAssessment[]>([]);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [riskTotal, setRiskTotal] = useState(0);
  const [incidentTotal, setIncidentTotal] = useState(0);
  const [selected, setSelected] = useState<ScoredRow | null>(null);

  const load = useCallback(async () => {
    setState("loading");
    try {
      // The risk endpoint is asked for incident assessments only; incident
      // rows supply lifecycle and host context. Both are GET-only reads.
      const [riskPage, incidentPage] = await Promise.all([
        api.getRisk({ entity_type: "incident", limit: RESULT_LIMIT }),
        api.getIncidents({ limit: RESULT_LIMIT }),
      ]);
      setAssessments(Array.isArray(riskPage.items) ? riskPage.items : []);
      setRiskTotal(typeof riskPage.total === "number" ? riskPage.total : 0);
      setIncidents(Array.isArray(incidentPage.items) ? incidentPage.items : []);
      setIncidentTotal(typeof incidentPage.total === "number" ? incidentPage.total : 0);
      setState("ready");
    } catch (err) {
      setAssessments([]);
      setIncidents([]);
      setState(isDenied(err) ? "denied" : "error");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  // Join strictly on incident entity type + id. Assessments for assets,
  // vulnerabilities or correlations must never attach to an incident.
  const assessmentIndex = new Map<string, RiskAssessment>();
  for (const assessment of assessments) {
    if (assessment.entity_type === "incident") assessmentIndex.set(assessment.entity_id, assessment);
  }

  const rows: QueueRow[] = incidents.map((incident) => ({
    incident,
    assessment: assessmentIndex.get(incident.id) ?? null,
  }));
  const viewRows = rows.filter((row) =>
    view === "active" ? ACTIVE_STATUSES.has(row.incident.status) : CLOSED_STATUSES.has(row.incident.status),
  );

  const scored: ScoredRow[] = viewRows
    .filter((row): row is ScoredRow => row.assessment !== null)
    .sort(compareScored);
  const unscored: QueueRow[] = viewRows
    .filter((row) => row.assessment === null)
    .sort(compareUnscored);

  const riskTruncated = riskTotal > assessments.length;
  const incidentTruncated = incidentTotal > incidents.length;

  return (
    <section aria-label="Risk prioritization">
      <div className="card">
        <h3>Risk prioritization</h3>
        <p>
          A read-only queue of active incidents ordered by the risk assessments the
          platform already stores. Priority and score come from the existing
          deterministic assessment; this page <strong>recalculates nothing</strong> and
          triggers no response. It is <strong>not a business-impact score</strong> — the
          platform stores no asset-criticality or business-impact field.
        </p>
      </div>

      <div className="card">
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <button
            className={view === "active" ? "button" : "button secondary"}
            type="button"
            aria-pressed={view === "active"}
            onClick={() => setView("active")}
          >
            Active incidents
          </button>
          <button
            className={view === "closed" ? "button" : "button secondary"}
            type="button"
            aria-pressed={view === "closed"}
            onClick={() => setView("closed")}
          >
            Resolved &amp; closed
          </button>
          <button className="button secondary" type="button" onClick={() => void load()}>
            Refresh
          </button>
        </div>
        {(riskTruncated || incidentTruncated) && (
          <p className="muted" style={{ marginTop: 8 }}>
            Results are bounded to the first {RESULT_LIMIT} records, so this queue may be
            incomplete
            {riskTruncated
              ? ` (${riskTotal} incident assessments exist)`
              : ""}
            {incidentTruncated ? ` (${incidentTotal} incidents exist)` : ""}.
          </p>
        )}
      </div>

      {state === "loading" && <p className="muted">Loading risk prioritization…</p>}
      {state === "denied" && (
        <div className="card">
          <h3>Risk prioritization restricted</h3>
          <p className="muted">
            Incident risk assessments are restricted for your account.
          </p>
        </div>
      )}
      {state === "error" && (
        <div className="card">
          <h3>Risk prioritization unavailable</h3>
          <p className="muted">
            Could not load the incident risk assessments or incidents from the API.
          </p>
          <button className="button secondary" type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      {state === "ready" && (
        <>
          <div className="card" aria-label="Risk priority queue">
            <h3>
              {view === "active" ? "Active incidents" : "Resolved & closed incidents"} (
              {scored.length})
            </h3>
            <p className="muted">
              Ordered by stored priority (P1 first), then score, then most recently seen.
              Scores and priorities are shown exactly as assessed.
            </p>
            {scored.length === 0 ? (
              <p>No assessed incidents in this view.</p>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table
                  aria-label="Scored incidents"
                  style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}
                >
                  <thead>
                    <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                      {["Priority", "Score", "Severity", "Incident", "Status", "Asset", "Last seen", ""].map(
                        (header) => (
                          <th
                            key={header}
                            style={{ padding: "10px 14px", color: "var(--text-muted)" }}
                          >
                            {header}
                          </th>
                        ),
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {scored.map(({ incident, assessment }) => (
                      <tr key={incident.id} style={{ borderBottom: "1px solid var(--border)" }}>
                        <td style={{ padding: "10px 14px" }}>
                          <span className={`badge ${priorityTone(assessment.priority)}`}>
                            {assessment.priority}
                          </span>
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          <strong>{assessment.score}</strong>
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          <span className={`badge ${severityTone(assessment.severity)}`}>
                            {assessment.severity}
                          </span>
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          <strong>{incident.incident_key}</strong>{" "}
                          <span className="muted">{incident.title}</span>
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          <span className="badge neutral">{incident.status}</span>
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          {incident.hostname ?? incident.primary_ip ?? "—"}
                        </td>
                        <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                          {formatDateTime(incident.last_seen)}
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          <button
                            className="button secondary"
                            type="button"
                            onClick={() => setSelected({ incident, assessment })}
                          >
                            Details
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card" aria-label="Unscored incidents">
            <h3>Unscored incidents ({unscored.length})</h3>
            <p className="muted">
              These incidents have no stored risk assessment, so no score or priority is
              shown. The incident's own stored <code>risk_score</code> snapshot is not
              treated as a current assessment.
            </p>
            {unscored.length === 0 ? (
              <p>No unscored incidents in this view.</p>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table
                  aria-label="Unscored incident records"
                  style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}
                >
                  <thead>
                    <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                      {["Incident", "Status", "Severity", "Asset", "Last seen"].map((header) => (
                        <th
                          key={header}
                          style={{ padding: "10px 14px", color: "var(--text-muted)" }}
                        >
                          {header}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {unscored.map(({ incident }) => (
                      <tr key={incident.id} style={{ borderBottom: "1px solid var(--border)" }}>
                        <td style={{ padding: "10px 14px" }}>
                          <strong>{incident.incident_key}</strong>{" "}
                          <span className="muted">{incident.title}</span>
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          <span className="badge neutral">{incident.status}</span>
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          <span className={`badge ${severityTone(incident.severity)}`}>
                            {incident.severity}
                          </span>
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          {incident.hostname ?? incident.primary_ip ?? "—"}
                        </td>
                        <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                          {formatDateTime(incident.last_seen)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      {selected && (
        <div className="card" aria-label="Risk prioritization detail">
          <h3>
            {selected.incident.incident_key} · {selected.assessment.priority} · score{" "}
            {selected.assessment.score}
          </h3>
          <p>
            <span className={`badge ${priorityTone(selected.assessment.priority)}`}>
              priority {selected.assessment.priority}
            </span>{" "}
            <span className={`badge ${severityTone(selected.assessment.severity)}`}>
              {selected.assessment.severity}
            </span>{" "}
            <span className="badge neutral">{selected.incident.status}</span>{" "}
            <span className="muted">{selected.incident.title}</span>
          </p>
          <p>
            <strong>Why this score: </strong>
            {selected.assessment.explanation}
          </p>
          <p className="muted">
            Scoring version {selected.assessment.scoring_version} · calculated{" "}
            {formatDateTime(selected.assessment.calculated_at)} · asset{" "}
            {selected.incident.hostname ?? selected.incident.primary_ip ?? "—"} · last seen{" "}
            {formatDateTime(selected.incident.last_seen)}
          </p>
          <p className="muted">{factorText(selected.assessment.factors)}</p>
          <p style={{ marginTop: 12 }}>
            <button className="button secondary" type="button" onClick={() => setSelected(null)}>
              Close detail
            </button>
          </p>
        </div>
      )}

      <div className="card" aria-label="Risk prioritization navigation">
        <h3>Continue the investigation</h3>
        <p>
          <Link to="/risk">Risk assessments</Link> · <Link to="/incidents">Incidents</Link> ·{" "}
          <Link to="/triage">Alert triage</Link>
        </p>
      </div>
    </section>
  );
}
