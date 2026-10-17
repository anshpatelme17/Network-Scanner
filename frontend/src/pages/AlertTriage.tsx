import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../services/api";
import type {
  AttackChain,
  CorrelationDetail,
  CorrelationSummary,
  IncidentSummary,
} from "../types";

type SectionState = "idle" | "loading" | "ready" | "error" | "denied";

const SEVERITIES = ["", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

const SEVERITY_RANK: Record<string, number> = {
  INFO: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

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

function severityRank(severity: string): number {
  return SEVERITY_RANK[severity] ?? 0;
}

function isCorrelationDetail(value: unknown): value is CorrelationDetail {
  return (
    value !== null &&
    typeof value === "object" &&
    Array.isArray((value as CorrelationDetail).evidence)
  );
}

function isAttackChain(value: unknown): value is AttackChain {
  return (
    value !== null &&
    typeof value === "object" &&
    Array.isArray((value as AttackChain).nodes)
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

/**
 * Alert triage (Phase 3, Step 37): a read-only, correlation-centric queue.
 *
 * Correlations are the existing grouped-activity records; this workspace
 * prioritizes them by severity and surfaces, from server data only, whether
 * an incident already exists for each group. It records no disposition and
 * invents no status: correlation status, confidence and evidence all come
 * from the API, and every operation is a GET.
 */
export function AlertTriage() {
  const [severity, setSeverity] = useState("");
  const [unlinkedOnly, setUnlinkedOnly] = useState(false);

  const [queueState, setQueueState] = useState<SectionState>("loading");
  const [items, setItems] = useState<CorrelationSummary[]>([]);
  const [total, setTotal] = useState(0);

  const [incidentsState, setIncidentsState] = useState<SectionState>("loading");
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detailState, setDetailState] = useState<SectionState>("idle");
  const [detail, setDetail] = useState<CorrelationDetail | null>(null);
  const [chainState, setChainState] = useState<SectionState>("idle");
  const [chain, setChain] = useState<AttackChain | null>(null);

  const loadQueue = useCallback(async (severityValue: string) => {
    setQueueState("loading");
    try {
      const page = await api.getCorrelations({
        severity: severityValue || undefined,
        limit: 100,
      });
      setItems(Array.isArray(page.items) ? page.items : []);
      setTotal(typeof page.total === "number" ? page.total : 0);
      setQueueState("ready");
    } catch (err) {
      setItems([]);
      setQueueState(isDenied(err) ? "denied" : "error");
    }
  }, []);

  const loadIncidents = useCallback(async () => {
    setIncidentsState("loading");
    try {
      const page = await api.getIncidents({ limit: 100 });
      setIncidents(Array.isArray(page.items) ? page.items : []);
      setIncidentsState("ready");
    } catch (err) {
      setIncidents([]);
      setIncidentsState(isDenied(err) ? "denied" : "error");
    }
  }, []);

  useEffect(() => {
    void loadQueue("");
    void loadIncidents();
  }, [loadQueue, loadIncidents]);

  const openDetail = useCallback(async (id: string) => {
    setSelectedId(id);
    await Promise.all([
      runSection(
        () => api.getCorrelation(id),
        isCorrelationDetail,
        setDetailState,
        setDetail,
      ),
      runSection(
        () => api.getAttackChain(id),
        isAttackChain,
        setChainState,
        setChain,
      ),
    ]);
  }, []);

  // Server data only: an incident maps to a correlation through the
  // stored `correlation_id`. Multiple incidents may reference one
  // correlation (one per linked risk assessment), so they are kept as a list.
  const incidentIndex = new Map<string, IncidentSummary[]>();
  for (const incident of incidents) {
    const bucket = incidentIndex.get(incident.correlation_id);
    if (bucket) bucket.push(incident);
    else incidentIndex.set(incident.correlation_id, [incident]);
  }

  const prioritised = [...items].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      b.window_end.localeCompare(a.window_end),
  );
  const visible =
    unlinkedOnly && incidentsState === "ready"
      ? prioritised.filter((item) => !incidentIndex.has(item.id))
      : prioritised;

  const associationKnown = incidentsState === "ready";

  const detailIncidents = selectedId ? incidentIndex.get(selectedId) ?? [] : [];

  return (
    <section aria-label="Alert triage">
      <div className="card">
        <h3>Alert triage</h3>
        <p>
          Read-only queue over correlated activity. Groups are prioritized by
          their stored severity and shown with the evidence the backend already
          grouped. Correlation is <strong>not proof of compromise</strong>, and
          this page records no acknowledgement or disposition — it only reads.
        </p>
      </div>

      <div className="card">
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <select
            aria-label="Filter by severity"
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
              void loadQueue(event.target.value);
            }}
            style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
          >
            {SEVERITIES.map((level) => (
              <option key={level} value={level}>
                {level === "" ? "All severities" : level}
              </option>
            ))}
          </select>
          <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
            <input
              type="checkbox"
              checked={unlinkedOnly}
              disabled={!associationKnown}
              onChange={(event) => setUnlinkedOnly(event.target.checked)}
            />
            Only groups without an incident
          </label>
          <button
            className="button secondary"
            type="button"
            onClick={() => void loadQueue(severity)}
          >
            Refresh queue
          </button>
        </div>
        {!associationKnown && (
          <p className="muted" style={{ marginTop: 8 }}>
            Incident association is unavailable, so the queue cannot say which
            groups already have an incident.
          </p>
        )}
      </div>

      <div className="card" aria-label="Alert queue">
        <h3>Queue ({total})</h3>
        {queueState === "loading" && <p className="muted">Loading alert queue…</p>}
        {queueState === "denied" && (
          <p className="muted">Correlated activity is restricted for your account.</p>
        )}
        {queueState === "error" && (
          <>
            <p className="muted">Alert queue could not be loaded.</p>
            <button
              className="button secondary"
              type="button"
              onClick={() => void loadQueue(severity)}
            >
              Retry queue
            </button>
          </>
        )}
        {queueState === "ready" && visible.length === 0 && (
          <p>
            {items.length === 0
              ? "No correlated activity to triage."
              : "No groups match the current filter."}
          </p>
        )}
        {queueState === "ready" && visible.length > 0 && (
          <div style={{ overflowX: "auto" }}>
            <table
              aria-label="Correlated activity to triage"
              style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}
            >
              <thead>
                <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                  {["Severity", "Group", "Rule", "Events", "Window", "Incident", ""].map(
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
                {visible.map((item) => {
                  const linked = incidentIndex.get(item.id) ?? [];
                  return (
                    <tr key={item.id} style={{ borderBottom: "1px solid var(--border)" }}>
                      <td style={{ padding: "10px 14px" }}>
                        <span className={`badge ${severityTone(item.severity)}`}>
                          {item.severity}
                        </span>
                      </td>
                      <td style={{ padding: "10px 14px" }}>
                        <strong>{item.title}</strong>{" "}
                        <span className="muted">
                          {item.hostname ?? item.primary_ip ?? "unknown target"}
                        </span>
                      </td>
                      <td style={{ padding: "10px 14px" }}>
                        {item.rule_name}{" "}
                        <span className="muted">
                          · confidence {item.confidence}
                          {item.confidence_label ? ` (${item.confidence_label})` : ""}
                        </span>
                      </td>
                      <td style={{ padding: "10px 14px" }}>{item.event_count}</td>
                      <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                        {formatDateTime(item.window_start)} → {formatDateTime(item.window_end)}
                      </td>
                      <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                        {!associationKnown ? (
                          <span className="muted">association unavailable</span>
                        ) : linked.length > 0 ? (
                          <>
                            <span className="badge neutral">
                              Incident {linked[0].incident_key}
                            </span>{" "}
                            <span className="muted">{linked[0].status}</span>
                          </>
                        ) : (
                          <span className="muted">No incident</span>
                        )}
                      </td>
                      <td style={{ padding: "10px 14px" }}>
                        <button
                          className="button secondary"
                          type="button"
                          onClick={() => void openDetail(item.id)}
                        >
                          Review
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedId && (
        <div className="card" aria-label="Alert detail">
          {detailState === "loading" && <p className="muted">Loading group detail…</p>}
          {detailState === "denied" && (
            <>
              <h3>Group detail restricted</h3>
              <p className="muted">This group's detail is restricted for your account.</p>
            </>
          )}
          {detailState === "error" && (
            <>
              <h3>Group detail unavailable</h3>
              <p className="muted">The group detail could not be loaded.</p>
              <button
                className="button secondary"
                type="button"
                onClick={() => void openDetail(selectedId)}
              >
                Retry detail
              </button>
            </>
          )}
          {detailState === "ready" && detail && (
            <>
              <h3>{detail.title}</h3>
              <p>
                <span className={`badge ${severityTone(detail.severity)}`}>
                  {detail.severity}
                </span>{" "}
                <span className="muted">
                  {detail.rule_name} · confidence {detail.confidence}
                  {detail.confidence_label ? ` (${detail.confidence_label})` : ""} · status{" "}
                  {detail.status}
                </span>
              </p>
              <p>
                <strong>Why correlated: </strong>
                {detail.explanation}
              </p>
              {detail.description && <p className="muted">{detail.description}</p>}

              <h4>Incident association</h4>
              {!associationKnown ? (
                <p className="muted">
                  Incident association is unavailable for your account.
                </p>
              ) : detailIncidents.length > 0 ? (
                <p>
                  {detailIncidents.map((incident) => (
                    <span key={incident.id}>
                      <span className="badge neutral">{incident.incident_key}</span>{" "}
                      {incident.title} <span className="muted">({incident.status})</span>{" "}
                    </span>
                  ))}
                  <Link to="/incidents">View incidents</Link>
                </p>
              ) : (
                <p>No incident has been opened for this group.</p>
              )}

              <h4>Supporting evidence (oldest first)</h4>
              {detail.evidence.length === 0 ? (
                <p className="muted">No stored evidence for this group.</p>
              ) : (
                <ol>
                  {detail.evidence.map((entry) => (
                    <li key={entry.event_id} style={{ marginBottom: 6 }}>
                      <span className={`badge ${severityTone(entry.severity)}`}>
                        {entry.severity}
                      </span>{" "}
                      <a href={`/events?event=${encodeURIComponent(entry.event_id)}`}>
                        {entry.title}
                      </a>{" "}
                      <span className="muted">
                        [{entry.source_type}/{entry.event_type}, role {entry.role},{" "}
                        {formatDateTime(entry.event_time)}]
                      </span>
                    </li>
                  ))}
                </ol>
              )}

              <h4>Attack-chain context</h4>
              {chainState === "loading" && <p className="muted">Loading attack chain…</p>}
              {chainState === "denied" && (
                <p className="muted">Attack-chain context is restricted for your account.</p>
              )}
              {chainState === "error" && (
                <>
                  <p className="muted">Attack-chain context could not be loaded.</p>
                  <button
                    className="button secondary"
                    type="button"
                    onClick={() => void openDetail(selectedId)}
                  >
                    Retry attack chain
                  </button>
                </>
              )}
              {chainState === "ready" &&
                chain &&
                (chain.nodes.length === 0 ? (
                  <p className="muted">No chain context for this group.</p>
                ) : (
                  <ol>
                    {chain.nodes.map((node) => (
                      <li key={node.id} style={{ marginBottom: 4 }}>
                        <span className="badge neutral">{node.kind}</span> {node.label}
                      </li>
                    ))}
                  </ol>
                ))}

              <p style={{ marginTop: 12 }}>
                <button
                  className="button secondary"
                  type="button"
                  onClick={() => {
                    setSelectedId(null);
                    setDetail(null);
                    setChain(null);
                    setDetailState("idle");
                    setChainState("idle");
                  }}
                >
                  Close detail
                </button>
              </p>
            </>
          )}
        </div>
      )}

      <div className="card" aria-label="Alert triage navigation">
        <h3>Continue the investigation</h3>
        <p>
          <Link to="/correlations">Correlated activity</Link> ·{" "}
          <Link to="/incidents">Incidents</Link> ·{" "}
          <Link to="/events">Security events</Link>
        </p>
      </div>
    </section>
  );
}
