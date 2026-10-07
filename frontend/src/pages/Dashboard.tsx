import { useCallback, useEffect, useState } from "react";
import type { CSSProperties } from "react";
import { useSystemStatus } from "../hooks/useSystemStatus";
import { StatusBadge } from "../components/layout/StatusBadge";
import { ApiError, api, safeErrorText } from "../services/api";
import type { OverviewCounts, SocOverview } from "../types";

const SEVERITY_BUCKETS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;
const PRIORITY_BUCKETS = ["P1", "P2", "P3", "P4", "UNSCORED"] as const;

type OverviewState = "loading" | "ready" | "error" | "denied";

const CELL: CSSProperties = { padding: "10px 14px" };

function formatDateTime(value: string | null | undefined): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function isSocOverview(value: unknown): value is SocOverview {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<SocOverview>;
  return (
    typeof candidate.generated_at === "string" &&
    typeof candidate.version === "string" &&
    typeof candidate.disclaimer === "string" &&
    typeof candidate.limits === "object" &&
    candidate.limits !== null &&
    typeof candidate.counts === "object" &&
    candidate.counts !== null
  );
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
    case "P3":
      return "warn";
    default:
      return "neutral";
  }
}

/**
 * SOC dashboard (Phase 2, Step 9): read-only roll-up of stored security
 * state served by `GET /api/v1/overview`. The readiness card below is kept
 * from the Phase 1 dashboard; the inventory/events/"what's next" cards are
 * replaced by the SOC overview. No number is computed client-side and
 * nothing on this screen performs an action.
 */
export function Dashboard() {
  const { state, backend, database, version, environment, lastChecked, detail, refresh } =
    useSystemStatus();
  const [overviewState, setOverviewState] = useState<OverviewState>("loading");
  const [overview, setOverview] = useState<SocOverview | null>(null);
  const [overviewMessage, setOverviewMessage] = useState<string | null>(null);

  const loadOverview = useCallback(async () => {
    setOverviewState("loading");
    try {
      const result = await api.getSocOverview();
      if (!isSocOverview(result)) {
        setOverview(null);
        setOverviewMessage("The server returned an unexpected response for the SOC overview.");
        setOverviewState("error");
        return;
      }
      setOverview(result);
      setOverviewMessage(null);
      setOverviewState("ready");
    } catch (err) {
      setOverview(null);
      if (err instanceof ApiError) {
        if (err.code === "PERMISSION_DENIED" || err.status === 403) {
          setOverviewMessage(safeErrorText(err, "You do not have permission to view the SOC overview."));
          setOverviewState("denied");
          return;
        }
        if (err.code === "AUTH_REQUIRED" || err.status === 401) {
          setOverviewMessage(safeErrorText(err, "Sign in to view the SOC overview."));
          setOverviewState("denied");
          return;
        }
      }
      setOverviewMessage(safeErrorText(err, "The SOC overview could not be loaded."));
      setOverviewState("error");
    }
  }, []);

  useEffect(() => {
    void loadOverview();
  }, [loadOverview]);

  const counts: OverviewCounts = overview?.counts ?? {
    assets_total: 0,
    assets_active: 0,
    services_total: 0,
    events_total: 0,
    correlations_total: 0,
    incidents_total: 0,
    incidents_open: 0,
    risk_assessments_total: 0,
    vulnerabilities_open: 0,
    response_actions_total: 0,
    response_actions_pending_approval: 0,
  };
  const summaryStats: Array<{ label: string; value: number; sub: string }> = [
    { label: "Assets", value: counts.assets_total, sub: "Stored assets" },
    { label: "Active assets", value: counts.assets_active, sub: "Reported state up" },
    { label: "Services", value: counts.services_total, sub: "Discovered services" },
    { label: "Events", value: counts.events_total, sub: "Stored security events" },
    { label: "Correlations", value: counts.correlations_total, sub: "Stored correlations" },
    { label: "Incidents", value: counts.incidents_total, sub: "Stored incidents" },
    { label: "Open incidents", value: counts.incidents_open, sub: "Open / in progress / pending approval" },
    { label: "Risk assessments", value: counts.risk_assessments_total, sub: "Stored assessments" },
    { label: "Open vulnerabilities", value: counts.vulnerabilities_open, sub: "Open finding statuses" },
    { label: "Response actions", value: counts.response_actions_total, sub: "Recorded response actions" },
    { label: "Pending approvals", value: counts.response_actions_pending_approval, sub: "Awaiting approval" },
  ];
  const topIncidents = Array.isArray(overview?.top_incidents) ? overview.top_incidents : [];
  const auditRows = Array.isArray(overview?.recent_audit) ? overview.recent_audit : [];
  const connectors = Array.isArray(overview?.connectors) ? overview.connectors : [];

  return (
    <section aria-label="System status">
      <div className="card">
        <h3>System status</h3>
        <p>
          Foundation build — the platform is running, but security monitoring,
          detection and automated response are <strong>not yet implemented</strong>.
        </p>
        <p>
          <StatusBadge state={state} />{" "}
          <span className="muted">
            {lastChecked ? `Last checked ${lastChecked.toLocaleTimeString()}` : "Checking backend…"}
          </span>
        </p>
        {detail && <p className="muted">Detail: {detail}</p>}
        <button className="button secondary" onClick={() => refresh()} type="button">
          Refresh status
        </button>
      </div>

      <div className="grid">
        <div className="stat">
          <div className="label">Backend</div>
          <div className="value">{backend}</div>
          <div className="sub">GET /api/v1/ready</div>
        </div>
        <div className="stat">
          <div className="label">Database</div>
          <div className="value">{database}</div>
          <div className="sub">PostgreSQL via readiness check</div>
        </div>
        <div className="stat">
          <div className="label">Version</div>
          <div className="value">{version}</div>
          <div className="sub">Reported by API</div>
        </div>
        <div className="stat">
          <div className="label">Environment</div>
          <div className="value">{environment}</div>
          <div className="sub">From server configuration</div>
        </div>
      </div>

      {overviewState === "loading" && <p className="muted">Loading SOC overview…</p>}

      {overviewState === "error" && (
        <div className="card">
          <h3>SOC overview unavailable</h3>
          <p>{overviewMessage}</p>
          <p>
            <button className="button secondary" type="button" onClick={() => void loadOverview()}>
              Retry
            </button>
          </p>
        </div>
      )}

      {overviewState === "denied" && (
        <div className="card">
          <h3>SOC overview unavailable</h3>
          <p>{overviewMessage}</p>
        </div>
      )}

      {overviewState === "ready" && overview && (
        <>
          <div className="card">
            <h3>SOC summary</h3>
            <p>
              Read-only roll-up of the security state currently stored by the
              platform. Counts only — nothing on this screen performs an action.
            </p>
            <div className="grid">
              {summaryStats.map((stat) => (
                <div className="stat" key={stat.label}>
                  <div className="label">{stat.label}</div>
                  <div className="value">{stat.value}</div>
                  <div className="sub">{stat.sub}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <h3>Incidents by severity</h3>
            <div className="grid">
              {SEVERITY_BUCKETS.map((bucket) => (
                <div className="stat" key={bucket}>
                  <div className="label">{bucket}</div>
                  <div className="value">{overview.incidents_by_severity[bucket] ?? 0}</div>
                  <div className="sub">incidents</div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <h3>Incidents by priority</h3>
            <div className="grid">
              {PRIORITY_BUCKETS.map((bucket) => (
                <div className="stat" key={bucket}>
                  <div className="label">{bucket}</div>
                  <div className="value">{overview.incidents_by_priority[bucket] ?? 0}</div>
                  <div className="sub">{bucket === "UNSCORED" ? "no stored risk score" : "derived from stored risk score"}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="card">
            <h3>Top open incidents</h3>
            <p>
              Most recent open incidents (bounded, read-only). An incident is
              an evidence-based investigation record and is{" "}
              <strong>not proof of compromise</strong>.
            </p>
            {topIncidents.length === 0 ? (
              <p className="muted">No open incidents.</p>
            ) : (
              <div style={{ padding: 0, overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
                  <thead>
                    <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                      {["Incident", "Severity", "Priority", "Status", "Host / asset", "Risk score", "First seen", "Last seen"].map(
                        (heading) => (
                          <th key={heading} style={CELL}>
                            {heading}
                          </th>
                        ),
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {topIncidents.map((incident) => (
                      <tr key={incident.id} style={{ borderBottom: "1px solid var(--border)" }}>
                        <td style={CELL}>
                          <strong>{incident.title}</strong>
                        </td>
                        <td style={CELL}>
                          <span className={`badge ${severityTone(incident.severity)}`}>{incident.severity}</span>
                        </td>
                        <td style={CELL}>
                          {incident.priority === null ? (
                            "—"
                          ) : (
                            <span className={`badge ${priorityTone(incident.priority)}`}>{incident.priority}</span>
                          )}
                        </td>
                        <td style={CELL}>{incident.status}</td>
                        <td style={CELL}>
                          <div>{incident.hostname ?? incident.primary_ip ?? incident.primary_asset_id ?? "—"}</div>
                          {incident.hostname && incident.primary_ip ? (
                            <div className="muted">{incident.primary_ip}</div>
                          ) : null}
                        </td>
                        <td style={CELL}>{incident.risk_score === null ? "—" : incident.risk_score}</td>
                        <td style={CELL}>{formatDateTime(incident.first_seen)}</td>
                        <td style={CELL}>{formatDateTime(incident.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <h3>Connector health</h3>
            {connectors.length === 0 ? (
              <p className="muted">No connectors configured.</p>
            ) : (
              <div style={{ padding: 0, overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
                  <thead>
                    <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                      {["Source", "Mode", "State", "Connector state", "Last check", "Last poll", "Last error", "Events retrieved"].map(
                        (heading) => (
                          <th key={heading} style={CELL}>
                            {heading}
                          </th>
                        ),
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {connectors.map((connector) => (
                      <tr key={connector.source} style={{ borderBottom: "1px solid var(--border)" }}>
                        <td style={CELL}>
                          <strong>{connector.source}</strong>
                        </td>
                        <td style={CELL}>{connector.mode}</td>
                        <td style={CELL}>
                          <span className={`badge ${connector.state === "OK" ? "ok" : connector.state === "ERROR" ? "bad" : "neutral"}`}>
                            {connector.state}
                          </span>
                        </td>
                        <td style={CELL}>{connector.connector_state}</td>
                        <td style={CELL}>{formatDateTime(connector.last_check_at)}</td>
                        <td style={CELL}>{formatDateTime(connector.last_poll_at)}</td>
                        <td style={CELL}>{connector.last_error_category ?? "—"}</td>
                        <td style={CELL}>{connector.events_retrieved}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <h3>Recent ingestion audit</h3>
            <p>
              Bounded feed of the most recent ingestion audit rows. This is
              not the complete platform audit trail.
            </p>
            {auditRows.length === 0 ? (
              <p className="muted">No ingestion audit entries yet.</p>
            ) : (
              <div style={{ padding: 0, overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
                  <thead>
                    <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                      {["Action", "Actor", "Event", "Detail", "Created"].map((heading) => (
                        <th key={heading} style={CELL}>
                          {heading}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {auditRows.map((row) => (
                      <tr key={row.id} style={{ borderBottom: "1px solid var(--border)" }}>
                        <td style={CELL}>{row.action}</td>
                        <td style={CELL}>{row.actor}</td>
                        <td style={CELL}>{row.event_id ?? "—"}</td>
                        <td style={CELL}>{row.detail}</td>
                        <td style={CELL}>{formatDateTime(row.created_at)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <p>
              <strong>{overview.disclaimer}</strong>
            </p>
            <p className="muted">
              Generated {formatDateTime(overview.generated_at)} · {overview.version} · lists
              bounded to {overview.limits.requested_items} of {overview.limits.max_items}
            </p>
          </div>
        </>
      )}
    </section>
  );
}