import { useEffect, useState } from "react";
import { useSystemStatus } from "../hooks/useSystemStatus";
import { StatusBadge } from "../components/layout/StatusBadge";
import { api } from "../services/api";
import type { EventSummary, InventorySummary } from "../types";

/**
 * Dashboard: live system status (Step 1), real inventory totals (Step 2)
 * and real event totals (Step 3). Counts only — no detections, no risk
 * scoring, no incidents.
 */
export function Dashboard() {
  const { state, backend, database, version, environment, lastChecked, detail, refresh } =
    useSystemStatus();
  const [summary, setSummary] = useState<InventorySummary | null>(null);
  const [eventSummary, setEventSummary] = useState<EventSummary | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .getInventorySummary()
      .then((result) => {
        if (!cancelled && typeof result.total_assets === "number") setSummary(result);
      })
      .catch(() => {
        /* inventory unavailable — system status still renders */
      });
    api
      .getEventSummary()
      .then((result) => {
        if (!cancelled && typeof result.total_events === "number") setEventSummary(result);
      })
      .catch(() => {
        /* no events yet — cards stay hidden */
      });
    return () => {
      cancelled = true;
    };
  }, []);

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

      <div className="card">
        <h3>Inventory</h3>
        {summary === null ? (
          <p className="muted">No inventory data yet — run an authorized scan from Network.</p>
        ) : (
          <div className="grid">
            <div className="stat">
              <div className="label">Total assets</div>
              <div className="value">{summary.total_assets}</div>
              <div className="sub">Known IP addresses</div>
            </div>
            <div className="stat">
              <div className="label">Active assets</div>
              <div className="value">{summary.active_assets}</div>
              <div className="sub">Last seen up</div>
            </div>
            <div className="stat">
              <div className="label">Discovered services</div>
              <div className="value">{summary.total_services}</div>
              <div className="sub">Current open ports</div>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <h3>Security events</h3>
        {eventSummary === null || eventSummary.total_events === 0 ? (
          <p className="muted">No security events received.</p>
        ) : (
          <div className="grid">
            <div className="stat">
              <div className="label">Total events</div>
              <div className="value">{eventSummary.total_events}</div>
              <div className="sub">Ingested via /api/v1/events</div>
            </div>
            <div className="stat">
              <div className="label">Critical events</div>
              <div className="value">{eventSummary.critical_events}</div>
              <div className="sub">Severity CRITICAL</div>
            </div>
            <div className="stat">
              <div className="label">High severity</div>
              <div className="value">{eventSummary.high_events}</div>
              <div className="sub">Severity HIGH</div>
            </div>
            <div className="stat">
              <div className="label">Last 24 hours</div>
              <div className="value">{eventSummary.last_24h_events}</div>
              <div className="sub">By event time</div>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <h3>What&apos;s next</h3>
        <p>
          Future stages will add event collection and normalization,
          correlation, risk scoring, policy-controlled response, audit trails
          and the full SOC workflow. Nothing on this screen is placeholder
          security data.
        </p>
      </div>
    </section>
  );
}
