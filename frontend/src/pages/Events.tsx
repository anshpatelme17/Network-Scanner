import { useCallback, useEffect, useState } from "react";
import { api } from "../services/api";
import type { ConnectorStatus, IngestionCheckpoint, IngestionStatus, SecurityEventInfo } from "../types";

const SEVERITIES = ["", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const SOURCES = [
  "",
  "NMAP",
  "GENERIC",
  "WINDOWS",
  "DEFENDER",
  "SURICATA",
  "ZEEK",
  "WAZUH",
  "VULNERABILITY_SCANNER",
  "FIREWALL",
];

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
      return "warn";
    case "MEDIUM":
      return "warn";
    default:
      return "neutral";
  }
}

/** Step 27 connector-state tones (falls back to the Step 26 state). */
function connectorTone(state: string): string {
  switch (state) {
    case "CONNECTED":
      return "ok";
    case "AUTH_FAILED":
    case "ERROR":
    case "INVALID_CONFIGURATION":
      return "bad";
    case "RATE_LIMITED":
    case "UNAVAILABLE":
    case "CONNECTING":
      return "warn";
    default:
      return "neutral"; // NOT_CONFIGURED, CONFIGURED, FIXTURE-only states
  }
}

function isFullyConfigured(item: ConnectorStatus): boolean {
  const values = Object.values(item.configured ?? {});
  return values.length > 0 && values.every(Boolean);
}

/** Step 28: only a server-shaped payload is rendered (never a guess). */
function isIngestionStatus(value: unknown): value is IngestionStatus {
  if (!value || typeof value !== "object") return false;
  const candidate = value as Partial<IngestionStatus>;
  return (
    Array.isArray(candidate.pipeline) &&
    Array.isArray(candidate.sources) &&
    typeof candidate.limits === "object" &&
    candidate.limits !== null &&
    typeof candidate.queue === "object" &&
    candidate.queue !== null &&
    typeof candidate.streaming === "object" &&
    candidate.streaming !== null
  );
}

/** Checkpoint provenance in operator language (no cursor internals). */
function checkpointLabel(checkpoint: IngestionCheckpoint | null): string {
  if (!checkpoint) return "no successful run yet";
  return `${checkpoint.advance_count} advance(s)`;
}

/** Real security-event list (Steps 3 + 26). Never fabricates events. */
export function Events() {
  const [events, setEvents] = useState<SecurityEventInfo[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");
  const [source, setSource] = useState("");
  const [selected, setSelected] = useState<SecurityEventInfo | null>(null);
  const [connectors, setConnectors] = useState<ConnectorStatus[]>([]);
  const [pollNotice, setPollNotice] = useState<string | null>(null);
  const [ingestion, setIngestion] = useState<IngestionStatus | null>(null);
  const [ingestionState, setIngestionState] = useState<"ready" | "unavailable">("unavailable");
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");

  /** Step 28 observability read: never triggers a run, tolerates junk. */
  const reloadIngestion = useCallback(async () => {
    try {
      const value: unknown = await api.getIngestionStatus();
      if (isIngestionStatus(value)) {
        setIngestion(value);
        setIngestionState("ready");
        return;
      }
    } catch {
      /* fall through: report absence rather than a fabricated state */
    }
    setIngestion(null);
    setIngestionState("unavailable");
  }, []);

  const load = useCallback(async (severityFilter: string, sourceFilter: string) => {
    setState("loading");
    try {
      const page = await api.getEvents({
        severity: severityFilter || undefined,
        source_type: sourceFilter || undefined,
        limit: 100,
      });
      setEvents(Array.isArray(page.items) ? page.items : []);
      setTotal(typeof page.total === "number" ? page.total : 0);
      setState("ready");
    } catch {
      setState("error");
    }
  }, []);

  useEffect(() => {
    void load("", "");
    api.getConnectors().then(
      (page) => setConnectors(Array.isArray(page.items) ? page.items : []),
      () => setConnectors([]),
    );
    void reloadIngestion();
  }, [load, reloadIngestion]);

  const poll = async (sourceName: string) => {
    setPollNotice(null);
    try {
      const result = await api.pollConnector(sourceName);
      const suffix = result.termination
        ? ` · termination ${result.termination}`
        : result.truncated
          ? " (truncated at 100 lines)"
          : "";
      const pipeline =
        typeof result.batches === "number" && result.batches > 0
          ? ` · ${result.batches} batch(es)` +
            (result.queue_dropped ? ` · ${result.queue_dropped} queue drop(s)` : "") +
            (result.checkpoint_advanced ? " · checkpoint advanced" : " · checkpoint held")
          : "";
      setPollNotice(
        `${result.source}: ${result.accepted} accepted, ${result.duplicates} duplicates, ` +
          `${result.rejected} rejected${suffix}${pipeline}.`,
      );
      const page = await api.getConnectors();
      setConnectors(Array.isArray(page.items) ? page.items : []);
      await load(severity, source);
      await reloadIngestion();
    } catch {
      setPollNotice(`${sourceName}: poll refused by the server.`);
    }
  };

  const check = async (sourceName: string) => {
    setPollNotice(null);
    try {
      const status = await api.checkConnector(sourceName);
      setPollNotice(`${status.source}: ${status.connector_state ?? status.state} — ${status.detail}`);
      const page = await api.getConnectors();
      setConnectors(Array.isArray(page.items) ? page.items : []);
      await reloadIngestion();
    } catch {
      setPollNotice(`${sourceName}: check refused by the server.`);
    }
  };

  const openEvent = useCallback(async (id: string) => {
    try {
      setSelected(await api.getEvent(id));
    } catch {
      setSelected(null);
    }
  }, []);

  // Step 29: deep link from incident evidence (Incident → Timeline →
  // Evidence → Original Event). Reads the URL once on mount; a missing or
  // unknown id simply leaves the detail closed — nothing is fabricated.
  useEffect(() => {
    const eventId = new URLSearchParams(window.location.search).get("event");
    if (eventId) void openEvent(eventId);
  }, [openEvent]);

  return (
    <section aria-label="Security events">
      <div className="card">
        <h3>Security events ({total})</h3>
        <p>
          Normalized vendor-neutral events from connected sources. Raw payloads
          are stored as data only and never executed. Each connector below
          reports its own truth: <span className="badge neutral">FIXTURE</span>{" "}
          means operator-supplied data, while a configured source must pass an
          explicit check before it can claim <em>connected</em> — receiving an
          event never means a threat was contained.
        </p>
        <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
          <select
            aria-label="Filter by severity"
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
              void load(event.target.value, source);
            }}
            style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
          >
            {SEVERITIES.map((level) => (
              <option key={level} value={level}>
                {level === "" ? "All severities" : level}
              </option>
            ))}
          </select>
          <select
            aria-label="Filter by source"
            value={source}
            onChange={(event) => {
              setSource(event.target.value);
              void load(severity, event.target.value);
            }}
            style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
          >
            {SOURCES.map((item) => (
              <option key={item} value={item}>
                {item === "" ? "All sources" : item}
              </option>
            ))}
          </select>
          <button
            className="button secondary"
            type="button"
            onClick={() => void load(severity, source)}
          >
            Refresh
          </button>
        </div>
      </div>

      <div className="card" aria-label="Event connectors">
        <h3>Event sources / connectors</h3>
        <p className="muted">
          Truthful connector state as evaluated by the backend. Reads never
          trigger network calls — only the per-row check and poll actions do,
          each gated by MANAGE_EVENTS and audited server-side. File sources
          read operator-configured local files only; API sources contact only
          their configured, allow-listed endpoint and report{" "}
          <span className="badge neutral">NOT_CONFIGURED</span> instead of
          pretending to be broken.
        </p>
        {pollNotice && <p className="muted">{pollNotice}</p>}
        {connectors.length === 0 ? (
          <p className="muted">Connector status unavailable.</p>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                {["Source", "Mode", "State", "Detail", "Last check", "Last success", ""].map((h) => (
                  <th key={h} style={{ padding: "8px 10px", color: "var(--text-muted)" }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {connectors.map((item) => {
                const connectorState = item.connector_state ?? item.state;
                const pollable =
                  item.source === "suricata" || item.source === "zeek" || isFullyConfigured(item);
                return (
                  <tr key={item.source} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "8px 10px" }}>
                      <strong>{item.source}</strong>
                    </td>
                    <td style={{ padding: "8px 10px" }}>
                      <span className="badge neutral">{item.mode}</span>
                    </td>
                    <td style={{ padding: "8px 10px" }}>
                      <span className={`badge ${connectorTone(connectorState)}`}>
                        {connectorState}
                      </span>
                    </td>
                    <td style={{ padding: "8px 10px" }}>
                      <span className="muted">{item.detail}</span>
                      {item.last_error_category && (
                        <span className="muted"> · last error: {item.last_error_category}</span>
                      )}
                    </td>
                    <td style={{ padding: "8px 10px", whiteSpace: "nowrap" }}>
                      {formatDateTime(item.last_check_at ?? null)}
                    </td>
                    <td style={{ padding: "8px 10px", whiteSpace: "nowrap" }}>
                      {formatDateTime(item.last_success_at)}
                    </td>
                    <td style={{ padding: "8px 10px", whiteSpace: "nowrap" }}>
                      <button
                        className="button secondary"
                        type="button"
                        onClick={() => void check(item.source)}
                      >
                        Check now
                      </button>{" "}
                      {pollable && (
                        <button
                          className="button secondary"
                          type="button"
                          onClick={() => void poll(item.source)}
                        >
                          Poll now
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      <div className="card" aria-label="Ingestion pipeline">
        <h3>Ingestion pipeline (Step 28)</h3>
        <p className="muted">
          Bounded, operator-initiated runs only: a run fetches at most the
          configured pages or lines, offers them to a capped in-process queue
          (overflow rejects the newest record, counts it, and audits it — never
          silently), processes fixed-size batches, and advances a per-source
          checkpoint only after every batch finished. Streaming stays{" "}
          <span className="badge neutral">MANUAL</span>: no worker, scheduler,
          timer, or automatic polling exists, cursors are written by the server,
          and a failed run leaves the stored cursor untouched.
        </p>
        {ingestionState === "unavailable" && (
          <p className="muted">Ingestion telemetry not reported by the server.</p>
        )}
        {ingestion && (
          <>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
              <thead>
                <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                  {[
                    "Run scope",
                    "Verified state",
                    "Stored",
                    "Repeat hits",
                    "Queue drops",
                    "Batches",
                    "Checkpoint",
                  ].map((h) => (
                    <th key={h} style={{ padding: "8px 10px", color: "var(--text-muted)" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ingestion.sources.map((item) => (
                  <tr key={item.source} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "8px 10px" }}>
                      <strong>run: {item.source}</strong>
                    </td>
                    <td style={{ padding: "8px 10px" }}>
                      <span className={`badge ${connectorTone(item.connector_state)}`}>
                        state: {item.connector_state}
                      </span>
                      {item.last_failure_reason && (
                        <span className="muted"> · {item.last_failure_reason}</span>
                      )}
                    </td>
                    <td style={{ padding: "8px 10px" }}>{item.events_accepted}</td>
                    <td style={{ padding: "8px 10px" }}>{item.events_deduplicated}</td>
                    <td style={{ padding: "8px 10px" }}>{item.events_dropped}</td>
                    <td style={{ padding: "8px 10px" }}>{item.batches}</td>
                    <td style={{ padding: "8px 10px" }} className="muted">
                      {checkpointLabel(item.checkpoint)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="muted" style={{ marginTop: 8 }}>
              Bounds: {ingestion.limits.max_pages} page(s) or{" "}
              {ingestion.limits.max_poll_lines} line(s) per run ·{" "}
              {ingestion.limits.batch_size} record(s) per batch · queue{" "}
              {ingestion.queue.max} capped ({ingestion.queue.overflow}) ·{" "}
              {ingestion.limits.retry_max} bounded retry(ies) · streaming{" "}
              {ingestion.streaming.mode} · {ingestion.totals.dropped} dropped in total
            </p>
          </>
        )}
      </div>

      {state === "loading" && <p className="muted">Loading events…</p>}
      {state === "error" && (
        <div className="card">
          <h3>Events unavailable</h3>
          <p>Could not load events from the API.</p>
          <button className="button secondary" type="button" onClick={() => void load(severity, source)}>
            Retry
          </button>
        </div>
      )}
      {state === "ready" && events.length === 0 && (
        <div className="card">
          <h3>
            {source === "SURICATA"
              ? "No Suricata events received."
              : source === "ZEEK"
                ? "No Zeek events received."
                : source === "WAZUH"
                  ? "No Wazuh events received."
                  : source === "DEFENDER"
                    ? "No Defender events received."
                    : "No security events received."}
          </h3>
          <p>
            Nothing has been ingested yet. Events appear here once a source
            submits to <code>POST /api/v1/events</code>.
          </p>
        </div>
      )}
      {state === "ready" && events.length > 0 && (
        <div className="card" style={{ padding: 0, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                {["Time", "Severity", "Source", "Type", "Title", "Src IP", "Dst IP", "Asset", ""].map(
                  (h) => (
                    <th key={h} style={{ padding: "10px 14px", color: "var(--text-muted)" }}>
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {events.map((event) => (
                <tr key={event.id} style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                    {formatDateTime(event.event_time)}
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <span className={`badge ${severityTone(event.severity)}`}>{event.severity}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    {event.source_type}
                    <span className="muted"> · {event.source_name}</span>{" "}
                    <span className="badge neutral">{event.ingest_mode ?? "FIXTURE"}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>{event.event_type}</td>
                  <td style={{ padding: "10px 14px" }}>{event.title}</td>
                  <td style={{ padding: "10px 14px" }}>{event.source_ip ?? "—"}</td>
                  <td style={{ padding: "10px 14px" }}>{event.destination_ip ?? "—"}</td>
                  <td style={{ padding: "10px 14px" }}>
                    {event.asset_id ?? (
                      <span className="muted">
                        {event.source_ip || event.destination_ip ? "unresolved" : "—"}
                      </span>
                    )}
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <button
                      className="button secondary"
                      type="button"
                      onClick={() => void openEvent(event.id)}
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

      {selected && (
        <div className="card" aria-label="Event details">
          <h3>{selected.title}</h3>
          <p>
            <span className="badge neutral">{selected.ingest_mode ?? "FIXTURE"}</span>{" "}
            <span className="muted">
              occurrences: {selected.occurrence_count ?? 1} · confidence:{" "}
              {selected.confidence ?? "unknown"}
            </span>
          </p>
          <p className="muted">
            {selected.severity} · {selected.source_type}/{selected.source_name} ·{" "}
            {selected.event_type} · {formatDateTime(selected.event_time)}
          </p>
          {selected.description && <p>{selected.description}</p>}
          <p className="muted">
            Host: {selected.hostname ?? "—"} · User: {selected.username ?? "—"} · Process:{" "}
            {selected.process_name ?? "—"} · Action: {selected.action ?? "—"} · Status:{" "}
            {selected.status ?? "—"}
          </p>
          <p className="muted">Fingerprint: {selected.fingerprint}</p>
          {selected.raw_event && (
            <pre
              style={{
                background: "var(--bg)",
                border: "1px solid var(--border)",
                borderRadius: 8,
                padding: 12,
                overflowX: "auto",
                fontSize: "0.82rem",
              }}
            >
              {JSON.stringify(selected.raw_event, null, 2)}
            </pre>
          )}
          <p style={{ marginTop: 12 }}>
            <button className="button secondary" type="button" onClick={() => setSelected(null)}>
              Close details
            </button>
          </p>
        </div>
      )}
    </section>
  );
}
