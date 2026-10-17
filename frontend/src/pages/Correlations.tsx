import { useCallback, useEffect, useState } from "react";
import { api } from "../services/api";
import type { AttackChain, CorrelationDetail, CorrelationSummary } from "../types";

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

/** Correlations (Step 9): related-event groups with ordered evidence. */
export function Correlations() {
  const [items, setItems] = useState<CorrelationSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");
  const [selected, setSelected] = useState<CorrelationDetail | null>(null);
  const [chain, setChain] = useState<AttackChain | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async (severityFilter: string) => {
    setState("loading");
    try {
      const page = await api.getCorrelations({
        severity: severityFilter || undefined,
        limit: 100,
      });
      setItems(Array.isArray(page.items) ? page.items : []);
      setTotal(typeof page.total === "number" ? page.total : 0);
      setState("ready");
    } catch {
      setState("error");
    }
  }, []);

  useEffect(() => {
    void load("");
  }, [load]);

  const openCorrelation = async (id: string) => {
    try {
      const [detail, attackChain] = await Promise.all([api.getCorrelation(id), api.getAttackChain(id)]);
      setSelected(detail);
      setChain(attackChain);
    } catch {
      setSelected(null);
      setChain(null);
    }
  };

  const recompute = async () => {
    setNotice(null);
    try {
      const result = await api.recomputeCorrelations();
      setNotice(
        `Recompute finished: ${result.events_scanned} events scanned, ` +
          `${result.created} created, ${result.refreshed} refreshed.`,
      );
      await load(severity);
    } catch {
      setNotice("Recompute failed.");
    }
  };

  return (
    <section aria-label="Correlated activity">
      <div className="card">
        <h3>Correlated activity ({total})</h3>
        <p>
          Deterministically grouped related events with their supporting
          evidence. Correlation is <strong>not proof of compromise</strong> —
          every group explains exactly why its records were related.
        </p>
        <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
          <select
            aria-label="Filter by severity"
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
              void load(event.target.value);
            }}
            style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
          >
            {["", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].map((level) => (
              <option key={level} value={level}>
                {level === "" ? "All severities" : level}
              </option>
            ))}
          </select>
          <button className="button secondary" type="button" onClick={() => void recompute()}>
            Recompute
          </button>
        </div>
        {notice && <p className="muted">{notice}</p>}
      </div>

      {state === "loading" && <p className="muted">Loading correlations…</p>}
      {state === "error" && (
        <div className="card">
          <h3>Correlations unavailable</h3>
          <p>Could not load correlations from the API.</p>
          <button className="button secondary" type="button" onClick={() => void load(severity)}>
            Retry
          </button>
        </div>
      )}
      {state === "ready" && items.length === 0 && (
        <div className="card">
          <h3>No correlated activity found.</h3>
          <p>
            Ingest events and press <strong>Recompute</strong>. Only events
            matching a documented rule within its time window are grouped.
          </p>
        </div>
      )}
      {state === "ready" && items.length > 0 && (
        <div className="card" style={{ padding: 0, overflowX: "auto" }}>
          <table
            aria-label="Correlations"
            style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}
          >
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                {["Severity", "Title", "Rule", "Events", "Window", ""].map((h) => (
                  <th key={h} style={{ padding: "10px 14px", color: "var(--text-muted)" }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "10px 14px" }}>
                    <span className={`badge ${severityTone(item.severity)}`}>{item.severity}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>{item.title}</td>
                  <td style={{ padding: "10px 14px" }}>{item.rule_name}</td>
                  <td style={{ padding: "10px 14px" }}>{item.event_count}</td>
                  <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                    {formatDateTime(item.window_start)} → {formatDateTime(item.window_end)}
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <button
                      className="button secondary"
                      type="button"
                      onClick={() => void openCorrelation(item.id)}
                    >
                      Evidence
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <div className="card" aria-label="Correlation evidence">
          <h3>{selected.title}</h3>
          <p>
            <span className={`badge ${severityTone(selected.severity)}`}>{selected.severity}</span>{" "}
            <span className="muted">
              {selected.rule_name} · confidence {selected.confidence} · status {selected.status}
            </span>
          </p>
          <p>
            <strong>Why correlated: </strong>
            {selected.explanation}
          </p>
          {selected.description && <p className="muted">{selected.description}</p>}
          <h3>Supporting evidence (oldest first)</h3>
          <ol>
            {selected.evidence.map((entry) => (
              <li key={entry.event_id} style={{ marginBottom: 6 }}>
                <strong>{entry.title}</strong>{" "}
                <span className="muted">
                  [{entry.source_type}/{entry.event_type}, {entry.severity}, role {entry.role},
                  {" "}{formatDateTime(entry.event_time)}]
                </span>
              </li>
            ))}
          </ol>
          {chain && (
            <>
              <h3>Potential attack chain</h3>
              <ol>
                {chain.nodes.map((node) => (
                  <li key={node.id} style={{ marginBottom: 4 }}>
                    <span className="badge neutral">{node.kind}</span> {node.label}
                  </li>
                ))}
              </ol>
            </>
          )}
          <p style={{ marginTop: 12 }}>
            <button
              className="button secondary"
              type="button"
              onClick={() => {
                setSelected(null);
                setChain(null);
              }}
            >
              Close evidence
            </button>
          </p>
        </div>
      )}
    </section>
  );
}
