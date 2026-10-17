import { useCallback, useEffect, useState } from "react";
import { api } from "../services/api";
import type { RiskAssessment } from "../types";

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

function factorText(factors: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(factors)) {
    if (value === null || value === undefined) continue;
    if (typeof value === "object") continue;
    parts.push(`${key}: ${String(value)}`);
  }
  return parts.join(" · ");
}

/** Risk assessments (Step 10): deterministic scores with factors. Read-only. */
export function Risk() {
  const [items, setItems] = useState<RiskAssessment[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");
  const [selected, setSelected] = useState<RiskAssessment | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async (severityFilter: string) => {
    setState("loading");
    try {
      const page = await api.getRisk({ severity: severityFilter || undefined, limit: 100 });
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

  const openDetail = async (entityType: string, entityId: string) => {
    try {
      setSelected(await api.getRiskDetail(entityType, entityId));
    } catch {
      setSelected(null);
    }
  };

  const recompute = async () => {
    setNotice(null);
    try {
      const result = await api.recomputeRisk();
      setNotice(
        `Recompute finished (scoring v${result.scoring_version}): ` +
          `${result.assessed} assessed, ${result.created} created, ${result.updated} updated.`,
      );
      await load(severity);
    } catch {
      setNotice("Recompute failed.");
    }
  };

  return (
    <section aria-label="Risk assessments">
      <div className="card">
        <h3>Risk assessments ({total})</h3>
        <p>
          Deterministic scores (0–100) computed only from stored platform
          data, with factors and explanations. A score is{" "}
          <strong>not proof of compromise</strong> and triggers no action.
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

      {state === "loading" && <p className="muted">Loading risk assessments…</p>}
      {state === "error" && (
        <div className="card">
          <h3>Risk assessments unavailable</h3>
          <p>Could not load risk assessments from the API.</p>
          <button className="button secondary" type="button" onClick={() => void load(severity)}>
            Retry
          </button>
        </div>
      )}
      {state === "ready" && items.length === 0 && (
        <div className="card">
          <h3>No risk assessments yet.</h3>
          <p>
            Press <strong>Recompute</strong> after assets, findings, or
            correlations exist. Identical data always reproduces identical scores.
          </p>
        </div>
      )}
      {state === "ready" && items.length > 0 && (
        <div className="card" style={{ padding: 0, overflowX: "auto" }}>
          <table
            aria-label="Stored risk assessments"
            style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}
          >
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                {["Score", "Severity", "Entity", "Version", "Calculated", ""].map((h) => (
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
                    <strong>{item.score}</strong>
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <span className={`badge ${severityTone(item.severity)}`}>{item.severity}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    {item.entity_type} <span className="muted">· {item.entity_id.slice(0, 8)}…</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>{item.scoring_version}</td>
                  <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                    {formatDateTime(item.calculated_at)}
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <button
                      className="button secondary"
                      type="button"
                      onClick={() => void openDetail(item.entity_type, item.entity_id)}
                    >
                      Factors
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <div className="card" aria-label="Risk factors">
          <h3>
            {selected.entity_type} · score {selected.score} ({selected.severity})
          </h3>
          <p>
            <span className="badge neutral">priority {selected.priority ?? "—"}</span>{" "}
            <span className="muted">advisory classification only — not an automated response</span>
          </p>
          <p>
            <strong>Why this score: </strong>
            {selected.explanation}
          </p>
          <p className="muted">
            Scoring version {selected.scoring_version} · calculated{" "}
            {formatDateTime(selected.calculated_at)}
          </p>
          <p className="muted">{factorText(selected.factors)}</p>
          <p style={{ marginTop: 12 }}>
            <button className="button secondary" type="button" onClick={() => setSelected(null)}>
              Close factors
            </button>
          </p>
        </div>
      )}
    </section>
  );
}
