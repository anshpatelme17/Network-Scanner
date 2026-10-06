import { useCallback, useEffect, useState } from "react";
import { api } from "../services/api";
import type {
  FindingLinks,
  FindingRisk,
  VulnerabilityDetail,
  VulnerabilitySummary,
  VulnScanJob,
  VulnScanProfile,
} from "../types";

const SEVERITIES = ["", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"];
const STATUSES = ["", "OPEN", "RESOLVED", "ACCEPTED_RISK", "NOT_SEEN"];
const NEXT_STATUS: Record<string, string[]> = {
  OPEN: ["ACCEPTED_RISK", "RESOLVED", "NOT_SEEN"],
  ACCEPTED_RISK: ["RESOLVED", "OPEN"],
  RESOLVED: ["OPEN"],
  NOT_SEEN: ["OPEN", "RESOLVED"],
};
const SCAN_PROFILES: VulnScanProfile[] = [
  "BASELINE_VULNERABILITY_ASSESSMENT",
  "SERVICE_VULNERABILITY_ASSESSMENT",
  "BASIC",
  "STANDARD",
];

function scannerBadge(scanner: string): string {
  return scanner === "nmap-vuln" ? "LIVE result" : "MOCK/TEST result";
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

/** Vulnerability findings (Steps 15 + 22): normalized assessment inventory + scan flow. */
export function Vulnerabilities() {
  const [items, setItems] = useState<VulnerabilitySummary[]>([]);
  const [total, setTotal] = useState(0);
  const [severity, setSeverity] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [selected, setSelected] = useState<VulnerabilityDetail | null>(null);
  const [risk, setRisk] = useState<FindingRisk | null>(null);
  const [links, setLinks] = useState<FindingLinks | null>(null);
  const [scanTarget, setScanTarget] = useState("");
  const [scanProfile, setScanProfile] = useState<VulnScanProfile>("BASIC");
  const [scanJob, setScanJob] = useState<VulnScanJob | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async (severityValue: string, statusValue: string) => {
    setState("loading");
    try {
      const page = await api.getVulnerabilities({
        severity: severityValue || undefined,
        status: statusValue || undefined,
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
    void load("", "");
  }, [load]);

  const openDetail = async (id: string) => {
    setNotice(null);
    setRisk(null);
    setLinks(null);
    try {
      const detail = await api.getVulnerability(id);
      setSelected(detail);
      const [riskResult, linksResult] = await Promise.allSettled([
        api.getVulnerabilityRisk(id),
        api.getVulnerabilityLinks(id),
      ]);
      if (riskResult.status === "fulfilled") setRisk(riskResult.value);
      if (linksResult.status === "fulfilled") setLinks(linksResult.value);
    } catch {
      setSelected(null);
    }
  };

  const changeStatus = async (id: string, next: string) => {
    setNotice(null);
    try {
      setSelected(await api.updateVulnerabilityStatus(id, next));
      await load(severity, statusFilter);
    } catch {
      setNotice("Status change was rejected by the server.");
    }
  };

  const startScan = async (event: React.FormEvent) => {
    event.preventDefault();
    setNotice(null);
    setScanJob(null);
    const trimmed = scanTarget.trim();
    if (!trimmed) {
      setNotice("Enter an inventoried asset IP or in-scope target.");
      return;
    }
    try {
      const job = await api.requestVulnScan(trimmed, scanProfile);
      setScanJob(job);
      setNotice(`Assessment ${job.id} queued for ${job.target} (${job.profile}).`);
      await load(severity, statusFilter);
    } catch {
      setNotice("Assessment request was rejected by the server.");
    }
  };

  return (
    <section aria-label="Vulnerability findings">
      <div className="card">
        <h3>Vulnerability findings ({total})</h3>
        <p>
          Normalized assessment findings. Findings are data — this page never
          triggers exploitation and takes no remediation actions. Reported
          findings are not proof of exploitation or compromise.
        </p>
        <form onSubmit={(event) => void startScan(event)} style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
          <input
            aria-label="Assessment target"
            value={scanTarget}
            onChange={(event) => setScanTarget(event.target.value)}
            placeholder="127.0.0.1 (inventoried asset)"
            style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
          />
          <select
            aria-label="Assessment profile"
            value={scanProfile}
            onChange={(event) => setScanProfile(event.target.value as VulnScanProfile)}
            style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
          >
            {SCAN_PROFILES.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
          <button className="button secondary" type="submit">
            Start assessment
          </button>
        </form>
        {scanJob && (
          <p className="muted">
            Job {scanJob.id}: {scanJob.status}
            {scanJob.result_summary ? ` — ${scanJob.result_summary}` : ""}
            {scanJob.error ? ` — ${scanJob.error}` : ""}
          </p>
        )}
        <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
          <select
            aria-label="Filter by severity"
            value={severity}
            onChange={(event) => {
              setSeverity(event.target.value);
              void load(event.target.value, statusFilter);
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
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(event) => {
              setStatusFilter(event.target.value);
              void load(severity, event.target.value);
            }}
            style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
          >
            {STATUSES.map((item) => (
              <option key={item} value={item}>
                {item === "" ? "All statuses" : item}
              </option>
            ))}
          </select>
        </div>
        {notice && <p className="muted">{notice}</p>}
      </div>

      {state === "loading" && <p className="muted">Loading findings…</p>}
      {state === "error" && (
        <div className="card">
          <h3>Findings unavailable</h3>
          <p>Could not load findings from the API.</p>
          <button className="button secondary" type="button" onClick={() => void load(severity, statusFilter)}>
            Retry
          </button>
        </div>
      )}
      {state === "ready" && items.length === 0 && (
        <div className="card">
          <h3>No vulnerability findings received.</h3>
          <p>
            Nothing has been assessed yet. Findings appear here once a
            vulnerability assessment runs against inventoried assets.
          </p>
        </div>
      )}
      {state === "ready" && items.length > 0 && (
        <div className="card" style={{ padding: 0, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                {["Severity", "Title", "Host/IP", "Port", "CVE", "CVSS", "Scanner", "Status", ""].map(
                  (h) => (
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
                    <span className={`badge ${severityTone(item.severity)}`}>{item.severity}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>{item.title}</td>
                  <td style={{ padding: "10px 14px" }}>
                    {item.hostname ?? item.destination_ip ?? "—"}
                  </td>
                  <td style={{ padding: "10px 14px" }}>{item.destination_port ?? "—"}</td>
                  <td style={{ padding: "10px 14px" }}>{item.cve_id ?? "—"}</td>
                  <td style={{ padding: "10px 14px" }}>{item.cvss_score ?? "—"}</td>
                  <td style={{ padding: "10px 14px" }}>
                    {item.scanner}{" "}
                    <span className="badge neutral">{scannerBadge(item.scanner)}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <span className="badge neutral">{item.status}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <button
                      className="button secondary"
                      type="button"
                      onClick={() => void openDetail(item.id)}
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
        <div className="card" aria-label="Finding details">
          <h3>{selected.title}</h3>
          <p>
            <span className={`badge ${severityTone(selected.severity)}`}>{selected.severity}</span>{" "}
            <span className="badge neutral">{selected.status}</span>{" "}
            <span className="badge neutral">{scannerBadge(selected.scanner)}</span>{" "}
            <span className="muted">
              {selected.scanner}
              {selected.scanner_version ? ` ${selected.scanner_version}` : ""} · first seen{" "}
              {formatDateTime(selected.first_seen)} · last seen {formatDateTime(selected.last_seen)}
            </span>
          </p>
          {selected.description && <p>{selected.description}</p>}
          <p className="muted">
            Host: {selected.hostname ?? selected.destination_ip ?? "—"}
            {selected.destination_port !== null && selected.destination_port !== undefined
              ? `:${selected.destination_port}`
              : ""}{" "}
            · CVE: {selected.cve_id ?? "—"} · CWE: {selected.cwe_id ?? "—"} · CVSS:{" "}
            {selected.cvss_score ?? "—"} · detected version: {selected.detected_version ?? "—"} ·
            fixed version: {selected.fixed_version ?? "—"}
          </p>
          {selected.extra_data !== null &&
            selected.extra_data !== undefined &&
            typeof selected.extra_data === "object" &&
            "scanner_severity" in selected.extra_data &&
            String((selected.extra_data as Record<string, unknown>).scanner_severity) !==
              selected.severity && (
              <p className="muted">
                Scanner reported severity{" "}
                {String((selected.extra_data as Record<string, unknown>).scanner_severity)},
                normalized to {selected.severity}.
              </p>
            )}
          {selected.evidence && (
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
              {selected.evidence}
            </pre>
          )}
          {selected.remediation_reference && (
            <p>
              <strong>Solution: </strong>
              {selected.remediation_reference}
            </p>
          )}
          <h3>Contextual risk</h3>
          {risk === null ? (
            <p className="muted">
              Not scored yet — run risk recompute to assess this finding. A risk
              score reflects available vulnerability evidence; it is not proof
              of compromise.
            </p>
          ) : (
            <>
              <p>
                <strong>
                  {risk.score} ({risk.severity})
                </strong>{" "}
                <span className="muted">
                  finding severity {selected.severity} · scoring v{risk.scoring_version}
                </span>
              </p>
              <p>{risk.explanation}</p>
              <p className="muted">Calculated {formatDateTime(risk.calculated_at)}</p>
            </>
          )}
          <h3>Correlated records</h3>
          {links === null ||
          (links.related_events.length === 0 && links.related_incidents.length === 0) ? (
            <p className="muted">
              No linked events or incidents — insufficient shared evidence.
            </p>
          ) : (
            <>
              <ul>
                {links.related_events.map((event) => (
                  <li key={event.id} style={{ marginBottom: 4 }}>
                    <strong>{event.title}</strong>{" "}
                    <span className="muted">
                      [{event.source_type}/{event.event_type}, {event.severity}]
                    </span>
                  </li>
                ))}
                {links.related_incidents.map((incident) => (
                  <li key={incident.id} style={{ marginBottom: 4 }}>
                    <strong>Incident {incident.incident_key ?? incident.id}</strong>{" "}
                    <span className="muted">[{incident.status}]</span>
                  </li>
                ))}
              </ul>
              <p className="muted">{links.reasons.join(" · ")}</p>
            </>
          )}
          <h3>Audit history ({(selected.audit ?? []).length})</h3>
          {(selected.audit ?? []).length === 0 ? (
            <p className="muted">No audit entries.</p>
          ) : (
            <ul>
              {(selected.audit ?? []).map((entry, index) => (
                <li key={`${entry.event}-${entry.created_at}-${index}`} style={{ marginBottom: 4 }}>
                  <strong>{entry.event}</strong>{" "}
                  <span className="muted">
                    {entry.previous_status ?? "—"} → {entry.new_status ?? "—"} · {entry.actor} ·{" "}
                    {formatDateTime(entry.created_at)}
                  </span>
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
                  Mark {next.charAt(0) + next.slice(1).toLowerCase().replace("_", " ")}
                </button>
              ))}
            </div>
          )}
          <p style={{ marginTop: 12 }}>
            <button
              className="button secondary"
              type="button"
              onClick={() => {
                setSelected(null);
                setRisk(null);
                setLinks(null);
              }}
            >
              Close details
            </button>
          </p>
        </div>
      )}
    </section>
  );
}
