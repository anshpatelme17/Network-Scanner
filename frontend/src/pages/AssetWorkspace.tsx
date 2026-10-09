import { useCallback, useEffect, useState } from "react";
import type { ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError, api } from "../services/api";
import type {
  AssetDetail,
  AssetVulnRisk,
  EventPage,
  RiskAssessment,
  VulnerabilityPage,
} from "../types";

type SectionState = "idle" | "loading" | "ready" | "error" | "denied";
type IdentityState = SectionState | "notfound";

function isDenied(err: unknown): boolean {
  return (
    err instanceof ApiError &&
    (err.code === "PERMISSION_DENIED" || err.status === 401 || err.status === 403)
  );
}

function isMissing(err: unknown, code: string): boolean {
  return err instanceof ApiError && (err.code === code || err.status === 404);
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

function factorText(factors: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(factors)) {
    if (value === null || value === undefined) continue;
    if (typeof value === "object") continue;
    parts.push(`${key}: ${String(value)}`);
  }
  return parts.join(" · ");
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <tr style={{ borderBottom: "1px solid var(--border)" }}>
      <td style={{ padding: "8px 10px", color: "var(--text-muted)", width: "34%" }}>
        {label}
      </td>
      <td style={{ padding: "8px 10px" }}>{children}</td>
    </tr>
  );
}

/** Asset investigation workspace (Step 36): read-only, one section per stored source. */
export function AssetWorkspace() {
  const { assetId } = useParams<{ assetId: string }>();

  const [identity, setIdentity] = useState<IdentityState>("loading");
  const [asset, setAsset] = useState<AssetDetail | null>(null);

  const [vuln, setVuln] = useState<SectionState>("idle");
  const [vulnRisk, setVulnRisk] = useState<AssetVulnRisk | null>(null);
  const [vulnFindings, setVulnFindings] = useState<VulnerabilityPage | null>(null);

  const [events, setEvents] = useState<SectionState>("idle");
  const [eventPage, setEventPage] = useState<EventPage | null>(null);

  const [risk, setRisk] = useState<SectionState>("idle");
  const [assessment, setAssessment] = useState<RiskAssessment | null>(null);

  const loadIdentity = useCallback(async (id: string): Promise<boolean> => {
    if (!id) {
      setAsset(null);
      setIdentity("notfound");
      return false;
    }
    setIdentity("loading");
    setAsset(null);
    try {
      setAsset(await api.getAsset(id));
      setIdentity("ready");
      return true;
    } catch (err) {
      setAsset(null);
      if (isDenied(err)) {
        setIdentity("denied");
        return true;
      }
      if (isMissing(err, "ASSET_NOT_FOUND")) {
        setIdentity("notfound");
        return false;
      }
      setIdentity("error");
      return true;
    }
  }, []);

  const loadVulnerabilities = useCallback(async (id: string) => {
    if (!id) return;
    setVuln("loading");
    setVulnRisk(null);
    setVulnFindings(null);
    const [riskResult, findingsResult] = await Promise.allSettled([
      api.getAssetVulnRisk(id),
      api.getVulnerabilities({ asset_id: id, limit: 100 }),
    ]);
    const nextRisk = riskResult.status === "fulfilled" ? riskResult.value : null;
    const nextFindings =
      findingsResult.status === "fulfilled" ? findingsResult.value : null;
    if (!nextRisk && !nextFindings) {
      setVuln(
        (riskResult.status === "rejected" && isDenied(riskResult.reason)) ||
          (findingsResult.status === "rejected" &&
            isDenied(findingsResult.reason))
          ? "denied"
          : "error",
      );
      return;
    }
    setVulnRisk(nextRisk);
    setVulnFindings(nextFindings);
    setVuln("ready");
  }, []);

  const loadEvents = useCallback(async (id: string) => {
    if (!id) return;
    setEvents("loading");
    setEventPage(null);
    try {
      setEventPage(await api.getEvents({ asset_id: id, limit: 50 }));
      setEvents("ready");
    } catch (err) {
      setEvents(isDenied(err) ? "denied" : "error");
    }
  }, []);

  const loadRisk = useCallback(async (id: string) => {
    if (!id) return;
    setRisk("loading");
    setAssessment(null);
    try {
      setAssessment(await api.getRiskDetail("asset", id));
      setRisk("ready");
    } catch (err) {
      if (isDenied(err)) {
        setRisk("denied");
        return;
      }
      if (isMissing(err, "RISK_NOT_FOUND")) {
        setAssessment(null);
        setRisk("ready");
        return;
      }
      setRisk("error");
    }
  }, []);

  useEffect(() => {
    if (!assetId) {
      setAsset(null);
      setIdentity("notfound");
      return;
    }
    void loadIdentity(assetId).then((found) => {
      if (!found) return;
      void loadVulnerabilities(assetId);
      void loadEvents(assetId);
      void loadRisk(assetId);
    });
  }, [assetId, loadIdentity, loadVulnerabilities, loadEvents, loadRisk]);

  const servicesVisible =
    identity === "loading" || identity === "ready" || identity === "denied";

  return (
    <section aria-label="Asset investigation">
      <div className="card">
        <h3>Asset investigation</h3>
        <p className="muted">
          Read-only workspace for one asset: identity and services, stored
          vulnerability findings, events linked by exact asset id, and stored
          risk. Nothing is written or recalculated in the browser.
        </p>
      </div>

      {identity === "notfound" ? (
        <div className="card" aria-label="Asset identity">
          <h3>Asset not found.</h3>
          {assetId ? (
            <p>
              No stored asset matches <code>{assetId}</code>.
            </p>
          ) : (
            <p className="muted">No asset id was provided in the address.</p>
          )}
          <p>
            <Link to="/assets">Back to asset inventory</Link>
          </p>
        </div>
      ) : (
        <div className="card" aria-label="Asset identity">
          <h3>Asset identity</h3>
          {identity === "loading" && (
            <p className="muted">Loading asset details…</p>
          )}
          {identity === "denied" && (
            <p className="muted">Asset details are restricted for your account.</p>
          )}
          {identity === "error" && (
            <>
              <p className="muted">Asset details could not be loaded.</p>
              <button
                className="button secondary"
                type="button"
                onClick={() => void loadIdentity(assetId ?? "")}
              >
                Retry asset details
              </button>
            </>
          )}
          {identity === "ready" && asset && (
            <table
              style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}
            >
              <tbody>
                <Row label="IP address">{asset.ip_address}</Row>
                <Row label="Hostname">{asset.hostname ?? "—"}</Row>
                <Row label="State">
                  <span
                    className={`badge ${asset.state === "up" ? "ok" : "neutral"}`}
                  >
                    {asset.state}
                  </span>{" "}
                  host availability only — not severity or risk
                </Row>
                <Row label="Asset type">{asset.asset_type}</Row>
                <Row label="Discovery source">{asset.discovery_source ?? "—"}</Row>
                <Row label="MAC">{asset.mac_address ?? "—"}</Row>
                <Row label="OS">{asset.operating_system ?? "—"}</Row>
                <Row label="First seen">{formatDateTime(asset.first_seen)}</Row>
                <Row label="Last seen">{formatDateTime(asset.last_seen)}</Row>
              </tbody>
            </table>
          )}
        </div>
      )}

      {servicesVisible && (
        <div className="card" aria-label="Asset services">
          <h3>Services</h3>
          {identity === "loading" && <p className="muted">Loading services…</p>}
          {identity === "denied" && (
            <p className="muted">Services are restricted for your account.</p>
          )}
          {identity === "ready" &&
            asset &&
            (asset.services.length === 0 ? (
              <p>No open services in the latest scan.</p>
            ) : (
              <table
                style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}
              >
                <thead>
                  <tr
                    style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}
                  >
                    {["Port", "Protocol", "Service", "Product", "Version", "Last seen"].map(
                      (header) => (
                        <th
                          key={header}
                          style={{ padding: "8px 10px", color: "var(--text-muted)" }}
                        >
                          {header}
                        </th>
                      ),
                    )}
                  </tr>
                </thead>
                <tbody>
                  {asset.services.map((service) => (
                    <tr
                      key={service.id}
                      style={{ borderBottom: "1px solid var(--border)" }}
                    >
                      <td style={{ padding: "8px 10px" }}>
                        <strong>{service.port}</strong>
                      </td>
                      <td style={{ padding: "8px 10px" }}>{service.protocol}</td>
                      <td style={{ padding: "8px 10px" }}>
                        {service.service_name ?? "—"}
                      </td>
                      <td style={{ padding: "8px 10px" }}>{service.product ?? "—"}</td>
                      <td style={{ padding: "8px 10px" }}>{service.version ?? "—"}</td>
                      <td style={{ padding: "8px 10px" }}>
                        {formatDateTime(service.last_seen)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ))}
        </div>
      )}

      {vuln !== "idle" && (
        <div className="card" aria-label="Vulnerability exposure">
          <h3>Vulnerability exposure</h3>
          {vuln === "loading" && (
            <p className="muted">Loading vulnerability exposure…</p>
          )}
          {vuln === "denied" && (
            <p className="muted">
              Vulnerability findings are restricted for your account.
            </p>
          )}
          {vuln === "error" && (
            <>
              <p className="muted">Vulnerability exposure could not be loaded.</p>
              <button
                className="button secondary"
                type="button"
                onClick={() => void loadVulnerabilities(assetId ?? "")}
              >
                Retry vulnerability exposure
              </button>
            </>
          )}
          {vuln === "ready" && (
            <>
              {!vulnRisk && (
                <p className="muted">Aggregate exposure unavailable.</p>
              )}
              {!vulnFindings && <p className="muted">Finding list unavailable.</p>}
              {vulnRisk && (
                <p>
                  <strong>
                    {vulnRisk.finding_count} stored finding
                    {vulnRisk.finding_count === 1 ? "" : "s"}
                  </strong>{" "}
                  <span className={`badge ${severityTone(vulnRisk.highest_severity)}`}>
                    {vulnRisk.highest_severity}
                  </span>{" "}
                  <span className="badge neutral">risk {vulnRisk.risk_level}</span>{" "}
                  aggregate {vulnRisk.aggregate_risk} · CVSS{" "}
                  {vulnRisk.highest_cvss ?? "—"} · critical {vulnRisk.critical_count} ·
                  high {vulnRisk.high_count}
                </p>
              )}
              {vulnFindings && vulnFindings.items.length === 0 && (
                <p>No vulnerability findings recorded for this asset.</p>
              )}
              {vulnFindings && vulnFindings.items.length > 0 && (
                <table
                  style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}
                >
                  <thead>
                    <tr
                      style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}
                    >
                      {["Finding", "Severity", "CVE", "CVSS", "Status", "Last seen"].map(
                        (header) => (
                          <th
                            key={header}
                            style={{ padding: "8px 10px", color: "var(--text-muted)" }}
                          >
                            {header}
                          </th>
                        ),
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {vulnFindings.items.map((finding) => (
                      <tr
                        key={finding.id}
                        style={{ borderBottom: "1px solid var(--border)" }}
                      >
                        <td style={{ padding: "8px 10px" }}>
                          <strong>{finding.title}</strong>
                        </td>
                        <td style={{ padding: "8px 10px" }}>
                          <span
                            className={`badge ${severityTone(finding.severity)}`}
                          >
                            {finding.severity}
                          </span>
                        </td>
                        <td style={{ padding: "8px 10px" }}>{finding.cve_id ?? "—"}</td>
                        <td style={{ padding: "8px 10px" }}>
                          {finding.cvss_score ?? "—"}
                        </td>
                        <td style={{ padding: "8px 10px" }}>
                          <span className="badge neutral">{finding.status}</span>
                        </td>
                        <td style={{ padding: "8px 10px" }}>
                          {formatDateTime(finding.last_seen)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </>
          )}
        </div>
      )}

      {events !== "idle" && (
        <div className="card" aria-label="Linked security events">
          <h3>Linked security events</h3>
          <p className="muted">
            Matched by exact asset id <code>{assetId}</code>. No hostname or IP
            inference.
          </p>
          {events === "loading" && <p className="muted">Loading linked events…</p>}
          {events === "denied" && (
            <p className="muted">Event history is restricted for your account.</p>
          )}
          {events === "error" && (
            <>
              <p className="muted">Linked events could not be loaded.</p>
              <button
                className="button secondary"
                type="button"
                onClick={() => void loadEvents(assetId ?? "")}
              >
                Retry events
              </button>
            </>
          )}
          {events === "ready" &&
            eventPage &&
            (eventPage.items.length === 0 ? (
              <p>No events are linked to this asset.</p>
            ) : (
              <>
                <h4>
                  {`Linked events (${eventPage.total} total, showing ${eventPage.items.length})`}
                </h4>
                <ul>
                  {eventPage.items.map((event) => (
                    <li key={event.id}>
                      <span className={`badge ${severityTone(event.severity)}`}>
                        {event.severity}
                      </span>{" "}
                      <a
                        href={`/events?event=${encodeURIComponent(event.id)}`}
                      >
                        {event.title}
                      </a>{" "}
                      <span className="muted">
                        {event.id} · {formatDateTime(event.event_time)}
                      </span>
                    </li>
                  ))}
                </ul>
              </>
            ))}
        </div>
      )}

      {risk !== "idle" && (
        <div className="card" aria-label="Stored asset risk">
          <h3>Stored asset risk</h3>
          <p className="muted">
            Stored assessment for this asset as an entity. It is not asset
            state, not finding severity, and it is never recalculated here.
          </p>
          {risk === "loading" && <p className="muted">Loading stored risk…</p>}
          {risk === "denied" && (
            <p className="muted">Risk assessments are restricted for your account.</p>
          )}
          {risk === "error" && (
            <>
              <p className="muted">Stored risk could not be loaded.</p>
              <button
                className="button secondary"
                type="button"
                onClick={() => void loadRisk(assetId ?? "")}
              >
                Retry risk
              </button>
            </>
          )}
          {risk === "ready" && !assessment && (
            <p>No stored risk assessment for this asset yet.</p>
          )}
          {risk === "ready" && assessment && (
            <>
              <p>
                <strong>Score {assessment.score}</strong>{" "}
                <span className={`badge ${severityTone(assessment.severity)}`}>
                  {assessment.severity}
                </span>{" "}
                <span className="badge neutral">priority {assessment.priority}</span>
              </p>
              <p>{assessment.explanation}</p>
              <p className="muted">
                Calculated {formatDateTime(assessment.calculated_at)} · Scoring
                version {assessment.scoring_version}
              </p>
              <p className="muted">{factorText(assessment.factors)}</p>
            </>
          )}
        </div>
      )}

      <div className="card" aria-label="Investigation navigation">
        <h3>Investigation navigation</h3>
        <p>
          <Link to="/assets">Asset inventory</Link> ·{" "}
          <Link to="/events">Security events</Link> ·{" "}
          <Link to="/vulnerabilities">Vulnerabilities</Link> ·{" "}
          <Link to="/risk">Risk assessments</Link>
        </p>
        <p className="muted">
          Related incidents are not available from the current asset API.
        </p>
      </div>
    </section>
  );
}
