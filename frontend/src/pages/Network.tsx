import { useCallback, useEffect, useState } from "react";
import { api, safeErrorText } from "../services/api";
import type { NmapStatus, ScanJob, ScanPreview, ScanProfile } from "../types";

function formatDateTime(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

/** Network page (Steps 2 + 21): Nmap capability + controlled scan/discovery jobs. */
export function Network() {
  const [nmap, setNmap] = useState<NmapStatus | null>(null);
  const [scans, setScans] = useState<ScanJob[]>([]);
  const [target, setTarget] = useState("127.0.0.1");
  const [profile, setProfile] = useState<ScanProfile>("quick");
  const [actor, setActor] = useState("operator");
  const [authorized, setAuthorized] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [preview, setPreview] = useState<ScanPreview | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [status, recent] = await Promise.all([api.getNmapStatus(), api.listScans(20)]);
      setNmap(status);
      setScans(Array.isArray(recent) ? recent : []);
    } catch {
      setNmap(null);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(), 8000);
    return () => window.clearInterval(id);
  }, [refresh]);

  const submitScan = async (event: React.FormEvent) => {
    event.preventDefault();
    setFormError(null);
    setNotice(null);
    setPreview(null);
    const trimmed = target.trim();
    if (!trimmed) {
      setFormError("Enter a target IP address or CIDR network.");
      return;
    }
    if (!authorized) {
      setFormError("Confirm you are authorized to scan this target.");
      return;
    }
    try {
      const job = await api.createScan(trimmed, profile, actor.trim() || "operator");
      setNotice(`Scan ${job.id} queued for ${job.target} (${job.profile}).`);
      await refresh();
    } catch (err) {
      setFormError(safeErrorText(err, "Scan request failed."));
    }
  };

  const previewScan = async () => {
    setFormError(null);
    setNotice(null);
    const trimmed = target.trim();
    if (!trimmed) {
      setFormError("Enter a target IP address or CIDR network.");
      return;
    }
    try {
      setPreview(await api.previewScan(trimmed, profile));
    } catch (err) {
      setPreview(null);
      setFormError(safeErrorText(err, "Preview failed."));
    }
  };

  const cancel = async (id: string) => {
    setNotice(null);
    try {
      await api.cancelScan(id);
      await refresh();
    } catch {
      setNotice("Cancel was rejected: only queued scans can be cancelled.");
    }
  };

  return (
    <section aria-label="Network scanning">
      <div className="card">
        <h3>Nmap status</h3>
        {nmap === null ? (
          <p className="muted">Checking scanner availability…</p>
        ) : nmap.available ? (
          <p>
            <span className="badge ok">Available</span>{" "}
            <span className="muted">Nmap {nmap.version ?? "unknown version"}</span>
          </p>
        ) : (
          <p>
            <span className="badge bad">Unavailable</span>{" "}
            <span className="muted">
              Nmap is not installed on the backend host — the API stays up, scans are refused
              with a controlled error.
            </span>
          </p>
        )}
      </div>

      <div className="card">
        <h3>New authorized scan</h3>
        <p>
          <strong>Only scan systems and networks you are explicitly authorized to assess.</strong>{" "}
          Targets are limited to a single IP address or a small CIDR network <em>inside the
          server-configured authorization scope</em> (loopback only by default); out-of-scope
          targets are refused. Scan behavior is fixed by the selected profile — there are no
          custom flags or commands.
        </p>
        <form onSubmit={(event) => void submitScan(event)} style={{ display: "grid", gap: 10 }}>
          <label style={{ display: "grid", gap: 4 }}>
            <span className="muted">Target (IP or CIDR, server-bounded scope)</span>
            <input
              aria-label="Scan target"
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              placeholder="127.0.0.1"
              style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
            />
          </label>
          <label style={{ display: "grid", gap: 4 }}>
            <span className="muted">Scan profile</span>
            <select
              aria-label="Scan profile"
              value={profile}
              onChange={(event) => setProfile(event.target.value as ScanProfile)}
              style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
            >
              <option value="quick">quick — common ports, service versions</option>
              <option value="standard">standard — broader ports, OS attempt</option>
              <option value="DISCOVERY_PING">DISCOVERY_PING — host discovery only, no ports</option>
              <option value="DISCOVERY_TCP_COMMON">DISCOVERY_TCP_COMMON — fixed common TCP ports</option>
            </select>
          </label>
          <label style={{ display: "grid", gap: 4 }}>
            <span className="muted">Requested by (operator label)</span>
            <input
              aria-label="Requested by"
              value={actor}
              onChange={(event) => setActor(event.target.value)}
              placeholder="operator"
              style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
            />
          </label>
          <label style={{ display: "flex", gap: 8, alignItems: "flex-start" }}>
            <input
              type="checkbox"
              checked={authorized}
              onChange={(event) => setAuthorized(event.target.checked)}
              aria-label="Authorization confirmation"
            />
            <span className="muted">
              I confirm I own this target or am explicitly authorized to scan it.
            </span>
          </label>
          {formError && (
            <p role="alert" style={{ color: "var(--bad)" }}>
              {formError}
            </p>
          )}
          {notice && <p className="muted">{notice}</p>}
          <div>
            <button className="button" type="submit">
              Start scan
            </button>{" "}
            <button className="button secondary" type="button" onClick={() => void previewScan()}>
              Preview discovery
            </button>{" "}
            <button className="button secondary" type="button" onClick={() => void refresh()}>
              Refresh
            </button>
          </div>
        </form>
        {preview && (
          <div className="card" aria-label="Discovery preview" style={{ marginTop: 12 }}>
            <h3>Discovery preview — no scan performed</h3>
            <p>{preview.profile_description}</p>
            <p className="muted">
              target: {preview.target} · profile: {preview.profile} · addresses:{" "}
              {preview.address_count} · probes ports: {String(preview.probes_ports)} · scope
              authorized: {String(preview.scope_authorized)} · Nmap available:{" "}
              {String(preview.nmap_available)}
            </p>
            <p className="muted">
              Validation success does not mean the target is safe — only that it is
              well-formed, authorized, and within scope.
            </p>
          </div>
        )}
      </div>

      <div className="card">
        <h3>Recent scans ({scans.length})</h3>
        {scans.length === 0 ? (
          <p className="muted">No scans yet.</p>
        ) : (
          <table
            aria-label="Recent scans"
            style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}
          >
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                {["Target", "Profile", "Status", "Requested by", "Assets", "Services", "Finished", "Error", ""].map(
                  (h) => (
                    <th key={h} style={{ padding: "8px 10px", color: "var(--text-muted)" }}>
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => (
                <tr key={scan.id} style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "8px 10px" }}>
                    <strong>{scan.target}</strong>
                  </td>
                  <td style={{ padding: "8px 10px" }}>{scan.profile}</td>
                  <td style={{ padding: "8px 10px" }}>
                    <span
                      className={`badge ${
                        scan.status === "completed"
                          ? "ok"
                          : scan.status === "failed"
                            ? "bad"
                            : "warn"
                      }`}
                    >
                      {scan.status}
                    </span>
                  </td>
                  <td style={{ padding: "8px 10px" }}>{scan.requested_by}</td>
                  <td style={{ padding: "8px 10px" }}>{scan.assets_found}</td>
                  <td style={{ padding: "8px 10px" }}>{scan.services_found}</td>
                  <td style={{ padding: "8px 10px" }}>{formatDateTime(scan.completed_at)}</td>
                  <td style={{ padding: "8px 10px" }}>{scan.error ?? "—"}</td>
                  <td style={{ padding: "8px 10px" }}>
                    {scan.status === "queued" && (
                      <button
                        className="button secondary"
                        type="button"
                        onClick={() => void cancel(scan.id)}
                      >
                        Cancel
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
