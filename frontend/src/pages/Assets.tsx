import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../services/api";
import type { AssetDetail, AssetSummary } from "../types";

function formatDateTime(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

/** Real asset inventory (Step 2): table + selectable asset detail. */
export function Assets() {
  const [assets, setAssets] = useState<AssetSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<AssetDetail | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [detailState, setDetailState] = useState<"idle" | "loading" | "error">("idle");

  const load = useCallback(async (ipFilter: string) => {
    setState("loading");
    try {
      const page = await api.getAssets({ ip: ipFilter || undefined, limit: 100 });
      setAssets(Array.isArray(page.items) ? page.items : []);
      setTotal(typeof page.total === "number" ? page.total : 0);
      setState("ready");
    } catch {
      setState("error");
    }
  }, []);

  useEffect(() => {
    void load("");
  }, [load]);

  const openAsset = async (id: string) => {
    setDetailState("loading");
    try {
      const detail = await api.getAsset(id);
      setSelected(detail);
      setDetailState("idle");
    } catch {
      setDetailState("error");
    }
  };

  return (
    <section aria-label="Asset inventory">
      <div className="card">
        <h3>Assets ({total})</h3>
        <p>
          Inventory built from authorized Nmap scans. One row per IP address —
          rescans update the row instead of duplicating it.
        </p>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void load(filter.trim());
          }}
          style={{ display: "flex", gap: 8, marginTop: 8 }}
        >
          <input
            aria-label="Filter by IP address"
            placeholder="Filter by IP, e.g. 127.0.0.1"
            value={filter}
            onChange={(event) => setFilter(event.target.value)}
            style={{ flex: 1, padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
          />
          <button className="button secondary" type="submit">
            Filter
          </button>
        </form>
      </div>

      {state === "loading" && <p className="muted">Loading inventory…</p>}
      {state === "error" && (
        <div className="card">
          <h3>Inventory unavailable</h3>
          <p>Could not load assets from the API.</p>
          <button className="button secondary" type="button" onClick={() => void load(filter.trim())}>
            Retry
          </button>
        </div>
      )}
      {state === "ready" && assets.length === 0 && (
        <div className="card">
          <h3>No assets yet</h3>
          <p>
            No hosts have been inventoried. Run an authorized scan from the{" "}
            <strong>Network</strong> page (e.g. target <code>127.0.0.1</code>).
          </p>
        </div>
      )}
      {state === "ready" && assets.length > 0 && (
        <div className="card" style={{ padding: 0, overflowX: "auto" }}>
          <table
            aria-label="Inventoried assets"
            style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}
          >
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                {["IP address", "Hostname", "OS", "State", "Type", "Source", "Services", "Last seen", ""].map((h) => (
                  <th key={h} style={{ padding: "10px 14px", color: "var(--text-muted)" }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {assets.map((asset) => (
                <tr key={asset.id} style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "10px 14px" }}>
                    <strong>{asset.ip_address}</strong>
                  </td>
                  <td style={{ padding: "10px 14px" }}>{asset.hostname ?? "—"}</td>
                  <td style={{ padding: "10px 14px" }}>{asset.operating_system ?? "—"}</td>
                  <td style={{ padding: "10px 14px" }}>
                    <span className={`badge ${asset.state === "up" ? "ok" : "neutral"}`}>
                      {asset.state}
                    </span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>{asset.asset_type ?? "UNKNOWN"}</td>
                  <td style={{ padding: "10px 14px" }}>{asset.discovery_source ?? "—"}</td>
                  <td style={{ padding: "10px 14px" }}>{asset.service_count}</td>
                  <td style={{ padding: "10px 14px" }}>{formatDateTime(asset.last_seen)}</td>
                  <td style={{ padding: "10px 14px" }}>
                    <button
                      className="button secondary"
                      type="button"
                      onClick={() => void openAsset(asset.id)}
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

      {detailState === "error" && <p className="muted">Could not load asset details.</p>}
      {selected && detailState !== "loading" && (
        <div className="card" aria-label="Asset details">
          <h3>
            {selected.ip_address}
            {selected.hostname ? ` (${selected.hostname})` : ""}
          </h3>
          <p className="muted">
            MAC: {selected.mac_address ?? "—"} · OS: {selected.operating_system ?? "—"} · First
            seen {formatDateTime(selected.first_seen)} · Last seen{" "}
            {formatDateTime(selected.last_seen)}
          </p>
          {selected.services.length === 0 ? (
            <p>No open services in the latest scan.</p>
          ) : (
            <table
              aria-label="Asset services"
              style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}
            >
              <thead>
                <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                  {["Port", "Protocol", "Service", "Product", "Version", "Last seen"].map((h) => (
                    <th key={h} style={{ padding: "8px 10px", color: "var(--text-muted)" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {selected.services.map((service) => (
                  <tr key={service.id} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "8px 10px" }}>
                      <strong>{service.port}</strong>
                    </td>
                    <td style={{ padding: "8px 10px" }}>{service.protocol}</td>
                    <td style={{ padding: "8px 10px" }}>{service.service_name ?? "—"}</td>
                    <td style={{ padding: "8px 10px" }}>{service.product ?? "—"}</td>
                    <td style={{ padding: "8px 10px" }}>{service.version ?? "—"}</td>
                    <td style={{ padding: "8px 10px" }}>{formatDateTime(service.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p style={{ marginTop: 12 }}>
            <Link
              className="button"
              to={`/assets/${selected.id}`}
              style={{ textDecoration: "none", marginRight: 8 }}
            >
              Investigate
            </Link>
            <button className="button secondary" type="button" onClick={() => setSelected(null)}>
              Close details
            </button>
          </p>
        </div>
      )}
    </section>
  );
}
