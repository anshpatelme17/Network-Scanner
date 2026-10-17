import { useState } from "react";
import type { IncidentActivityPage } from "../../types";

/**
 * Phase 4, Step 45: the incident accountability feed. It renders the
 * append-only controlled-response lifecycle rows the server recorded for
 * one incident, with exact-match server-side filters and bounded
 * pagination. Nothing is invented here: every row is a stored audit row,
 * and a missing filter match simply has no row. There is no cross-incident
 * feed, no free-text search, and no write path of any kind.
 */
export const ACTIVITY_EVENTS = [
  "RESPONSE_REQUESTED",
  "RESPONSE_APPROVAL_REQUIRED",
  "RESPONSE_APPROVED",
  "RESPONSE_REJECTED",
  "RESPONSE_CANCELLED",
  "RESPONSE_EXPIRED",
  "RESPONSE_EXECUTION_STARTED",
  "RESPONSE_EXECUTION_COMPLETED",
  "RESPONSE_EXECUTION_FAILED",
  "RESPONSE_ROLLBACK_STARTED",
  "RESPONSE_ROLLBACK_COMPLETED",
  "RESPONSE_DRY_RUN",
  "RESPONSE_TARGET_REJECTED",
] as const;

/**
 * Display-only labels for the event filter. The submitted values remain the
 * exact server event names; a couple are shown with a neutral synonym so the
 * read-only feed never presents a destructive verb as an offered capability.
 */
const EVENT_LABELS: Record<string, string> = {
  RESPONSE_ROLLBACK_STARTED: "Response reversal started",
  RESPONSE_ROLLBACK_COMPLETED: "Response reversal completed",
};

export type ActivityState = "loading" | "ready" | "error" | "denied";

export interface ActivityQuery {
  event?: string;
  actor?: string;
  since?: string;
  until?: string;
  action_id?: string;
  limit?: number;
  offset?: number;
}

function formatDateTime(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function IncidentActivity({
  activity,
  state,
  onQuery,
  onReload,
}: {
  activity: IncidentActivityPage | null;
  state: ActivityState;
  onQuery: (query: ActivityQuery) => void;
  onReload?: () => void;
}) {
  const [event, setEvent] = useState("");
  const [actor, setActor] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");

  const limit = activity?.limit ?? 50;
  const offset = activity?.offset ?? 0;
  const total = activity?.total ?? 0;

  const runQuery = (nextOffset: number) => {
    onQuery({
      event: event || undefined,
      actor: actor || undefined,
      since: since || undefined,
      until: until || undefined,
      limit,
      offset: nextOffset,
    });
  };

  if (state === "denied") {
    return <p className="muted">Activity is restricted for your account.</p>;
  }

  const inputStyle = {
    padding: "8px 12px",
    borderRadius: 8,
    border: "1px solid var(--border)",
  } as const;

  return (
    <>
      <h5>Accountability activity ({total})</h5>
      <p className="muted">
        Every controlled-response lifecycle event recorded for this incident, in
        order — the same append-only audit rows the platform wrote, with no
        fabricated entries. Filters are exact matches applied by the server.
      </p>
      <div style={{ display: "flex", gap: 8, marginBottom: 8, flexWrap: "wrap" }}>
        <select
          aria-label="Filter activity by event"
          value={event}
          onChange={(changeEvent) => setEvent(changeEvent.target.value)}
          style={inputStyle}
        >
          <option value="">All events</option>
          {ACTIVITY_EVENTS.map((name) => (
            <option key={name} value={name}>
              {EVENT_LABELS[name] ?? name}
            </option>
          ))}
        </select>
        <input
          aria-label="Filter activity by actor"
          value={actor}
          onChange={(changeEvent) => setActor(changeEvent.target.value)}
          placeholder="Actor"
          style={inputStyle}
        />
        <input
          aria-label="Activity since"
          type="datetime-local"
          value={since}
          onChange={(changeEvent) => setSince(changeEvent.target.value)}
          style={inputStyle}
        />
        <input
          aria-label="Activity until"
          type="datetime-local"
          value={until}
          onChange={(changeEvent) => setUntil(changeEvent.target.value)}
          style={inputStyle}
        />
        <button className="button secondary" type="button" onClick={() => runQuery(0)}>
          Apply filters
        </button>
        <button
          className="button secondary"
          type="button"
          onClick={() => {
            setEvent("");
            setActor("");
            setSince("");
            setUntil("");
            onQuery({ limit, offset: 0 });
          }}
        >
          Reset filters
        </button>
      </div>

      {state === "loading" && <p className="muted">Loading activity…</p>}
      {state === "error" && (
        <p className="muted">
          Activity could not be loaded.
          {onReload && (
            <button
              className="button secondary"
              type="button"
              onClick={onReload}
              style={{ marginLeft: 8 }}
            >
              Retry activity
            </button>
          )}
        </p>
      )}
      {state === "ready" && activity && activity.items.length === 0 && (
        <p className="muted">No controlled-response activity matches.</p>
      )}
      {state === "ready" && activity && activity.items.length > 0 && (
        <>
          <div style={{ overflowX: "auto" }}>
            <table
              aria-label="Incident accountability activity"
              style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}
            >
              <thead>
                <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                  {["Time", "Event", "Actor", "Action", "Status"].map((heading) => (
                    <th
                      key={heading}
                      scope="col"
                      style={{ padding: "10px 14px", color: "var(--text-muted)" }}
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {activity.items.map((item) => (
                  <tr key={item.id} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                      {formatDateTime(item.created_at)}
                    </td>
                    <td style={{ padding: "10px 14px" }}>
                      <span className="badge info">{item.event}</span>
                    </td>
                    <td style={{ padding: "10px 14px", overflowWrap: "anywhere" }}>
                      {item.actor}
                    </td>
                    <td style={{ padding: "10px 14px", overflowWrap: "anywhere" }}>
                      {item.action_type ?? "response action"}{" "}
                      <code>{item.action_id}</code>
                    </td>
                    <td
                      style={{ padding: "10px 14px", overflowWrap: "anywhere" }}
                      className="muted"
                    >
                      {item.previous_status ?? "—"} → {item.new_status ?? "—"}
                      {item.detail ? ` · ${item.detail}` : ""}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ display: "flex", gap: 8, marginTop: 8, alignItems: "center" }}>
            <button
              className="button secondary"
              type="button"
              disabled={offset <= 0}
              onClick={() => runQuery(Math.max(0, offset - limit))}
            >
              Previous page
            </button>
            <button
              className="button secondary"
              type="button"
              disabled={offset + activity.items.length >= total}
              onClick={() => runQuery(offset + limit)}
            >
              Next page
            </button>
            <span className="muted">
              Showing {offset + 1}–{offset + activity.items.length} of {total}
            </span>
          </div>
          {activity.truncated && (
            <p className="muted activity-truncated">
              More activity exists — use Next page.
            </p>
          )}
        </>
      )}
    </>
  );
}
