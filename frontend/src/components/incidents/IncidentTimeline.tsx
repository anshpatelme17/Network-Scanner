import { useState } from "react";
import type { ReactNode } from "react";
import type { IncidentTimeline as IncidentTimelineData } from "../../types";

/**
 * Phase 3, Step 35: the security timeline for an incident, rendered as a
 * self-contained section. The server decides the chronological content and
 * its truncation bound (correlation_timeline_max_entries); this view only
 * groups entries by day and lets the analyst narrow by kind. Nothing is
 * invented here — a missing event reference or a transaction simply has no
 * row.
 */
export const TIMELINE_KINDS = [
  "event",
  "observation",
  "opened",
  "status",
  "evidence",
  "update",
  "audit",
  "resolution",
] as const;

export type TimelineSectionState = "loading" | "ready" | "error" | "denied";

function formatDateTime(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function dayLabel(value: string): string {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleDateString();
}

function kindBadge(kind: string): string {
  switch (kind) {
    case "event":
      return "warn";
    case "resolution":
      return "ok";
    default:
      return "neutral";
  }
}

export function IncidentTimeline({
  timeline,
  state,
  onReload,
}: {
  timeline: IncidentTimelineData | null;
  state: TimelineSectionState;
  onReload?: () => void;
}) {
  const [filter, setFilter] = useState("");

  if (state === "loading") return <p className="muted">Loading timeline…</p>;
  if (state === "error") {
    return (
      <p className="muted">
        Timeline could not be loaded.
        {onReload && (
          <button
            className="button secondary"
            type="button"
            onClick={onReload}
            style={{ marginLeft: 8 }}
          >
            Retry timeline
          </button>
        )}
      </p>
    );
  }
  if (state === "denied") {
    return <p className="muted">Timeline is restricted for your account.</p>;
  }
  if (state === "ready" && timeline && timeline.entries.length === 0) {
    return <p className="muted">No timeline entries are stored yet.</p>;
  }
  if (!timeline) return null;

  const entries = timeline.entries;
  const visible = filter ? entries.filter((entry) => entry.kind === filter) : entries;

  const rows: ReactNode[] = [];
  let previousDay = "";
  visible.forEach((entry, index) => {
    const label = entry.at ? dayLabel(entry.at) : "Unknown date";
    if (label !== previousDay) {
      rows.push(
        <li key={`day-${index}-${label}`} className="timeline-day">
          {label}
        </li>,
      );
      previousDay = label;
    }
    rows.push(
      <li key={`${entry.kind}-${index}`} style={{ marginBottom: 4 }}>
        <span className={`badge ${kindBadge(entry.kind)}`}>{entry.kind}</span>{" "}
        <strong>{entry.label}</strong>{" "}
        <span className="muted">{formatDateTime(entry.at)}</span>
        {entry.detail && <span className="muted"> · {entry.detail}</span>}
        {entry.event_id && (
          <span className="muted">
            {" · entity "}
            {entry.entity ?? "unknown"}
            {entry.explanation ? ` · ${entry.explanation}` : ""} ·{" "}
            <a href={`/events?event=${encodeURIComponent(entry.event_id)}`}>
              <code>{entry.event_id}</code>
            </a>
          </span>
        )}
      </li>,
    );
  });

  return (
    <>
      <h5>Timeline ({visible.length})</h5>
      <select
        aria-label="Filter timeline by type"
        value={filter}
        onChange={(event) => setFilter(event.target.value)}
        style={{
          padding: "8px 12px",
          borderRadius: 8,
          border: "1px solid var(--border)",
          marginBottom: 8,
        }}
      >
        <option value="">All types</option>
        {TIMELINE_KINDS.map((kind) => (
          <option key={kind} value={kind}>
            {kind}
          </option>
        ))}
      </select>
      <ul>{rows}</ul>
      {visible.length === 0 && (
        <p className="muted">No timeline entries match this filter.</p>
      )}
      {timeline.truncated && (
        <p className="muted timeline-truncated">
          Timeline truncated at the server bound — earlier entries are omitted.
        </p>
      )}
    </>
  );
}