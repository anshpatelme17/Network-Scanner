import type { SystemState } from "../../types";

const LABELS: Record<SystemState, { text: string; tone: string }> = {
  loading: { text: "Checking…", tone: "neutral" },
  online: { text: "Online", tone: "ok" },
  degraded: { text: "Degraded", tone: "warn" },
  offline: { text: "Offline", tone: "bad" },
};

export function StatusBadge({ state }: { state: SystemState }) {
  const { text, tone } = LABELS[state];
  return (
    <span className={`badge ${tone}`} role="status" aria-label={`Status: ${text}`}>
      {text}
    </span>
  );
}
