import { useCallback, useEffect, useState } from "react";
import { api } from "../services/api";
import type { ReadinessStatus, SystemState } from "../types";

export interface SystemStatus {
  state: SystemState;
  backend: string;
  database: string;
  version: string;
  environment: string;
  lastChecked: Date | null;
  detail: string | null;
}

/**
 * Polls the backend readiness endpoint (which itself checks PostgreSQL)
 * so the dashboard shows live status instead of hardcoded "online".
 */
export function useSystemStatus(pollIntervalMs = 30000): SystemStatus & { refresh: () => void } {
  const [status, setStatus] = useState<SystemStatus>({
    state: "loading",
    backend: "checking…",
    database: "checking…",
    version: "—",
    environment: "—",
    lastChecked: null,
    detail: null,
  });

  const refresh = useCallback(() => {
    let cancelled = false;
    (async () => {
      try {
        const ready: ReadinessStatus = await api.getReadiness();
        if (cancelled) return;
        const dbUp = ready.checks?.database === "up";
        setStatus({
          state: ready.status === "ready" ? "online" : "degraded",
          backend: ready.status === "ready" ? "online" : "degraded",
          database: dbUp ? "up" : "down",
          version: ready.version,
          environment: ready.environment,
          lastChecked: new Date(),
          detail: dbUp ? null : "Backend reachable, database check failed.",
        });
      } catch (err) {
        if (cancelled) return;
        setStatus((prev) => ({
          ...prev,
          state: "offline",
          backend: "offline",
          database: "unknown",
          lastChecked: new Date(),
          detail: err instanceof Error ? err.message : "Backend unreachable.",
        }));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    const cancel = refresh();
    const id = window.setInterval(refresh, pollIntervalMs);
    return () => {
      cancel();
      window.clearInterval(id);
    };
  }, [refresh, pollIntervalMs]);

  return { ...status, refresh };
}
