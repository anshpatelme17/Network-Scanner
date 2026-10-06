import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { api } from "../services/api";
import type { AuthUser } from "../types";

/**
 * Advisory permission context (Step 31).
 *
 * This exists so the UI can *communicate* what the signed-in account may
 * do. It is emphatically NOT the security boundary: the API remains the
 * only authority, every governed endpoint re-checks permissions
 * server-side, and hiding or disabling a control here grants nothing. A
 * caller who ignores this context entirely still gets 401/403 from the
 * server.
 *
 * Unknown state is treated as "not permitted", so a failed or not-yet-
 * loaded identity never enables a governed control.
 */

interface SessionState {
  user: AuthUser | null;
  loading: boolean;
  can: (permission: string) => boolean;
  refresh: () => Promise<void>;
}

const SessionContext = createContext<SessionState>({
  user: null,
  loading: true,
  can: () => false,
  refresh: async () => undefined,
});

export function SessionProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setUser(await api.me());
    } catch {
      // An unauthenticated or unreachable identity is not an error state
      // to render; it simply means no governed control is offered.
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const value = useMemo<SessionState>(
    () => ({
      user,
      loading,
      can: (permission: string) =>
        Array.isArray(user?.permissions) && user.permissions.includes(permission),
      refresh,
    }),
    [user, loading, refresh],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): SessionState {
  return useContext(SessionContext);
}

/** True when the signed-in account is known to hold `permission`. */
export function useCan(permission: string): boolean {
  return useSession().can(permission);
}
