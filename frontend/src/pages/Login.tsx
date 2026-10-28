import { useCallback, useEffect, useState } from "react";
import { api } from "../services/api";
import type { AuthUser } from "../types";

/** Authentication (Step 20): login form, current identity, logout. Tokens stay in localStorage. */
export function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [identity, setIdentity] = useState<AuthUser | null>(null);
  const [state, setState] = useState<"checking" | "anonymous" | "authenticated" | "error">(
    "checking",
  );
  const [notice, setNotice] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!api.getAuthToken()) {
      setIdentity(null);
      setState("anonymous");
      return;
    }
    try {
      setIdentity(await api.me());
      setState("authenticated");
    } catch {
      api.clearAuthToken();
      setIdentity(null);
      setState("anonymous");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setNotice(null);
    try {
      await api.login(username, password);
      setUsername("");
      setPassword("");
      await refresh();
    } catch {
      setState("error");
      setNotice("Login failed: invalid username or password.");
    }
  };

  const logout = async () => {
    setNotice(null);
    try {
      await api.logout();
    } catch {
      api.clearAuthToken();
    }
    setIdentity(null);
    setState("anonymous");
  };

  return (
    <section aria-label="Authentication">
      <div className="card">
        <h3>Authentication</h3>
        <p className="muted">
          Sign in to act with your own identity. Permissions are enforced by
          the backend — hiding buttons never grants access. Your account is authenticated by the backend. Permissions are checked
          server-side for protected actions.
        </p>
        {notice && <p className="muted">{notice}</p>}
      </div>

      {state === "checking" && <p className="muted">Checking session…</p>}

      {(state === "anonymous" || state === "error") && (
        <div className="card">
          <h3>Sign in</h3>
          <form onSubmit={(event) => void submit(event)}>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <input
                aria-label="Username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="Username"
                autoComplete="username"
                style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
              />
              <input
                aria-label="Password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Password"
                autoComplete="current-password"
                style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
              />
              <button className="button secondary" type="submit">
                Sign in
              </button>
            </div>
          </form>
        </div>
      )}

      {state === "authenticated" && identity && (
        <div className="card">
          <h3>
            Signed in as {identity.display_name} ({identity.username})
          </h3>
          <p>
            <span className="badge neutral">{identity.roles.join(", ") || "no roles"}</span>
          </p>
          <p className="muted">
            {identity.permissions.length} permission(s): {identity.permissions.join(", ")}
          </p>
          <button className="button secondary" type="button" onClick={() => void logout()}>
            Sign out
          </button>
        </div>
      )}
    </section>
  );
}
