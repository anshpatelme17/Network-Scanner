import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Login } from "./Login";
import { api } from "../services/api";

const IDENTITY = {
  id: "u-1",
  username: "analyst",
  display_name: "Analyst",
  is_active: true,
  roles: ["SECURITY_ANALYST"],
  permissions: ["READ_INCIDENTS", "PROPOSE_RESPONSE"],
};

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(
    async (url: unknown, init?: RequestInit) => ({
      ok: true,
      status: 200,
      json: async () => handler(String(url), init),
    }),
  );
}

describe("Login page (Step 20)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    window.localStorage.clear();
  });

  it("signs in, persists the token, and shows identity", async () => {
    const seen: Array<{ url: string; auth?: string }> = [];
    mockFetch((url, init) => {
      const headers = (init?.headers ?? {}) as Record<string, string>;
      seen.push({ url, auth: headers.Authorization });
      if (url.endsWith("/auth/login")) {
        return { access_token: "tok-123", token_type: "bearer", expires_in_minutes: 15 };
      }
      return IDENTITY;
    });
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("Sign in", { selector: "h3" })).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "analyst" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "secret-secret-secret" } });
    fireEvent.click(screen.getByText("Sign in", { selector: "button" }));
    await waitFor(() => expect(screen.getByText(/Signed in as/)).toBeInTheDocument());
    expect(window.localStorage.getItem("sp.auth.token")).toBe("tok-123");
    expect(screen.getByText("SECURITY_ANALYST")).toBeInTheDocument();
    // The token is attached to subsequent API calls server-sideStyle.
    expect(seen.some((entry) => entry.auth === "Bearer tok-123")).toBe(true);
  });

  it("reports failed logins without leaking details", async () => {
    mockFetch(() => {
      throw new Error("INVALID_CREDENTIALS");
    });
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByLabelText("Username")).toBeInTheDocument());
    fireEvent.change(screen.getByLabelText("Username"), { target: { value: "analyst" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "wrong" } });
    fireEvent.click(screen.getByText("Sign in", { selector: "button" }));
    await waitFor(() =>
      expect(screen.getByText("Login failed: invalid username or password.")).toBeInTheDocument(),
    );
    expect(window.localStorage.getItem("sp.auth.token")).toBeNull();
  });

  it("signs out and clears the token", async () => {
    window.localStorage.setItem("sp.auth.token", "tok-123");
    mockFetch((url) => {
      if (url.endsWith("/auth/me")) return IDENTITY;
      return { logged_out: true };
    });
    render(
      <MemoryRouter>
        <Login />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText(/Signed in as/)).toBeInTheDocument());
    fireEvent.click(screen.getByText("Sign out"));
    await waitFor(() => expect(screen.getByText("Sign in", { selector: "h3" })).toBeInTheDocument());
    expect(window.localStorage.getItem("sp.auth.token")).toBeNull();
    expect(api.getAuthToken()).toBeNull();
  });
});
