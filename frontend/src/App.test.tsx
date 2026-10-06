import { render, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { App } from "./App";

function mockFetch(payload: unknown, ok = true, status = 200) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async () => ({
    ok,
    status,
    json: async () => payload,
  }));
}

describe("Security Platform frontend (Step 1 foundation)", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the application shell with navigation", async () => {
    mockFetch({
      status: "ready",
      app: "Security Platform",
      version: "0.1.0",
      environment: "test",
      checks: { database: "up" },
    });
    render(<App />);
    expect(screen.getByText("Security Platform")).toBeInTheDocument();
    for (const item of [
      "Dashboard",
      "Assets",
      "Events",
      "Incidents",
      "Network",
      "Vulnerabilities",
      "Response",
      "Settings",
    ]) {
      expect(screen.getAllByText(item).length).toBeGreaterThan(0);
    }
  });

  it("dashboard displays live backend health from the API (not hardcoded)", async () => {
    mockFetch({
      status: "ready",
      app: "Security Platform",
      version: "0.1.0",
      environment: "test",
      checks: { database: "up" },
    });
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText("0.1.0")).toBeInTheDocument();
    });
    expect(screen.getByText("PostgreSQL via readiness check")).toBeInTheDocument();
  });

  it("dashboard degrades honestly when the backend is unreachable", async () => {
    (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async () => {
      throw new Error("Network error");
    });
    render(<App />);
    await waitFor(() => {
      expect(screen.getAllByText("Offline").length).toBeGreaterThan(0);
    });
  });
});
