import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi, beforeEach } from "vitest";
import { Risk } from "./Risk";

const RISK_PAGE = {
  items: [
    {
      id: "risk-1",
      entity_type: "vulnerability",
      entity_id: "evt-1",
      score: 85,
      severity: "CRITICAL",
      factors: { severity_pts: 40, cvss_pts: 14 },
      explanation: "Risk score 85 (CRITICAL). Finding severity contributes 40 points.",
      calculated_at: "2026-09-27T06:11:00",
      scoring_version: "1.0.0",
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

function mockFetch(handler: (url: string, init?: RequestInit) => unknown) {
  (globalThis as unknown as { fetch: unknown }).fetch = vi.fn(async (url: unknown, init?: RequestInit) => ({
    ok: true,
    status: 200,
    json: async () => handler(String(url), init),
  }));
}

describe("Risk page (Step 10)", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("renders assessments with score, factors and explanation", async () => {
    mockFetch((url) => {
      if (url.includes("/api/v1/risk/vulnerability/evt-1")) return RISK_PAGE.items[0];
      return RISK_PAGE;
    });
    render(
      <MemoryRouter>
        <Risk />
      </MemoryRouter>,
    );
    await waitFor(() => expect(screen.getByText("85")).toBeInTheDocument());
    expect(screen.getByText("not proof of compromise")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Factors"));
    await waitFor(() =>
      expect(screen.getByText("Why this score:")).toBeInTheDocument(),
    );
    expect(screen.getByText(/Finding severity contributes 40 points/)).toBeInTheDocument();
    expect(screen.getByText("1.0.0")).toBeInTheDocument();
  });

  it("shows an honest empty state and recomputes", async () => {
    const seen: string[] = [];
    mockFetch((url, init) => {
      seen.push(`${init?.method ?? "GET"} ${url}`);
      if (url.includes("/recompute")) {
        return { assessed: 2, created: 2, updated: 0, scoring_version: "1.0.0" };
      }
      return { items: [], total: 0, limit: 50, offset: 0 };
    });
    render(
      <MemoryRouter>
        <Risk />
      </MemoryRouter>,
    );
    await waitFor(() =>
      expect(screen.getByText("No risk assessments yet.")).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Recompute" }));
    await waitFor(() =>
      expect(seen.some((entry) => entry.startsWith("POST") && entry.includes("/risk/recompute"))).toBe(true),
    );
    await waitFor(() => expect(screen.getByText(/Recompute finished/)).toBeInTheDocument());
  });
});
