import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, api } from "../services/api";
import type { ResponseCenterSummary, ResponseProposal } from "../types";

/**
 * Phase 4, Step 40: a read-only operator workspace for controlled
 * defensive responses.
 *
 * Everything on this page is an aggregate of rows the platform already
 * stores. It performs no action of its own: the only call it makes is a
 * single GET, and every control that needs a decision (approve, execute,
 * roll back) links to the existing /response page rather than
 * reimplementing it. No proposal is created, approved, executed, or
 * cancelled from here.
 */
type PageState = "loading" | "ready" | "error" | "denied";

const RESULT_LIMIT = 100;

// The statuses the backend reports for controlled responses, in the order
// they are presented. Anything the server reports outside this list is
// still shown, so an unexpected status is never silently dropped.
const STATUS_ORDER = [
  "PENDING_APPROVAL",
  "APPROVED",
  "RUNNING",
  "COMPLETED",
  "FAILED",
  "ROLLED_BACK",
  "REJECTED",
  "CANCELLED",
  "EXPIRED",
  "DRY_RUN_COMPLETED",
];

function isDenied(err: unknown): boolean {
  return (
    err instanceof ApiError &&
    (err.code === "PERMISSION_DENIED" || err.status === 401 || err.status === 403)
  );
}

function formatDateTime(value: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function statusTone(status: string): string {
  switch (status) {
    case "APPROVED":
    case "COMPLETED":
      return "ok";
    case "REJECTED":
    case "CANCELLED":
    case "EXPIRED":
    case "FAILED":
      return "bad";
    case "PENDING_APPROVAL":
    case "DRY_RUN_COMPLETED":
    case "RUNNING":
      return "warn";
    default:
      return "neutral";
  }
}

function statusCounts(counts: Record<string, number>): Array<[string, number]> {
  const known = STATUS_ORDER.filter((status) => status in counts).map(
    (status) => [status, counts[status]] as [string, number],
  );
  // Report anything the server sent that this list does not know about,
  // rather than hiding it: an unknown status is information, not noise.
  const extra = Object.entries(counts)
    .filter(([status]) => !STATUS_ORDER.includes(status))
    .sort(([a], [b]) => a.localeCompare(b));
  return [...known, ...extra];
}

/**
 * Phase 4, Step 40: pending-approval / upcoming-expiration rows.
 *
 * Every row repeats the mock-provider notice: the platform records a
 * defensive step inside itself and contacts no firewall, endpoint agent,
 * identity provider, or cloud API.
 */
function ResponseTable({
  label,
  rows,
}: {
  label: string;
  rows: ResponseProposal[];
}) {
  return (
    <div className="card" aria-label={label}>
      <h3>
        {label} ({rows.length})
      </h3>
      <p>
        <span className="badge warn">
          MOCK PROVIDER — PLATFORM RECORD ONLY, NO EXTERNAL SYSTEM CHANGED
        </span>
      </p>
      <p className="muted">
        Every controlled action is recorded inside this platform only. No firewall, endpoint,
        account, or cloud system is contacted, and none of these actions runs automatically.
      </p>
      {rows.length === 0 ? (
        <p className="muted">Nothing to show here.</p>
      ) : (
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                {["Action", "Target", "State", "Approval", "Requested by", "Expires", "Evidence"].map(
                  (header) => (
                    <th
                      key={header}
                      style={{ padding: "10px 14px", color: "var(--text-muted)" }}
                    >
                      {header}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {rows.map((item) => (
                <tr key={item.id} style={{ borderBottom: "1px solid var(--border)" }}>
                  <td style={{ padding: "10px 14px" }}>
                    <strong>{item.action_type}</strong>
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    {item.target_type}:{item.target_reference}
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <span className={`badge ${statusTone(item.status)}`}>{item.status}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    {item.approved_by ? (
                      <span className="muted">approved by {item.approved_by}</span>
                    ) : (
                      <span className="badge warn">
                        {item.approval_required ? "PENDING APPROVAL" : "APPROVAL NOT REQUIRED"}
                      </span>
                    )}
                  </td>
                  <td style={{ padding: "10px 14px" }}>{item.requested_by}</td>
                  <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                    {formatDateTime(item.expires_at)}
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    {item.target_evidence.length} event(s)
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

export function ResponseCenter() {
  const [state, setState] = useState<PageState>("loading");
  const [summary, setSummary] = useState<ResponseCenterSummary | null>(null);

  const load = useCallback(async () => {
    setState("loading");
    try {
      setSummary(await api.getResponseCenterSummary({ limit: RESULT_LIMIT }));
      setState("ready");
    } catch (err) {
      setSummary(null);
      setState(isDenied(err) ? "denied" : "error");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <section aria-label="Response center">
      <div className="card">
        <h3>Response center</h3>
        <p>
          <span className="badge warn">DRY RUN — NO EXTERNAL ACTION PERFORMED</span>
        </p>
        <p>
          A read-only roll-up of the controlled defensive responses this platform has stored.
          Every number and timestamp below comes straight from stored records; nothing here
          recalculates anything, and nothing here runs. To approve, execute, or roll back an
          action, open it on the <Link to="/response">Response</Link> page.
        </p>
        <p className="muted">
          Legacy dry-run proposals from the earlier response steps are deliberately excluded:
          this workspace reports governed controlled actions only.
        </p>
      </div>

      {state === "loading" && <p className="muted">Loading response center…</p>}
      {state === "denied" && (
        <div className="card">
          <h3>Response center restricted</h3>
          <p className="muted">
            Controlled response records are restricted for your account.
          </p>
        </div>
      )}
      {state === "error" && (
        <div className="card">
          <h3>Response center unavailable</h3>
          <p className="muted">
            Could not load the controlled-response summary from the API.
          </p>
          <button className="button secondary" type="button" onClick={() => void load()}>
            Retry
          </button>
        </div>
      )}

      {state === "ready" && summary && (
        <>
          <div className="card" aria-label="Controlled response counts">
            <h3>Controlled responses ({summary.total})</h3>
            <p>
              <span className="badge warn">
                MOCK PROVIDER — PLATFORM RECORD ONLY, NO EXTERNAL SYSTEM CHANGED
              </span>
            </p>
            <p className="muted">
              Exact counts across every stored controlled action, so a state that is not listed
              here genuinely has no rows.
            </p>
            <ul>
              {statusCounts(summary.counts).map(([status, count]) => (
                <li key={status}>
                  <span className={`badge ${statusTone(status)}`}>{status}</span>{" "}
                  <strong>{count}</strong>
                </li>
              ))}
            </ul>
          </div>

          {/*
            Bounded-output disclosure. The server reports `truncated` when
            either list was cut off at the bound, so an incomplete view is
            stated rather than implied.
          */}
          {summary.truncated && (
            <div className="card" aria-label="Response center notice">
              <h3>Results are incomplete</h3>
              <p>
                This view is bounded to the first {summary.limit} records, so some rows are not
                shown ({summary.total} controlled actions exist in total). The counts above are
                complete; the tables below are not.
              </p>
            </div>
          )}

          <ResponseTable label="Awaiting approval" rows={summary.pending_approval} />

          <div className="card" aria-label="Expiring soon">
            <h3>
              Expiring within {summary.expiry_warning_hours} hours (
              {summary.expiring_soon.length})
            </h3>
            <p>
              <span className="badge warn">
                MOCK PROVIDER — PLATFORM RECORD ONLY, NO EXTERNAL SYSTEM CHANGED
              </span>
            </p>
            <p className="muted">
              These actions still have a bounded lifetime left. The {summary.expiry_warning_hours}
              -hour window is a warning only — it never extends, shortens, or otherwise changes
              any action&apos;s deadline. Rows that have already expired, and actions with no
              expiry at all, are excluded.
            </p>
            {summary.expiring_soon.length === 0 ? (
              <p className="muted">
                No controlled action expires within {summary.expiry_warning_hours} hours.
              </p>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
                  <thead>
                    <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                      {["Action", "Target", "State", "Requested by", "Expires", "Evidence"].map(
                        (header) => (
                          <th
                            key={header}
                            style={{ padding: "10px 14px", color: "var(--text-muted)" }}
                          >
                            {header}
                          </th>
                        ),
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {summary.expiring_soon.map((item) => (
                      <tr key={item.id} style={{ borderBottom: "1px solid var(--border)" }}>
                        <td style={{ padding: "10px 14px" }}>
                          <strong>{item.action_type}</strong>
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          {item.target_type}:{item.target_reference}
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          <span className={`badge ${statusTone(item.status)}`}>{item.status}</span>
                        </td>
                        <td style={{ padding: "10px 14px" }}>{item.requested_by}</td>
                        <td style={{ padding: "10px 14px", whiteSpace: "nowrap" }}>
                          {formatDateTime(item.expires_at)}
                        </td>
                        <td style={{ padding: "10px 14px" }}>
                          {item.target_evidence.length} event(s)
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="card">
            <h3>Act on a response</h3>
            <p>
              Approvals, executions, rollbacks and new requests live on the{" "}
              <Link to="/response">Response</Link> page. This workspace only reads.
            </p>
          </div>
        </>
      )}
    </section>
  );
}
