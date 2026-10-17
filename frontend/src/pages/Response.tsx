import { useCallback, useEffect, useRef, useState } from "react";
import { CONTROLLED_ACTION_TYPES } from "../types";
import { api, ApiError, safeErrorText } from "../services/api";
import { useSession } from "../context/SessionContext";
import type {
  AdapterPreview,
  DryRunResult,
  ProviderDryRun,
  ResponseAuditPage,
  ResponseDetail,
  ResponsePolicy,
  ResponseProposal,
  RollbackRecord,
} from "../types";

const STATUSES = [
  "",
  "PROPOSED",
  "PENDING_APPROVAL",
  "APPROVED",
  "REJECTED",
  "CANCELLED",
  "EXPIRED",
  "DRY_RUN_COMPLETED",
  "READY_FOR_EXECUTION",
  "RUNNING",
  "COMPLETED",
  "FAILED",
  "ROLLED_BACK",
];

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
    case "PROPOSED":
    case "DRY_RUN_COMPLETED":
    case "READY_FOR_EXECUTION":
    case "RUNNING":
      return "warn";
    default:
      return "neutral";
  }
}

const NEXT_ACTIONS: Record<string, Array<"approve" | "reject" | "cancel">> = {
  PROPOSED: ["approve", "reject", "cancel"],
  DRY_RUN_COMPLETED: ["approve", "reject", "cancel"],
  APPROVED: ["cancel"],
  REJECTED: [],
  CANCELLED: [],
  EXPIRED: [],
  READY_FOR_EXECUTION: [],
  RUNNING: [],
  COMPLETED: [],
  FAILED: [],
};

// Step 30: the governed lifecycle for controlled defensive actions. A
// consequential request waits for a second human, may never be executed
// straight from a proposal, expires on a bounded TTL, and can only leave
// COMPLETED through an explicit rollback.
const CONTROLLED_NEXT_ACTIONS: Record<string, Array<"approve" | "reject" | "cancel">> = {
  PENDING_APPROVAL: ["approve", "reject", "cancel"],
  APPROVED: ["cancel"],
  ROLLED_BACK: [],
  EXPIRED: [],
  REJECTED: [],
  CANCELLED: [],
  COMPLETED: [],
  FAILED: [],
};

const CONTROLLED_ACTIONS: readonly string[] = CONTROLLED_ACTION_TYPES;

// Step 42A: audit history page size and the states the section can be in.
const AUDIT_PAGE_SIZE = 50;
type AuditState = "loading" | "ready" | "denied" | "error";

function isControlled(item: { action_type: string }): boolean {
  return CONTROLLED_ACTIONS.includes(item.action_type);
}

const SAFE_ACTIONS = [
  "REVIEW",
  "COLLECT_EVIDENCE",
  "MARK_FOR_INVESTIGATION",
  "ACKNOWLEDGE",
  "CLOSE",
];

/** Response proposals (Steps 12 + 18): approval-controlled; safe actions execute on records only. */
export function Response() {
  const [items, setItems] = useState<ResponseProposal[]>([]);
  const [total, setTotal] = useState(0);
  const [statusFilter, setStatusFilter] = useState("");
  const [selected, setSelected] = useState<ResponseDetail | null>(null);
  const [dryRun, setDryRun] = useState<DryRunResult | null>(null);
  const [adapterPreview, setAdapterPreview] = useState<AdapterPreview | null>(null);
  const [state, setState] = useState<"loading" | "ready" | "error">("loading");
  const [notice, setNotice] = useState<string | null>(null);
  const [policy, setPolicy] = useState<ResponsePolicy | null>(null);
  const [providerDryRun, setProviderDryRun] = useState<ProviderDryRun | null>(null);
  const [rollback, setRollback] = useState<RollbackRecord | null>(null);
  // Step 41: synchronous duplicate-submission guard for approve/reject/
  // cancel. State alone cannot stop a second click fired before React
  // re-renders the disabled button, so a ref holds the in-flight flag.
  const [decisionPending, setDecisionPending] = useState(false);
  const decisionPendingRef = useRef(false);
  const [rejectReason, setRejectReason] = useState("");
  // Step 42A: audit history is loaded from the read-only v2 endpoint, not
  // from the detail payload, so the workspace uses one bounded, paginated
  // contract. It is display-only: no control here can mutate anything.
  const [audit, setAudit] = useState<ResponseAuditPage | null>(null);
  const [auditState, setAuditState] = useState<AuditState>("loading");
  const [auditError, setAuditError] = useState<string | null>(null);
  // Step 31: advisory permission reflection. `can()` only decides whether
  // a governed control is *offered*; the server still authorizes it, and
  // an unknown identity is treated as not permitted.
  const { can } = useSession();
  const canApprove = can("APPROVE_RESPONSE");
  const canExecute = can("EXECUTE_RESPONSE");
  const canRollback = can("ROLLBACK_RESPONSE");
  const canCancel = can("CANCEL_RESPONSE");

  const load = useCallback(async (statusValue: string) => {
    setState("loading");
    try {
      const page = await api.getResponses({ status: statusValue || undefined, limit: 100 });
      setItems(Array.isArray(page.items) ? page.items : []);
      setTotal(typeof page.total === "number" ? page.total : 0);
      setState("ready");
    } catch {
      setState("error");
    }
  }, []);

  // Step 42A: fetch one bounded page of an action's audit history. Only
  // the server's stable error code decides the message shown; no server
  // message or exception text is rendered verbatim.
  const loadAudit = useCallback(async (id: string, offset: number) => {
    setAuditState("loading");
    setAuditError(null);
    try {
      const page = await api.getResponseAudit(id, { limit: AUDIT_PAGE_SIZE, offset });
      // Normalise defensively so a malformed payload degrades to an honest
      // empty list rather than crashing the detail view.
      setAudit({ ...page, entries: Array.isArray(page.entries) ? page.entries : [] });
      setAuditState("ready");
    } catch (err) {
      setAudit(null);
      if (err instanceof ApiError && err.status === 403) {
        setAuditState("denied");
      } else {
        setAuditError(safeErrorText(err, "Audit history could not be loaded."));
        setAuditState("error");
      }
    }
  }, []);

  useEffect(() => {
    void load("");
  }, [load]);

  const openDetail = async (id: string) => {
    setDryRun(null);
    setAdapterPreview(null);
    setNotice(null);
    setPolicy(null);
    setProviderDryRun(null);
    setRollback(null);
    setAudit(null);
    void loadAudit(id, 0);
    try {
      setSelected(await api.getResponse(id));
    } catch {
      setSelected(null);
    }
  };

  // Step 30: the policy verdict is fetched for controlled actions only,
  // so the detail view can state the decision and its deterministic
  // reason instead of guessing an authorization state.
  const loadPolicy = useCallback(async (id: string) => {
    try {
      setPolicy(await api.getResponsePolicy(id));
    } catch {
      setPolicy(null);
    }
  }, []);

  const runProviderPreview = async (id: string) => {
    setNotice(null);
    try {
      setProviderDryRun(await api.providerPreviewResponse(id));
    } catch {
      setProviderDryRun(null);
      setNotice("Provider dry run was refused by policy.");
    }
  };

  const runRollback = async (id: string) => {
    setNotice(null);
    try {
      setRollback(await api.rollbackResponse(id));
      setSelected(await api.getResponse(id));
      void loadAudit(id, 0);
      await load(statusFilter);
    } catch {
      setRollback(null);
      setNotice("Rollback was refused by policy.");
    }
  };

  const decide = async (id: string, decision: "approve" | "reject" | "cancel") => {
    // Fail closed on a repeat click: the server re-checks everything, but
    // the operator should not be able to queue the same decision twice.
    if (decisionPendingRef.current) return;
    decisionPendingRef.current = true;
    setDecisionPending(true);
    setNotice(null);
    try {
      // A rejection rationale is optional and only sent when the operator
      // actually typed one. Approval and cancellation send none.
      await api.decideResponse(
        id,
        decision,
        "operator",
        decision === "reject" && rejectReason.trim() ? rejectReason.trim() : undefined,
      );
      setRejectReason("");
      setSelected(await api.getResponse(id));
      void loadAudit(id, 0);
      await load(statusFilter);
    } catch (err) {
      // Only the server's stable machine code is inspected; no server
      // message or exception text is ever rendered.
      setNotice(safeErrorText(err, "Decision was rejected by the server."));
    } finally {
      decisionPendingRef.current = false;
      setDecisionPending(false);
    }
  };

  const preview = async (id: string) => {
    setNotice(null);
    try {
      setDryRun(await api.dryRunResponse(id));
      setSelected(await api.getResponse(id));
      void loadAudit(id, 0);
      await load(statusFilter);
    } catch {
      setNotice("Dry-run preview failed.");
    }
  };

  const executeSimulation = async (id: string) => {
    setNotice(null);
    try {
      await api.executeResponse(id);
      setSelected(await api.getResponse(id));
      void loadAudit(id, 0);
      await load(statusFilter);
    } catch {
      setNotice("Execution was refused by policy.");
    }
  };

  const previewAdapter = async (id: string) => {
    setNotice(null);
    try {
      setAdapterPreview(await api.previewResponse(id));
      setSelected(await api.getResponse(id));
      void loadAudit(id, 0);
    } catch {
      setAdapterPreview(null);
      setNotice("Adapter preview was refused by policy.");
    }
  };

  const controlled = items.filter(isControlled);

  return (
    <section aria-label="Response proposals">
      <div className="card">
        <h3>Response proposals ({total})</h3>
        <p>
          <span className="badge warn">DRY RUN — NO ACTION EXECUTED</span>
        </p>
          <p>
            Proposals describe actions for operator approval. Dangerous action
            types are simulation-only. Safe foundation actions
            (REVIEW, COLLECT_EVIDENCE, MARK_FOR_INVESTIGATION, ACKNOWLEDGE,
            CLOSE) execute only after approval and affect workflow records
            only — never external systems. Every state change is audit-logged.
          </p>
        <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
          <select
            aria-label="Filter by status"
            value={statusFilter}
            onChange={(event) => {
              setStatusFilter(event.target.value);
              void load(event.target.value);
            }}
            style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
          >
            {STATUSES.map((item) => (
              <option key={item} value={item}>
                {item === "" ? "All statuses" : item}
              </option>
            ))}
          </select>
        </div>
        {notice && <p className="muted">{notice}</p>}
      </div>

      {/*
        Step 30: controlled defensive responses. Kept in its own card so a
        consequential action is never presented as if it were a plain
        proposal. The provider is a platform-side mock by default: nothing
        here contacts a firewall, endpoint, or identity provider.
      */}
      <div className="card" aria-label="Controlled defensive responses">
        <h3>Controlled defensive responses ({controlled.length})</h3>
        <p>
          <span className="badge warn">DRY RUN — NO EXTERNAL ACTION PERFORMED</span>
        </p>
        <p>
          Controlled actions are allow-listed and evidence-backed: the target must appear in
          the incident&apos;s stored events, a second operator must approve, and the action
          expires on a bounded TTL. Nothing executes automatically, and no risk score can
          trigger an action.
        </p>
        {controlled.length === 0 ? (
          <p className="muted">No controlled defensive responses.</p>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
              <thead>
                <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                  {["Action", "Target", "State", "Approval", "Provider", "Expires", ""].map((h) => (
                    <th key={h} style={{ padding: "10px 14px", color: "var(--text-muted)" }}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {controlled.map((item) => (
                  <tr key={item.id} style={{ borderBottom: "1px solid var(--border)" }}>
                    <td style={{ padding: "10px 14px" }}>
                      <strong>{item.action_type}</strong>
                    </td>
                    <td style={{ padding: "10px 14px" }}>
                      {item.target_type}:{item.target_reference}
                      <span className="muted"> · {item.target_evidence.length} evidence event(s)</span>
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
                    <td style={{ padding: "10px 14px" }}>{item.provider}</td>
                    <td style={{ padding: "10px 14px" }}>{formatDateTime(item.expires_at)}</td>
                    <td style={{ padding: "10px 14px" }}>
                      <button
                        className="button secondary"
                        type="button"
                        onClick={() => {
                          void openDetail(item.id);
                          void loadPolicy(item.id);
                        }}
                      >
                        Open Controlled Response
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {state === "loading" && <p className="muted">Loading proposals…</p>}
      {state === "error" && (
        <div className="card">
          <h3>Proposals unavailable</h3>
          <p>Could not load proposals from the API.</p>
          <button className="button secondary" type="button" onClick={() => void load(statusFilter)}>
            Retry
          </button>
        </div>
      )}
      {state === "ready" && items.length === 0 && (
        <div className="card">
          <h3>No response proposals.</h3>
          <p>
            Proposals are created explicitly via{" "}
            <code>POST /api/v1/responses</code> against an existing incident.
          </p>
        </div>
      )}
      {state === "ready" && items.length > 0 && (
        <div className="card" style={{ padding: 0, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.9rem" }}>
            <thead>
              <tr style={{ textAlign: "left", borderBottom: "1px solid var(--border)" }}>
                {["Action", "Target", "Status", "Dry run", "Policy", "Requested", ""].map((h) => (
                  <th key={h} style={{ padding: "10px 14px", color: "var(--text-muted)" }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
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
                  <td style={{ padding: "10px 14px" }}>{item.dry_run ? "yes" : "no"}</td>
                  <td style={{ padding: "10px 14px" }}>{item.policy_version}</td>
                  <td style={{ padding: "10px 14px" }}>
                    {item.requested_by}
                    <span className="muted"> · {formatDateTime(item.created_at)}</span>
                  </td>
                  <td style={{ padding: "10px 14px" }}>
                    <button
                      className="button secondary"
                      type="button"
                      onClick={() => void openDetail(item.id)}
                    >
                      Open
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <div className="card" aria-label="Proposal detail">
          <h3>
            {selected.action_type} → {selected.target_type}:{selected.target_reference}
          </h3>
          <p>
            <span className={`badge ${statusTone(selected.status)}`}>{selected.status}</span>{" "}
            <span className="badge warn">DRY RUN — NO ACTION EXECUTED</span>
          </p>
          <p>
            <strong>Reason: </strong>
            {selected.reason}
          </p>
          <p className="muted">
            Incident: {selected.incident_id} · Requested by {selected.requested_by} · Policy{" "}
            {selected.policy_version}
            {selected.approved_at ? ` · Approved ${formatDateTime(selected.approved_at)}` : ""}
            {selected.approved_by ? ` by ${selected.approved_by}` : ""}
            {selected.started_at ? ` · Started ${formatDateTime(selected.started_at)}` : ""}
            {selected.completed_at ? ` · Finished ${formatDateTime(selected.completed_at)}` : ""}
          </p>
          {selected.result_summary && (
            <p>
              <strong>Result: </strong>
              {selected.result_summary}
            </p>
          )}
          {selected.failure_reason && (
            <p>
              <strong>Failure reason: </strong>
              {selected.failure_reason}
            </p>
          )}
          <div style={{ display: "flex", gap: 8, marginTop: 8, flexWrap: "wrap" }}>
            {(
              (isControlled(selected) ? CONTROLLED_NEXT_ACTIONS : NEXT_ACTIONS)[selected.status] ??
              []
            ).map((decision) => (
              <button
                key={decision}
                className="button secondary"
                type="button"
                // Advisory only: a governed decision is disabled when the
                // signed-in account is known to lack the permission. The
                // server re-checks it either way. Step 41: also disabled
                // while any decision on this action is in flight.
                disabled={
                  decisionPending ||
                  (isControlled(selected) &&
                    ((decision === "approve" && !canApprove) ||
                      (decision === "cancel" && !canCancel)))
                }
                onClick={() => void decide(selected.id, decision)}
              >
                {decision.charAt(0).toUpperCase() + decision.slice(1).toLowerCase()}
              </button>
            ))}
            {isControlled(selected) && (
              <>
                <button
                  className="button secondary"
                  type="button"
                  disabled={decisionPending}
                  onClick={() => void runProviderPreview(selected.id)}
                >
                  Preview Controlled Action
                </button>
                {/*
                  Step 41: an optional, bounded rationale sent only with a
                  rejection. Empty or whitespace-only input is omitted, so
                  the server records no reason — never an empty-looking one.
                */}
                <input
                  aria-label="Rejection reason"
                  placeholder="Optional reason for rejecting"
                  value={rejectReason}
                  maxLength={2000}
                  disabled={decisionPending || selected.status !== "PENDING_APPROVAL"}
                  onChange={(event) => setRejectReason(event.target.value)}
                  style={{ padding: "8px 12px", borderRadius: 8, border: "1px solid var(--border)" }}
                />
                {selected.status === "APPROVED" && (
                  <button
                    className="button"
                    type="button"
                    disabled={!canExecute}
                    title={
                      canExecute
                        ? "Runs the approved action through its registry provider."
                        : "Your account does not hold EXECUTE_RESPONSE. The server enforces this regardless of the button state."
                    }
                    onClick={() => void executeSimulation(selected.id)}
                  >
                    Execute Controlled Action
                  </button>
                )}
                {selected.status === "COMPLETED" && selected.rollback_supported && (
                  <button
                    className="button secondary"
                    type="button"
                    disabled={!canRollback}
                    title={
                      canRollback
                        ? "Rolls the action back to the recorded prior state."
                        : "Your account does not hold ROLLBACK_RESPONSE."
                    }
                    onClick={() => void runRollback(selected.id)}
                  >
                    Roll Back
                  </button>
                )}
              </>
            )}
            <button
              className="button secondary"
              type="button"
              onClick={() => void preview(selected.id)}
            >
              Dry Run
            </button>
            {selected.status === "DRY_RUN_COMPLETED" && (
              <button
                className="button secondary"
                type="button"
                onClick={() => void executeSimulation(selected.id)}
              >
                Execute Simulation
              </button>
            )}
            {(selected.status === "APPROVED" || selected.status === "DRY_RUN_COMPLETED") && (
              <button
                className="button secondary"
                type="button"
                onClick={() => void previewAdapter(selected.id)}
              >
                Preview Response
              </button>
            )}
            {selected.status === "APPROVED" && SAFE_ACTIONS.includes(selected.action_type) && (
              <button
                className="button secondary"
                type="button"
                onClick={() => void executeSimulation(selected.id)}
              >
                Execute
              </button>
            )}
          </div>
          {dryRun && (
            <div
              className="card"
              aria-label="Dry-run result"
              style={{ marginTop: 12, background: "var(--bg)" }}
            >
              <h3>Dry-run preview</h3>
              <p>{dryRun.explanation}</p>
              <p className="muted">
                would_execute: {String(dryRun.would_execute)} · result: {dryRun.result} ·
                policy {dryRun.policy_version}
              </p>
            </div>
          )}
          {adapterPreview && (
            <div
              className="card"
              aria-label="Adapter preview"
              style={{ marginTop: 12, background: "var(--bg)" }}
            >
              <h3>Adapter preview</h3>
              <p>
                <span className="badge warn">SIMULATION ONLY — NO EXTERNAL SYSTEM MODIFIED</span>
              </p>
              <p>{adapterPreview.result_summary}</p>
              <p className="muted">
                adapter: {adapterPreview.adapter_type} · accepted: {String(adapterPreview.accepted)} ·
                executed: {String(adapterPreview.executed)} · simulated: {String(adapterPreview.simulated)} ·
                would_execute: {String(adapterPreview.would_execute)} · policy {adapterPreview.policy_decision}
              </p>
              {adapterPreview.evidence.length > 0 && (
                <ul>
                  {adapterPreview.evidence.map((item, index) => (
                    <li key={`${item.kind}-${item.reference}-${index}`} style={{ marginBottom: 4 }}>
                      <code>{item.kind}:{item.reference}</code>
                      {item.detail && <span className="muted"> · {item.detail}</span>}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
          {/*
            Step 30 governance panels. Each one states the server's
            decision, its deterministic reason, and what was NOT done, so
            the interface can never imply a success the platform did not
            verify.
          */}
          {isControlled(selected) && policy && (
            <div
              className="card"
              aria-label="Response policy"
              style={{ marginTop: 12, background: "var(--bg)" }}
            >
              <h3>Response policy</h3>
              <p>
                <span className="badge warn">PENDING APPROVAL</span>{" "}
                <span className="badge">{policy.decision}</span>
              </p>
              <p>{policy.reason}</p>
              <p className="muted">
                provider: {policy.provider} · capable: {String(policy.provider_capable)} · target
                proven: {String(policy.target_proven)} · approval required:{" "}
                {String(policy.approval_required)} · policy {policy.policy_version}
              </p>
            </div>
          )}
          {isControlled(selected) && providerDryRun && (
            <div
              className="card"
              aria-label="Provider dry run"
              style={{ marginTop: 12, background: "var(--bg)" }}
            >
              <h3>Provider dry run</h3>
              <p>
                <span className="badge warn">DRY RUN — NO EXTERNAL ACTION PERFORMED</span>
              </p>
              <p>{providerDryRun.explanation}</p>
              <p className="muted">
                provider: {providerDryRun.provider} · executed: {String(providerDryRun.executed)} ·
                would_execute: {String(providerDryRun.would_execute)} · result:{" "}
                {providerDryRun.result} · policy {providerDryRun.policy_decision}
              </p>
            </div>
          )}
          {isControlled(selected) && rollback && (
            <div
              className="card"
              aria-label="Rollback record"
              style={{ marginTop: 12, background: "var(--bg)" }}
            >
              <h3>Rollback record</h3>
              <p>
                <span className="badge warn">ROLLBACK</span>{" "}
                <span className="badge">{rollback.result}</span>
              </p>
              <p>{rollback.explanation}</p>
              <p className="muted">
                provider: {rollback.provider} · {formatDateTime(rollback.created_at)} · policy{" "}
                {rollback.policy_version}
              </p>
            </div>
          )}
          {selected.execution && (
            <div
              className="card"
              aria-label="Execution result"
              style={{ marginTop: 12, background: "var(--bg)" }}
            >
              <h3>
                {selected.execution.adapter === "simulation"
                  ? "Simulation execution record"
                  : selected.execution.adapter === "MOCK"
                    ? "Controlled execution record (mock provider)"
                    : "Safe execution record"}
              </h3>
              <p>
                {selected.execution.adapter === "simulation" ? (
                  <span className="badge warn">SIMULATION ONLY — NO REAL ACTION EXECUTED</span>
                ) : selected.execution.adapter === "MOCK" ? (
                  <span className="badge warn">
                    MOCK PROVIDER — PLATFORM RECORD ONLY, NO EXTERNAL SYSTEM CHANGED
                  </span>
                ) : (
                  <span className="badge warn">
                    WORKFLOW RECORDS ONLY — NO EXTERNAL CHANGE
                  </span>
                )}
              </p>
              <p>{selected.execution.explanation}</p>
              <p className="muted">
                adapter: {selected.execution.adapter} · result: {selected.execution.result} ·
                would_execute: {String(selected.execution.would_execute)} · policy{" "}
                {selected.execution.policy_version}
              </p>
            </div>
          )}
          {/*
            Step 42A: read-only audit history for this action, loaded from
            the v2 endpoint. It is display-only — there is deliberately no
            approve, reject, cancel, execute, or delete control here, and
            no request_id is shown. `detail` appears only where the server
            recorded one (a rejection), never on an execute entry.
          */}
          <section aria-label="Audit history">
            <h3>Audit history{audit ? ` (${audit.total})` : ""}</h3>
            {auditState === "loading" && <p className="muted">Loading audit history…</p>}
            {auditState === "denied" && (
              <p className="muted">Your account is not permitted to view audit history.</p>
            )}
            {auditState === "error" && (
              <p className="muted">{auditError ?? "Audit history could not be loaded."}</p>
            )}
            {auditState === "ready" && (audit?.entries.length ?? 0) === 0 && (
              <p className="muted">No audit entries.</p>
            )}
            {auditState === "ready" && audit && audit.entries.length > 0 && (
              <>
                <ul aria-label="Audit entries">
                  {audit.entries.map((entry) => (
                    <li key={entry.id} style={{ marginBottom: 4 }}>
                      <strong>{entry.event}</strong>{" "}
                      <span className="muted">
                        {entry.previous_status ?? "—"} → {entry.new_status ?? "—"} · {entry.actor} ·{" "}
                        {formatDateTime(entry.created_at)}
                      </span>
                      {entry.detail && (
                        <div className="muted" style={{ marginLeft: 16 }}>
                          Reason: {entry.detail}
                        </div>
                      )}
                    </li>
                  ))}
                </ul>
                {(audit.offset > 0 || audit.truncated) && (
                  <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
                    <button
                      className="button secondary"
                      type="button"
                      disabled={audit.offset === 0}
                      onClick={() =>
                        void loadAudit(selected.id, Math.max(0, audit.offset - AUDIT_PAGE_SIZE))
                      }
                    >
                      Previous
                    </button>
                    <button
                      className="button secondary"
                      type="button"
                      disabled={!audit.truncated}
                      onClick={() => void loadAudit(selected.id, audit.offset + AUDIT_PAGE_SIZE)}
                    >
                      Next
                    </button>
                  </div>
                )}
              </>
            )}
          </section>
          <p style={{ marginTop: 12 }}>
            <button className="button secondary" type="button" onClick={() => setSelected(null)}>
              Close proposal
            </button>
          </p>
        </div>
      )}
    </section>
  );
}
