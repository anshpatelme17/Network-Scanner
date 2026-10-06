# Architecture - Security Platform (Steps 31-32: Hardening, Production Readiness & Security Review)

Version: `0.1.0` · Status: **foundation + auth/RBAC + discovery + Nmap assessment + telemetry ingestion + correlation formation + risk scoring + generic ingestion + 5 adapters + correlation + risk + incidents + detection + controlled response + adapter simulation + fixture assessment + finding risk/links + live connector foundation + controlled live Wazuh/Defender connectors + bounded audited ingestion pipeline (streaming disabled) + deterministic incident intelligence (rule-bound, operator-initiated) + controlled defensive response & response governance (allow-listed, evidence-backed, approval-gated, expiring, mock-provider only) + hardening/performance/production readiness (bounded pool, deterministic rate limits, request correlation, security headers, bounded body size, non-root containers) + Step 32 security review (five defects remediated: validation-log secret exposure, dead scan-start rate-limit setting, unthrottled login, `REQUIRE_AUTH` not forwarded to the container, unbounded asset-detail risk query) + read-only SOC overview endpoint (Step 9, API complete and verified; dashboard UI deferred — no Node toolchain in this environment)**

> Step 32 scope note: Step 32 changed no feature, API, schema, permission
> model or connector behaviour. It found and fixed five defects, each with
> regression tests, then ran a full audit whose result was
> `STEP 32 FINAL AUDIT: PASS — PROJECT READY`. Details are in README §13.
> Two consequences are worth stating here: the asset finding-risk query is
> now scoped and bounded by `MAX_ASSET_FINDINGS` rather than reading every
> risk row, and login throttling counts *failed* attempts only. The known
> limitations in §6.7 and README §12.9 still apply unchanged.

> Step 31 scope note: Step 31 adds **no feature and removes no safety control** — it hardens what already exists (see §6). Step 30's governance is unchanged: six allow-listed controlled action types (`BLOCK_INDICATOR`, `DISABLE_INDICATOR_BLOCK`, `ISOLATE_ENDPOINT`, `RELEASE_ENDPOINT`, `DISABLE_ACCOUNT`, `ENABLE_ACCOUNT`), each bound to permitted target types, with targets that must be justified by stored incident evidence; a `PENDING_APPROVAL` state requiring a *different* human to approve; bounded TTL with enforced, audited expiry; a server-side provider registry whose only functioning entry (`MOCK`) writes a platform-side record and whose `NOT_CONFIGURED` entry refuses everything; explicit, separately authorized rollback that reports `UNSUPPORTED` rather than guessing prior state. There is **no** real Defender/Wazuh/firewall/endpoint/cloud provider, no autonomous response, no action triggered by a risk score, and no permanent block. Step 29's deterministic incident intelligence, Step 28's bounded audited ingestion pipeline, and Steps 20–27 (RBAC, allow-listed outbound HTTP, streaming disabled) are unchanged. Still no automation or AI (see §3). With no external service configured, live connectivity is not verified.

> Scope note: Step 30 adds controlled defensive response *governance*, not a defensive capability: six allow-listed controlled action types (`BLOCK_INDICATOR`, `DISABLE_INDICATOR_BLOCK`, `ISOLATE_ENDPOINT`, `RELEASE_ENDPOINT`, `DISABLE_ACCOUNT`, `ENABLE_ACCOUNT`), each bound to permitted target types, with targets that must be justified by stored incident evidence; a `PENDING_APPROVAL` state that requires a *different* human to approve; bounded TTL with enforced, audited expiry; a server-side provider registry whose only functioning entry (`MOCK`) writes a platform-side record and whose `NOT_CONFIGURED` entry refuses everything; explicit, separately authorized rollback that reports `UNSUPPORTED` rather than guessing prior state; and deterministic policy verdicts and recommendations. There is **no** real Defender/Wazuh/firewall/endpoint/cloud provider, no autonomous response, no action triggered by a risk score, and no permanent block. Step 29's deterministic incident intelligence is unchanged: a rule catalog with server-side enable/disable, eight bounded analysis rules, stored `incident_relationships` with fixed confidence labels, and an operator-initiated `POST /incidents/{id}/recalculate` (MANAGE_INCIDENT) — no scheduler, no AI/ML, no client-supplied rules or risk values, no invented entities. Step 28's bounded, audited, operator-driven ingestion pipeline is unchanged, as are Steps 20–27 (RBAC, allow-listed outbound HTTP, streaming disabled). Still no automation or AI (see §3). With no external service configured, live connectivity is not verified.

## 1. What exists today (implemented)

```text
Frontend (React + TS, Vite; nginx /api/ reverse proxy in production serving)
   ↓  /api/v1/ready, /api/v1/assets/*, /api/v1/network/*
API (FastAPI, /api/v1)
   ↓  calls service layer
Services (health, target_validation, nmap_runner, nmap_parser,
          inventory, scan_service)
   ↓  SELECT 1 readiness probe; controlled Nmap; normalized upserts
Database (PostgreSQL 16 via Docker Compose: assets, discovered_services,
          scan_jobs — migration step2_asset_inventory)
```

Step 1 (unchanged): app factory, CORS allow-list, error envelope,
secret-redacting logging, engine/session factory, liveness vs readiness,
dashboard system-status cards.

Step 2 (kept): asset inventory, controlled scans, Assets/Network UI.

Step 3 (kept — generic ingestion foundation): canonical `SecurityEvent`,
closed severity/source vocabularies, `normalize_event()` + `store_event()`
(idempotent triple, 64 KB raw cap, informational fingerprint), generic
`POST/GET /events` API, Events UI + dashboard cards.

Step 23 (new — telemetry ingestion foundation, fixture grade):

```text
operator payload → registry adapter (static key, KeyError → 422)
   ↓  normalize (422/413) → server-side asset correlation (read-only)
   ↓  store (created → RECEIVED | replay → occurrence+1 → DEDUPLICATED)
append-only event_audits (RECEIVED/NORMALIZED/DEDUPLICATED/REJECTED)
```

- Static `event_adapters` registry (SURICATA/ZEEK/WAZUH/DEFENDER, all
  FIXTURE mode); one shared audited orchestration helper for every
  single/batch path; unknown sources rejected, no dynamic imports.
- Model: +`confidence` (source-supplied 0–100, else NULL),
  +`occurrence_count`/`last_seen_at` (replay accounting; first-seen
  never rewritten); responses carry `ingest_mode: FIXTURE`.
- Asset correlation: existing links kept, bogus links dropped, IP then
  hostname resolution, no-match stays unresolved; inventory never
  created or overwritten. Same RBAC/limits; UI shows fixture badges,
  unresolved assets, occurrences. Observed data only.

Step 24 (new — correlation + incident formation foundation):

```text
stored events/findings → rule engine (static map, capped windows)
   ↓  POST /correlations/recompute (RUN_ANALYSIS, bodiless, audited)
Correlation rows (deterministic ids) → POST /incidents/detect
   ↓  typed incident + observation links + timeline + audit
GET /incidents/{id}/observations → typed links + per-kind counts
```

- Rules (multi-source-target 60 min / vuln-exposure 24 h /
  repeated-source 15 min; fixed confidences 75/70/60) run over ≤500
  recent events; effective window = min(rule, `correlation_max_
  window_minutes` ≤ 7 days); explanations state the effective window.
- Recompute audits RUN_STARTED/MATCHED/COMPLETED with actor; request
  bodies rejected (422). Severity = evidence maximum with pivot-naming
  reasons; confidence = correlation strength, not compromise probability.
- Incidents reuse the Step 11/17 model and lifecycle (no second
  system, no auto-close); observation links are idempotent references
  with reasons; timeline stays deterministic and timestamp-preserving.

Step 25 (new — risk scoring & incident prioritization, advisory only):

```text
stored incident + evidence links → score_incident() (pure, versioned)
   ↓  POST /risk/incidents/{id}/calculate (MANAGE_INCIDENT, bodiless)
upsert snapshot (same deterministic id) + change-only audit → GET detail
```

- Factors: incident severity + 2/observation (cap 10) + 3/linked-vuln
  (cap 9) + confidence//10 + recency; unknowns score 0, never guessed;
  same 10-base/clamp family (min 10, max 104→100); centralized
  PRIORITY_BANDS (P1≥80/P2≥60/P3≥40/P4) alongside severity bands.
- `incident` entity joins bounded recompute (Step 10 counting contract
  preserved); per-incident calculate upserts idempotently; `risk_audits`
  records creations + genuine changes with actor (repeats are silent);
  policy `1.0.0` stored per row and inside the identity.
- UI: incident Advisory-risk panel (score/severity/priority/factors/
  version/explanation + Calculate/Recalculate) and priority in Risk
  detail; CALCULATED RISK wording throughout, zero response controls.

Step 28 (new — bounded, audited ingestion pipeline):

```text
operator POST /events/connectors/{source}/poll[?replay=true]  (MANAGE_EVENTS)
   |   ingestion.poll_source -> audited INGESTION_STARTED / INGESTION_REPLAY
   |   connectors poll (bounded fetch: <= CONNECTOR_MAX_PAGES /
   |   CONNECTOR_MAX_EVENTS, transient-only bounded retries,
   |   rotation/truncation/offset detection on file sources)
   v  records split into batches of <= INGESTION_MAX_BATCH_SIZE
BoundedQueue (<= INGESTION_QUEUE_MAX, overflow REJECT_NEW + audit)
   |   one fully committed batch at a time -> normalize -> dedupe -> persist
   v  INGESTION_BATCH_COMPLETED -> INGESTION_CHECKPOINT_ADVANCED (per source)
failure / backpressure -> checkpoint NOT advanced -> the next poll re-reads
   the bounded window (dedup absorbs repeats); a failed batch returns
   422 INGESTION_FAILED and persists nothing new
GET /events/ingestion/status, GET /events/ingestion/checkpoints  (READ_EVENTS)
   -> pipeline stages, bounds, queue, streaming state, provenance
```

- Checkpoint model (`models/ingestion.py`, migration `step28_ingestion`,
  one row per source) behind `services/checkpoints.py`: cursors are
  sanitized before storage (secret-like keys/values refused, scalars
  only, ≤ 4096 bytes) and the sanitized map is exposed only through the
  authenticated READ_EVENTS checkpoint/status readers — never to
  anonymous callers, never in application logs, never in responses to
  any other endpoint.
- Server-enforced bounds from settings: `INGESTION_MAX_BATCH_SIZE`
  (default 50), `INGESTION_QUEUE_MAX` (default 500, overflow
  `REJECT_NEW` audited as `INGESTION_BACKPRESSURE`), and
  `INGESTION_RETRY_MAX` / `INGESTION_RETRY_BACKOFF_SECONDS` for
  transient fetch failures only (timeout/connection categories; 401/403
  authentication failures are never retried).
- Recovery/replay: the checkpoint advances only after a fully committed
  batch, so failed or backpressure-limited runs re-read the window and
  dedup absorbs repeats; `?replay=true` re-reads idempotently
  (`INGESTION_REPLAY`, occurrence counting, no checkpoint advance).
  File sources detect rotation, truncation and offset drift and restart
  at byte 0 (`INGESTION_ROTATION_DETECTED`); byte resume is opt-in via
  `CONNECTOR_FILE_RESUME` (default false).
- Streaming is an architected foundation, NOT enabled:
  `services/ingestion_stream.py` (connector stream protocol, bounded
  poll stream, poll worker) refuses to start while
  `STREAMING_ENABLED=false` — no background threads, timers or
  scheduled polls exist anywhere in the codebase.
- Audits reuse the append-only `event_audits` table with the Step 28
  vocabulary (`INGESTION_STARTED`, `INGESTION_BATCH_*`,
  `INGESTION_CHECKPOINT_*`, `INGESTION_REPLAY`,
  `INGESTION_BACKPRESSURE`, `INGESTION_RETRY`,
  `INGESTION_ROTATION_DETECTED`): actor, source, counters, categories
  and the already-sanitized cursor on advancement — never credentials,
  tokens or response bodies. All actions fit the 32-character `action`
  column.
- UI: Events page "Ingestion pipeline" panel (run scope, verified
  state, stored/repeat/queue-drop counters, batch and queue bounds,
  streaming state, checkpoint provenance) with an honest
  "Ingestion telemetry not reported by the server." fallback when the
  status endpoint is unavailable. GET reads never poll anything.

Step 29 (new — deterministic incident intelligence, analysis only):

```text
operator POST /incidents/{id}/recalculate  (MANAGE_INCIDENT, bodiless, audited)
   ↓  bounded newest-first slice (<= CORRELATION_MAX_EVENTS_PER_OPERATION)
rule catalog (enabled/conditions; CORRELATION_DISABLED_RULES CSV skips
   |   rules server-side — disabled rules produce nothing)
   v  8 pure predicates: stored asset/user/indicator pivots, temporal auth
   |   chains (identity break ends the chain), cross-source groups, same-
   |   entity pairs, repeated sources, vuln links, multi-source pivots
bounded upsert + prune (<= CORRELATION_RELATIONSHIP_MAX /
   |   CORRELATION_RELATIONSHIP_EVIDENCE_MAX) + INCIDENT_RECALCULATED and
   |   INCIDENT_CORRELATED audits (actor, rule, bounds — no payloads)
incident_relationships rows (rule, confidence, explanation, evidence ids)
   ↓  GET /incidents/{id}/relationships  (READ_INCIDENTS, rule/limit/offset)
GET /incidents/{id}/evidence|/timeline  → bounded overview + truncation flags
   ↓  confidence labels: DIRECT >=85 / STRONG >=70 / MODERATE >=55 / WEAK <55
risk factor snapshot gains relationship_count (score formula unchanged)
```

- Rule model: every Step 24/29 rule carries `enabled`/`conditions`;
  `CORRELATION_DISABLED_RULES` (server-side CSV, unknown ids ignored) or
  per-run defaults disable evaluation — a disabled rule never evaluates
  and never writes a relationship, and enabled rules keep their
  conditions intact. The eight analysis rules are pure documented
  predicates with fixed catalog confidences 90→45; the catalog is data,
  never machine learning.
- Bounds are server-side ceilings, never client input: the three rule
  windows (`CORRELATION_TEMPORAL_WINDOW_MINUTES` 60,
  `CORRELATION_CROSS_SOURCE_WINDOW_MINUTES` 60,
  `CORRELATION_ENTITY_WINDOW_MINUTES` 5) plus
  `CORRELATION_MAX_EVENTS_PER_OPERATION` (200),
  `CORRELATION_RELATIONSHIP_MAX` (200),
  `CORRELATION_RELATIONSHIP_EVIDENCE_MAX` (20),
  `CORRELATION_EVIDENCE_MAX` (200) and
  `CORRELATION_TIMELINE_MAX_ENTRIES` (500); responses report
  `truncated` instead of growing unbounded.
- Confidence labels are fixed mappings (DIRECT ≥85 / STRONG ≥70 /
  MODERATE ≥55 / WEAK <55) — analysis strength, never compromise
  probability. Relationships reference stored ids only (incident, event,
  asset, vulnerability); no asset, user or identity is ever invented,
  and a vulnerability finding alone creates nothing.
- Audits: every run appends `INCIDENT_RECALCULATED`, runs that create
  rows also append `INCIDENT_CORRELATED`, both on the append-only
  `incident_audits` table with actor, rule and bounds — never event
  payloads or secrets. Analysis is operator-initiated only: no
  scheduler, no automatic scoring, no background threads.
- Migration `step29_intelligence` (additive): `incident_relationships`
  table with FKs to incidents/events/vulnerabilities plus deterministic
  identity; rows are upserted (refresh) or pruned — never duplicated.
- Recalculate response: `analysis_version`, `rules_evaluated`,
  `events_considered`, `relationships_created` / `_refreshed` / `_total`,
  `truncated` and the effective `bounds` echoed back (deterministic
  counts, bodiless request — any body is 422 `INVALID_REQUEST`).

Step 30 (new — controlled defensive response & response governance):

```text
DETECTION -> CORRELATION -> RISK (Step 25) -> RECOMMENDED RESPONSE
          -> HUMAN APPROVAL -> AUTHORIZED ACTION -> VERIFICATION -> AUDIT

POST /responses/controlled              (REQUEST_RESPONSE)
   |  1. action type in CONTROLLED_ACTION_TYPES          (else 422)
   |  2. target type in ACTION_TARGET_TYPES[action]     (else 422)
   |  3. provider from PROVIDER_SELECTION (server-side; client cannot name one)
   |  4. provider.validate_target()  - shape/format only, never resolves
   |  5. target must appear in STORED incident evidence
   |     (correlation_evidence -> security_events, incident_evidence,
   |      Asset inventory) -> target_evidence, bounded to 20 event ids
   |     (else 422 TARGET_NOT_SUPPORTED + RESPONSE_TARGET_REJECTED audit)
   v  row created in PENDING_APPROVAL, expires_at = now + bounded TTL
GET  /responses/{id}/policy             (READ_RESPONSES, read-only verdict)
POST /responses/{id}/provider-preview   (RUN_ANALYSIS; executed:false always)
POST /responses/{id}/approve            (APPROVE_RESPONSE; approver != requester)
POST /responses/{id}/execute            (EXECUTE_SAFE_RESPONSE + EXECUTE_RESPONSE)
   v  row lock -> re-check state/TTL/approver -> provider.execute_action()
   v  MOCK records a platform-side step; nothing external is contacted
POST /responses/{id}/rollback           (ROLLBACK_RESPONSE; COMPLETED only)
   v  provider.rollback_action() using the recorded prior-state reference,
   |  or UNSUPPORTED with the expected inverse action named
repeat execute -> replays the stored row (200); after rollback -> 409
```

- **Provider architecture.** `services/response_providers.py` holds a
  `ResponseProvider` interface (`validate_target`, `preview_action`,
  `execute_action`, `rollback_action`, `get_action_status`) and a
  server-side registry with exactly two entries: `MOCK` (deterministic,
  supports execution and rollback) and `NOT_CONFIGURED` (refuses
  everything with an explicit reason). It is deliberately a *separate*
  registry from the frozen Step 13/19 simulation adapters in
  `response_executors.py`. The module imports no `subprocess`, `os`,
  `socket`, `requests`, `httpx`, `urllib`, or `http`, so a provider
  structurally cannot execute a command, open a socket, or make an HTTP
  call — there is no transport in scope.
- **Real integrations are NOT CONFIGURED.** Names exist for Defender,
  Wazuh, firewall, endpoint-management and cloud providers, and every
  one of them resolves to `NOT_CONFIGURED`. There is no arbitrary
  URL-based provider, no webhook execution, and no client-selectable
  provider.
- **State machine (additive to Steps 12/13/18/19).** Two states are
  added: `PENDING_APPROVAL` (created by a controlled request; may only
  become APPROVED, REJECTED, CANCELLED, EXPIRED, or previewed) and
  `ROLLED_BACK` (the only exit from COMPLETED). `EXPIRED` was already a
  reserved terminal value in Step 12 and is now actually written.
- **Expiry.** `expires_at` is fixed at request time from
  `RESPONSE_DEFAULT_TTL_MINUTES` and clamped to
  `RESPONSE_MAX_TTL_MINUTES`. Approving never extends it. Because the
  platform has no scheduler, expiry is enforced on the read path
  (`expire_due`) and again inside `approve`/`execute`, and is audited as
  `RESPONSE_EXPIRED`. There is no unlimited TTL and no permanent block.
- **Rollback.** `response_rollbacks` is UNIQUE on `action_id`, so an
  action can be rolled back at most once and a repeat call replays the
  stored record. If the provider recorded no prior state, the row is
  `UNSUPPORTED` and names the expected inverse action
  (`ROLLBACK_PAIRS`) rather than guessing prior state.
- **Idempotency & concurrency.** Request identity is the Step 12
  `response-action:v1` hash; execution identity is
  `response-execution:v1` with a UNIQUE `action_id`. `execute`, `approve`,
  `reject`, `cancel` and `rollback` take a row lock (`SELECT ... FOR
  UPDATE`, honoured by PostgreSQL) and re-check the stored state inside
  the transaction, so two operators cannot act twice and approval after
  expiry/cancellation is refused.
- **Policy.** `evaluate_policy` is a pure function of the stored action,
  stored evidence, the registry, the settings and the clock. It returns
  `NOT_ALLOWED` | `DRY_RUN_ONLY` | `APPROVAL_REQUIRED` |
  `ALLOWED_WITH_APPROVAL` plus a stated reason. Step 25 score/priority
  is read for reporting and recommendation wording only; it can never
  create, approve, or execute an action.
- **Audit.** Thirteen `RESPONSE_*` events on the existing append-only
  `response_audit` table (all ≤ 32 chars): REQUESTED,
  APPROVAL_REQUIRED, APPROVED, REJECTED, CANCELLED, EXPIRED,
  EXECUTION_STARTED, EXECUTION_COMPLETED, EXECUTION_FAILED,
  ROLLBACK_STARTED, ROLLBACK_COMPLETED, DRY_RUN, TARGET_REJECTED. Actor,
  status transition, policy version only — no passwords, tokens, keys,
  headers, or cookies.
- **Migration `step30_controlled_response`** (additive, revises
  `step29_intelligence`): seven columns on `response_actions`
  (`provider`, `policy_decision`, `approval_required`,
  `rollback_supported`, `rollback_state`, `rollback_reference`,
  `target_evidence`) plus the `response_rollbacks` table. Every
  pre-Step-30 row keeps the dry-run-only defaults, so previously stored
  proposals stay exactly as truthful as they were.
- **RBAC.** New `REQUEST_RESPONSE` and `CANCEL_RESPONSE` (analyst and
  above) and `EXECUTE_RESPONSE` / `ROLLBACK_RESPONSE` (operator and
  above). Separation of duties is a property of the role map, not a
  client setting; there is still no permission anywhere that grants
  command execution or unrestricted firewall/account/endpoint action.
- **NOT implemented / NOT enabled:** autonomous response, response driven
  by AI/ML or by risk score alone, permanent blocking, real Defender /
  Wazuh / firewall / EDR / cloud execution, rollback against a real
  system, and response merge/split. `RESPONSE_PROVIDER` defaults to
  `MOCK`; set it to `NOT_CONFIGURED` to refuse every consequential
  action.
- UI: Incidents page relationship-analysis panel (rule ids, confidence
  labels, effective window, explanation, stored-evidence counts,
  Recalculate analysis button, honest empty state), evidence overview
  with entity/asset/source-distribution context, original-event links
  that deep-link the Events page (`/events?event=…`), correlation-rule
  list and event-linked timeline entries. Neutral wording — "not a
  machine-learning prediction"; incident merge/split (spec §10) is
  explicitly NOT implemented.

Step 27 (new - controlled live Wazuh + Microsoft Defender connectors):

```text
env config (allow-list hosts) -> GET /events/connectors[/{source}]
   |   READ_EVENTS, no network I/O, adds connector_state + health fields
POST /events/connectors/{source}/check (MANAGE_EVENTS, bodiless)
   |   http_connector -> wazuh_client / defender_client (allow-list,
   |   timeout, size cap, no redirects, GET-only retries)
   v  one audited outcome: CONNECTED / AUTH_FAILED / UNAVAILABLE / RATE_LIMITED / ERROR
POST /events/connectors/{source}/poll (MANAGE_EVENTS)
   |   bounded pages (<= CONNECTOR_MAX_PAGES, <= CONNECTOR_MAX_EVENTS)
   v  Step 23 registry -> normalize -> dedupe -> persist -> audit
```

- Single shared HTTP foundation (`services/http_connector.py`): hosts
  allow-listed from settings only, fixed `CONNECTOR_TIMEOUT_SECONDS`,
  `CONNECTOR_MAX_RESPONSE_BYTES` hard cap, redirects refused (3xx is an
  error), safe GET-only retries, structured categories mapped onto the
  8-state vocabulary, correlation id + redaction on every error.
- Wazuh: Basic auth then JWT bearer held in memory only; health
  `GET /manager/info`; alerts paged by `limit/offset`. Defender:
  client-credentials token provider; health `GET /me` style probe;
  alerts paged by `@odata.nextLink`, each hop re-validated against the
  allow-list with repeated-cursor detection. Termination reasons
  COMPLETED / MAX_PAGES / MAX_EVENTS / REPEATED_CURSOR /
  MALFORMED_PAGINATION; `truncated` reported; `event_type` from the
  resource, timestamps/device names only from real response fields.
- `connector_state` (NOT_CONFIGURED, CONFIGURED, CONNECTING, CONNECTED,
  AUTH_FAILED, UNAVAILABLE, RATE_LIMITED, ERROR) rides alongside the
  preserved Step 26 `mode`/`state` columns; per-process runtime health
  (last check/poll, error category, events retrieved, latency) is
  reset with the app process; file-source truth (Step 26) unchanged.
- Audits for check and poll record actor, source and category only -
  never a credential, token or response body; reads stay audited-free.

Step 26 (new — live event connector foundation, file input only):

```text
env config → health() per source (file checks / config-shape only)
   ↓  GET /events/connectors[/{source}] (READ_EVENTS, no audit on reads)
operator poll → POST /events/connectors/{source}/poll (MANAGE_EVENTS)
   ↓  bounded file read (≤100 lines, no client paths) → shared pipeline
dedup + occurrence accounting + CONNECTOR_* audit → summary
```

- Lifecycle configure → validate → health → fetch → normalize →
  dedupe → persist → audit; static registry selection; unknown sources
  → 422; no subprocess, no shell, no network calls, no dynamic imports.
- Truth table: file path missing → FIXTURE/UNAVAILABLE; readable →
  LIVE/CONNECTED; broken → LIVE/UNAVAILABLE; partial API creds →
  LIVE/INVALID_CONFIGURATION; full API creds → LIVE/UNAVAILABLE
  (connection never attempted, never claimed). Secrets surface as
  presence booleans only, never values, never in audits.
- UI: Events page Connectors panel (badges, details, Poll now +
  summary notice). Future extension points from Step 26, status now:
  verified API polling (implemented in Step 27), SIEM streaming
  (architected as a bounded foundation in Step 28 but explicitly NOT
  enabled), scheduled/background jobs (not implemented - ingestion
  stays operator-initiated).

Step 4 (kept — Suricata EVE adapter, first vendor source): EVE
`alert`/`dns`/`http`/`tls`/`flow`/`fileinfo` → `SURICATA_*`
(`SURICATA_UNKNOWN` fallback), severity 1→CRITICAL…4→LOW else INFO,
deterministic `suricata:<sha256(…)>` identity, single + bounded-batch
endpoints, synthetic fixtures, no live sensor.

Step 5 (kept — Zeek adapter, second vendor source): Zeek-style records
with declared `event_type` → `ZEEK_*` (`ZEEK_UNKNOWN` fallback),
epoch/ISO timestamps, explicit-severity-only policy, deterministic
`zeek:<sha256(…)>` identity, single + bounded-batch endpoints, synthetic
fixtures, no live sensor or tailing.

Step 6 (kept — Wazuh adapter, third vendor source): Wazuh-style alerts
with declared `event_type` → `WAZUH_*` (`WAZUH_UNKNOWN` fallback),
ISO/epoch/ms timestamps, rule-level severity bands, deterministic
`wazuh:<sha256(…)>` identity, single + bounded-batch endpoints, synthetic
fixtures, no manager install or agent deployment.

Step 7 (kept — Defender adapter, fourth vendor source): Defender-style
records with declared `event_type` → `DEFENDER_*` (`DEFENDER_UNKNOWN`
fallback), ISO/epoch/ms timestamps, textual + numeric (0–100) severity,
deterministic `defender:<sha256(…)>` identity, single + bounded-batch
endpoints, synthetic fixtures, no live connectivity or remediation.

Step 11 (kept — incident management, records only; extended by Step 17 below):

```text
Existing correlation (+ optional existing risk assessment)
   ↓  POST /api/v1/incidents {correlation_id, risk_assessment_id?}
services/incident_service.create_incident() — validate refs, deterministic
sha256("incident:v1" | correlation | risk or "") identity, create or return
   ↓  status moves only via PATCH /{id}[//status] through TRANSITIONS
incidents rows → query API + Incidents UI (evidence = referenced IDs)
```

- Identity/replay: same logical incident → same row (`INC-` + 12 hex
  key); missing correlation/risk → 404 `REFERENCE_NOT_FOUND`, never
  manufactured.
- Severity: linked risk severity, else correlation severity (documented
  fallback); confidence: correlation confidence; first/last_seen:
  correlation window; asset linked by primary IP when known.
- Lifecycle: OPEN→ACKNOWLEDGED/CLOSED, ACKNOWLEDGED→INVESTIGATING/
  CLOSED, INVESTIGATING→RESOLVED/CLOSED, RESOLVED→CLOSED, CLOSED
  terminal; violations → 422 `INVALID_TRANSITION`.
- Detail exposes `evidence_event_ids` (ordered original event IDs) +
  correlation/risk references — references, never payload copies.
- UI: Incidents nav (already reserved) + page (table, status/severity
  filters, detail with evidence, explicit status buttons, honest empty
  state). Management-only wording; zero response/remediation controls.
- Fixtures: none needed — incidents are built from correlation fixtures
  via the public API in tests.

Step 17 (new — incident detection & model foundation, analysis only):

```text
Stored correlations (+ optional stored risk assessments / findings)
   ↓  POST /api/v1/incidents/detect {correlation_id?} — conservative,
   ↓  deterministic assess(): vuln-exposure (finding+activity) | ≥3 events
   ↓  | HIGH/CRITICAL severity, else explained skip (lead, not incident)
detect_for_correlation() — Step 11 identity reused (same evidence twice
→ same row); wider window / new links update + audit; first_seen kept
   ↓  typed incident + incident_evidence links + incident_audits rows
GET /incidents/{id}[/evidence|/timeline|/audit] → Incidents UI
```

- Types (classification only, fixed rule→type map): vuln-exposure →
  VULNERABILITY_ACTIVITY, multi-source-target →
  SUSPICIOUS_NETWORK_ACTIVITY, repeated-source →
  CORRELATED_SECURITY_EVENT, else OTHER. AUTHENTICATION_ANOMALY,
  MALWARE_INDICATOR, POLICY_VIOLATION are reserved vocabulary with no
  producing rule yet. A finding alone never qualifies.
- Risk/confidence: risk_score = linked Step 10 assessment verbatim
  (NULL when unlinked — no second formula); confidence = correlation
  confidence (evidence strength, not compromise probability); severity
  stays distinct from risk_score; resolved_at on first RESOLVED/CLOSED.
- Evidence = reference links with reasons (never payload copies);
  timeline merges observation markers with the audit trail; every
  lifecycle change is audited (OPENED/EVIDENCE_ATTACHED/
  STATUS_CHANGED/UPDATED with actor).
- UI: type/risk columns + type filter, Run detection with result
  notice, detail with risk-vs-severity note, detection reason,
  role-tagged evidence, related findings, explanation, timeline,
  audit — neutral wording throughout.

Step 13 (kept — controlled execution architecture, simulation only):

```text
DRY_RUN_COMPLETED proposal
   ↓  POST /api/v1/responses/{id}/execute (no executor choice for clients)
policy.evaluate_for_execution() — ALLOW / REQUIRE_APPROVAL / DENY (pure)
   ↓  ALLOW only: SimulationResponseExecutor.execute(stored row)
persist response_executions row (deterministic id) + READY_FOR_EXECUTION
+ EXECUTION_REQUESTED/COMPLETED audit; replay returns stored row
```

- `ResponseExecutor` ABC + `SimulationResponseExecutor` (pure,
  deterministic apart from the generation timestamp; always
  `would_execute: false` / `SIMULATED`); `EXECUTORS` allowlist with
  only `"simulation"`; unknown names raise `KeyError` (no dynamic
  imports, no client-selected executors).
- Policy: approved+previewed → ALLOW; PROPOSED/APPROVED → REQUIRE_APPROVAL;
  anything else (or unknown type / non-dry-run) → DENY. Denials return
  403 (`EXECUTION_DENIED` / `REQUIRE_APPROVAL`) and audit the denial
  without touching action state.
- Lifecycle addition: APPROVED→DRY_RUN_COMPLETED (preview edge) and
  DRY_RUN_COMPLETED→READY_FOR_EXECUTION (execute endpoint only);
  READY_FOR_EXECUTION is terminal; re-execution is a byte-identical
  replay (no new rows, no new audit).

Step 18 (new — controlled response foundation, safe actions only):

```text
Incident → POST /incidents/{id}/responses {safe type, reason} (target = incident)
   ↓  PROPOSED → APPROVED (actor stamped once) → POST /responses/{id}/execute
policy.evaluate_for_execution() — ALLOW_SAFE_EXECUTION for approved safe types
   ↓  RUNNING → platform-record effect via incident services → COMPLETED | FAILED
safe-record execution row persisted; replays return it; audit covers every step
```

- Safe allow-list (workflow records only, never external systems):
  REVIEW (read-only), COLLECT_EVIDENCE (counts references),
  MARK_FOR_INVESTIGATION / ACKNOWLEDGE / CLOSE (validated incident
  transitions; rejections become honest FAILED rows, never leaks).
  Dangerous Step 12 types stay simulation-only; dry_run=true still
  guarantees no external change; dry-run previews stay pure.
- Idempotency: deterministic proposal identity (replays 200 the same
  row); one execution row per action (replays 200 it); rejected/
  cancelled/failed work never (re-)executes (403/409).
- UI: incident Controlled-responses section (propose/decide/execute,
  approval/result/failure display); Response page handles new statuses
  and safe-execution records. Truthful result language only
  ("Incident acknowledged.", "No external system change was performed.").
- Limitation: no authentication infrastructure — requested_by/actor are
  recorded operator labels (existing convention), not verified identities.

Step 19 (new — controlled response adapter foundation, simulation only):

```text
APPROVED proposal → POST /responses/{id}/preview (policy-gated, read-only)
   ↓  static select_adapter_name() → allowlisted registry (KeyError otherwise)
validate_target() — strict syntax (HOSTNAME never resolved/contacted)
   ↓  executor.preview() → typed AdapterResult (executed=false, simulated=true)
stored-reference evidence + RESPONSE_PREVIEWED audit → structured response
```

- Contracts: `AdapterRequest`/`AdapterResult`/`AdapterEvidence`/
  `PreviewResponse` (Pydantic, `extra=forbid`); executors expose
  `validate_target()` / `preview()` / `execute()` — all pure simulation
  in Step 19. Legacy `execute()` wire shape frozen by Step 13 tests.
- Registry: SIMULATION, EVIDENCE_COLLECTION_SIMULATION,
  FIREWALL_SIMULATION, ISOLATION_SIMULATION (+ legacy `simulation`
  for existing rows). Firewall/isolation names are contract placeholders:
  no netsh/PowerShell/iptables/nftables/Defender/endpoint/cloud contact
  exists or is possible from these classes (no subprocess/socket/file/os).
- would_execute answers current policy truthfully (ALLOW/ALLOW_SAFE →
  true, anything else → 403, never previewed as executable).
- UI: Preview Response button + adapter panel with SIMULATION ONLY
  badge, would_execute, evidence. No Block/Isolate/Kill/Disable buttons.
- Future extension points (documented, NOT implemented): Windows
  Firewall, Linux firewall (iptables/nftables), endpoint isolation,
  account controls, process controls, cloud security controls — each
  needs its own explicitly approved stage with real policy, auth, and
  safety review.
- Statuses `READY_FOR_EXECUTION`/`EXPIRED` display in amber/neutral —
  never green, never as executed.
- UI: Execute Simulation button (previewed proposals only), simulation
  record panel ("SIMULATION ONLY — NO REAL ACTION EXECUTED").

Step 20 (new — authentication + RBAC foundation, no new execution capability):

```text
POST /users (bootstrap: first ADMIN only) → argon2id User row
POST /auth/login (generic 401, last_login_at on success) → short JWT
Authorization: Bearer → resolve_context() → role-derived permissions
   ↓  require_permission(P) per endpoint → 401 / 403 + audit
approvals/executions/status changes record the token identity
```

- Enforcement activates with the first user; empty-table bootstrap
  preserves legacy behavior (REQUIRE_AUTH disables it). Health stays
  public; reads → READ_*, writes → manage/create/approve/execute,
  audits → VIEW_AUDIT, users → MANAGE_USERS (+ MANAGE_ROLES for role
  changes, last-admin guards). No EXECUTE_ARBITRARY_COMMAND exists.
- Roles: VIEWER (reads) → ANALYST (+ analysis/incidents/proposals/
  audits/content-manage) → OPERATOR (+ approve/execute) → ADMIN (+
  users/roles/settings). Frontend login + token wiring; backend never
  trusts client roles/headers/params.
- Audit: LOGIN_SUCCESS/FAILURE, LOGOUT, AUTHORIZATION_DENIED,
  PERMISSION_DENIED, USER_CREATED/DISABLED/UPDATED, ROLE_CHANGED —
  usernames and outcomes only, never passwords/hashes/tokens.

Step 14 (kept — authorized Nmap discovery hardening):

```text
POST /api/v1/network/scans {target, profile, requested_by}
   ↓  format validation (422) → profile allow-list (422)
   ↓  authorization scope check vs SCAN_ALLOWED_NETWORKS (403 if outside)
   ↓  Nmap availability (503) → persist QUEUED + SCAN_REQUESTED audit → 202
BackgroundTasks worker: skip if CANCELLED → RUNNING + audit → fixed-argv
Nmap (shell=False, timeout, 8 MB cap) → XML parse → upsert with provenance
   ↓  COMPLETED (counts + "N hosts, M ports" + audit) | FAILED + audit
POST /api/v1/network/scans/{id}/cancel — QUEUED only, else 409
```

Step 21 (new — asset discovery profiles + preview, discovery only):

- Profiles: DISCOVERY_PING (host discovery, `probes_ports=False`) and
  DISCOVERY_TCP_COMMON (fixed 19-port `-sT` set) join quick/standard in
  the server-side allow-list; the API still accepts names only.
- Preview: `POST /network/scans/preview` (MANAGE_SCANS) validates
  target/profile/scope/availability and returns the plan — no argv, no
  scan, no assets, no processes. RBAC grant is the approval; lifecycle
  and `ScanAudit` reuse Step 2/14 states (QUEUED≈proposed → RUNNING →
  COMPLETED/FAILED/CANCELLED).
- Scope: `discovery_max_addresses` (default 256, conservative,
  configurable without secrets) bounds target size; CIDRs must sit
  inside SCAN_ALLOWED_NETWORKS (loopback default).
- Normalization: IP-deterministic upsert (first_seen kept, no
  blanking); ping scans preserve previously observed services.
- UI: discovery options + Preview discovery panel on the Network page.
- Limitations: no OS/service-version data from ping; no hostname
  targets (IP/CIDR only, unchanged); running scans cannot be stopped;
  discovery reports reachability, never compromise.

- Scope: `SCAN_ALLOWED_NETWORKS` CIDR allow-list (default loopback
  only), fail-closed on empty/misconfigured; single IPs must be
  contained, CIDRs fully contained (`subnet_of`, version-matched —
  mixed-version comparisons can never match); scope never expanded.
- Provenance: `scan_type`/`requested_by`/`result_summary` on jobs;
  `asset_type` (UNKNOWN unless determined), `discovery_source`,
  `discovery_scan_id` on assets/services; upserts fill-but-never-blank.
- Audit: `scan_audit` rows (REQUESTED/STARTED/COMPLETED/FAILED/
  CANCELLED) with actor, embedded in scan responses chronologically
  (microsecond client-side timestamps — same SQLite lesson as Step 12).
- UI: Network page (scope warning, actor input, requested-by column,
  Cancel for queued), Assets page (Type/Source columns). No command
  boxes, no flag inputs, no schedulers, no auto-start.

Step 15 (kept — vulnerability assessment, fixture-backed, data only):

```text
POST /api/v1/vulnerability-scans {asset_id | target, profile, requested_by}
   ↓  exactly-one-of validation (422) → asset exists (404) → authorize
   ↓  scope via Step 14 policy (403) → profile allow-list (422)
   ↓  persist QUEUED scan_job (scan_type="vulnerability") + audit → 202
BackgroundTasks worker: skip if CANCELLED → RUNNING + audit →
FixtureVulnerabilityScanner over STORED asset/services (no traffic,
no subprocess) → normalize → upsert by deterministic identity
   ↓  COMPLETED ("N new, M refreshed" + audit) | FAILED + audit
GET /vulnerabilities (filters/pagination) → detail (+ audit) →
POST /vulnerabilities/{id}/status (explicit transitions, else 409)
```

- `VulnerabilityScanner` ABC + `FixtureVulnerabilityScanner` only:
  TEST-labeled catalog matched on discovered (port, protocol)/service;
  unknown ports yield nothing; BASELINE adds the asset-level note,
  SERVICE omits it. Server-selected; `get_scanner` raises `KeyError`
  otherwise (no dynamic imports, no client-selected implementations).
- Normalized `Vulnerability` rows: stable `VULNERABILITY_FINDING`
  category is implied by endpoint (single finding kind); severity
  text→canonical else UNKNOWN; CVSS validated 0–10 else NULL; CVEs
  uppercased/pattern-gated/deduped (non-matching stays out of
  normalized storage); unknown input preserved in `extra_data`;
  full record is NOT duplicated as an event (findings reference
  asset/service rows instead).
- Identity `sha256("vulnerability:v1" | scanner | finding | asset |
  service)`; repeats refresh `last_seen`/metadata, preserve
  `first_seen` + `status`; absence never auto-resolves.
- Lifecycle OPEN→ACCEPTED_RISK/RESOLVED, ACCEPTED_RISK→RESOLVED/OPEN,
  RESOLVED→OPEN; violations → 409. `vulnerability_audits` rows
  (OPENED/UPDATED/STATUS_CHANGED) with actor, embedded chronologically.
- UI: Vulnerabilities page (severity/CVE/CVSS/scanner/status table +
  detail with evidence/solution/audit + status buttons, severity+
  status filters, honest empty state). Scans stay API-driven — no scan
  form, no remediation controls.

Step 22 (new — vulnerability assessment foundation, LIVE + MOCK):

```text
POST /vulnerability-scans {asset_id | target, profile=BASIC|STANDARD|...}
   ↓  profile→adapter routing (server map) → nmap binary check (503)
   ↓  stored-service context check (422: discovery first, ports≠vulns)
   ↓  persist QUEUED job (+ scanner name) + audit → 202
BackgroundTasks worker → RUNNING → adapter.scan() → normalize → upsert
   ↓  COMPLETED ("N new, M refreshed") | FAILED (controlled message)
```

- Staged adapters (`configure`/`validate_context`/`execute`/`parse`);
  `nmap-vuln` runs fixed `-sV` + `vuln and not intrusive` (+ version
  intensity for STANDARD) over stored ports ≤100, 600 s timeout, 8 MB
  cap, fixed env, no shell. Findings only from CVE-bearing script
  output (UNKNOWN severity, excerpt evidence, no invented data).
- Model: +`scanner_version`/`detected_version`/`fixed_version`
  (nullable, missing stays missing); raw scanner severity kept in
  `extra_data`; jobs carry `scanner` (LIVE vs MOCK everywhere incl. UI
  badges). Statuses gain NOT_SEEN: service findings unobserved by a
  rescan flip (audited, history kept); re-observation reopens; failed
  scans change nothing; asset-level notes never expire.
- Same endpoints/RBAC/audit; UI gains Start assessment flow, version
  fields, NOT_SEEN state. Reported findings ≠ proof of exploitation.

Step 16 (new — vulnerability risk correlation, analysis only):

```text
Step 15 Vulnerability rows + stored events/incidents
   ↓  services/vuln_correlation.py — derived links, never stored/guessed
risk_service recompute — new "vuln_finding" entity via the same v1.0.0
formula (severity + CVSS + known-asset + covering-correlations + recency)
   ↓  upserts by deterministic identity; stale rows pruned
GET /vulnerabilities/{id}/risk → stored assessment (404 unscored)
GET /vulnerabilities/{id}/correlations → events + incidents + reasons
GET /assets/{id}/vuln-risk → counts, highest severity/CVSS,
aggregate = max finding score, level, timestamp (honest zeros)
```

- Links: finding↔asset/service via FKs; finding↔events via shared
  asset IP/hostname (time-ordered, id tiebreak); finding↔incidents via
  correlation evidence containing a related event. Reasons attached;
  empty results explain why. No thresholds hidden, no AI judgment.
- Risk: same pure `score_vulnerability` math (unchanged formula and
  version); `asset_known` from the FK asset; covering set from the
  shared-asset rule; recency from finding `last_seen` vs dataset max.
  Existing asset/event/correlation branches untouched.
- UI: finding detail shows risk score vs finding severity (explicitly
  distinct), explanation, calculation time, correlated records, and
  unscored/unlinked empty states. No response controls.

Step 12 detail (kept — controlled response & SOAR foundation):

```text
Existing incident
   ↓  POST /api/v1/responses {incident, type, target, reason, requester} (dry_run forced true)
services/response_service.propose_action() — validate refs/types, deterministic
sha256("response-action:v1" | incident | type | target | reference | requester)
   ↓  explicit approve/reject/cancel/dry-run operations through TRANSITIONS
response_actions + response_audit rows → query API + Response UI
```

- Closed action enum (ISOLATE_ASSET/BLOCK_IP/BLOCK_DOMAIN/
  DISABLE_ACCOUNT/QUARANTINE_ASSET/FIREWALL_RULE/REMEDIATION) and target
  enum (ASSET/IP/DOMAIN/ACCOUNT); IP targets validated as IP literals;
  `dry_run` forced true; policy version 1.0.0 persisted everywhere;
  approvals stamp `approved_at` + 7-day `expires_at` (no automatic
  expiry — no background processes exist).
- Lifecycle PROPOSED→APPROVED/REJECTED/CANCELLED/DRY_RUN_COMPLETED,
  DRY_RUN_COMPLETED→APPROVED/REJECTED/CANCELLED, APPROVED→CANCELLED,
  rest terminal; violations → 409 `INVALID_TRANSITION`. APPROVED means
  "approved for a future execution layer that does not exist" — never
  displayed or stored as executed.
- Deterministic identity; replays return the row unchanged (even if
  CLOSED); audit appends per event with actor, transition, policy
  version, microsecond timestamps.
- API: `POST /responses` (201/200), `GET /responses` (status/action/
  incident filters, pagination, deterministic order),
  `GET /responses/{id}` (+ audit history),
  `POST /{id}/approve|reject|cancel` (optional actor),
  `POST /{id}/dry-run` (pure SIMULATED preview, `would_execute: false`).
  No /execute, /block, /isolate, /quarantine, /remediate, /firewall,
  or /disable-account endpoint exists anywhere.
- UI: Response nav + page (table, status filter, detail with audit +
  Dry Run + Approve/Reject/Cancel, "DRY RUN — NO ACTION EXECUTED"
  banners, honest empty state). Zero execution controls of any kind.
- Fixtures: none needed — proposals are built from incident fixtures
  via the public API in tests.

Step 10 detail (kept — deterministic risk scoring):

```text
Stored assets + VULNERABILITY_FINDING events + correlations
   ↓  POST /api/v1/risk/recompute (parameter-free, ≤1000, id order)
services/risk_service: pure compute_* math (no clock/randomness/order)
   + DB input gathering (bounded, NULL-safe joins)
   ↓  upsert by sha256("risk-assessment:v1" | version | type | id);
      stale rows pruned; calculated_at recorded, never scored
risk_assessments rows → query API + Risk UI
```

- Formula v1.0.0: `clamp(10 + severity_pts + signal_pts + recency_pts)`;
  severity INFO 0/LOW 10/MEDIUM 25/HIGH 40/CRITICAL 55; bands 80/60/40/20;
  vuln signals = CVSS→0–15 + known-asset 5 + 3/covering-correlation (cap
  9); correlation signals = 2/evidence (cap 10) + confidence//10; asset
  signals = 2/port (cap 10) + 3/finding (cap 12) + 5/correlation (cap
  10); recency vs dataset-max event_time: ≤7d +10, ≤30d +5, else +0.
- Factors JSON stores inputs + point breakdown; explanation names each
  contribution; `scoring_version` in both row and identity (future
  formula revisions create fresh rows, preserving history).
- API: `GET /risk` (entity/severity filters, score-desc with id
  tiebreak, pagination), `GET /risk/{type}/{id}` (`INVALID_ENTITY_TYPE`
  422, `RISK_NOT_FOUND` 404), `POST /risk/recompute`.
- UI: Risk nav + page (score table, severity filter, Recompute with
  result notice, factors + explanation detail, version + calculated
  time, honest empty state). No response/remediation controls.

Step 9 summary (kept — deterministic correlation, analysis only):

```text
SecurityEvent rows (bounded: last 500 by event_time)
   ↓  POST /api/v1/correlations/recompute (parameter-free)
services/correlation_rules.apply_all_rules() — 3 pure, documented rules
   ↓  drafts {rule, sorted evidence ids, pivot, explanation}
services/correlation_service.upsert_draft() — deterministic
sha256("correlation:v1" | rule | ids); severity = evidence max;
confidence = rule fixed value; evidence links unique per pair
   ↓
correlations + correlation_evidence rows → query API + UI
```

- Rules: `multi-source-target` (≥2 sources, same dst IP, 60 min, 75),
  `vuln-exposure` (finding + touching activity, 24 h, 70),
  `repeated-source` (≥3 same-src incl. MEDIUM+, 15 min, 60). Greedy
  windowing; out-of-order safe (sorted); aware datetimes coerced.
- Attack chain: correlation node + optional asset pivot + time-ordered
  event/vulnerability nodes; neutral `pivot` / `supported by` /
  `observed in` edges; original evidence IDs preserved verbatim.
- Status column exists (`open` default; filter supports open/
  acknowledged/resolved for forward compatibility).
- API: `GET /correlations` (status/severity/rule filters, pagination),
  `GET /correlations/{id}` (`CORRELATION_NOT_FOUND` 404),
  `GET /correlations/{id}/attack-chain`,
  `POST /correlations/recompute` (no params, no rule selection).
- UI: Correlations nav + page (table, severity filter, Recompute with
  result notice, evidence + chain timeline, "not proof of compromise"
  wording, honest empty state). No response/block/remediation controls.

```text
Scanner-style finding record(s) — submitted data, never executed
   ↓  POST /api/v1/events/ingest/vulnerabilities[/batch] (bounded: 100/batch)
services/vulnerability_adapter.adapt_vulnerability_finding()
   ↓  field map + text/CVSS severity + deterministic external_event_id
existing event_service.normalize_event() / store_event()
   ↓  same validation, idempotency, storage as generic ingestion
SecurityEvent rows in PostgreSQL → existing Events API + Vulnerabilities UI
```

- Every record is a finding by endpoint definition → stable canonical
  `VULNERABILITY_FINDING` (no category guessing); record must declare
  string `title`/`name`, else `INVALID_VULNERABILITY` (422).
- Field map: `title`/`name`→title; `affected_host`/`hostname`→hostname;
  `ip` (or `affected_host` when an IP literal)→destination_ip;
  `port`→destination_port; `protocol`/`service`/`product`/`version`/
  `evidence`/`solution`/`references`/`first_seen`/`last_seen`/`status`→
  namespaced `normalized_data`; full record→`raw_event` untouched.
  Absent fields → NULL, never faked.
- CVE: `cve`/`cves` uppercased, kept only if matching `CVE-YYYY-NNNN+`;
  non-matching strings stay in raw only (never presented as findings).
- Severity precedence: explicit text (case-insensitive) → CVSS bands
  9.0–10 CRITICAL / 7.0–8.9 HIGH / 4.0–6.9 MEDIUM / 0.1–3.9 LOW / 0 INFO
  (central constants) → INFO. Never from title/description. CVSS stored
  as data; no risk score calculated.
- `source_name` caller-declared (default `"vulnerability-scanner"`).
- `external_event_id = vuln:<sha256(scanner|finding|plugin|cves|host|
  port|proto)>`, content-hash fallback — deterministic, never
  ingest-time.
- Fixtures: `backend/tests/fixtures/vulnerabilities/*.json` (10
  synthetic files, TEST-NET only, no secrets). No scanners run, no
  Nmap/Nessus/OpenVAS execution, no exploitation, no remediation, no
  firewall changes, no privileged mode, no host networking.

Step 8 detail (kept — vulnerability ingestion building blocks):

```text
Defender-style record(s), each declaring event_type (platform contract —
raw exports do not self-categorize)
   ↓  POST /api/v1/events/ingest/defender[/batch] (bounded: 100/batch)
services/defender_adapter.adapt_defender_event()
   ↓  field map + textual/numeric severity + deterministic external_event_id
existing event_service.normalize_event() / store_event()
   ↓  same validation, idempotency, storage as generic ingestion
SecurityEvent rows in PostgreSQL → existing Events API/UI
```

- Supported categories → `DEFENDER_ALERT/INCIDENT/MALWARE/
  AUTHENTICATION/DEVICE/PROCESS`; unknown → `DEFENDER_UNKNOWN`
  (accepted, documented); missing/non-string `event_type` →
  `INVALID_DEFENDER` (422).
- Field map: `timestamp`/`eventTime` (ISO/epoch s/epoch ms;
  unparseable→now, documented)→event_time; `deviceId/deviceName/
  machineName`, `threatName`, `processName/processId/commandLine`,
  `fileName/fileHash`, `detectionSource`, `remediationStatus`,
  `category`, `status`, `url`/`domain`, IPs/ports, `user`/`account`→
  username; extras → `normalized_data`; full record→`raw_event`
  untouched. Absent fields → NULL, never faked.
- Severity: textual case-insensitive critical/high/medium/low/
  informational/info; numeric 0–100 scores (>=80/50/20/1, central
  constants), 0→INFO; missing/malformed/unknown→INFO. Never from
  title/description wording. Nothing invented.
- Title: `title`/`name` → `description` → `threatName` → generic fallback.
- `source_name` caller-declared (default `"defender"`); no credentials,
  tenant IDs, or secrets anywhere in the contract.
- `external_event_id = defender:<sha256(type|alert_id|timestamp)>`,
  content-hash fallback — deterministic, never ingest-time.
- Fixtures: `backend/tests/fixtures/defender/*.json` (6 synthetic files,
  no credentials/secrets). No live agent, connectivity, polling, or
  remediation; no privileged mode, host networking, or filesystem
  watching.

Step 7 detail (kept — Defender adapter building blocks):

Step 6 detail (kept — Wazuh adapter building blocks):

```text
Wazuh-style alert(s), each declaring event_type (platform contract —
raw manager output does not self-categorize)
   ↓  POST /api/v1/events/ingest/wazuh[/batch] (bounded: 100/batch)
services/wazuh_adapter.adapt_wazuh_event()
   ↓  field map + rule-level severity + deterministic external_event_id
existing event_service.normalize_event() / store_event()
   ↓  same validation, idempotency, storage as generic ingestion
SecurityEvent rows in PostgreSQL → existing Events API/UI
```

- Supported categories → `WAZUH_ALERT/FIM/AUTH/SYSCHECK/SCA/
  VULNERABILITY/ROOTCHECK/COMMAND`; unknown → `WAZUH_UNKNOWN`
  (accepted, documented); missing/non-string `event_type` →
  `INVALID_WAZUH` (422).
- Field map: `timestamp`/`@timestamp` (ISO/epoch s/epoch ms;
  unparseable→now, documented)→event_time; `agent.id/name/ip`→
  `normalized_data.agent` (+name→hostname); `manager.name`;
  `rule.id/level/description/groups/mitre` (+level preserved);
  `decoder.name/parent`; `location`; `full_log`→description when
  distinct; `data.srcip/dstip` (fallback top-level)→IP columns;
  ports→columns; `syscheck.{path,event,md5/sha256/size_after}`→`fim`;
  `vulnerability.{id,severity,package,reference}`→`vulnerability`;
  auth fields→`authentication`; full record→`raw_event` untouched.
  Absent fields → NULL, never faked.
- Severity from numeric `rule.level` only: 12–16→CRITICAL, 9–11→HIGH,
  5–8→MEDIUM, 1–4→LOW, missing/invalid→INFO (central constants
  `CRITICAL/HIGH/MEDIUM/LOW_MIN_LEVEL`). Nothing invented from text.
- Title: `rule.description` → first `full_log` line → decoder info →
  generic fallback.
- `source_name` caller-declared (default `"wazuh"`); never a fake hostname.
- `external_event_id = wazuh:<sha256(type|alert_id|timestamp|agent.id|
  rule.id|addrs)>`, content-hash fallback — deterministic, never
  ingest-time.
- Fixtures: `backend/tests/fixtures/wazuh/*.json` (10 synthetic files,
  TEST-NET only, no secrets). No manager install, no agent deployment,
  no privileged mode, no host networking, no filesystem watching.

Step 5 detail (kept — Zeek adapter building blocks):

```text
Zeek-style record(s), each declaring event_type (platform contract —
raw Zeek logs do not self-identify)
   ↓  POST /api/v1/events/ingest/zeek[/batch] (bounded: 100/batch)
services/zeek_adapter.adapt_zeek_event()
   ↓  field map + explicit-severity-only + deterministic external_event_id
existing event_service.normalize_event() / store_event()
   ↓  same validation, idempotency, storage as generic ingestion
SecurityEvent rows in PostgreSQL → existing Events API/UI
```

- Supported logs → `ZEEK_CONN/DNS/HTTP/SSL/X509/SSH/NOTICE`;
  unknown → `ZEEK_UNKNOWN` (accepted, documented); missing/non-string
  `event_type` → `INVALID_ZEEK` (422).
- Field map: epoch-or-ISO `ts`→event_time (unparseable→now, documented),
  `uid`→identity + correlation_key, `id.orig_h`/`src`→source_ip,
  `id.resp_h`/`dst`→destination_ip, `id.orig_p`/`src_p`,
  `id.resp_p`/`dst_p`, `proto` (lowercased), `service`/`host`,
  http `method`→action, notice `note`/`msg`→title/description; service,
  byte counters, conn_state, query/uri/status_code/user_agent/server and
  similar → `normalized_data.vendor`; full record → `raw_event` untouched.
  Absent fields → NULL, never faked (x509 fixture proves it).
- Severity: explicit integer `severity` 1–4 only (platform table), else
  INFO. Notices without severity → INFO. Nothing invented.
- `source_name` caller-declared (default `"zeek"`); never a fake hostname.
- `external_event_id = zeek:<sha256(event_type|uid|ts|addrs|ports)>`,
  content-hash fallback without UID — deterministic, never ingest-time.
- Fixtures: `backend/tests/fixtures/zeek/*.json` (9 synthetic files,
  TEST-NET/TEST-v6 only). No live sensor, no log tailing, no privileged
  mode, no host networking, no filesystem watching.

Step 4 detail (kept — Suricata adapter building blocks):

```text
Suricata EVE JSON object(s)
   ↓  POST /api/v1/events/ingest/suricata[/batch] (bounded: 100/batch)
services/suricata_adapter.adapt_eve_event()
   ↓  field map + severity map + deterministic external_event_id
existing event_service.normalize_event() / store_event()
   ↓  same validation, idempotency, storage as generic ingestion
SecurityEvent rows in PostgreSQL → existing Events API/UI
```

- Supported EVE types → `SURICATA_ALERT/DNS/HTTP/TLS/FLOW/FILEINFO`;
  unknown types → `SURICATA_UNKNOWN` (accepted, documented); missing
  `event_type` → `INVALID_EVE` (422).
- Field map: timestamp→event_time, event_type→event_type, src_ip/dest_ip,
  src_port/dest_port, proto→protocol (lowercased), flow_id→correlation_key,
  alert.signature→title, alert.category→description, alert.action→action,
  alert fields + app_proto + http/dns/tls/flow/fileinfo sub-objects →
  `normalized_data.vendor`; full EVE object → `raw_event` untouched.
- Severity: 1→CRITICAL, 2→HIGH, 3→MEDIUM, 4→LOW, absent/invalid/non-alert
  → INFO. No new severity vocabulary.
- `source_name` caller-declared (default `"suricata"`); never a fake hostname.
- `external_event_id = suricata:<sha256(event_type|flow_id|timestamp|
  sig_id|sig_rev|gid|addrs|ports)>` — deterministic, never ingest-time.
- Fixtures: `backend/tests/fixtures/suricata/*.json` (10 synthetic files,
  TEST-NET addresses only). No live sensor, no privileged mode, no host
  networking, no filesystem watching (fixed fixture dir only).

Step 3 detail (kept — generic ingestion building blocks):

- `models/event_enums.py` — closed `Severity` (INFO/LOW/MEDIUM/HIGH/CRITICAL)
  and `SourceType` (NMAP/GENERIC/WINDOWS/DEFENDER/SURICATA/ZEEK/WAZUH/
  VULNERABILITY_SCANNER/FIREWALL) vocabularies; source values are extension
  points, not integrations.
- `models/events.py` — canonical `SecurityEvent` (nullable details, naive
  UTC, unique `(source_type, source_name, external_event_id)`).
- `services/event_service.py` — `normalize_event()` (clean/default/
  fingerprint) + `store_event()` (idempotent persist). Raw JSON stored as
  data only, 64 KB cap (413 over). Fingerprint = SHA-256 over stable attrs
  (no ingest timestamps); informational, never drops events.
- `api/v1/endpoints/events.py` — `POST /events` (201 new / 200 replay),
  `GET /events` (severity/source/type/asset/time filters, pagination),
  `GET /events/summary`, `GET /events/{id}` (`EVENT_NOT_FOUND` 404).
- Frontend: real Events table + severity filter + detail (raw shown as
  escaped text), honest "No security events received." empty state;
  dashboard event cards from live summary data.

Step 2 (kept — asset inventory + controlled scans):

- `models/assets.py` — `Asset` (one row per IP, unique) + `DiscoveredService`
  (unique per asset/port/protocol); service set replaced per scan.
- `models/scans.py` — `ScanJob` lifecycle queued → running → completed/failed.
- `services/target_validation.py` — `ipaddress`-based allow-list: single
  IPv4/IPv6 or CIDR ≤ 256 addresses; everything else rejected.
- `services/nmap_runner.py` — fixed `SCAN_PROFILES` (`quick`, `standard`);
  argv built server-side; `shell=False`, timeouts, 8 MB output cap, minimal
  env; `is_available()`/`get_version()` capability reporting.
- `services/nmap_parser.py` — `-oX` XML only; tolerant of missing fields;
  malformed XML → controlled `NmapParseError`.
- `services/inventory.py` — upsert by IP (no duplicates), metadata merge,
  service-set replace, `first_seen` preserved.
- `services/scan_service.py` — 202-then-background via `BackgroundTasks`;
  per-run DB session; failures recorded with safe messages.
- `api/v1/endpoints/network.py` — `GET nmap/status`, `POST/GET scans`,
  `GET scans/{id}`. `api/v1/endpoints/assets.py` — list (filter/paginate),
  summary, detail, services.
- Frontend: real Assets table + detail, Network page (status, authorized
  scan form with confirmation checkbox, recent scans), dashboard inventory
  cards. Nginx proxies same-origin `/api/` to `backend:8000`; SPA fallback
  is `try_files $uri /index.html` (no `$uri/`, so the `/assets` route is not
  shadowed by the static `assets/` directory).
- `backend/Dockerfile` installs only `nmap` (no privileged, no host net).

## 2. API summary (Steps 2–29 additions)

```text
GET  /api/v1/network/nmap/status   {available, version, profiles}
POST /api/v1/network/scans         {target, scan_profile} -> 202 job
GET  /api/v1/network/scans[?limit] recent jobs, newest first
GET  /api/v1/network/scans/{id}    job status/counts/error
GET  /api/v1/assets[?ip&hostname&state&limit&offset]  {items, total}
GET  /api/v1/assets/summary        {total_assets, active_assets, total_services, ...}
GET  /api/v1/assets/{id}           asset + services
GET  /api/v1/assets/{id}/services  service list
POST /api/v1/events                ingest envelope -> 201 (200 on idempotent replay)
GET  /api/v1/events[?severity&source_type&event_type&asset_id&since&until&limit&offset]
GET  /api/v1/events/summary        {total_events, critical_events, high_events, last_24h_events}
GET  /api/v1/events/{id}           single normalized event
GET  /api/v1/events/connectors     connector truth (mode/state + connector_state/health, presence-only config)
GET  /api/v1/events/connectors/{source}  health detail (no network I/O, no audit on reads)
POST /api/v1/events/connectors/{source}/check  one allow-listed live check (MANAGE_EVENTS, audited)
POST /api/v1/events/connectors/{source}/poll[?replay=true]  bounded file/API poll -> accepted/duplicates/rejected + batches/queue_dropped/checkpoint_advanced
GET  /api/v1/events/ingestion/status     bounded pipeline status (stages, bounds, queue, streaming state, per-source counters)
GET  /api/v1/events/ingestion/checkpoints  per-source provenance (sanitized cursor map, READ_EVENTS)
POST /api/v1/events/ingest/suricata        EVE object -> 201 (200 replay)
POST /api/v1/events/ingest/suricata/batch  ≤100 EVE objects -> accepted/duplicates/rejected
POST /api/v1/events/ingest/zeek            Zeek record -> 201 (200 replay)
POST /api/v1/events/ingest/zeek/batch      ≤100 Zeek records -> accepted/duplicates/rejected
POST /api/v1/events/ingest/wazuh           Wazuh record -> 201 (200 replay)
POST /api/v1/events/ingest/wazuh/batch     ≤100 Wazuh records -> accepted/duplicates/rejected
POST /api/v1/events/ingest/defender        Defender record -> 201 (200 replay)
POST /api/v1/events/ingest/defender/batch  ≤100 Defender records -> accepted/duplicates/rejected
POST /api/v1/events/ingest/vulnerabilities      finding -> 201 (200 replay)
POST /api/v1/events/ingest/vulnerabilities/batch  ≤100 findings -> accepted/duplicates/rejected
POST /api/v1/correlations/recompute            bounded deterministic recompute
GET  /api/v1/correlations[?status&severity&rule_id&limit&offset]
GET  /api/v1/correlations/{id}                 correlation + ordered evidence
GET  /api/v1/correlations/{id}/attack-chain    nodes + neutral edges
POST /api/v1/risk/recompute                    bounded deterministic scoring
POST /api/v1/risk/incidents/{id}/calculate    incident snapshot (MANAGE_INCIDENT)
GET  /api/v1/risk[?entity_type&severity&limit&offset]
GET  /api/v1/risk/{entity_type}/{entity_id}    single assessment
POST /api/v1/incidents                      {correlation_id, risk_assessment_id?} -> 201 (200 replay)
GET  /api/v1/incidents[?status&severity&limit&offset]
GET  /api/v1/incidents/{id}                 incident + evidence references
PATCH /api/v1/incidents/{id}                status/title/description (validated)
PATCH /api/v1/incidents/{id}/status         explicit transition
POST  /api/v1/incidents/{id}/status         same transitions (POST alias)
POST  /api/v1/incidents/detect              conservative detection (single/bulk)
GET   /api/v1/incidents/{id}/evidence       correlation + events + findings
GET   /api/v1/incidents/{id}/timeline       observations + audits + resolution
GET   /api/v1/incidents/{id}/audit          append-only lifecycle trail
GET   /api/v1/incidents/{id}/observations   typed observation links + counts
GET   /api/v1/incidents/{id}/relationships  stored Step 29 relationships (rule/limit/offset, READ_INCIDENTS)
POST  /api/v1/incidents/{id}/recalculate    bounded deterministic analysis (MANAGE_INCIDENT, bodiless)
POST /api/v1/responses                      proposal -> 201 (200 replay)
GET  /api/v1/responses[?status&action_type&incident_id&limit&offset]
GET  /api/v1/responses/{id}                 proposal + audit history
POST /api/v1/responses/{id}/approve|reject|cancel
POST /api/v1/responses/{id}/dry-run         SIMULATED preview, never executes
POST /api/v1/responses/{id}/execute         simulation or safe-record -> 201 (200 replay)
POST /api/v1/responses/{id}/preview         adapter preview, read-only -> 200 (403 unapproved)
POST /api/v1/incidents/{id}/responses        safe proposal only -> 201 (200 replay)
# Step 30 controlled defensive responses
POST /api/v1/responses/controlled            evidenced request -> PENDING_APPROVAL, 201 (200 replay)
GET  /api/v1/responses/{id}/policy           deterministic verdict + reason (READ_RESPONSES)
POST /api/v1/responses/{id}/provider-preview provider dry run, executed:false (RUN_ANALYSIS)
POST /api/v1/responses/{id}/rollback         completed -> ROLLED_BACK / UNSUPPORTED (ROLLBACK_RESPONSE)
GET  /api/v1/incidents/{id}/response-recommendations  deterministic, never automatic (READ_RESPONSES)
GET  /api/v1/incidents/{id}/responses        incident response list
POST /api/v1/network/scans                  validated profile scan -> 202 (503 no Nmap)
POST /api/v1/network/scans/preview           validation-only plan -> 200 (no scan/assets)
GET  /api/v1/network/scans[/{id}]            job history + audit
POST /api/v1/auth/login                      credentials -> JWT (401 generic)
GET  /api/v1/auth/me                         token identity + permissions
POST /api/v1/auth/logout                     revoke token + audit
GET  /api/v1/auth/audit                      auth audit trail (VIEW_AUDIT)
POST /api/v1/users                           bootstrap ADMIN or MANAGE_USERS
GET  /api/v1/users[/{id}]                    user admin (MANAGE_USERS)
PATCH /api/v1/users/{id}                     update/disable/roles (MANAGE_ROLES for roles)
POST /api/v1/network/scans                  {target, profile, requested_by} -> 202
POST /api/v1/network/scans/{id}/cancel      queued-only -> 200 (else 409)
POST /api/v1/vulnerability-scans            {asset_id|target, profile} -> 202
GET  /api/v1/vulnerability-scans[?limit]
GET  /api/v1/vulnerability-scans/{id}       assessment + audit
GET  /api/v1/vulnerabilities[?severity&status&asset_id&scanner&limit&offset]
GET  /api/v1/vulnerabilities/{id}           finding + audit
GET  /api/v1/assets/{asset_id}/vulnerabilities
POST /api/v1/vulnerabilities/{id}/status    explicit transition (else 409)
GET  /api/v1/vulnerabilities/{id}/risk         stored finding assessment
GET  /api/v1/vulnerabilities/{id}/correlations linked events + incidents
GET  /api/v1/assets/{id}/vuln-risk             aggregate summary
```

Error codes used: `INVALID_TARGET` (422), `NMAP_UNAVAILABLE` (503),
`SCAN_NOT_FOUND` / `ASSET_NOT_FOUND` / `EVENT_NOT_FOUND` (404),
`PAYLOAD_TOO_LARGE` (413), `INVALID_FILTER` (422), `INVALID_EVE` (422),
`INVALID_ZEEK` (422), `INVALID_WAZUH` (422), `INVALID_DEFENDER` (422),
`INVALID_VULNERABILITY` (422), `CORRELATION_NOT_FOUND` (404),
`INVALID_ENTITY_TYPE` (422), `RISK_NOT_FOUND` (404),
`REFERENCE_NOT_FOUND` (404), `INCIDENT_NOT_FOUND` (404),
`INVALID_TRANSITION` (422 incident lifecycle, 409 response lifecycle),
`INVALID_REQUEST` (422 bodiless guards incl. recalculate),
`INVALID_PROPOSAL` (422), `RESPONSE_NOT_FOUND` (404),
`TARGET_NOT_AUTHORIZED` (403), `SCAN_NOT_FOUND` (404),
`SCAN_NOT_CANCELLABLE` (409),
`INGEST_FAILED` (per-item, batch), plus the Step 1 envelope.

## 3. What is NOT implemented (later stages)

```text
Vendor adapters (Suricata/Zeek/Wazuh/Defender/findings — built) + Nmap inventory
        ↓
Event Normalization (canonical SecurityEvent — generic + 5 adapters built)
        ↓
Correlation (deterministic rules → correlations + evidence — built, analysis only)
        ↓
Event Bus (durable transport — introduced only when required)
        ↓
Risk Engine (deterministic scoring v1.0.0 — built, analysis only)
        ↓
Response Engine (approval + audit + simulation/safe-record executors — built; safe-record touches workflow records only)
        ↓
Vulnerability Assessment (fixture-backed findings over inventory — built, data only)
        ↓
Dashboard / Audit (SOC view + audit trails — API complete, UI not delivered)
        │   GET /overview (Step 9) rolls up stored state read-only
        │   UI blocked: no Node/npm/yarn/pnpm and no usable Docker engine
        │   in this environment, so vitest/tsc/vite cannot run
```

Streaming/SIEM live tail and scheduled polling are architected only
(`services/ingestion_stream.py`: stream protocol, bounded poll stream,
poll worker) and explicitly NOT enabled - `STREAMING_ENABLED=false`,
`PollWorker.start()` refuses, and no background threads, timers or
schedulers exist. Ingestion remains operator-initiated and bounded.

Incident intelligence (Step 29) is likewise analysis-only: no AI/ML
inference, no autonomous recalculation, no incident merge/split, no
manufactured entities — relationships show related stored records and
never prove compromise.

Each future engine gets:
1. Its own service interface under `backend/app/services/`.
2. Its own models + Alembic migration (one bounded context at a time).
3. Its own tests before any wiring to other engines.
4. No shell execution, no blocking actions, no scanner integrations until
   explicitly designed with safety review.

## 4. Key decisions (Steps 1–30)

- **Readiness vs liveness split** (Step 1, kept).
- **One row per IP; service set replaced per scan** — inventory shows the
  current known state; `first_seen` preserves host history.
- **Profiles, not flags** — exact Nmap argv is backend-controlled;
  `BackgroundTasks` instead of Celery/Redis (single-node simplicity).
- **Bounded scans** — CIDR ≤ 256 addresses, per-profile timeouts, 8 MB
  output cap, minimal child env.
- **Frontend polls APIs** — status and inventory are observed, never hardcoded.
- **Restrained SOC styling** kept; authorization notice + confirmation
  checkbox on the scan form.
- **Checkpoint after commit, never before** (Step 28) — a batch must be
  fully persisted before its cursor advances, so retries, replay and
  backpressure are idempotent instead of lossy; the cursor itself is
  treated as potentially sensitive and sanitized before storage.
- **Bounded over background** (Step 28) — fixed batch/queue/retry caps
  with audited rejection beats unbounded buffering; streaming and
  scheduled polling exist only as non-startable code.
- **Deterministic labels, not inferred truth** (Step 29) — confidence
  comes from a fixed rule catalog mapped to DIRECT/STRONG/MODERATE/WEAK;
  relationships are references to stored ids only, and analysis never
  invents an asset, user or identity.
- **Operator-triggered analysis** (Step 29) — one bodiless MANAGE_INCIDENT
  endpoint with server-enforced windows/caps and an operator disable-list
  replaces any temptation of background scoring; every run is bounded,
  counted and audited.
- **A target must be evidenced, never asserted** (Step 30) — a defensive
  action is only accepted when the incident's *stored* records justify
  the target. This is the single most important guard in the step: it
  turns "an operator typed an address" into "the platform observed this
  address in this incident", and it is why an unevidenced request is
  rejected rather than merely flagged.
- **A provider without a transport cannot act externally** (Step 30) —
  rather than relying on review to keep a provider harmless, the provider
  module imports no subprocess/socket/HTTP client at all. Safety is a
  property of the module's scope, not of a convention.
- **Two registries, not one mutated registry** (Step 30) — the Step 13/19
  simulation adapters are frozen by regression tests, so controlled
  providers live in their own registry. Step 30 is additive at every
  layer: model columns, statuses, action types, audit events, and routes.
- **Separation of duties is a role-map property** (Step 30) — requesting
  and cancelling are analyst-level, approving/executing/rolling back are
  operator-level. `RESPONSE_ALLOW_SELF_APPROVAL` exists for
  single-operator deployments and is off by default.
- **Bounded, expiring, reversible** (Step 30) — every controlled action
  carries an `expires_at` clamped to a server ceiling, and a completed
  action can only leave `COMPLETED` through an explicit, separately
  authorized rollback that reports `UNSUPPORTED` rather than guessing a
  previous state.

## 5. Risks / review before Step 29

- Confirm Postgres credentials strategy (secrets manager vs env) for staging/prod.
- Decide authN/Z approach (users table, sessions/OIDC) before any protected endpoints.
- Decide event-bus need (Postgres LISTEN/NOTIFY vs Redis/Kafka) only when
  collector throughput demands it.
- `BackgroundTasks` runs in-process: concurrent/long scans need a real job
  queue before scan volume grows.
- Step 29 windows/caps and `CORRELATION_DISABLED_RULES` are process-wide
  ceilings — tune them per deployment, and keep recalculation manual;
  any future automatic scoring would need explicit design review first.
- Step 30: no real response provider exists. `MOCK` writes a platform-side
  record and `NOT_CONFIGURED` refuses; before any Defender, firewall, EDR
  or cloud provider is considered it needs its own threat model, its own
  credential handling, an approval and rollback design that matches the
  real system's semantics, and an explicit decision about whether
  `expires_at` can be honoured there at all.
- Step 30: `RESPONSE_ALLOW_SELF_APPROVAL=true` removes the two-person rule
  and should stay false; with it on, a single compromised operator
  account can request and approve a consequential action in one session.
- Step 30: expiry is enforced on read because there is no scheduler, so a
  long-idle deployment can hold an overdue approval until someone lists
  responses. The state is never *executable* while overdue (approve and
  execute both re-check the clock), but the audit of the transition is
  delayed rather than immediate.

## 6. Hardening and production readiness (Step 31)

Step 31 changes no feature and removes no control. This section is the
engineering reference for what was added; operational guidance is in
README §12.

### 6.1 Middleware stack (added outermost-last)

```text
request
  -> TrustedHostMiddleware          (only when TRUSTED_HOSTS is set)
  -> CORS                           (explicit origin allow-list, never "*")
  -> RequestContextMiddleware       correlation id + one access log line
  -> BodySizeLimitMiddleware        413 before the body is buffered
  -> SecurityHeadersMiddleware      nosniff / DENY / no-referrer / CSP / no-store
  -> routing -> auth -> permission -> rate limit -> handler
```

`RequestContextMiddleware` publishes a sanitised correlation id through
`app.core.request_context` (a `ContextVar`), so the audit appenders and the
error handler can attach it without changing any public signature. An
inbound `X-Request-ID` is only honoured when it matches
`^[A-Za-z0-9-]{1,64}$`; otherwise a fresh id is generated, which removes
the log-injection vector.

`BodySizeLimitMiddleware` inspects `Content-Length` and refuses with
`413 PAYLOAD_TOO_LARGE` without echoing the submitted size. It is
defence in depth: the ingest services' `MAX_RAW_BYTES` per-field cap
remains the authoritative content limit.

### 6.2 Rate limiting

`app/core/ratelimit.py` implements a deterministic fixed-window counter:

* keyed by `(window, operation + caller)`; caller is the authenticated
  username when a token is present, else the client host;
* bounded to `RATE_LIMIT_MAX_BUCKETS` buckets with LRU eviction, so the
  limiter's own memory is a fixed ceiling that an attacker cannot grow
  with distinct keys;
* **no threads, timers, scheduler or external store** — expiry is lazy
  (a stale window is overwritten when next seen);
* the limiter lives on `app.state`, not in a module global, so one
  process cannot leak budgets between two application instances;
* a limit of `0` disables that check.

`app/api/v1/limits.py` exposes `rate_limit(operation, setting)` as a
FastAPI dependency. It **raises** `RateLimitExceeded`; `register_exception_
handlers` renders `429 RATE_LIMITED` with `Retry-After`. (A response
*returned* from a dependency is not reliably treated as the final
response, so raising is the correct mechanism.)

Ordering matters and is deliberate: the dependency is listed last, after
`require_permission`, so an anonymous or unauthorized caller receives
401/403 and never consumes a budget. A limit is resource protection, not
authorization — it can never widen what an authorized caller may do.

Budgeted operations (Step 32; the `rate_limit()` calls in
`app/api/v1/endpoints/` are the source of truth):

* `correlation_recompute`, `incident_recalculate`, `risk_recompute`,
  `risk_calculate`, `connector_poll`
* controlled response: `response_request`, `response_approve`,
  `response_execute`, `response_rollback`
* `scan_start` and `vuln_scan_start`, both reading `RATE_LIMIT_SCAN_START`
  as separate operation keys

`POST /auth/login` is budgeted differently and deliberately: only the
handler knows whether an attempt failed, so `RATE_LIMIT_LOGIN_FAILURES`
(default 5) is charged against the caller after a failed credential check
rather than as a dependency. A correct password is therefore never
throttled. The failure is audited and committed *before* the charge, so a
`429` cannot hide the evidence. The bucket is keyed by client host — there
is no token yet — so this bounds per-source guessing; it is not a
per-account lockout and does not detect a distributed attacker.

### 6.3 Database

`init_engine` applies a bounded pool for server dialects only
(`pool_size`, `max_overflow`, `pool_timeout`, `pool_recycle`,
`connect_args={"connect_timeout": …}`) plus a `connect` event that sets
PostgreSQL `statement_timeout` from `DB_STATEMENT_TIMEOUT_MS`. SQLite
(the test suite) is skipped because it has no server-side pool.
`pool_pre_ping` is retained.

Migration `step31_hardening` (additive, revises `step30_controlled_response`):

| Object | Kind | Reason |
|---|---|---|
| `response_actions.expires_at` | index | the Step 30 expiry sweep filters and orders on it on every response read |
| `response_actions.provider` | index | policy/provider reporting |
| `response_actions.policy_decision` | index | policy verdict grouping |
| `response_actions.target_reference` | index | per-incident target lookup |
| `response_audit.created_at` | index | every audit read orders by it |
| `response_audit.request_id` | index | request correlation |
| `incident_audits.action` | index | audit filtering |
| `incident_audits.created_at` | index | audit ordering |
| `incident_audits.request_id` | index | request correlation |
| `response_audit.request_id` | nullable column | correlation |
| `incident_audits.request_id` | nullable column | correlation |

No data is written or removed; `downgrade` drops only what this
migration created.

### 6.4 Performance fixes (behaviour identical)

* `response_governance.recommendations` previously called
  `target_evidence()` inside three loops, re-running the evidence-event
  query once per candidate address/account/asset. The evidence index is
  now built once from the already-loaded event set, so the total query
  count is constant.
* `response_governance.expire_due` previously committed and refreshed
  per row (up to 500 transactions from a single read). It now performs
  one `SELECT` — filtered and ordered by `expires_at` in SQL — and at
  most one `commit`, bounded by `MAX_EXPIRY_SCAN`.
* `correlations._evidence_items` previously issued one `SELECT` per
  evidence link; it now batches with a single `IN` query.

### 6.5 Error handling

The unhandled-exception handler returns `500 INTERNAL_ERROR`. In
development it includes the exception **type only** — the message is
withheld, because a SQLAlchemy or OSError message can contain SQL text,
bound parameters, filesystem paths or DSN fragments. The correlation id
is returned in `X-Request-ID` so an operator can find the full trace in
the server log. Validation failures, 404s, auth failures and rate limits
all use the same `{"error": {"code", "message"}}` envelope.

### 6.6 Container boundaries

The backend image runs as an unprivileged user (uid/gid 10001) with
`no-new-privileges`, `cap_drop: ALL`, tmpfs `/tmp`, memory/PID limits and
size-capped logs. PostgreSQL gets `no-new-privileges` plus the same log
caps. **The frontend intentionally keeps its default capabilities**:
nginx binds `:80` as master and drops privileges for its workers, so
`cap_drop: ALL` would prevent it listening — this is documented, not
overlooked. PostgreSQL remains bound to `127.0.0.1` only.

### 6.7 Not implemented (Step 31)

* Shared/multi-replica rate-limit state (limits are per-process).
* TLS termination and HSTS-at-edge (headers are set; TLS is not).
* Secret rotation or a secrets manager (env vars are validated, never
  echoed, and redacted in logs).
* Read-only container filesystems.
* An unprivileged nginx listener.
* Centralised metrics/tracing (correlation ids and structured access logs
  only).
* Any external connectivity validation — all connectors remain
  `NOT_CONFIGURED`.

## 7. Wazuh live read-only foundation (Phase 2, Step 3)

> **Live Wazuh connectivity not validated in this environment.** The
> integration below is exercised entirely against `httpx.MockTransport`. No
> real Wazuh manager was contacted, so no claim is made about a working live
> deployment.

### 7.1 Mode separation

Two paths exist and must not be conflated. **Fixture mode** is the
`POST /api/v1/events/ingest/wazuh` endpoint: an operator or test submits
records directly, no network is touched, no credentials exist.
**Live mode** is `app/services/wazuh_client.py`: the connector performs an
allow-listed HTTPS call to a real Wazuh manager. Both converge on the same
`wazuh_adapter` normalization, the same deduplication by deterministic
`external_event_id`, the same asset correlation and the same audit trail —
there is no second event store.

### 7.2 Component placement

| Concern | Module |
|---|---|
| Wazuh REST client + token minting | `app/services/wazuh_client.py` |
| Shared allow-listed transport | `app/services/http_connector.py` |
| Lifecycle, states, audit | `app/services/connectors.py` |
| Bounded ingest orchestration | `app/services/ingestion.py` |
| Normalization | `app/services/wazuh_adapter.py` |
| API | `app/api/v1/endpoints/connectors.py` |

`wazuh_client.py` never touches a socket, process or generic HTTP helper
directly; every call goes through `ConnectorHttpClient`, which owns the
destination allow-list, timeout, response-size cap, redirect refusal, safe
retries and secret redaction.

### 7.3 Configuration and authentication

Configuration is environment-only: `WAZUH_API_URL`, `WAZUH_USERNAME`,
`WAZUH_PASSWORD`, plus the shared `CONNECTOR_TIMEOUT_SECONDS`,
`CONNECTOR_MAX_RESPONSE_BYTES`, `CONNECTOR_MAX_PAGES`,
`CONNECTOR_MAX_EVENTS`, `CONNECTOR_VERIFY_TLS`, `CONNECTOR_RETRY_MAX`.
All default to empty or disabled, so the application runs normally with
Wazuh unconfigured.

Authentication is HTTP Basic against `POST /security/user/authenticate`,
yielding a bearer token. `WazuhAuthenticator` is the sole minter. The token
is held in memory on the client instance only, is never returned to a caller,
never persisted to an audit row, never logged, and is appended to the
client's redaction secrets on receipt. `CONNECTED` is reported only after a
real successful API response; a tokenless or non-JSON authentication
response is `MALFORMED_RESPONSE`, never `CONNECTED`.

### 7.4 Bounded, read-only retrieval

`/alerts` is read with `limit`/`offset`, at most 100 per page, capped by
`CONNECTOR_MAX_PAGES` and `CONNECTOR_MAX_EVENTS`. Each poll terminates with
an explicit reason (`COMPLETED`, `MAX_PAGES`, `MAX_EVENTS`,
`REPEATED_CURSOR`, `MALFORMED_PAGINATION`) so a replayed or malformed cursor
cannot produce an unbounded loop. Wazuh history is never walked: each poll
starts at offset 0 and relies on deduplication.

The connector is strictly read-only toward Wazuh. Its only non-GET request
is the authentication POST — no active response, agent control, file
management, or restart path exists in the client.

### 7.5 States and audit

The eight-state vocabulary is `NOT_CONFIGURED`, `CONFIGURED`, `CONNECTING`,
`CONNECTED`, `AUTH_FAILED`, `UNAVAILABLE`, `RATE_LIMITED`, `ERROR`. Audit
events: `CONNECTOR_CHECK_STARTED`, `CONNECTOR_CONNECTED`,
`CONNECTOR_AUTH_FAILED`, `CONNECTOR_UNAVAILABLE`, `CONNECTOR_RATE_LIMITED`,
`CONNECTOR_ERROR`, `CONNECTOR_POLL_STARTED`, `CONNECTOR_POLL_COMPLETED`,
`CONNECTOR_POLL_FAILED`. Audit rows carry operational metadata (source,
outcome, counts, termination reason, correlation id) and never a credential
or token.

### 7.6 Not implemented

* Live connectivity validation against a real Wazuh manager.
* Background/scheduled polling, streaming, or any autonomous trigger — every
  check and poll is operator-initiated.
* Any write, action or remediation against Wazuh or its agents.
* Per-account (rather than per-source) lockout, and shared rate-limit state
  across replicas (see §6.7).

## 8. Microsoft Defender connector foundation (Phase 2, Step 4)

> **Live Microsoft Defender connectivity not validated in this environment.**
> The integration is exercised entirely against `httpx.MockTransport`. No
> Microsoft Graph or identity endpoint was contacted, so no claim is made
> about a working live tenant.

### 8.1 Second implementation of one architecture

Defender reuses the Step 26/27 connector architecture rather than
duplicating it: `app/services/defender_client.py` holds the Graph client and
token provider, and every call goes through the same
`ConnectorHttpClient` that owns the destination allow-list, timeout,
response-size cap, redirect refusal, safe retries and secret redaction.
Lifecycle and states live in `connectors.py`; bounded ingest in
`ingestion.py`; normalization in `defender_adapter.py`; the API in
`endpoints/connectors.py`. Fixture mode
(`POST /api/v1/events/ingest/defender`) and live mode converge on the same
adapter, deduplication, asset correlation and audit trail.

### 8.2 Authentication architecture

OAuth2 client-credentials token acquisition lives in
`DefenderTokenProvider`, injected into `DefenderClient` so a future
MSAL-backed provider can replace it without touching retrieval code. The
scope requested is `https://graph.microsoft.com/.default`. The token is
memory-only on the provider, is never returned to a caller, never written to
an audit row, never logged, and is registered as a redaction secret on
receipt; the client secret is a redaction secret from construction.
Token-endpoint rejections (400/401/403) map to `AUTH_FAILED`, and
`CONNECTED` additionally requires a real successful Graph read.

### 8.3 Bounded retrieval and cursor safety

`GET /security/alerts?$top=N` is followed through `@odata.nextLink` up to
`CONNECTOR_MAX_PAGES` pages and `CONNECTOR_MAX_EVENTS` records, terminating
with an explicit reason (`COMPLETED`, `MAX_PAGES`, `MAX_EVENTS`,
`REPEATED_CURSOR`, `MALFORMED_PAGINATION`). A repeated nextLink terminates
instead of looping, and each server-supplied nextLink is re-validated with
`validate_destination()` against the allow-list before it is used — the
cursor is untrusted input. A page without a `value` list is
`MALFORMED_RESPONSE`, never an empty success.

### 8.4 Read-only guarantee

The connector issues exactly one kind of non-GET request: the token
exchange. There is no remediation, blocking, isolation, agent control or
any other write to Graph or Defender, and the response provider registry
remains `MOCK`-only.

### 8.5 Not implemented

* Live connectivity validation against a real tenant.
* Background/scheduled polling, streaming, or any autonomous trigger.
* Any write or action against Defender, Graph, or an endpoint.
* MSAL / interactive or device-code auth, certificate credentials, and
  on-behalf-of flows; client credentials only.
* Per-tenant budgeting and shared state across replicas (see §6.7).

## 9. Controlled polling policy (Phase 2, Step 5)

> **Polling, not streaming.** Step 5 adds no streaming path; the Step 28
> `STREAMING_ENABLED=false` foundation stays disabled.

### 9.1 Placement

`app/services/connector_polling.py` is a policy layer, not a second
pipeline. `ingestion.poll_source` remains the only bounded, audited route
from a connector to stored canonical events, so normalization,
deduplication, asset correlation, RBAC, rate limiting and audit behaviour
are unchanged and cannot drift between the manual and automated paths.

### 9.2 Guarantees

* **Overlap prevention** — a `threading.Lock` per connector source refuses a
  concurrent poll (`PollInProgress` → `409 POLL_IN_PROGRESS`). A mutex is
  not a scheduler; no thread, timer, event loop or daemon is created, which
  the Step 31 `test_no_autonomous_response_wiring` guard continues to
  enforce (the module is on that test's allow-list for the same reason
  `app.core.ratelimit` is).
* **Interval** — after a successful poll the source is not due again until
  `connector_poll_interval_seconds` has elapsed.
* **Failure cool-down** — after a failure the source is not due until
  `connector_failure_cooldown_seconds` has elapsed, extended when the
  connector recorded `RATE_LIMITED`, and extended further when a
  `Retry-After` is available. A failing or unreachable source is therefore
  not hammered.
* **Disabled by default** — `connector_auto_poll_enabled` defaults to
  `false`, so `run_due_polls` performs no network I/O and starts nothing.
  Enabling it does not start a scheduler; it only permits an invoker to run
  the pass.
* **Never polls a NOT_CONFIGURED connector** — the due-poll pass skips such
  sources, and `poll_source` already refuses them before any fetch.

### 9.3 Manual polling

Manual `POST /events/connectors/{source}/poll` is deliberately **not**
interval-gated: an operator asking for a poll gets a poll, including the
idempotent repeat that dedup absorbs. Frequency is bounded by the existing
`RATE_LIMIT_CONNECTOR_POLL` budget, and overlap is still refused.

### 9.4 Health metadata

`PollHealth` / `PollHealthResponse` expose poll start, completion, last
success, last error category, events received / accepted / deduplicated,
next permitted poll time, in-flight flag and poll/failure counts. These are
presentation values only: they are never persisted and never audited, and no
credential or token is representable in them.

### 9.5 Not implemented

* Any background scheduler, timer, thread or streaming tail.
* Per-tenant or shared-state coordination across replicas.
* Propagating a server `Retry-After` through the poll error type (the check
  path exposes it; the poll path does not yet).
* Autonomous response, blocking, isolation or any other action.

## 10. Event normalization layer (Phase 2, Step 6)

Step 6 adds no model, no migration and no second event store. It reuses the
Step 23 pipeline — `SecurityEvent` / `EventIngest` / `normalize_event` /
`correlate_asset` / `store_event` — and closes three gaps.

### 10.1 Vendor symmetry

`wazuh_adapter` and `defender_adapter` emit the same canonical field set.
Wazuh now also emits `username` and `process_name`; Defender additionally
recognises Graph's `accountName` and `remoteIp`. Both leave absent fields
`None`; neither infers an identity, a confidence value or an asset.

### 10.2 Pipeline statistics

`SourceMetrics` and the poll result carry `fetched`, `normalized`,
`accepted`, `deduplicated` and `rejected` separately, where
`normalized = accepted + deduplicated` and
`fetched = normalized + rejected`. The identity is asserted by tests, so a
regression in one stage cannot be masked by another.

### 10.3 Secret scrubbing before persistence

`event_service.scrub_secrets` walks the vendor payload before it is
serialized into `raw_event` and the normalized snapshot, replacing values
whose key names a credential with `***REDACTED***`. The key set is narrow
and the walk is bounded by depth (12) and breadth (200 keys per level);
the existing `MAX_RAW_BYTES` ceiling still applies afterwards. Canonical
columns, fingerprints and `correlation_key` are computed from the canonical
values, so scrubbing does not alter event identity or deduplication.

### 10.4 Preserved

Server-side validation, per-record failure isolation inside a batch, bounded
batch/page/event limits, dedup by the `(source_type, source_name,
external_event_id)` triple, exact-match asset correlation (unknown stays
unresolved), and the append-only audit trail are unchanged.

## 11. Correlation target identity (Phase 2, Step 7)

Step 7 reuses the Step 9 engine — `correlation_rules` (pure functions over
`EventView`), `correlation_service` (bounded scan, deterministic identity,
upsert), the `Correlation` / `CorrelationEvidence` / `CorrelationAudit`
models and the `incidents` grouping path. No new model or engine.

### 11.1 What changed and why

`rule_multi_source_target` grouped by `destination_ip` alone. A Wazuh alert
carries `dstip`; a Defender alert carries `remoteIp` and `computerName` and
usually no destination address, so two vendor alerts about one machine
shared no key and correlated never. A target is now keyed by
`destination_ip` **or** `hostname`, each namespace-prefixed (`ip:` / `host:`)
to prevent collision, with an ordered key list so the pivot is
deterministic. Address-based grouping is a strict superset of the previous
behaviour.

### 11.2 Invariants unchanged

* The catalog is a fixed set of three rules; `confidence` is a fixed
  per-rule integer and `severity` is the evidence maximum — no probabilistic
  or learned scoring.
* Windows are `min(rule window, correlation_max_window_minutes)` with a hard
  7-day ceiling; the recompute scan is capped at 500 events.
* Identity is `sha256("correlation:v1", rule_id, sorted(event_ids))` and
  writes go through `upsert_draft`, so an identical evidence set refreshes
  instead of duplicating — at both correlation and incident level.
* `recompute_correlations` takes no caller parameters: rule selection,
  window, severity and asset identity are never client-supplied.
* Evidence is preserved with position and role; the explanation names the
  rule, the count, the source types and the observed target, and every
  description states that related events are not proof of compromise.
* An unresolved asset remains unresolved; correlation states only what was
  observed.

### 11.3 Not added

No AI/ML, no probabilistic scoring, no autonomous response, and no blocking,
isolation, process termination, file deletion or firewall modification.

## 12. Incident intelligence and priority refinement (Phase 2, Step 8)

`app/services/incident_intelligence.py` is a read-only enrichment over an
incident that Step 7 already correlated. It creates no model, writes no
incident, and does not replace the Step 10/25 risk score — the incident's
`risk_score`, `severity` and `confidence` are read, never written.

### 12.1 Inputs and bounds

Inputs are stored rows only: the correlation's evidence events, the
inventoried assets those events resolve to, the open findings recorded for
those assets, the Step 29 relationships, and the incident's own timestamps.
All lookups are batched and capped by `Settings`
(`correlation_max_events_per_operation`, `correlation_relationship_max`);
truncation is reported in the payload.

### 12.2 Determinism

Contributions are evidence count, highest evidence severity, relationship
count, vulnerability context and recency. Each is a pure function of stored
rows, ordering is total (event id), and thresholds are fixed integers. The
same evidence therefore always yields the same factors, points and priority;
a test asserts three consecutive reads are byte-identical.

### 12.3 Integrity properties

* **Duplicate evidence cannot inflate risk.** Evidence is loaded with
  `SELECT DISTINCT` over the unique `(correlation_id, event_id)` constraint.
* **Nothing is invented.** Asset resolution is exact-match only; an
  unresolved event is counted, not attached to a guess. Absent findings and
  relationships contribute zero and are stated as such.
* **Vulnerability context is bounded and weighted by worst severity**, so a
  large number of low findings cannot outrank one critical exposure.
* **Recency** is derived from the stored `last_seen` against an explicit
  `now` (defaulting to the current time), never from event arrival order.

### 12.4 Surface and audit

`GET /incidents/{id}/intelligence` (`READ_INCIDENTS`) re-derives the summary
on every call and writes nothing, so it cannot be steered by a caller.
`POST /incidents/{id}/intelligence/refresh` (`MANAGE_INCIDENT`, rate-limited)
performs the same calculation and appends one `INTELLIGENCE_REFRESHED`
`IncidentAudit` row describing the inputs and the result. Neither returns
event payloads or credentials.


### 13. SOC overview aggregation (Step 9 — PARTIAL: API complete, UI deferred)

`services/soc_overview.py` answers one question � "what is stored right
now?" � so a dashboard needs no N requests and no client-side arithmetic.
It is a **reader**: no model, no migration, no table is written, and no
detection, scoring, correlation or response decision is taken.

* **Counts** are SQL `COUNT` aggregates (assets, services, events,
  correlations, incidents, open incidents, risk assessments, open
  vulnerabilities, response actions, pending approvals) � never a full
  table read.
* **Priority** is not stored. It is the existing `risk_service.priority_for`
  band applied to the stored `risk_score`; incidents without a score are
  reported as `UNSCORED` rather than assigned an invented band. Severity and
  priority buckets are emitted complete, zeros included.
* **Bounds.** `GET /overview` accepts only `limit` (`ge=1 le=50`), clamped
  again server-side; every list is capped at 50 and any unknown parameter is
  ignored rather than obeyed.
* **Authorization.** `READ_INCIDENTS` � held by every role in
  `ROLE_PERMISSIONS`, so the surface fails closed for any principal without
  it. Bootstrap mode (no users yet) still applies and is asserted by a test.
* **Secrets.** Connector health reuses the Step 27 truth machine, which
  reports configured/state only; a test asserts no password, client secret,
  token or `Authorization` header appears in the payload.
* **Status, not action.** Response workflow is surfaced as counts only; a
  test asserts no action verb is present in the response. The payload
  carries a disclaimer that related events are not proof of compromise.

The UI half of this step is **not delivered**: the dashboard in
`frontend/src/pages/Dashboard.tsx` is still the Phase 1 status/inventory
card, because this environment has no Node/npm/yarn/pnpm and no usable
Docker engine, so `vitest`, `tsc --noEmit` and `vite build` cannot be run.
Writing untested TypeScript would risk the production build and the
existing frontend suite, so the endpoint is provided and the UI is left for
an environment with a working toolchain.

### 14. Production hardening (Step 10)

Hardening only: no feature, model, migration, dependency or endpoint was
added, and no safety control was removed.

**Startup gate.** `validate_production()` now also refuses `REQUIRE_AUTH=false`
(bootstrap would let the first anonymous caller create the first ADMIN),
`CONNECTOR_VERIFY_TLS=false` (connector credentials without server
verification) and an empty `TRUSTED_HOSTS` (an empty allow-list makes
`TrustedHostMiddleware` a no-op, silently disabling Host validation). All
three are production-only; messages name the variable and never its value.

**Log redaction.** The root-handler filter was bypassable, because
`uvicorn`/`uvicorn.access` run with `propagate: False` and private handlers
that uvicorn configures *after* the app imports. Redaction moved to a
`LogRecord` factory, which runs before any handler or formatter, so no
handler configuration can defeat it. The factory chains any previous one, is
idempotent, and cannot raise.

**Deployment surface.** API and frontend ports are loopback-bound by default
(`API_BIND` / `FRONTEND_BIND`), matching the database, and the backend
container root filesystem is `read_only: true` with `/tmp` on tmpfs. The
database and frontend keep their existing capability behaviour, which cannot
be changed and verified without a running Docker engine.

**Concurrency model.** Rate-limit buckets, poll health/cooldowns/overlap
locks, connector runtime counters and ingestion metrics are per-process; the
durable, transactional state (audit, incidents, correlations, risk,
responses) is in the database. Supported scale-out is a single replica, or a
shared store behind the same interfaces — not approximated in-process.

**Not verified here.** No container was started (no Docker engine), and no
Wazuh or Defender instance was contacted (all connector tests use
`httpx.MockTransport`). Container configuration is verified statically.

### 15. Append-only audit enforcement (Step 11)

`models/audit_guard.py` turns audit immutability from a convention into an
invariant at the ORM unit of work. Two listeners on `orm.Session`, installed
once at import of `database/session.py`:

* `before_flush` refuses `UPDATE`/`DELETE` of a loaded audit instance.
* `do_orm_execute` refuses a bulk `UPDATE`/`DELETE` targeting an audit table.

Failure mode is fail-closed: `AuditRecordMutationBlocked` (a `RuntimeError`)
is raised before any statement reaches the database.

Coverage is by class-name suffix `*Audit` over the ORM registry, not by table
name - `response_audit` and `scan_audit` are singular and a `_audits` check
would have missed them.

**Boundary.** Only statements routed through the ORM `Session` are guarded.
`text()` SQL, `session.connection()` and any external writer bypass, which is
why database-level enforcement plus a restricted database role remains the
stated answer for tamper-evidence (README 21.7).

**Test-only escape hatch.** `allow_audit_purge_for_tests()` lets the fixtures
truncate audit tables, and refuses to arm unless `ENVIRONMENT=test`. It uses a
module-level counter rather than a thread-local so that the Step 31 ban on
`threading`/`asyncio`/`sched`/`multiprocessing` in `app/` stays intact.

No endpoint, model, migration, dependency or capability was added.

### 16. Database-level audit immutability (Step 12)

Migration `phase2_step12_audit_immutability` (after `step31_hardening`)
installs a `BEFORE UPDATE OR DELETE ... FOR EACH ROW` trigger on each of the
eight audit tables, backed by one `audit_append_only_guard()` PL/pgSQL
function that raises `restrict_violation` — SQLSTATE **23001**. `INSERT` is
unaffected.

This closes the boundary Step 11 documented: raw `text()` SQL, a raw
connection and external writers now hit the database-level refusal instead of
slipping past the ORM guard. The two layers are complementary, not redundant.

PostgreSQL only; `upgrade()` is a no-op on other dialects, which is what keeps
the SQLite-based suite working. The target table list is a frozen snapshot
(never derived from live models) with a test asserting it still matches
`audit_guard.audit_table_names()`.

Follow-up revision `phase2_step12_guard_sqlstate_fix` replaces the function
body only: the original `format()` template contained bare `%` characters that
PostgreSQL read as conversion specifiers, so the guard failed with SQLSTATE
`22023` while formatting the message and never reached its intended `23001`
refusal. Step 12's own migration is not edited — it is already applied. See
README 24.6.

**Boundary:** `TRUNCATE`, `DROP TABLE` and superuser bypass remain, by design.
**Verified by execution** against PostgreSQL 16.15: all eight triggers present
and enabled, `UPDATE` and `DELETE` refused with 23001 on each, `INSERT` still
accepted.

### 17. Runtime verification harness (Step 13)

Step 13's scope was runtime verification of Steps 10 and 12, delivered while the
environment could not run it and recording that gap rather than claiming a pass.
The gap is now closed: Docker Desktop 4.92.0 (engine 29.8.0) and PostgreSQL
16.15 run the stack, and the harness reports 36 passed, 0 failed, 0 skipped.

The harness reads container hardening from `docker inspect`, checks the eight
Step 12 audit triggers for existence, enablement and both UPDATE and DELETE
coverage, and proves each refuses both operations with SQLSTATE 23001. Probes
are single-row and scoped by `ctid`, inside a transaction that is rolled back,
and it never inserts. It never mutates Docker state.

Failure signalling is deliberately strict: an unreachable prerequisite reports
`SKIP`, never `PASS`; nothing verifiable exits 2 with an explicit "absence of
evidence" message; a refusal is judged on the exact SQLSTATE, so no other error
can pass as append-only enforcement. The engine is considered reachable only if
the CLI exits zero *and* prints a version on stdout, with stdout and stderr kept
apart so an error message cannot be read as an answer.

Running it exposed eight defects in the harness itself and one in the guard —
none of which could turn a real failure into a pass. See README 24.5 and 24.6.
