# Security Platform — vendor-neutral security orchestration & incident correlation

> **Step 11 — Incident management (records only).**
> Incidents are opened explicitly from existing correlations (plus an
> optional existing risk assessment): deterministic identity, explicit
> status lifecycle, severity/confidence inherited from source records,
> evidence preserved as references. Status changes record workflow only —
> no response, remediation, or automation of any kind.

> **Step 13 — Controlled execution architecture (simulation only, kept).**
> Approved, previewed proposals can be "executed" through a single
> endpoint that runs ONLY a deterministic simulation adapter, persists
> the SIMULATED result idempotently, and audits every step under policy
> version 1.0.0. NOTHING REAL HAPPENS.

> **Step 14 — Authorized Nmap discovery hardening (kept).**
> The Step 2 scanner is now bound to an explicit authorization scope
> (`SCAN_ALLOWED_NETWORKS`, loopback-only by default): well-formed but
> out-of-scope targets are refused with 403. Scans record actor, engine
> type, result summary and a full audit trail; queued scans can be
> cancelled; assets carry type/source/scan provenance. No new scanners,
> no automatic scanning, no exploitation — discovery only, and only
> where authorized.

> **Step 15 — Vulnerability assessment (fixture-backed, data only, kept).**
> Stored assets/services are assessed by a deterministic fixture scanner
> through the same authorized-scan machinery: normalized findings with
> CVE/CVSS handling, deterministic dedup, explicit lifecycle, and audit.
> No live scanners run, nothing is exploited or remediated. Still no
> correlation, risk, incidents, response or automation beyond prior steps.

> **Step 16 — Vulnerability risk correlation (analysis only, kept).**
> Step 15 findings are scored by the existing deterministic risk engine
> (new `vuln_finding` entity type; same v1.0.0 formula) and linked to
> related events/incidents through shared asset identifiers — derived
> on read, never guessed, with reasons. Asset-level summaries aggregate
> stored assessments. Scores are neutral numbers, never proof of
> compromise. The risk score represents risk inferred from available vulnerability/security evidence. It is not proof that an asset has been compromised. Still no AI, incidents beyond Step 11, response or
> automation.

> **Step 17 — Incident detection & incident model foundation (kept).**
> A conservative detector over stored correlations opens typed incidents
> (VULNERABILITY_ACTIVITY / SUSPICIOUS_NETWORK_ACTIVITY /
> CORRELATED_SECURITY_EVENT / OTHER) only for qualifying evidence —
> finding-plus-activity, 3+ grouped events, or HIGH/CRITICAL severity —
> with deterministic reasons; lone observations stay leads and a finding
> alone never opens one. Same evidence reprocessed returns the same
> incident (Step 11 identity); wider windows and new links update it
> with audit rows. Risk score is the linked Step 10 assessment verbatim
> (NULL otherwise); confidence is correlation evidence strength.
> Evidence, timeline and audit endpoints expose every link. An incident
> is an evidence-based investigation record and does not by itself prove
> that a host has been compromised. Active response/remediation is NOT
> implemented in Step 17.

> **Step 18 — Controlled response foundation (kept).**
> Incident → proposal → approval → execution → result → audit, for SAFE
> foundation actions only (REVIEW, COLLECT_EVIDENCE,
> MARK_FOR_INVESTIGATION, ACKNOWLEDGE, CLOSE) that touch workflow
> records and never external systems. Explicit PROPOSED → APPROVED →
> RUNNING → COMPLETED/FAILED machine with recorded approval identity,
> deterministic idempotent proposals, replay-safe execution, honest
> failure reasons, and a full audit trail. The seven Step 12 action
> types stay simulation-only. Step 18 provides controlled response
> orchestration but does not perform external security remediation or
> blocking. No arbitrary command execution is supported.

> **Step 19 — Controlled response adapter foundation (kept).**
> Typed adapter contracts (`AdapterRequest`/`AdapterResult`, Pydantic)
> over an explicit simulation-only registry (SIMULATION,
> EVIDENCE_COLLECTION_SIMULATION, FIREWALL_SIMULATION,
> ISOLATION_SIMULATION — server-selected by static action map, unknown
> names rejected, no dynamic imports). `POST
> /responses/{id}/preview` validates, policy-gates (unapproved refused),
> validates strict targets (new HOSTNAME kind, syntactic only — never
> resolved), and returns truthful simulation results with
> stored-reference evidence. Step 19 provides controlled
> response-adapter orchestration and simulation only. No external
> security control is modified by Step 19.

> **Step 20 — Authentication + RBAC foundation (kept).**
> Argon2id users with closed role vocabulary (ADMIN / SECURITY_ANALYST
> / OPERATOR / VIEWER) and centrally derived permissions; short-lived
> JWTs (15 min, denylisted on logout); server-side per-endpoint
> enforcement (401/403 in the standard envelope) with a documented
> bootstrap mode (empty user table = legacy open access so the first
> ADMIN can be created; `REQUIRE_AUTH=true` disables it). Response
> approvals/executions record the token identity; no
> `EXECUTE_ARBITRARY_COMMAND` permission exists and none can — the
> Step 18/19 safe/simulation workflow is unchanged. Auth lifecycle
> audited without secrets. No auth bypass for administrators.

> **Step 21 — Asset discovery + controlled Nmap (kept).**
> Discovery profiles (`DISCOVERY_PING`, `DISCOVERY_TCP_COMMON`) on the
> authorized scan machinery plus a read-only preview; scope bounded by
> `SCAN_ALLOWED_NETWORKS` and configurable `discovery_max_addresses`.

> **Step 22 — Vulnerability assessment foundation (kept).**
> Staged scanner adapters with server-side profile→adapter routing, plus
> one LIVE adapter (`nmap-vuln`: fixed non-intrusive `vuln` NSE set over
> stored service ports; findings only from CVE-bearing script output,
> severity UNKNOWN never guessed) beside the MOCK/TEST fixture scanner
> — always distinguished by name, job row, and UI badges. Fixed
> `BASIC`/`STANDARD` profiles; Step 21 target boundary reused;
> deterministic identity with `first_seen` kept; service findings unseen
> by a rescan become `NOT_SEEN` (never deleted, never auto-resolved;
> re-observation reopens). Vulnerability assessment identifies reported
> or observed security findings; it does not prove exploitation or
> compromise. No exploitation or autonomous remediation.

> **Step 23 — Security telemetry ingestion foundation (kept).**
> The existing event pipeline gains a static adapter registry
> (SURICATA/ZEEK/WAZUH/DEFENDER, all FIXTURE grade — operator-supplied
> test data, no live sensors), server-side asset correlation
> (destination/source IP then hostname; read-only, never created;
> unknown stays unresolved), replay occurrence counting, optional
> source confidence, and an append-only ingest audit
> (RECEIVED/NORMALIZED/DEDUPLICATED/REJECTED). Events page shows
> fixture badges, unresolved assets, and occurrence counts. Telemetry
> is observed data only — never proof of compromise, never a trigger
> for automatic response.

> **Step 24 — Correlation + incident formation foundation (new).**
> Deterministic rule engine (multi-source-target, vuln-exposure,
> repeated-source) over stored events/findings with a configurable,
> hard-bounded correlation window (`correlation_max_window_minutes`,
> default 1440, ceiling 7 days). Recompute lifecycle audited
> (RUN_STARTED/MATCHED/COMPLETED); incidents expose typed observation
> links (`GET /incidents/{id}/observations`, idempotent by unique
> constraint) with event/vulnerability/correlation counts. Severity is
> the evidence maximum with pivot-naming reasons; confidence is
> correlation strength, never compromise probability. Correlation
> indicates related security observations; it does not by itself prove
> compromise. No AI/ML, no auto-response, no scheduled jobs.

> **Step 32 — Security review, remediation and final audit.**
> A review of the Steps 1–31 result found five defects, all now fixed and
> covered by regression tests. Validation failures log the failure *shape*
> (error type and field location) instead of the submitted values, so a
> password can no longer reach the log. `RATE_LIMIT_SCAN_START` is enforced
> on scan start and vulnerability-scan start. Failed logins are throttled
> per caller and window; a correct password is never throttled.
> `REQUIRE_AUTH` is forwarded to the backend container. The asset-detail
> finding-risk query is scoped to that asset's findings and bounded
> server-side. No feature, API, schema or auth behaviour changed beyond
> these five fixes. The Step 32 final audit passed.

## 1. What the product is (long-term vision)

A vendor-neutral security orchestration and incident-correlation platform that
integrates tools such as Nmap, Suricata, Zeek, Wazuh, Windows telemetry,
vulnerability scanners and firewall controls to:

1. Discover and maintain an inventory of authorized assets
2. Collect security events from multiple sources
3. Normalize events into a common model
4. Correlate events into incidents
5. Calculate contextual risk
6. Explain why an incident is risky
7. Recommend or execute policy-controlled defensive actions
8. Provide a unified dashboard
9. Maintain complete audit trails
10. Operate safely in monitoring and controlled automated-response modes

## 2. Build log (Steps 1–30)

Each entry below records the state **as of that step**, in the order the
steps were built. Where a later step changed something noted here, the later
step's section is authoritative — see §12 (Step 31) and §13 (Step 32). Steps
25–30 are recorded in the same list below.

Step 1 Implemented (unchanged):

- FastAPI backend with versioned API (`/api/v1`), liveness (`/health`),
  readiness with PostgreSQL check (`/ready`, `/health/db`) and `/version`
- Environment-based config, structured secret-redacting logging, consistent
  error envelope `{"error": {"code", "message"}}`
- React + TypeScript shell: sidebar/header/content, dashboard shows
  **live** backend/database/version/environment from the API
- Docker Compose: `db` (Postgres 16) → `backend` → `frontend` (nginx), healthchecks
- pytest + Vitest + ruff, all passing (see §9)
- README + `docs/architecture.md` distinguishing implemented vs planned

Step 2 Implemented (new — first security capability):

- `assets`, `discovered_services`, `scan_jobs` tables (migration
  `step2_asset_inventory`); one row per IP, service set replaced per scan
- Controlled Nmap scans: Pydantic `ScanRequest{target, scan_profile}` with
  allow-listed `quick`/`standard` profiles; exact argv built server-side;
  `shell=False`, per-profile timeouts, 8 MB output cap, minimal child env
- Strict target validation: single IPv4/IPv6 or CIDR ≤ 256 addresses;
  injection strings rejected with `INVALID_TARGET` (422)
- `GET /api/v1/network/nmap/status`, `POST/GET /api/v1/network/scans`,
  `GET /api/v1/assets*` (list/filter/paginate, summary, detail, services)
- Assets page (table + detail), Network page (Nmap status, authorized-only
  scan form, recent scans), dashboard inventory cards
- Nmap 7.95 installed in the backend image only (no privileged, no host net)

> **Authorized use only.** Scan exclusively systems/networks you own or are
> explicitly authorized to assess. The safe lab target is `127.0.0.1`. The
> platform never accepts raw Nmap flags, shell commands, or hostnames.

Step 3 Implemented (generic ingestion foundation):

- Canonical `SecurityEvent` (migration `step3_security_events`): severity
  enum (INFO→CRITICAL), source-type enum (NMAP/GENERIC/WINDOWS/DEFENDER/
  SURICATA/ZEEK/WAZUH/VULNERABILITY_SCANNER/FIREWALL — extension points,
  no adapters), UTC timestamps, nullable detail fields (never faked)
- `POST /api/v1/events` → validate → normalize → store → 201 (200 +
  existing row on `external_event_id` replay); `GET /api/v1/events`
  (severity/source/type/asset/time filters, pagination), detail, summary
- Raw payloads stored as JSON text, data-only, 64 KB cap (413 over);
  SHA-256 fingerprint over stable attrs (informational; never drops events)
- Events page (table, severity filter, detail with inert raw view, honest
  empty state) + dashboard event cards (total/critical/high/last-24h)

Step 4 Implemented (Suricata EVE adapter, first vendor source — kept):

- `services/suricata_adapter.py`: EVE `alert`/`dns`/`http`/`tls`/`flow`/
  `fileinfo` → generic envelope; unknown types accepted as
  `SURICATA_UNKNOWN`; missing `event_type` rejected (`INVALID_EVE` 422)
- Severity: Suricata 1→CRITICAL, 2→HIGH, 3→MEDIUM, 4→LOW; else INFO default
- Deterministic `external_event_id` (`suricata:<sha256(type|flow|time|sig…
  )>`); Step 3 triple deduplicates replays
- `POST /api/v1/events/ingest/suricata` (201/200) and `/batch` (≤100,
  accepted/duplicates/rejected counts + per-item errors, one bad event
  never crashes the batch); oversize → 413
- Synthetic fixtures in `backend/tests/fixtures/suricata/` (10 files);
  no real sensor, no privileged container, no host networking
- Events page source filter incl. SURICATA + "No Suricata events received."

Step 5 Implemented (Zeek adapter, second vendor source — kept):

- `services/zeek_adapter.py`: `conn`/`dns`/`http`/`ssl`/`x509`/`ssh`/
  `notice` → `ZEEK_*`; unknown types → `ZEEK_UNKNOWN`; missing
  `event_type` → `INVALID_ZEEK` 422. Record must declare `event_type`
  (raw Zeek logs don't self-identify — platform contract, documented).
- Field map: epoch-or-ISO `ts`→event_time, `uid`→identity/correlation,
  `id.orig_h`/`src`→source_ip, `id.resp_h`/`dst`→destination_ip, ports,
  `proto`, `service`/`host`/`method`→action (http)/`note`+`msg`→title/
  description (notice); vendor extras → `normalized_data.vendor`
- Severity: explicit integer 1–4 only (same platform table), else INFO —
  nothing invented
- Deterministic `external_event_id` (`zeek:<sha256(type|uid|ts|addrs|
  ports)>`, content-hash fallback without UID); Step 3 triple dedupes
- `POST /api/v1/events/ingest/zeek` (201/200) and `/batch` (≤100, same
  accepted/duplicates/rejected shape); oversize → 413
- Synthetic fixtures in `backend/tests/fixtures/zeek/` (9 files, no real
  sensor, no tailing, no privileged changes)
- Events page "No Zeek events received." empty state

Step 6 Implemented (Wazuh adapter, third vendor source — kept):

- `services/wazuh_adapter.py`: `alert`/`fim`/`auth`/`syscheck`/`sca`/
  `vulnerability`/`rootcheck`/`command` → `WAZUH_*`; unknown strings →
  `WAZUH_UNKNOWN`; missing `event_type` → `INVALID_WAZUH` 422. Record must
  declare `event_type` (raw manager output doesn't self-categorize).
- Field map: `timestamp`/`@timestamp` (ISO/epoch/epoch-ms, unparseable→now)
  →event_time; `agent.{id,name,ip}`→`normalized_data.agent`+hostname;
  `manager.name`, `rule.{id,level,description,groups,mitre}`,
  `decoder.{name,parent}`, `location`, `full_log`→namespaced sections;
  `data.srcip/dstip` (fallback top-level)→IP columns; ports→columns;
  `syscheck.*`→`fim`, `vulnerability.*`→`vulnerability`,
  auth fields→`authentication`; full record→`raw_event` untouched
- Severity from numeric `rule.level` only: 12–16→CRITICAL, 9–11→HIGH,
  5–8→MEDIUM, 1–4→LOW, else INFO (central threshold constants)
- Title: `rule.description` → first `full_log` line → decoder info →
  generic fallback
- Deterministic `external_event_id` (`wazuh:<sha256(type|alert_id|time|
  agent|rule|addrs)>`, content-hash fallback); Step 3 triple dedupes
- `POST /api/v1/events/ingest/wazuh` (201/200) and `/batch` (≤100, same
  accepted/duplicates/rejected shape); oversize → 413
- Synthetic fixtures in `backend/tests/fixtures/wazuh/` (10 files,
  TEST-NET only, no secrets); no manager install, no agent deployment,
  no privileged changes
- Events page "No Wazuh events received." empty state

Step 7 Implemented (Defender adapter, fourth vendor source — kept):

- `services/defender_adapter.py`: `alert`/`incident`/`malware`/
  `authentication`/`device`/`process` → `DEFENDER_*`; unknown strings →
  `DEFENDER_UNKNOWN`; missing `event_type` → `INVALID_DEFENDER` 422.
  Record must declare `event_type` (raw exports don't self-categorize).
- Field map: `timestamp`/`eventTime` (ISO/epoch s/epoch ms,
  unparseable→now) →event_time; `deviceId/deviceName/machineName`,
  `threatName`, `processName/processId/commandLine`, `fileName/fileHash`,
  `detectionSource`, `remediationStatus`, `category`, `status`,
  `url/domain`, IPs/ports, `user/account`→username; vendor extras →
  `normalized_data`; full record→`raw_event` untouched
- Severity: textual case-insensitive (critical/high/medium/low/
  informational/info); numeric 0–100 scores (>=80/50/20/1 bands);
  missing/malformed/unknown → INFO (central constants); never from
  title/description wording
- Title: `title`/`name` → `description` → `threatName` → generic fallback
- Deterministic `external_event_id` (`defender:<sha256(type|alert_id|
  time)>`, content-hash fallback); Step 3 triple dedupes
- `POST /api/v1/events/ingest/defender` (201/200) and `/batch` (≤100,
  same accepted/duplicates/rejected shape); oversize → 413
- Synthetic fixtures in `backend/tests/fixtures/defender/` (6 files,
  no credentials/secrets); no live agent, connectivity, or remediation
- Events page "No Defender events received." empty state

Step 8 Implemented (vulnerability findings — kept):

- `services/vulnerability_adapter.py`: scanner-style records →
  canonical `VULNERABILITY_FINDING` (stable single category; record must
  declare string `title`/`name`, else `INVALID_VULNERABILITY` 422)
- Field map: `title`/`name`→title; `affected_host`/`hostname`→hostname;
  `ip` (or `affected_host` when an IP literal)→destination_ip;
  `port`→destination_port; `protocol`, `service`, `product`/`version`,
  `evidence`, `solution`, `references`, `first_seen`/`last_seen`,
  `status`→namespaced `normalized_data`; full record→`raw_event`
- CVE: `cve`/`cves` uppercased, kept only if matching `CVE-YYYY-NNNN+`
  (non-matching stays in raw only, never presented as a finding)
- Severity precedence: explicit text (case-insensitive) → CVSS bands
  (9.0–10 CRITICAL, 7.0–8.9 HIGH, 4.0–6.9 MEDIUM, 0.1–3.9 LOW, 0 INFO)
  → INFO; never from title/description; no risk score calculated
- Deterministic `external_event_id` (`vuln:<sha256(scanner|finding|
  plugin|cves|host|port|proto)>`, content-hash fallback); Step 3 triple
  dedupes
- `POST /api/v1/events/ingest/vulnerabilities` (201/200) and `/batch`
  (≤100, same accepted/duplicates/rejected shape); oversize → 413
- Synthetic fixtures in `backend/tests/fixtures/vulnerabilities/` (10
  files, TEST-NET only, no secrets); no scanners run, no exploitation,
  no remediation, no firewall changes
- Vulnerabilities page (severity/CVE/CVSS/scanner/status table + detail
  with solution, severity filter, honest empty state)

Step 9 Implemented (deterministic correlation — kept):

- `correlations` + `correlation_evidence` tables (migration
  `step9_correlations`); deterministic `sha256("correlation:v1" |
  rule | sorted event ids)` identity; severity inherited as evidence
  maximum; fixed per-rule confidence; explanation names rule + pivot
- Rules (all bounded windows, documented): `multi-source-target`
  (≥2 sources, same dst IP, 60 min, conf 75), `vuln-exposure`
  (finding + touching activity, 24 h, conf 70), `repeated-source`
  (≥3 same-src incl. MEDIUM+, 15 min, conf 60)
- `POST /api/v1/correlations/recompute` (parameter-free, last 500
  events, idempotent upserts); `GET /correlations` (status/severity/
  rule filters, pagination), `GET /correlations/{id}` (evidence),
  `GET /correlations/{id}/attack-chain` (ordered nodes/edges, neutral
  "supported by"/"observed in" relations)
- Correlations page (table, severity filter, Recompute, evidence view
  with why-correlated + potential-attack-chain timeline, honest empty
  state); neutral wording everywhere — never claims compromise

Step 10 Implemented (deterministic risk scoring — kept):

- `risk_assessments` table (migration `step10_risk_assessments`);
  deterministic `sha256("risk-assessment:v1" | version | type | id)`
  identity (recompute updates in place; stale rows pruned)
- Formula v1.0.0 (central constants):
  `score = clamp(10 + severity_pts + signal_pts + recency_pts, 0, 100)`
  with severity INFO 0 / LOW 10 / MEDIUM 25 / HIGH 40 / CRITICAL 55;
  bands 80+ CRITICAL / 60+ HIGH / 40+ MEDIUM / 20+ LOW / else INFO
- Signals: vulnerability = CVSS→0–15 pts + known-asset 5 + 3/correlating
  correlation (cap 9); correlation = evidence 2 each (cap 10) +
  confidence//10; asset = open ports 2 each (cap 10) + findings 3 each
  (cap 12) + correlations 5 each (cap 10)
- Recency from newest contributing timestamp vs newest event_time in the
  dataset (never wall-clock): ≤7 d +10, ≤30 d +5, else +0
- `POST /api/v1/risk/recompute` (parameter-free, ≤1000 entities,
  deterministic id order), `GET /api/v1/risk` (entity/severity filters,
  score-desc with id tiebreak, pagination),
  `GET /api/v1/risk/{type}/{id}` (`INVALID_ENTITY_TYPE` 422,
  `RISK_NOT_FOUND` 404)
- Risk page (score table, severity filter, Recompute, factors +
  explanation detail, version + calculated time, honest empty state)

Step 11 Implemented (incident management — kept):

- `incidents` table (migration `step11_incidents`); deterministic
  `sha256("incident:v1" | correlation_id | risk_id or "")` identity
  (`INC-` + 12 hex key); repeat creation returns the existing row
- Open explicitly via `POST /api/v1/incidents {correlation_id,
  risk_assessment_id?}` (201 new / 200 replay); missing references →
  404 `REFERENCE_NOT_FOUND` (nothing manufactured)
- Severity from linked risk, else correlation (documented fallback);
  confidence from correlation; first/last_seen from correlation window;
  asset linked by correlation primary IP when known
- Explicit lifecycle only: OPEN→ACKNOWLEDGED/CLOSED,
  ACKNOWLEDGED→INVESTIGATING/CLOSED, INVESTIGATING→RESOLVED/CLOSED,
  RESOLVED→CLOSED, CLOSED terminal; violations → 422
  `INVALID_TRANSITION`; `PATCH /{id}` (status/title/description) and
  `PATCH /{id}/status`; list filters (status/severity), pagination,
  deterministic ordering
- Detail exposes `evidence_event_ids` (ordered original event IDs) +
  correlation/risk references — references, never payload copies
- Incidents page (key/title/severity/confidence/status/asset table,
  status+severity filters, detail with evidence, explicit status
  buttons, honest empty state); management-only disclaimer, zero
  response/remediation controls

Step 17 Implemented (new — incident detection & model foundation):

- Migration `step17_incidents` (additive): `incidents` gains
  `incident_type` (default OTHER), `risk_score` (nullable),
  `resolved_at` (nullable), `detection_reason`; new `incident_audits`
  (OPENED/EVIDENCE_ATTACHED/STATUS_CHANGED/UPDATED, actor/detail) and
  `incident_evidence` (correlation/event/vulnerability reference links
  with reasons, unique per incident/kind/id) tables
- Conservative detector (`services/incident_detection.py`, stored data
  only, no scanning/execution): qualifies finding-plus-activity
  (`vuln-exposure`), 3+ grouped events, or HIGH/CRITICAL severity —
  everything else is an explained skip; fixed rule→type map
  (VULNERABILITY_ACTIVITY / SUSPICIOUS_NETWORK_ACTIVITY /
  CORRELATED_SECURITY_EVENT / OTHER; AUTHENTICATION_ANOMALY,
  MALWARE_INDICATOR, POLICY_VIOLATION reserved); Step 11 identity
  reused so reprocessing is idempotent, wider windows/new links update
  with audit, `first_seen` never rewritten
- Risk/confidence: `risk_score` is the linked Step 10 assessment
  verbatim (NULL when unlinked — no second formula); confidence is
  correlation evidence strength, not compromise probability;
  `resolved_at` stamped on first RESOLVED/CLOSED entry
- `POST /api/v1/incidents/detect` (single or bulk, idempotent
  summary), `GET /{id}/evidence` (correlation + role-tagged events +
  related findings), `GET /{id}/timeline` (observation markers +
  audits + resolution), `GET /{id}/audit`, `POST /{id}/status` alias,
  `incident_type` list filter; existing routes/behaviors unchanged
- Incidents page: type/risk columns + type filter, Run detection
  button with result notice, detail with risk-vs-severity note,
  detection reason, role-tagged evidence, related findings,
  correlation explanation, timeline, audit history — neutral wording
  throughout ("investigation lead", never "hacked"/"confirmed")

Step 12 Implemented (controlled response & SOAR foundation — kept):

- `response_actions` + `response_audit` tables (migrations
  `step12_responses`, `step12b_response_status_length` — the latter
  widens status columns to VARCHAR(32) after PostgreSQL rejected the
  17-char `DRY_RUN_COMPLETED` in a VARCHAR(16); SQLite ignores the
  limit, which is why a column-width regression test was added)
- Closed action enum (ISOLATE_ASSET/BLOCK_IP/BLOCK_DOMAIN/
  DISABLE_ACCOUNT/QUARANTINE_ASSET/FIREWALL_RULE/REMEDIATION) and
  target enum (ASSET/IP/DOMAIN/ACCOUNT); IP targets validated as IP
  literals; `dry_run` forced true; policy version 1.0.0 persisted
  everywhere; approvals stamp `approved_at` + 7-day `expires_at`
  (no automatic expiry — no background processes exist)
- Lifecycle PROPOSED→APPROVED/REJECTED/CANCELLED/DRY_RUN_COMPLETED,
  DRY_RUN_COMPLETED→APPROVED/REJECTED/CANCELLED, APPROVED→CANCELLED,
  rest terminal; violations → 409 `INVALID_TRANSITION`
- Deterministic `sha256("response-action:v1" | incident | type |
  target | reference | requester)` identity; replays return the row
  unchanged (even if CLOSED); audit appends per event with actor,
  transition, policy version, microsecond timestamps
- `POST /api/v1/responses` (201/200), `GET /responses` (status/action/
  incident filters, pagination, deterministic order),
  `GET /responses/{id}` (+ audit history),
  `POST /{id}/approve|reject|cancel` (optional actor),
  `POST /{id}/dry-run` (pure SIMULATED preview,
  `would_execute: false`, records audit only)
- Response page (table, status filter, detail with audit + Dry Run +
  Approve/Reject/Cancel, "DRY RUN — NO ACTION EXECUTED" banners,
  honest empty state); zero execution controls of any kind

Step 18 Implemented (new — controlled response foundation):

- Migration `step18_response_foundation` (additive):
  `response_actions` gains `approved_by`, `started_at`,
  `completed_at`, `failure_reason`, `result_summary`; existing rows
  keep NULLs, Step 12/13 semantics unchanged
- Safe allow-list extension (REVIEW, COLLECT_EVIDENCE,
  MARK_FOR_INVESTIGATION, ACKNOWLEDGE, CLOSE) with `INCIDENT` targets
  bound to the proposal's own incident; the seven Step 12 types stay
  simulation-only and cannot take incident targets
- Lifecycle gains RUNNING → COMPLETED/FAILED (synchronous, no workers):
  APPROVED/DRY_RUN_COMPLETED → RUNNING; approval stamps `approved_by`
  once (no transition re-enters APPROVED); policy gains
  `ALLOW_SAFE_EXECUTION` for approved safe actions; everything else
  follows the existing policy/simulation path untouched
- Safe executor runs platform-record-only effects through the existing
  incident services (acknowledge/investigate/close via validated
  transitions; review/evidence-collection read and report); failures
  record FAILED + honest reason without leaking; both outcomes persist
  a `safe-record` execution row so replays return stored results
- `POST /api/v1/incidents/{id}/responses` (safe types only, 201/200) +
  `GET /api/v1/incidents/{id}/responses` (404 unknown incident);
  `POST /responses/{id}/execute` routes safe vs simulation by policy
  (409 bad lifecycle, 403 denial, 422 invalid)
- Incident detail gains a Controlled responses section (propose form,
  approve/reject/execute/cancel, approval/result/failure display);
  Response page gains new statuses, Execute for approved safe actions,
  and safe-execution record panels — neutral wording throughout
- No authentication infrastructure exists yet: `requested_by`/actor
  are operator-supplied labels recorded verbatim (existing convention)

Step 19 Implemented (new — controlled response adapter foundation):

- Typed contracts (`AdapterRequest`/`AdapterResult`/`AdapterEvidence`/
  `PreviewResponse`, all `extra=forbid`): adapter input built
  server-side from stored rows; results always `executed=false` /
  `simulated=true` with truthful simulation language
- Explicit registry (`SIMULATION`, `EVIDENCE_COLLECTION_SIMULATION`,
  `FIREWALL_SIMULATION`, `ISOLATION_SIMULATION` + legacy
  `simulation` for frozen Step 13 rows): static action→adapter map,
  unknown names → `KeyError` → structured error; no dynamic imports,
  no client-selectable executor, no `command` field anywhere (rejected
  422 by `extra=forbid`)
- Strict targets (+`HOSTNAME`: charset/length/scheme checks, never
  resolved or contacted); `POST /responses/{id}/preview` enforces
  policy (PROPOSED/REJECTED/CANCELLED/COMPLETED/FAILED → 403),
  validates target (422 `INVALID_TARGET`), returns what-would-happen
  with stored-reference evidence (COLLECT_EVIDENCE) + one
  `RESPONSE_PREVIEWED` audit row; execution paths byte-identical
- Response page: Preview Response button + adapter panel (adapter,
  would_execute, evidence, "SIMULATION ONLY — NO EXTERNAL SYSTEM
  MODIFIED"); no Block/Isolate/Kill/Disable buttons exist
- No migration: no new tables/columns (adapter names fit existing
  columns; preview persists no execution rows)

Step 20 Implemented (new — authentication + RBAC foundation):

- Migration `step20_auth` (additive): `users` (username unique,
  Argon2id hash, display name, active flag, JSON roles, login
  timestamps), `revoked_tokens` (logout denylist), `auth_audits`
  (append-only, never secrets)
- Closed roles ADMIN/SECURITY_ANALYST/OPERATOR/VIEWER with a central
  `ROLE_PERMISSIONS` map (19 permissions incl. `RUN_ANALYSIS` and
  `MANAGE_ASSETS/EVENTS/SCANS/VULNERABILITIES`); permissions derived,
  never stored; no `EXECUTE_ARBITRARY_COMMAND` exists by design
- JWT access tokens (HS256, deployment secret, 15 min, jti-denylisted
  on logout); generic login failures (no enumeration); `last_login_at`
  on success only; `/auth/login|/me|/logout` + `/auth/audit` +
  `/users` CRUD (bootstrap-only first ADMIN, last-admin guards)
- Per-endpoint server-side enforcement (health stays public; reads →
  `READ_*`; writes → manage/create/approve/execute permissions;
  audits → `VIEW_AUDIT`): 401 missing/invalid token, 403 missing
  permission, all in the standard envelope with audit rows
- Token identity drives security-sensitive actors (approver, executor,
  status/detection actors, `approved_by`); body `requested_by` labels
  preserved for compatibility and proposal identity; no admin bypass
- Login page + token wiring (localStorage, Authorization header);
  backend never trusts frontend roles/headers/params

Step 21 Implemented (new — asset discovery + controlled Nmap, discovery only):

- Additive profiles on the existing scan machinery: `DISCOVERY_PING`
  (ping sweep, `probes_ports=False`, 120 s timeout) and
  `DISCOVERY_TCP_COMMON` (fixed 19-port `-sT` set, 300 s); quick/
  standard untouched; profile names allow-listed server-side, unknown
  → 422, no flags/scripts/commands accepted anywhere
- Read-only `POST /network/scans/preview` (MANAGE_SCANS): validates
  target/profile/scope/availability and returns the plan (no argv, no
  scan, no assets); validation success never claims target safety
- Scope: `validate_target` honors configurable
  `discovery_max_addresses` (default 256, conservative); CIDR must
  additionally sit inside `SCAN_ALLOWED_NETWORKS` (loopback default);
  hostname/URL/shell-metacharacter/flag inputs rejected
- Normalization: deterministic IP-keyed upsert, `first_seen` kept,
  unknown fields never blank existing values; ping scans preserve
  previously observed services (`probes_ports` on the profile)
- Lifecycle/audit reuse `ScanJob` + `ScanAudit`
  (QUEUED≈proposed → RUNNING → COMPLETED/FAILED/CANCELLED with counts);
  RBAC reuses `READ_ASSETS`/`MANAGE_SCANS` (RBAC grant is the approval)
- Network page: discovery profile options, Preview discovery button +
  panel, scope/authorization wording; no command/flag/script inputs

Step 22 Implemented (new — vulnerability assessment foundation):

- Migration `step22_vuln_foundation` (additive): findings gain
  `scanner_version`/`detected_version`/`fixed_version` (nullable,
  missing stays missing); jobs gain `scanner` (LIVE vs MOCK on every
  row); `NOT_SEEN` fits existing columns
- Staged adapters (`configure`/`validate_context`/`execute`/`parse`)
  with static profile→adapter map + `KeyError` rejection, no dynamic
  imports: `fixture-scanner` (MOCK/TEST, unchanged) and `nmap-vuln`
  (LIVE, fixed `-sV` + `vuln and not intrusive` + `-oX -` over stored
  ports capped at 100, 600 s timeout, 8 MB cap, fixed env, no shell)
- `BASIC` (default intensity) / `STANDARD` (version-intensity 5) fixed
  profiles; nmap requires binary (503) + discovered services (422
  otherwise — open ports are never vulnerabilities by themselves);
  findings only from CVE-bearing script output, UNKNOWN severity,
  evidence excerpts, no invented CVEs/remediation
- Deterministic identity (scanner+finding+asset+service); `first_seen`
  kept; raw scanner severity preserved in `extra_data`; service-linked
  findings unseen by a rescan → `NOT_SEEN` (audited, never deleted);
  re-observation reopens; failed scans change nothing
- Same endpoints/RBAC/audit conventions (`READ_`/`MANAGE_VULNERABILITIES`,
  `VULNERABILITY_*` events); Vulnerabilities page gains Start
  assessment flow, LIVE/MOCK badges, version fields, NOT_SEEN status

Step 23 Implemented (new — telemetry ingestion foundation):

- Migration `step23_events` (additive): events gain `confidence`
  (nullable, unknown stays null), `occurrence_count` (default 1, bumped
  on idempotent replay), `last_seen_at`; new append-only
  `event_audits` (RECEIVED/NORMALIZED/DEDUPLICATED/REJECTED with actor,
  never secrets); per-event `GET /events/{id}/audit` reader
- Static `event_adapters` registry (SURICATA/ZEEK/WAZUH/DEFENDER, all
  FIXTURE mode; unknown keys → `KeyError` → 422; no dynamic imports);
  all adapter + generic paths share one audited orchestration helper
- Server-side asset correlation (destination/source IP, then hostname;
  existing links kept, bogus links dropped, no-match stays unresolved;
  never creates or overwrites inventory); responses carry
  `ingest_mode: FIXTURE`, occurrence counts, confidence
- Same RBAC (`READ_`/`MANAGE_EVENTS`, 401/403 + audit); same
  payload/batch limits; Events page shows fixture badges, unresolved
  assets, occurrences, and confidence

Step 24 Implemented (new — correlation + incident formation foundation):

- Configurable bounded window: `correlation_max_window_minutes`
  (default 1440, hard ceiling 7 days); effective window =
  min(rule window, cap); explanations state the effective window used
- Migration `step24_correlation` (additive): append-only
  `correlation_audits` (RUN_STARTED/MATCHED/RUN_COMPLETED with actor,
  never secrets); recompute threads the authenticated actor
- `GET /incidents/{id}/observations` (READ_INCIDENTS): typed
  observation links (correlation/event/vulnerability + reason +
  timestamp, dedup-proof) with per-kind counts; references only
- Detection reasons name actual pivots (asset IP/hostname, counts,
  rule); severity stays the evidence maximum; confidence stays
  rule-fixed correlation strength
- Arbitrary bodies on recompute → 422; Incidents page shows correlated
  observation counts; neutral language, no response/remediation controls

Step 25 Implemented (new — risk scoring & incident prioritization):

- `score_incident()` pure function (severity + 2/obs capped 10 + 3/vuln
  capped 9 + confidence//10 + recency; same 10-base/clamp family, min 10,
  max 104→100); unknown inputs score 0, never guessed; centralized
  `PRIORITY_BANDS` (P1≥80/P2≥60/P3≥40/P4)
- `incident` entity type joins recompute (bounded, deterministic order,
  prune-aware); `POST /risk/incidents/{id}/calculate` (MANAGE_INCIDENT,
  bodiless-guarded, 404 unknown) upserts one snapshot idempotently
- Migration `step25_risk` (additive): `risk_assessments.priority`
  (nullable, readers fall back to the stored score) + append-only
  `risk_audits` (creation + genuine changes only; actor, old→new,
  classification, reason; no secrets)
- Incident detail Advisory-risk panel (score/severity/priority/factors/
  version/explanation + Calculate/Recalculate; honest empty state) and
  priority in Risk detail; CALCULATED RISK wording, no response controls

Step 27 Implemented (new - controlled live Wazuh + Microsoft Defender
connector foundation):

- Shared HTTP layer (`http_connector.py`): destination allow-list built
  from settings only (`WAZUH_API_URL`, `DEFENDER_API_ENDPOINT`,
  `DEFENDER_AUTHORITY`), fixed timeout, hard response-size cap, 3xx
  treated as HTTP_ERROR (redirects never followed), safe GET-only
  retries on 429/503/timeout, structured error categories, response
  redaction (no secret value ever appears in an error, detail or audit)
- Wazuh client (Basic then JWT bearer kept in memory only, never logged
  or persisted) and Defender client (OAuth2 client-credentials token
  provider abstraction); health checks (`GET /manager/info`, Graph
  `$top=1`) and bounded pagination - Wazuh `limit/offset`, Defender
  `@odata.nextLink` re-validated against the allow-list on every hop
  with repeated-cursor detection - terminating COMPLETED / MAX_PAGES /
  MAX_EVENTS / REPEATED_CURSOR / MALFORMED_PAGINATION, `truncated`
  reported honestly, event timestamps/device fields taken only from
  real response fields (never guessed)
- 8-state `connector_state` vocabulary (NOT_CONFIGURED, CONFIGURED,
  CONNECTING, CONNECTED, AUTH_FAILED, UNAVAILABLE, RATE_LIMITED, ERROR)
  reported alongside the preserved Step 26 `mode`/`state` truth table;
  GET reads never perform network I/O; per-process runtime health
  (last check/poll, error category, events retrieved, latency)
- `POST /events/connectors/{source}/check` (MANAGE_EVENTS, bodiless)
  runs one audited check; polls dispatch through the shared client into
  the Step 23 registry, then normalize, dedupe, persist; audits
  CHECK_STARTED / CONNECTED / AUTH_FAILED / UNAVAILABLE / RATE_LIMITED /
  ERROR / POLL_STARTED / POLL_COMPLETED / POLL_FAILED with actor and no
  secrets; Step 26 tests byte-unchanged, backend 445 -> 470 passed
  (27 new mocked-HTTP tests, no live external service required)
- Events page: `connector_state` badges, Last check column, Check now
  for every source and Poll now only when a file path or API
  credentials are configured; no remediation, isolation, streaming or
  scheduled jobs; `LIVE EXTERNAL CONNECTIVITY: NOT VERIFIED - NO
  CONFIGURED EXTERNAL SERVICE` remains true by default

Step 26 Implemented (new — live event connector foundation):

- Staged connector lifecycle (configure → validate → health → bounded
  file fetch → normalize → dedupe → persist → audit) over the static
  Step 23 adapter registry; unknown sources → KeyError → 422; no
  dynamic imports, no subprocess, no network calls, no shell
- Env-driven config (empty = unconfigured; presence-only in responses,
  never secret values); truthful states FIXTURE/LIVE × CONNECTED/
  UNAVAILABLE/INVALID_CONFIGURATION; Wazuh/Defender report UNAVAILABLE
  (no live calls in Step 26, never fake CONNECTED)
- Bounded file poll (≤100 lines, per-line errors, truncation flag)
  through the shared audited ingest pipeline (dedup + occurrence
  accounting); no client-supplied paths; MANAGE_EVENTS to poll
- Events page Connectors panel (badges, details, Poll now + summary);
  no block/isolate/kill/remediate controls

Step 28 Implemented (new — bounded, audited ingestion pipeline):

- Migration `step28_ingestion` (additive): per-source
  `ingestion_checkpoints` (source key, sanitized cursor, byte/line
  counters, event/batch counters, timestamps) behind
  `services/checkpoints.py` (secret-like keys and values refused,
  scalars only, ≤4096-byte cursor; the sanitized cursor is stored, shown
  only to READ_EVENTS readers and never written to application logs)
- Bounded ingestion pipeline (`services/ingestion.py`): operator-driven
  `poll_source()` orchestration with audited run lifecycle
  (INGESTION_STARTED / REPLAY / BATCH_STARTED / BATCH_COMPLETED /
  BATCH_FAILED / CHECKPOINT_ADVANCED / CHECKPOINT_REJECTED /
  BACKPRESSURE), one fully committed batch at a time
  (`INGESTION_MAX_BATCH_SIZE`, default 50), bounded `BoundedQueue`
  (`INGESTION_QUEUE_MAX`, default 500, REJECT_NEW overflow) and bounded
  transient retries (timeout/connection-error only, linear backoff,
  `INGESTION_RETRY_*`; 401/403 never retried)
- Replay/recovery semantics: the checkpoint advances only after a fully
  committed batch — failed or backpressure-limited runs re-read the
  window and rely on dedup; `?replay=true` re-reads idempotently
  (audited INGESTION_REPLAY, no duplicates, no new checkpoint advance)
- File-state detection (always on): rotation, truncation and invalid
  offset restart the stream from byte 0 with an audited
  `INGESTION_ROTATION_DETECTED`; byte resume is opt-in
  (`CONNECTOR_FILE_RESUME`, default false)
- Streaming architecture as a bounded foundation, NOT ENABLED:
  `services/ingestion_stream.py` (connector stream protocol, bounded
  poll stream, poll worker) refuses to start —
  `STREAMING_ENABLED=false`, no background threads, timers or
  scheduled polling anywhere in the codebase
- API: `GET /events/ingestion/status` (pipeline stages, limits, queue,
  streaming state, per-source counters) and
  `GET /events/ingestion/checkpoints` (sanitized-cursor provenance), both
  READ_EVENTS; poll responses gain `batches`, `queue_dropped` and
  `checkpoint_advanced`; a failed batch returns 422 `INGESTION_FAILED`
  and leaves the checkpoint untouched
- Events page: Ingestion pipeline panel (run scope, verified state,
  stored/repeat/queue-drop counters, batch and queue bounds, streaming
  state, checkpoint provenance, honest unavailable   state); Step 26/27
  tests byte-unchanged, backend 470 → 496 passed (26 new tests),
  frontend 72 → 78 passed (6 new tests); no live external connectivity
  is claimed — `LIVE EXTERNAL CONNECTIVITY: NOT VERIFIED - NO
  CONFIGURED EXTERNAL SERVICE` remains true by default

Step 29 Implemented (new — deterministic incident intelligence):

- Rule model with `enabled`/`conditions`: every Step 24/29 rule can be
  disabled server-side (`CORRELATION_DISABLED_RULES` CSV or per-run
  defaults); disabled rules never evaluate and produce no
  relationships, and enabled rules keep their conditions intact
- Eight analysis rules over a bounded, newest-first slice of stored
  events (`CORRELATION_MAX_EVENTS_PER_OPERATION`, default 200): stored
  asset/user/indicator entity pivots, temporal auth chains (a break in
  identity ends the chain), cross-source observation groups within the
  group window, same-entity source→target pairs, repeated sources,
  vulnerability links (asset required), and multi-source pivots — each
  a pure documented predicate with a fixed catalog confidence
  (90→45); the rule catalog is data, never machine learning
- Deterministic bounded engine (`services/incident_analysis.py`):
  upsert + prune under `CORRELATION_RELATIONSHIP_MAX` /
  `CORRELATION_RELATIONSHIP_EVIDENCE_MAX`, writing
  `incident_relationships` through additive migration
  `step29_intelligence`; audits `INCIDENT_RECALCULATED` and
  `INCIDENT_CORRELATED` (actor, rule, bounds — no secrets, no event
  payloads)
- Confidence labels are fixed mappings — DIRECT ≥85 / STRONG ≥70 /
  MODERATE ≥55 / WEAK <55 — exposed on evidence, relationships and
  correlation summaries as analysis strength, never compromise
  probability; relationships reference existing ids only and no asset,
  user or identity is ever invented
- API: `GET /incidents/{id}/relationships` (READ_INCIDENTS, rule/limit/
  offset filters, 422 `INVALID_FILTER`, limit ≤200) and
  `POST /incidents/{id}/recalculate` (MANAGE_INCIDENT, bodiless — any
  body is 422 `INVALID_REQUEST`, unknown incident 404) returning
  deterministic created/refreshed/stored counts; evidence and timeline
  gain bounded overview fields (`CORRELATION_EVIDENCE_MAX` /
  `CORRELATION_TIMELINE_MAX_ENTRIES`, `truncated` flag, first/last
  observed, entities, affected assets, source distribution,
  correlation rules); timeline entries carry entity, explanation and
  the linked event id
- Risk integration stays informational: `relationship_count` joins the
  stored factor snapshot (score formula unchanged — same v1.0.0)
- Incidents page: relationship analysis panel (rule ids, confidence
  labels, window, explanation, stored-evidence counts, Recalculate
  analysis button, honest empty state), evidence overview with
  original-event links (`/events?event=…` deep links), correlation-rule
  list, event-linked timeline entries; neutral wording — "not a
  machine-learning prediction", no AI language anywhere
- Step 24/25 pins byte-unchanged, backend 496 → 519 passed (23 new
  tests), frontend 78 → 87 passed (9 new tests); incident merge/split
  (spec A10) explicitly NOT implemented; no scheduler, no automatic
  scoring, no client-supplied rules or risk values

Step 30 Implemented (new — controlled defensive response & response
governance):

- **IMPLEMENTED** — a governed action layer between detection/correlation/
  risk and any authorized action, so the platform can never move silently
  from detection to response. Six allow-listed controlled action types:
  `BLOCK_INDICATOR`, `DISABLE_INDICATOR_BLOCK`, `ISOLATE_ENDPOINT`,
  `RELEASE_ENDPOINT`, `DISABLE_ACCOUNT`, `ENABLE_ACCOUNT`. Each is bound
  to the target types it may address (`ACTION_TARGET_TYPES`), so an
  account action can never be pointed at an IP and vice versa
- **Targets must be evidenced, not asserted** — a request is accepted
  only if the target appears in the incident's *stored* evidence (the
  correlation evidence events, the incident evidence links, and the asset
  inventory), recorded server-side as `target_evidence` (bounded to 20
  event ids). An unjustified target is rejected with
  `TARGET_NOT_SUPPORTED` and audited as `RESPONSE_TARGET_REJECTED`;
  nothing is invented. Indicator hashes are reported as unsupported
  because Steps 1–29 store no hash field
- **Human approval is structural** — a request is created in
  `PENDING_APPROVAL` and waits for a *different* operator to approve; the
  role map keeps `APPROVE_RESPONSE` out of `SECURITY_ANALYST`, and
  `RESPONSE_ALLOW_SELF_APPROVAL=false` (the default) blocks self-approval
  by any identity. Approval stamps the approver once; it never extends
  the original expiry window
- **Bounded expiry, no permanent actions** — `expires_at` is set at
  request time from `RESPONSE_DEFAULT_TTL_MINUTES`, clamped to
  `RESPONSE_MAX_TTL_MINUTES` (an over-long request is clamped, not
  honoured). Expiry is enforced on the read path (there is no scheduler)
  and audited as `RESPONSE_EXPIRED`; an expired request or approval can
  never be executed
- **Provider registry (`services/response_providers.py`)** — a separate
  registry from the Step 13/19 simulation adapters. Two entries: `MOCK`
  (records a platform-side step and returns a deterministic prior-state
  reference) and `NOT_CONFIGURED` (refuses everything with an explicit
  reason). The module imports no `subprocess`/`os`/`socket`/`requests`/
  `httpx`/`urllib`, so a provider *cannot* run a command, open a socket,
  or make an HTTP call; `get_provider` only resolves server-side names
- **Dry run is a first-class capability** — every provider implements
  `validate_target`, `preview_action`, `execute_action`,
  `rollback_action`, `get_action_status`. `POST
  /responses/{id}/provider-preview` returns `executed: false` and an
  explanation stating no firewall/endpoint/account/cloud system was
  contacted
- **Rollback is explicit and honest** — only a completed action can be
  rolled back, only with `ROLLBACK_RESPONSE`, and only through
  `response_rollbacks` (UNIQUE `action_id`, so at most one). When the
  provider recorded no prior state, the record is `UNSUPPORTED` with an
  explanation naming the expected inverse action — never a fabricated
  compensating action
- **Idempotency and races** — deterministic request identity
  (`response-action:v1`) and execution identity
  (`response-execution:v1`, UNIQUE `action_id`); a repeated execute
  replays the stored row (200) instead of acting twice, and a rolled-back
  action is refused (409) rather than replayed as if still standing.
  State changes take a row lock and re-check state inside the
  transaction
- **Policy is deterministic and read-only** — `evaluate_policy` returns
  one of `NOT_ALLOWED` / `DRY_RUN_ONLY` / `APPROVAL_REQUIRED` /
  `ALLOWED_WITH_APPROVAL` with a stated reason. Step 25 risk score and
  priority are read for *reporting only*: a high-risk incident never
  creates, approves, or executes anything
- **Recommendations are deterministic** —
  `GET /incidents/{id}/response-recommendations` lists actions the stored
  evidence makes available, each labelled `requires_approval: true` and
  `automatic: false`. No machine learning, no "AI recommends" wording
- **RBAC** — new `REQUEST_RESPONSE` and `CANCEL_RESPONSE` (analyst+) and
  `EXECUTE_RESPONSE` / `ROLLBACK_RESPONSE` (operator+); `READ_RESPONSES`
  unchanged. The server is authoritative for action type, target,
  provider, policy, approval, state, and expiry; every request schema
  sets `extra="forbid"`, so `command`, `provider`, `policy_decision`,
  `status`, `approved_by`, and `risk_score` are all 422
- **Audit** — thirteen new events in the existing append-only
  `response_audit` table (`RESPONSE_REQUESTED`,
  `RESPONSE_APPROVAL_REQUIRED`, `RESPONSE_APPROVED`,
  `RESPONSE_REJECTED`, `RESPONSE_CANCELLED`, `RESPONSE_EXPIRED`,
  `RESPONSE_EXECUTION_STARTED`, `RESPONSE_EXECUTION_COMPLETED`,
  `RESPONSE_EXECUTION_FAILED`, `RESPONSE_ROLLBACK_STARTED`,
  `RESPONSE_ROLLBACK_COMPLETED`, `RESPONSE_DRY_RUN`,
  `RESPONSE_TARGET_REJECTED`) — actor, transition, policy version; no
  passwords, tokens, keys, headers, or cookies
- **UI** — a separate "Controlled defensive responses" card on the
  Response page (state, approval, provider, expiry, target-evidence
  count, policy verdict, provider dry run, rollback record) and a
  "Recommended defensive responses" panel on the incident page. Execute
  and Roll back controls appear only in the states that permit them
- **NOT CONFIGURED / NOT IMPLEMENTED** — there is **no** real Microsoft
  Defender, Wazuh, firewall, endpoint-management, or cloud provider. The
  interface and registry names exist; the capability does not, and the
  `NOT_CONFIGURED` provider says so. `RESPONSE_PROVIDER` defaults to
  `MOCK`. Also not implemented: autonomous response, response triggered
  by risk score, permanent blocks, rollback against a real system, and
  per-action rate limiting beyond the stored-state guards
- Step 1–29 pins preserved: backend 519 → 565 passed (46 new tests),
  frontend 87 → 96 passed (9 new tests); the only pre-existing assertion
  changed is the Step 29 migration test, which now pins that
  `step29_intelligence` is still in the chain and that `step30` is purely
  additive on top of it


Step 13 Implemented (controlled execution architecture — kept):

- `response_executions` table (migration `step13_response_execution`;
  one row per action, deterministic `sha256("response-execution:v1" |
  action_id)`) + `execution_status` column on proposals
- `ResponseExecutor` interface + `SimulationResponseExecutor` only:
  pure function of the stored row, always `would_execute: false` /
  `SIMULATED`; explicit `EXECUTORS` allowlist, server-selected
- Deterministic policy (`ALLOW_SIMULATION` / `REQUIRE_APPROVAL` /
  `DENY`, policy 1.0.0): only approved+previewed proposals may run;
  denials audited as `EXECUTION_DENIED` without state change
- `POST /api/v1/responses/{id}/execute` (201 first run / 200 byte-
  identical replay; 404 unknown; 403 policy denial); persists the
  result, sets `READY_FOR_EXECUTION` + `SIMULATED`, audits
  `EXECUTION_REQUESTED` + `EXECUTION_COMPLETED`; lifecycle extended
  with APPROVED→DRY_RUN_COMPLETED (preview edge)
- Response page: Execute Simulation button (previewed proposals only),
  simulation record panel ("SIMULATION ONLY — NO REAL ACTION
  EXECUTED"), execution shown in detail; zero real-action controls

Step 14 Implemented (authorized Nmap discovery hardening — kept):

- Explicit authorization scope: `SCAN_ALLOWED_NETWORKS` (CIDR allow-list,
  loopback-only by default, fail-closed); well-formed but out-of-scope
  targets → 403 `TARGET_NOT_AUTHORIZED` (format errors stay 422);
  CIDR targets must be fully contained — scope never silently expanded
- `POST /api/v1/network/scans` accepts `requested_by` (operator label);
  jobs record `scan_type`, `requested_by`, `result_summary`
  ("N hosts, M ports"); full audit trail (`SCAN_REQUESTED/STARTED/
  COMPLETED/FAILED/CANCELLED`) embedded in scan responses
- `POST /api/v1/network/scans/{id}/cancel` — queued-only best-effort
  cancellation (running scans report 409 `SCAN_NOT_CANCELLABLE`)
- Assets carry `asset_type` (UNKNOWN unless determined — never guessed),
  `discovery_source`, `discovery_scan_id`; services carry
  `discovery_scan_id`; upserts never blank existing provenance
- Migration `step14_scan_hardening` (additive columns + `scan_audit`
  table); Network page (scope warning, actor input, cancel button,
  requested-by column), Assets page (Type/Source columns)

Step 15 Implemented (vulnerability assessment, fixture-backed — kept):

- `vulnerabilities` + `vulnerability_audits` tables (migration
  `step15_vulnerabilities`); `scan_jobs` gains asset link + wider
  profile column; deterministic `sha256("vulnerability:v1" | scanner
  | finding | asset | service)` identity; repeats refresh instead of
  duplicating; absence never auto-resolves
- `VulnerabilityScanner` interface + `FixtureVulnerabilityScanner`
  only: catalog matches over stored services (unknown ports yield
  nothing); BASELINE (asset note included) vs SERVICE profiles;
  server-selected, no client flags/paths/commands
- Normalized findings: stable `VULNERABILITY_FINDING` type, CVE
  uppercased/pattern-gated/deduped, CVSS validated 0–10, severity
  text→canonical else UNKNOWN, unknown input fields preserved in
  `extra_data`, raw full record NOT stored as event (findings reference
  asset/service rows instead)
- `POST /api/v1/vulnerability-scans {asset_id|target, profile}`
  (exactly-one-of, 202; 404 unknown asset, 403 out-of-scope, 422
  malformed); `GET` scan list/detail with audit;
  `GET /api/v1/vulnerabilities` (severity/status/asset/scanner
  filters, pagination), detail (+ audit),
  `GET /assets/{id}/vulnerabilities`,
  `POST /vulnerabilities/{id}/status` (explicit transitions only,
  violations → 409)
- Vulnerabilities page (severity/CVE/CVSS/scanner/status table +
  detail with evidence/solution/audit + status buttons, severity+
  status filters, honest empty state); scans stay API-driven in
  Step 15 — no scan form, no remediation controls

Step 16 Implemented (new — vulnerability risk correlation, analysis only):

- `services/vuln_correlation.py`: derived links (finding↔asset via FK,
  finding↔service via FK, finding↔events via shared asset IP/hostname,
  finding↔incidents via correlation evidence containing a related
  event); every link carries reasons, absence yields explained empties
- Risk engine extended (no existing branch touched): new
  `vuln_finding` entity type scored by the same v1.0.0 formula
  (severity + CVSS + known-asset + covering-correlations + recency);
  recompute remains deterministic and idempotent
- `GET /api/v1/vulnerabilities/{id}/risk` (404 unscored/missing),
  `GET /api/v1/vulnerabilities/{id}/correlations` (events + incidents
  + reasons), `GET /api/v1/assets/{id}/vuln-risk` (counts, highest
  severity/CVSS, aggregate = max finding score, level, timestamp;
  honest zeros when empty)
- Vulnerabilities detail shows risk score vs finding severity,
  explanation, calculation time, correlated records, and unscored/
  unlinked empty states

Explicitly **not** implemented: AI/ML, SOAR actions, real response
execution, blocking, auth.

## 3. Architecture

```text
Frontend → API (/api/v1) → Services → Database
```

Details: [`docs/architecture.md`](docs/architecture.md). Future pipeline
(collectors → normalization → event bus → correlation → risk → response →
dashboard/audit) is documented there but **not built**.

## 4. Tech stack

| Layer | Choice |
|---|---|
| Backend | Python 3.13, FastAPI 0.116.1, Pydantic 2.11.7, SQLAlchemy 2.0.43, psycopg 3.2.9, Alembic 1.16.5 |
| Frontend | React 18, TypeScript 5, Vite 6, react-router-dom 6, Vitest 2 |
| Infra | Docker, Docker Compose, PostgreSQL 16, nginx |
| Tests | pytest + httpx TestClient; Vitest + Testing Library + jsdom |

## 5. Repository structure

```text
backend/
  app/
    api/v1/endpoints/  # assets, events, network, correlations, risk, incidents,
                       # responses, vulnerabilities, ingestion, connectors,
                       # auth, users, overview, health
    api/v2/endpoints/  # read-only response audit history (Step 42A)
    core/              # config, logging, errors, ratelimit, request_context
    database/          # engine/session, Base
    models/            # assets, events, scans, correlations, incidents, risk,
                       # responses, vulnerabilities, ingestion, auth
    schemas/           # request/response schemas per domain
    services/          # scan, event, correlation, incident, risk, response
                       # governance, connectors, ingestion, vulnerability
    utils/             # pure helpers (currently empty)
    main.py            # app factory + lifespan
  tests/               # pytest suite (SQLite-isolated); migration checks
  alembic/             # env.py + versions/ (head: step41_response_rejection_reason)
  requirements.txt     # pinned
  Dockerfile
frontend/
  src/
    components/        # layout/ (Sidebar, Header, StatusBadge), incidents/
    context/ hooks/ layouts/ services/ styles/ types/
    pages/             # Dashboard, Assets, AssetWorkspace, Events, AlertTriage,
                       # Correlations, Risk, RiskPrioritization, Incidents,
                       # Network, Vulnerabilities, Response, ResponseCenter,
                       # Login + a Settings placeholder
  Dockerfile + nginx.conf
docs/architecture.md
scripts/smoke_check.py    # read-only HTTP smoke test
scripts/verify_runtime.py # deployment verification harness
docker-compose.yml  .env.example  README.md
```

## 6. Run locally (backend dev, without Docker)

```powershell
Copy-Item .env.example .env
pip install -r backend/requirements.txt
# needs PostgreSQL; or run tests (SQLite-isolated, no DB needed):
python -m pytest backend/tests -v
# start API (from backend/):
uvicorn app.main:app --reload --port 8000
# Frontend needs Node 20+: cd frontend; npm install; npm run dev
# (vite dev binds 127.0.0.1 only — no firewall exception needed)
```

## 7. Run with Docker Compose

```powershell
Copy-Item .env.example .env
# set strong POSTGRES_PASSWORD + SECRET_KEY in .env, then:
docker compose up --build -d
# apply migrations inside the backend container (first domain migration):
docker compose exec backend alembic upgrade head
# Frontend: http://localhost:5173   Backend: http://localhost:8000/api/v1/health
# Authorized lab scan (your own container loopback only):
#   POST /api/v1/network/scans {"target":"127.0.0.1","scan_profile":"quick"}
docker compose down
```

Compose chain: PostgreSQL starts → backend starts (waits healthy) →
frontend starts (waits backend healthy). PostgreSQL's host port is bound to
`127.0.0.1` only (local-dev access for migrations/psql); inter-service
traffic stays on the Compose network. Health endpoints:

- `GET /api/v1/health` → `{"status":"ok", ...}` (no DB touch)
- `GET /api/v1/ready` → `200 {"status":"ready","checks":{"database":"up"}}`
  or `503 {"status":"not_ready",...}`
- `GET /api/v1/version` → app/version/environment

## 8. Environment configuration

See [`.env.example`](.env.example). Minimum keys: `APP_NAME`, `ENVIRONMENT`,
`DEBUG`, `API_HOST`, `API_PORT`, `DATABASE_URL` (or `POSTGRES_*`),
`LOG_LEVEL`, `SECRET_KEY`, `BACKEND_CORS_ORIGINS` (backend default allow-list:
`http://localhost:5173`, `http://localhost:3000`, `http://localhost`).
Production refuses placeholder secrets / `DEBUG=true` at startup.

## 9. Tests

```powershell
python -m pytest backend/tests -v        # 1131 passed, 14 skipped (Steps 1–64)
cd backend; python -m ruff check app tests # 2 pre-existing findings only (note in section 28)
cd frontend; npm install; npm test       # 246 passed across 39 files (Node 26; flag in section 28)
npm run build                            # tsc + vite build, exit 0
python scripts/smoke_check.py --base-url http://localhost:8000
python scripts/verify_runtime.py --database-url ...   # deployment harness (needs the compose stack; see section 28)
```

Backend tests cover all steps: Step 1 (startup, health/version,
readiness up + 503, 404 envelope, secret leakage, prod-config guards);
Step 2 (target validation incl. injection corpus, XML parser incl.
malformed input, inventory upsert incl. rescan idempotency, scan API
lifecycle, subprocess `shell=False` + exact argv proof); Steps 3–8
(envelope validation, filters/pagination, idempotent replays, adapter
mappings incl. severity/CVE/timestamp edge cases, injection-as-data,
oversize 413, batch bounds/partial failure); Step 9 (rule match/
non-match, window boundaries, determinism, attack-chain order);
Step 10 (score boundaries/clamp, determinism sans timestamps);
Step 11 (lifecycle, transitions, dedup, evidence refs, migration);
Step 12 (proposal lifecycle incl. 409s, dry-run purity, simulation
idempotency, audit order, AST proofs); Step 14 (scope allow/deny incl.
CIDR containment + version isolation, cancel semantics, audit trail,
provenance fields); Step 26 (connector truth table, poll RBAC, AST
security proof, audit secret hygiene); Step 27 (mocked-HTTP allow-list,
redirect refusal, response-size cap, retry/timeout categories, Wazuh and
Defender check outcomes + bounded pagination terminations,
`connector_state` vocabulary, check/poll RBAC + audit secret hygiene);
Step 28 (bounded batches, queue backpressure with held checkpoints,
replay idempotency, transient-only retry budget, auth failures never
retried, rotation/truncation restart, checkpoint secret refusal and
sanitization, failed-batch 422 with no checkpoint advance, ingestion
audit vocabulary bounds, streaming explicitly not started, status/
checkpoint RBAC, no secret payloads; frontend: ingestion panel with
server-shaped guards, backpressure/held-checkpoint notice, fallback
state).
Step 29 (enabled/disabled rules with conditions preserved, temporal
chains with identity-break termination, cross-source groups inside the
window, same-entity pairs, repeated sources, vuln links requiring an
asset, multi-source pivots, disabled-rule and bounded-slice early
exits, deterministic upsert/prune with relationship/evidence/timeline
caps and truncation flags, confidence-label mapping,
relationships/recalculate RBAC + body guards, deterministic
recalculate counts, `INCIDENT_RECALCULATED`/`INCIDENT_CORRELATED`
audit vocabulary, risk `relationship_count` factor without score
change, migration `step29_intelligence` head; frontend: relationship
analysis panel with neutral wording, evidence overview, original-event
links, `?event=` deep links, recalculation notice, hidden-section
guards).
Frontend tests cover every page (render, filters,
forms, detail views, empty/error states) plus live-health and offline
degradation. No tests assert trivial constants; all exercise real behavior.

## 10. Current limitations

- Authentication and authorization **are implemented** (Step 20): Argon2id
  password hashing, short-lived JWT bearer tokens, server-side revocation,
  role-based permissions on every application route, and append-only
  authentication/audit records. `POST /api/v1/users` permits creating the
  first `ADMIN` only while the user table is empty; `REQUIRE_AUTH=true`
  disables that bootstrap path entirely (see §12.1 and §13.4). An
  unauthenticated caller receives 401/403 and never reaches application
  logic. Scan scope is *additionally* enforced by allow-list (fail-closed).
- Background scans run in-process (`BackgroundTasks`): fine for occasional
  inventory scans, not for concurrent/heavy scan volume (a job queue belongs
  to a later stage if needed).
- Scan scope is capped (single IP or CIDR ≤ 256 addresses, inside
  `SCAN_ALLOWED_NETWORKS`) by design; queued-only cancellation (running
  scans cannot be stopped).
- No event bus, no live sensor/tailing integrations beyond submitted
  records, no risk beyond v1.0.0 formula, no automated response of any kind.
- Connector HTTP is operator-initiated only (check/poll), allow-listed
  to configured hosts with fixed timeout/size/page/event bounds and no
  redirects. Ingestion is equally bounded and operator-driven (fixed
  batch and queue caps, transient-only retries, checkpoint advance only
  after a committed batch); streaming is architected as a foundation but
  explicitly disabled (`STREAMING_ENABLED=false`) with no background
  threads, timers or scheduled polling. With no external service
  configured, `LIVE EXTERNAL CONNECTIVITY: NOT VERIFIED - NO
  CONFIGURED EXTERNAL SERVICE`.
- Incident intelligence (Step 29) is rule-bound and operator-initiated
  only: fixed catalog with server-side enable/disable, bounded windows
  and per-operation caps, fixed confidence labels — no AI/ML, no
  automatic recalculation, no client-supplied rules or risk values, and
  no incident merge/split (explicitly not implemented). Relationships
  show related stored records; they never prove compromise.

## 11. Development status

Steps 1–64 are complete, including the Step 32 final audit. The items once
listed here as candidates — authentication, users and audit-log tables —
were implemented in Step 20 (see §2, Step 20). Event ingestion and
normalization contracts followed in Step 3.

Later stages through Step 64 have since been delivered. Security rules still in force: no shell
execution endpoints, no automated blocking, no autonomous response, and no
further scanner or live-connector integrations until they are explicitly
designed and reviewed. With no external service configured, live
Wazuh/Defender connectivity is not verified (see §12.9).

## 12. Hardening, operations and production readiness (Step 31)

Step 31 changes no feature and removes no safety control. It hardens what
already exists. Everything below is **IMPLEMENTED and verified** unless
it is marked otherwise.

### 12.1 Configuration requirements

| Variable | Default | Production behaviour |
|---|---|---|
| `ENV` / `ENVIRONMENT` | `development` | Closed vocabulary `development\|test\|staging\|production`; an unknown value is **rejected at parse time**, not coerced |
| `DEBUG` | `false` | Must be `false` or startup fails |
| `SECRET_KEY` | `CHANGE_ME_dev_only` | Placeholder **or** shorter than 32 characters fails startup; the message never echoes the value |
| `DATABASE_URL` | dev DSN | A `changeme` password fails startup; the DSN is never echoed |
| `BACKEND_CORS_ORIGINS` | localhost dev origins | Must be non-empty and must not consist solely of the development origins; a wildcard is rejected in **every** environment |
| `TRUSTED_HOSTS` | empty | Optional. When set, `TrustedHostMiddleware` validates the `Host` header. A wildcard is rejected |
| `MAX_REQUEST_BYTES` | `1048576` | `0` is rejected in production (it would disable the body cap) |

`ENV=production` additionally disables `/docs`, `/redoc` and
`/openapi.json`, and enables HSTS. Configuration errors name the variable
to fix and never include the offending value.

### 12.2 Transport hardening

- `RequestContextMiddleware` — mints a sanitised correlation id per
  request, publishes it for audit rows and log lines, echoes it as
  `X-Request-ID`, and logs one access line (method, path, status,
  duration). An inbound `X-Request-ID` is accepted only if it is
  alphanumeric/dash and ≤64 chars, so a caller cannot inject newlines
  into logs.
- `SecurityHeadersMiddleware` — `X-Content-Type-Options: nosniff`,
  `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
  `Cross-Origin-Resource-Policy`, `Permissions-Policy`, a strict
  `Content-Security-Policy` (`default-src 'none'; frame-ancestors
  'none'`) and `Cache-Control: no-store` on `/api/*`. HSTS only in
  production (it would poison a browser's localhost HSTS cache in dev).
- `BodySizeLimitMiddleware` — refuses an over-sized declared body with
  `413 PAYLOAD_TOO_LARGE` **before** it is buffered. This is defence in
  depth: the per-field ingest caps (`MAX_RAW_BYTES`) remain the
  authoritative content limits.
- nginx serves the SPA with `server_tokens off`, the same baseline
  headers, `client_max_body_size 1m`, `Cache-Control: no-cache` on
  `index.html` and immutable caching on fingerprinted `/assets/`.

### 12.3 Rate limiting (resource protection, not authorization)

A deterministic **fixed-window** counter, in-process, bounded to
`RATE_LIMIT_MAX_BUCKETS` LRU buckets, with **no background worker, timer
or scheduler**. Each budgeted operation is a `rate_limit(operation, setting)`
dependency listed last in its route's dependency list; the single source of
truth is those calls in `app/api/v1/endpoints/`.

Currently enforced (11 operations, 6 settings):

| Operation key | Setting | Route (all under `/api/v1`) |
|---|---|---|
| `correlation_recompute` | `RATE_LIMIT_RECOMPUTE` | `POST /correlations/recompute` |
| `incident_recalculate` | `RATE_LIMIT_RECALCULATE` | `POST /incidents/{incident_id}/recalculate` |
| `risk_recompute` | `RATE_LIMIT_RISK_CALCULATE` | `POST /risk/recompute` |
| `risk_calculate` | `RATE_LIMIT_RISK_CALCULATE` | `POST /risk/incidents/{incident_id}/calculate` |
| `connector_poll` | `RATE_LIMIT_CONNECTOR_POLL` | `POST /events/connectors/{source}/poll` |
| `response_request` | `RATE_LIMIT_RESPONSE_GOVERNANCE` | `POST /responses/controlled` |
| `response_approve` | `RATE_LIMIT_RESPONSE_GOVERNANCE` | `POST /responses/{action_id}/approve` |
| `response_execute` | `RATE_LIMIT_RESPONSE_GOVERNANCE` | `POST /responses/{action_id}/execute` |
| `response_rollback` | `RATE_LIMIT_RESPONSE_GOVERNANCE` | `POST /responses/{action_id}/rollback` |
| `scan_start` | `RATE_LIMIT_SCAN_START` | `POST /network/scans` (Step 32) |
| `vuln_scan_start` | `RATE_LIMIT_SCAN_START` | `POST /vulnerability-scans` (Step 32) |

The two scan-start operations read the same `RATE_LIMIT_SCAN_START` setting
but are separate operation keys, so each route is budgeted and logged
independently.

**Login throttling (Step 32) is counted differently.** `POST /auth/login`
has no dependency-based limit, because only the handler knows whether the
attempt failed. `RATE_LIMIT_LOGIN_FAILURES` (default 5) is charged against
the caller *after* a failed credential check, so password guessing is
bounded while a correct password is never throttled. The failure is audited
and committed before the budget is charged, so a throttled attempt is still
recorded.

Keyed by authenticated username, else client host. A limit of `0`
disables a check. Over-budget calls get `429 RATE_LIMITED` with
`Retry-After`. Authorization is unchanged: on the dependency-based routes an
unauthorized caller is refused 401/403 *before* any budget is consumed, and
a limit never widens what an authorized caller may do.

### 12.4 Database

- Bounded pool: `DB_POOL_SIZE` (10) + `DB_MAX_OVERFLOW` (10) cap total
  connections; `DB_POOL_TIMEOUT_SECONDS` (10) bounds the wait;
  `DB_POOL_RECYCLE_SECONDS` (1800) retires connections;
  `DB_CONNECT_TIMEOUT_SECONDS` (10) bounds connect. SQLite (tests) is
  excluded because it has no server-side pool.
- `DB_STATEMENT_TIMEOUT_MS` (15000) sets a PostgreSQL
  `statement_timeout` on every new connection, so a runaway query cannot
  hold a connection indefinitely.
- Migration `step31_hardening` (additive, reversible) adds eight
  indexes and two nullable `request_id` columns. It adds no data and
  drops nothing; `downgrade` removes only what it added.

### 12.5 Performance fixes (behaviour unchanged)

| Fix | Before | After |
|---|---|---|
| `response_governance.recommendations` | one evidence query **per candidate** address/account/asset (unbounded loop) | evidence indexed once from the already-loaded events; total queries constant |
| `response_governance.expire_due` | `commit()` + `refresh()` **per row** (up to 500 transactions per read) | one `SELECT` (now index-backed and filtered in SQL) + at most one `commit`; bounded by `MAX_EXPIRY_SCAN` |
| `correlations._evidence_items` | one `SELECT` per evidence link | one batched `IN` query + in-memory index |

### 12.6 Logging and audit

- The existing redacting filter is unchanged and still covers
  `password`, `passwd`, `api_key`, `secret`, `token`, `Bearer …` and
  `scheme://user:pass@`. New access-log lines pass through it.
- Step 32 changed the validation-error call site rather than the filter:
  the handler logs only the error type and field location, never the
  submitted value (see §13.1). The filter remains defence in depth for
  other messages.
- `incident_audits` and `response_audit` rows now carry a nullable
  `request_id`, so an approval, execution, rollback or expiry can be tied
  to the HTTP request that caused it. Both tables remain append-only;
  there is still no API that edits or deletes an audit row.
- Unexpected exceptions are logged server-side with the correlation id
  and returned to the client as `500 INTERNAL_ERROR` with a **type-only**
  message. SQL text, bound parameters, filesystem paths and DSN fragments
  are never returned — including in debug mode, where the exception
  *message* is still withheld.

### 12.7 Docker

- Backend image runs as an unprivileged user (uid/gid 10001), with
  `no-new-privileges`, `cap_drop: ALL`, a tmpfs `/tmp`, memory and PID
  limits, `stop_grace_period`, and size-capped JSON logs.
- Database and frontend get `no-new-privileges` and the same log caps.
  **Frontend capabilities are deliberately not dropped**: nginx binds
  `:80` as master and drops privileges for its workers, so `cap_drop:
  ALL` would stop it listening. Making it an unprivileged listener is a
  documented future option, not a claim.
- PostgreSQL stays bound to `127.0.0.1` only. Backend/frontend host
  ports are unchanged so the development workflow still works — a
  production deployment should front them with a TLS-terminating proxy
  and not publish them directly.
- `.dockerignore` for both contexts keeps `node_modules`, `dist`, `.env`
  and local databases out of image layers.

### 12.8 Frontend

- `ApiError` carries only the server's stable `error.code`; the response
  body, any message field and headers are discarded, so a backend message
  can never be rendered into the DOM. `safeErrorText` maps codes to
  fixed sentences and falls back for anything unknown.
- `SessionContext` reflects the signed-in account's permissions so
  governed Step 30 controls (Approve/Execute/Roll Back) are disabled with
  an explanatory `title` when the account lacks them. **This is a
  usability affordance only** — it is not the security boundary, an
  unknown identity is treated as not permitted, and the API still
  authorizes every call.

### 12.9 Known limitations (Step 31)

- **Rate limits are per-process.** Multiple replicas enforce them
  independently; a shared store would be needed for a global budget.
- **No TLS in the stack.** The compose deployment serves plain HTTP on
  localhost-bound ports. A production deployment must terminate TLS in
  front; HSTS and the strict API CSP are already in place for that.
- **Secrets come from environment variables**, not a secrets manager.
  Step 31 validates and redacts them but does not rotate or scope them.
- **No read-only container filesystem** for the backend (it would need
  explicit tmpfs mounts); documented rather than claimed.
- **Frontend nginx still runs as root** to bind `:80`.
- **No external connectivity is configured or verified.** Wazuh,
  Defender, Suricata, Zeek, firewall, endpoint and cloud connectors all
  report `NOT_CONFIGURED`. Fixture/mock providers remain available for
  deterministic testing. No real-world deployment validation was
  performed.

### 12.10 Deterministic and bounded read paths (Steps 57, 58, 63, 64)

List and history endpoints were audited for two read-path defects: orderings
that were not deterministic when records share a timestamp, and reads whose
cost grew with stored data instead of with the caller's request. Each fix is
additive and keeps every existing response field.

| Surface | Before | After |
|---|---|---|
| `GET /assets`, `GET /events`, `GET /correlations` (Step 57) | ordered by one timestamp with no tie-break; offset paging could duplicate or skip rows on an unchanged set | ordered `<timestamp> DESC, id ASC`, so paging is stable |
| `GET /network/scans`, `GET /vulnerability-scans`, `GET /assets/summary` (Step 63) | the same single-column ordering; the summary's "last scan" pick was ambiguous under tied `created_at` | an `id` tie-break on both lists and on the summary's last-scan selection |
| `GET /events/{id}/audit`, `GET /incidents/{id}/audit` (Step 64) | returned every audit fact for the subject, with no ceiling | paged `limit`/`offset` (default 50, capped 200), ordered `(created_at, id)`, with `total` and `truncated` |

Step 64 reuses the exact convention of the Step 42A response-audit reader
(section 25): `limit` defaults to 50 and is capped at 200, `offset` defaults
to 0, and `truncated` is true exactly when `offset + len(entries) < total`.
The added `total`/`limit`/`offset`/`truncated` fields are additive and
`entries` keeps its existing shape, so current callers are unaffected except
that a subject with more than 200 facts is now paged rather than returned in
one response. `risk_service`'s recompute still reads all `RiskAssessment`
rows to evict stale ones; that scan is inherent to the eviction and was left
unchanged deliberately.

## 13. Security review, remediation and final audit (Step 32)

Step 32 reviewed the Steps 1–31 result and changed no feature, API, schema
or control. It found five defects, fixed each one, added regression tests
for each, and finished with a full audit. The final audit result was
`STEP 32 FINAL AUDIT: PASS — PROJECT READY`.

### 13.1 Finding 4 — secret material in logs

The `RequestValidationError` handler logged `exc.errors()`, which includes
the submitted value — and, for a missing field, the entire request body. A
password therefore reached the log verbatim. The existing redaction filter
could not compensate, because its patterns require a field name immediately
followed by `:`/`=`, while Pydantic renders `'password': '…'`.

Now `safe_validation_summary()` in `app/core/errors.py` logs only the
error `type` and field `loc`. No value is passed to the logger, so the leak
does not depend on a pattern staying in sync.

### 13.2 Finding 1 — dead `RATE_LIMIT_SCAN_START` setting

`rate_limit_scan_start` existed in `Settings`, `.env.example` and
`docker-compose.yml` but no endpoint read it, so the documented budget for
the most expensive action in the product was never enforced. It is now
applied to `POST /network/scans` and `POST /vulnerability-scans` (see
§12.3).

### 13.3 Finding 2 — unthrottled login endpoint

`POST /auth/login` had no throttle of any kind — no lockout, no
failed-attempt counter, nothing but an audit row. `RATE_LIMIT_LOGIN_FAILURES`
(default 5) now bounds *failed* attempts per caller and window. The budget
is charged in the handler after a failed credential check — not as a
dependency — so a correct password is never throttled, and the failure is
audited and committed before the charge so a `429` never hides the evidence.
Keying is by client host, because no token exists yet; it is not a
per-account lockout and does not detect a distributed attacker. Failed
logins for unknown usernames draw on the same budget, so name-spraying is
not a bypass.

### 13.4 Finding 3 — `REQUIRE_AUTH` not forwarded to the container

`REQUIRE_AUTH` was documented in `.env.example` and read by `Settings`, but
was absent from the backend service's `environment:` block. The backend
image contains no `.env` file, so the `env_file` setting resolved to
nothing inside the container and the variable was simply never delivered: a
deployment could set `REQUIRE_AUTH=true` and still start in bootstrap mode.
It is now forwarded as `REQUIRE_AUTH: ${REQUIRE_AUTH:-false}`.

Because there is no CLI that creates the first administrator, setting
`REQUIRE_AUTH=true` against an *empty* database means no one can
authenticate. The intended order is: create the first admin while bootstrap
is available, then set `REQUIRE_AUTH=true`. `validate_production()` does not
yet require `require_auth=True`, so this remains an operator decision.

### 13.5 Finding 5 — unbounded asset-detail query

`GET /assets/{id}/vuln-risk` read every `vuln_finding` risk row in the
database and filtered it in Python, so one asset's summary cost an O(global)
scan with no `LIMIT`. The query is now scoped to that asset's own findings
(indexed by `entity_type`/`entity_id`) and bounded by
`MAX_ASSET_FINDINGS = 1000`, ordered by id so truncation is deterministic.
The bound is a server-side constant; the endpoint accepts no size parameter,
so a client cannot widen it. An asset with more than 1,000 findings reports
a summary over the first 1,000 — a documented ceiling, in place of a global
read.

### 13.6 Regression coverage

67 tests were added across the five findings, each mutation-checked (removing
the fix makes the relevant test fail). Two guard tests prevent recurrence: no
declared `rate_limit_*` budget may go unenforced, and every value passed to
`rate_limit()` must name a real setting. The full backend suite is 683
tests, all passing.

## 14. Wazuh live read-only integration foundation (Phase 2, Step 3)

> **Live Wazuh connectivity not validated in this environment.** No real
> Wazuh manager was reachable from the development machine, so every test in
> this area runs against `httpx.MockTransport`. Nothing in this section is a
> report of a successful connection to a real Wazuh deployment.

### 14.1 Two distinct modes — do not confuse them

| | **FIXTURE mode** | **LIVE Wazuh mode** |
|---|---|---|
| What it is | Records submitted to `POST /api/v1/events/ingest/wazuh` by an operator or a test | The connector retrieving alerts from a real Wazuh manager over its REST API |
| Transport | None — the payload arrives in the request | Outbound HTTPS through the shared allow-listed `ConnectorHttpClient` |
| Needs credentials | No | Yes (`WAZUH_*`, see §14.2) |
| Uses | Deterministic tests, parsing/normalization work | Operator-initiated health check and bounded alert poll |
| Network | Never touches the network | Allow-listed destination, bounded, no redirects |

Both paths converge on the **same** normalization (`wazuh_adapter`), the
same deduplication, the same asset correlation and the same audit trail.
There is no second event store: live alerts are ingested through the existing
`ingestion` pipeline.

### 14.2 Configuration (environment variables, by name only)

Never put real values in documentation, `.env.example`, or a commit.

| Variable | Purpose |
|---|---|
| `WAZUH_API_URL` | Base URL of the Wazuh manager API. The task brief calls this `WAZUH_BASE_URL`; the shipped name is `WAZUH_API_URL` and it was **not** renamed, because `docker-compose.yml`, `.env.example` and Step 27 already ship that name and renaming would break existing deployments. |
| `WAZUH_USERNAME` | API username |
| `WAZUH_PASSWORD` | API password — server-side only |
| `CONNECTOR_TIMEOUT_SECONDS` | Per-request timeout |
| `CONNECTOR_MAX_RESPONSE_BYTES` | Hard cap on a single response body |
| `CONNECTOR_MAX_PAGES` | Maximum pages per poll |
| `CONNECTOR_MAX_EVENTS` | Maximum events per poll |
| `CONNECTOR_VERIFY_TLS` | TLS verification (default on; disabling it is explicit and visible) |
| `CONNECTOR_RETRY_MAX` | Extra attempts, idempotent GETs only |

All default to empty/disabled, so **the application starts and works normally
with Wazuh unconfigured** (`NOT_CONFIGURED`, no network attempt).

### 14.3 Authentication

HTTP Basic over `POST /security/user/authenticate` returns a bearer token.
`WazuhAuthenticator` is the only code that mints it. The token lives on the
client instance in memory, is never returned to a caller, never written to an
audit row, never logged, and is registered as a redaction secret the moment
it is received so it cannot appear in any downstream message. The password is
likewise a redaction secret for the client's whole lifetime. A response with
no usable token is refused as `MALFORMED_RESPONSE` — never treated as
authenticated.

### 14.4 Read-only, bounded polling

`POST /api/v1/events/connectors/wazuh/poll` retrieves `/alerts` with
`limit`/`offset`, capped at 100 per page, `CONNECTOR_MAX_PAGES` pages and
`CONNECTOR_MAX_EVENTS` events. Every poll ends with an explicit termination
reason — `COMPLETED`, `MAX_PAGES`, `MAX_EVENTS`, `REPEATED_CURSOR` (the
server replayed a cursor) or `MALFORMED_PAGINATION` — so no loop can run
away. History is never walked: the poll starts at offset 0 each time and
relies on deduplication.

**The connector never writes to Wazuh.** The only non-GET request it issues
is the authentication POST. A test asserts this directly: no DELETE, PUT,
PATCH, active-response, agent-control or restart path is ever requested.

### 14.5 Security limitations

- **No live validation.** Everything is verified against mocks only.
- **Per-source-IP budgeting.** Login/connector budgets key on client host;
  there is no per-account lockout.
- **In-process state.** Connector runtime and rate-limit budgets live in one
  process; a multi-replica deployment needs shared state.
- **Allow-list is mandatory.** A destination outside `allowed_hosts_for(...)`
  is refused before a socket is opened, so a misconfigured URL cannot become
  an SSRF primitive.
- **No secrets manager.** Values come from environment variables only.
- **Still operator-initiated.** There is no background polling, no scheduler
  and no streaming; a human triggers every check and poll.

## 15. Microsoft Defender connector foundation (Phase 2, Step 4)

> **Live Microsoft Defender connectivity not validated in this environment.**
> No Microsoft Graph or Microsoft identity endpoint was reachable, so every
> test runs against `httpx.MockTransport`. Nothing here is a report of a
> successful connection to a real tenant.

### 15.1 Same architecture as Wazuh

The Defender connector is the second implementation of the Step 26/27
connector architecture, sharing the same safety machinery rather than
re-implementing it:

| Concern | Module |
|---|---|
| Graph client + OAuth2 token provider | `app/services/defender_client.py` |
| Shared allow-listed transport | `app/services/http_connector.py` |
| Lifecycle, states, audit | `app/services/connectors.py` |
| Bounded ingest orchestration | `app/services/ingestion.py` |
| Normalization | `app/services/defender_adapter.py` |
| API | `app/api/v1/endpoints/connectors.py` |

As with Wazuh, fixture mode (`POST /api/v1/events/ingest/defender`) and live
mode both converge on the same adapter, deduplication, asset correlation and
audit trail. There is no second event store.

### 15.2 Configuration (environment variables, by name only)

`DEFENDER_TENANT_ID`, `DEFENDER_CLIENT_ID`, `DEFENDER_CLIENT_SECRET`,
`DEFENDER_API_ENDPOINT`, `DEFENDER_AUTHORITY`, plus the same shared
`CONNECTOR_TIMEOUT_SECONDS`, `CONNECTOR_MAX_RESPONSE_BYTES`,
`CONNECTOR_MAX_PAGES`, `CONNECTOR_MAX_EVENTS`, `CONNECTOR_VERIFY_TLS`,
`CONNECTOR_RETRY_MAX` bounds used by every connector. No credential, secret
or certificate is hard-coded; `.env.example` ships all of them empty.

### 15.3 Authentication

OAuth2 **client credentials**: `POST {authority}/{tenant}/oauth2/v2.0/token`
returns an `access_token`. `DefenderTokenProvider` is the only code that
requests it, and it is injected into `DefenderClient` so a future MSAL-backed
implementation can replace it without touching retrieval code. The token is
held in memory on the provider, never returned, never audited, never logged,
and is appended to the redaction secrets the moment it arrives; the client
secret is a redaction secret from construction. Token-endpoint rejections
(400/401/403) map to `AUTH_FAILED`. Because the token endpoint cannot report
a "connected" state without valid credentials, `CONNECTED` requires a real
successful Graph read as well.

### 15.4 Bounded, read-only retrieval

`GET /security/alerts?$top=N`, following `@odata.nextLink` up to
`CONNECTOR_MAX_PAGES` pages and `CONNECTOR_MAX_EVENTS` records, terminating
explicitly with `COMPLETED`, `MAX_PAGES`, `MAX_EVENTS`, `REPEATED_CURSOR`
or `MALFORMED_PAGINATION`. Every server-supplied `nextLink` is re-validated
against the destination allow-list before use, so a hostile or misconfigured
server cannot steer the backend at another host. The connector writes
nothing: its only non-GET request is the token exchange.

### 15.5 Security limitations

- **No live validation.** Everything is verified against mocks only.
- **Client-credentials scope is all-or-nothing.** The token carries
  `https://graph.microsoft.com/.default`, i.e. whatever the app registration
  is granted. Least privilege is a tenant-side configuration duty.
- **Per-source-IP budgeting**, not per-tenant or per-app.
- **In-process state**; multi-replica deployments need shared state.
- **No secrets manager, no secret rotation.**
- **Still operator-initiated** — no background polling or streaming.

## 16. Controlled polling foundation (Phase 2, Step 5)

> This is **polling, not streaming**. Nothing in the platform tails Wazuh or
> Defender. The existing `STREAMING_ENABLED=false` foundation remains
> disabled, and Step 5 adds no streaming path.

### 16.1 What was added — and what was not

`app/services/connector_polling.py` adds *policy* around the existing Step
26–28 pipeline. `ingestion.poll_source` remains the single bounded, audited
path that fetches, normalizes, deduplicates, correlates, stores and audits.
The Wazuh and Defender clients, the connector lifecycle, the canonical event
model, RBAC, rate limiting, pagination bounds and dedup are **unchanged**.

| Added | Not added |
|---|---|
| Overlap prevention (one poll per connector at a time) | No background thread, timer, scheduler or event loop |
| Interval + failure cool-down for the automated pass | No streaming / tailing |
| An opt-in "poll whatever is due" pass, **off by default** | No autonomous response, blocking or isolation |
| Secret-free polling health metadata | No change to any connector's fetch or auth logic |

### 16.2 Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CONNECTOR_AUTO_POLL_ENABLED` | `false` | Permits the due-poll pass to run. Off by default; never schedules itself |
| `CONNECTOR_POLL_INTERVAL_SECONDS` | `300` | Minimum spacing between two automated polls of one connector |
| `CONNECTOR_FAILURE_COOLDOWN_SECONDS` | `60` | Wait after a failed poll so a failing source is not hammered |

Per-poll bounds remain the existing `CONNECTOR_MAX_PAGES`,
`CONNECTOR_MAX_EVENTS`, `CONNECTOR_MAX_RESPONSE_BYTES`,
`CONNECTOR_TIMEOUT_SECONDS`, `CONNECTOR_RETRY_MAX` and
`CONNECTOR_VERIFY_TLS`.

### 16.3 Manual Poll Now is unchanged

A manual `POST /events/connectors/{source}/poll` always does what the
operator asked, including the idempotent repeat poll (re-read, dedup
absorbs). Its frequency is bounded by the pre-existing
`RATE_LIMIT_CONNECTOR_POLL` budget. Two new refusals exist:

* `409 POLL_IN_PROGRESS` — a poll for that connector is already running.
* `429 POLL_COOLDOWN` — only when a caller opts into the cool-down; the
  manual path does not by default.

### 16.4 Health metadata

`GET /events/connectors/{source}` now includes a `polling` object with
`last_poll_started_at`, `last_poll_completed_at`, `last_successful_poll_at`,
`last_error_category`, `events_received`, `events_accepted`,
`events_deduplicated`, `next_permitted_poll_at`, `in_flight`, `polls` and
`failures`. Every field is a timestamp, a count, or a stable category
label; **no credential or token is representable there**, and nothing in it
is written to an audit row.

### 16.5 Anti-hammering

After a failed poll the connector is not due again until the cool-down
elapses; when the source is `RATE_LIMITED` the wait is extended, and a
server-supplied `Retry-After` is honoured when the connector surfaces one.
A connector that is `NOT_CONFIGURED` is never selected by the due-poll pass.

### 16.6 Known limitations

- **`Retry-After` on the poll path.** The check path surfaces the server's
  `Retry-After`; the poll path raises a bare `ConnectorUnavailableError`
  that does not carry it, so the poll cool-down uses the configured value
  (multiplied when rate-limited). Threading the header through would mean
  changing the shared connector error type, which Step 5 does not do.
- **In-process state.** The overlap lock, interval and cool-down live in one
  process; a multi-replica deployment needs shared state, and the lock does
  not span replicas.
- **The due-poll pass has no caller.** It is deliberately not wired to
  anything; enabling the setting alone does not start it. Wiring it to a
  scheduler is a future, explicit operator decision.
- **No per-tenant budgeting** and no shared rate-limit state.

## 17. Event normalization and statistics (Phase 2, Step 6)

Step 6 changed no model, no schema migration and no pipeline. It closed
three gaps found by inspecting the existing canonical-event path.

### 17.1 Consistent vendor normalization

Wazuh now populates the same two canonical identity fields the Defender
adapter already set — `username` and `process_name` — from
`data.uname`/`srcuser`/`dstuser` and `data.process_name`/`cmdline`/
`program`/`exe`. The Defender adapter additionally recognises the real
Microsoft Graph field names `accountName` and `remoteIp`. Absent fields stay
`None`: never inferred, never defaulted, exactly as before.

### 17.2 Unambiguous pipeline statistics

Polling and `GET /api/v1/events/ingestion/status` now report
`normalized` alongside the existing counters, so each stage is separately
checkable:

| Field | Meaning |
|---|---|
| `fetched` / `retrieved` | received from the connector |
| `normalized` | produced a canonical event (accepted + deduplicated) |
| `accepted` | newly stored |
| `duplicated` | already known; dedup absorbed it |
| `rejected` | failed server-side validation |

`received = normalized + rejected` and `normalized = accepted + duplicated`
hold for every poll.

## 18. Correlation and incident grouping (Phase 2, Step 7)

Step 7 reused the Step 9 correlation engine and closed **one**
empirically-confirmed defect. No new incident model, rule engine, or
recompute path was introduced.

### 18.1 The defect

The `multi-source-target` rule ("same target, multiple sources") grouped
events by `destination_ip` only. A Wazuh alert reports `dstip`, while a
Defender alert reports `remoteIp` and `computerName` and usually has **no**
destination address. Two alerts about the *same machine*, from two vendors,
therefore shared no key: a live probe produced **zero** correlations where
one is plainly warranted.

### 18.2 The fix

A target is now identified by `destination_ip` **or** `hostname`, each
prefixed (`ip:` / `host:`) so an address can never collide with a name, and
the key list is ordered so the chosen pivot is deterministic. The
destination-address behaviour is unchanged — it is a superset. The rule's
description and conditions were updated to match.

Confirmed before/after on the same input (Wazuh `dstip=10.0.0.5, host
ws-01` + Defender `remoteIp=203.0.113.10, host ws-01`): **0 correlations →
1** `multi-source-target` correlation, severity `CRITICAL` (evidence
maximum), naming both vendors in its explanation.

### 18.3 What was deliberately not changed

The rule catalog is still the same three fixed rules; confidence is still a
fixed per-rule integer; severity is still the evidence maximum. Windows stay
bounded by `correlation_max_window_minutes` and a hard 7-day ceiling, scans
stay bounded at 500 events, and identity stays
`sha256(namespace, rule_id, sorted event_ids)` with upsert, so reprocessing
the same events refreshes rather than duplicates. Recompute remains
server-side only and takes **no request body** — a client cannot select a
rule, widen a window, or supply a severity or asset id (a steered request is
refused with 422).

### 18.4 Honesty guarantees re-asserted

Two unrelated events that merely share a `source_ip` do **not** correlate;
neither do two vendors reporting different hosts. An unresolved asset stays
unresolved and the explanation states only what was observed. Every
correlation carries its rule id, matched evidence with positions and roles,
window start/end, and an explanation, and is audited (`RUN_STARTED`,
`CORRELATION_MATCHED`, `RUN_COMPLETED`). Every description states that
related events are not proof of compromise.

No AI/ML, no probabilistic scoring, no autonomous response: no blocking,
isolation, process termination, file deletion or firewall change was added.

## 19. Incident intelligence and priority refinement (Phase 2, Step 8)

Step 8 adds a **read-only enrichment layer** over an incident that Step 7 has
already correlated. It is not a second incident model and does not replace
the Step 10/25 risk score.

### 19.1 What it does and does not touch

| Reads (stored rows only) | Never writes |
|---|---|
| The correlation's evidence events | `Incident.risk_score` (left as the linked Step 10 assessment set it) |
| Inventoried assets those events resolve to | `Incident.severity` / `confidence` |
| Open vulnerability findings for those assets | Any incident, correlation, event or risk row |
| Step 29 relationships, timestamps | Any network, host, or firewall |

### 19.2 The refinement

Points come from five deterministic, individually reported contributions:
de-duplicated evidence count (≤10), highest evidence severity, relationship
count (≤10), open vulnerability context for the affected asset(s) (capped,
weighted by the **worst** finding severity so many low findings cannot
outrank one critical exposure), and recency from the incident's stored
`last_seen`. The total is clamped 0–100 and mapped to a review priority
(P1 ≥40, P2 ≥25, P3 ≥12, else P4) by fixed integer thresholds.

Every point is returned in `factors`, and `explanation` states each
contribution, the total, and the resulting priority — including the explicit
statement that this is a review ordering, not a verdict and not proof of
compromise.

### 19.3 Honesty and bounds

- Evidence is de-duplicated by event id (`SELECT DISTINCT` over a unique
  constraint), so repeated processing **cannot** inflate the score.
- Assets resolve by exact address/host match only; an unresolved event
  leaves `asset_id` unset and is reported as `unresolved_event_count`.
- Nothing is invented: a missing asset, finding or relationship contributes
  zero and says so.
- Queries are batched and capped by the existing `Settings` limits
  (`correlation_max_events_per_operation`, `correlation_relationship_max`);
  truncation is reported rather than hidden. There is no N+1 lookup and no
  unbounded history scan.
- Results are deterministic — the same stored rows always yield the same
  factors, points and priority.

### 19.4 API and audit

- `GET /api/v1/incidents/{id}/intelligence` — read-only summary, requires
  `READ_INCIDENTS`. Re-derives from stored rows on every call and writes
  nothing, so a caller cannot steer it.
- `POST /api/v1/incidents/{id}/intelligence/refresh` — same calculation plus
  an `INTELLIGENCE_REFRESHED` audit row recording the inputs and result;
  requires `MANAGE_INCIDENT` and is rate-limited.

Both return a payload of counts, bounded integers, stored identifiers, ISO
timestamps and fixed labels — no event payloads and no secrets.

## 20. SOC overview endpoint (Phase 2, Step 9 — API and dashboard UI delivered)

Step 9 is **complete**: the endpoint is verified by
`backend/tests/test_soc_overview_step9.py` and
`backend/tests/test_soc_overview_integration_step60.py`, and the SOC dashboard
UI that consumes it is delivered (see below). Nothing unverified was left in
the repository.

`GET /api/v1/overview` is a single **read-only** roll-up of stored security
state, intended for a dashboard. It adds no detection, scoring or
correlation logic: every number is a SQL `COUNT` over rows the platform
already stores, and priority is the existing `risk_service.priority_for`
band applied to the already-stored `risk_score`.

| Guard | Behaviour |
|---|---|
| Authorization | Requires `READ_INCIDENTS`; anonymous/invalid token → 401/403. While the user table is empty the documented Step 20 **bootstrap** mode still applies (asserted by a test) |
| Caller input | Only `limit`, validated `ge=1 le=50` and clamped again server-side. Unknown parameters (`severity`, `priority`, `status`, `order_by`, …) are ignored, not obeyed |
| Bounds | Every list capped at 50; every count is a database aggregate; no table is read in full; two queries total for the incident + connector sections (no N+1) |
| Writes | None. A test compares row counts in `incidents`, `security_events`, `event_audits` and `incident_audits` before and after |
| Secrets | Connector health reuses the Step 27 truth machine (`state` only, never a configured value). A test asserts no password, client secret, token or `Authorization` appears in the payload |
| Action | None. Response workflow appears as counts (total / pending approval) only; a test asserts no action verb appears in the response |

Payload: `counts` (assets, services, events, correlations, incidents, open
incidents, risk assessments, open vulnerabilities, response actions and
pending approvals), `incidents_by_severity` and `incidents_by_priority`
(every bucket present, including zeros and `UNSCORED`), a bounded
`top_incidents` list with derived priority, a bounded `recent_audit` feed,
connector states, the applied `limits`, and a `disclaimer` stating that
related events are not proof of compromise and that nothing on the screen
performs an action.

### Delivered: the SOC dashboard UI

`frontend/src/pages/Dashboard.tsx` renders this endpoint. It loads
`GET /api/v1/overview` and shows the counts, the severity and priority buckets,
the bounded top-incident list, the recent ingestion audit feed and connector
health, beside the readiness card. It performs no client-side arithmetic and
offers no action. It is exercised by
`frontend/src/pages/Step9_SOC_dashboard.test.tsx` (render, empty, error and
denied states), and its data tables carry accessible names (Step 59).

### 17.3 No credential material in stored events

A vendor payload is stored verbatim so no forensic detail is lost — which
also meant a rule reporting a failed login or a config file could persist a
password, token or key inside `raw_event`. Values under a credential-named
key (`password`, `*_token`, `*_secret`, `api_key`, `private_key`,
`authorization`, …) are now replaced with `***REDACTED***` before the event
is written. The key list is deliberately narrow, so ordinary forensic text
is untouched, and the scrub is bounded in depth and breadth so a hostile
payload cannot turn normalization into a CPU sink.

### 17.4 Unchanged guarantees

Server-side validation, per-record failure isolation (one bad record never
discards a valid batch), bounded batch and page sizes, deduplication by the
`(source_type, source_name, external_event_id)` triple, exact-match-only
asset correlation that leaves an unknown asset explicitly unresolved, and
the append-only audit trail are all as they were — each re-asserted by a
Step 6 test.

## 21. Production hardening (Phase 2, Step 10)

Step 10 changed no feature and removed no safety control. It closed three
concrete gaps that were evidenced by the code, and documented two that
genuinely cannot be closed inside this repository.

### 21.1 Production configuration now fails fast on three unsafe states

`Settings.validate_production()` previously allowed a production deployment
to start in a state that is unsafe by design. It now refuses to start, and
each message still names only the variable — never the offending value:

| Refused | Why it matters |
|---|---|
| `REQUIRE_AUTH=false` | Bootstrap mode stays open: the first unauthenticated caller can create the first ADMIN user. That is an unauthenticated privilege-escalation path, acceptable only in development |
| `CONNECTOR_VERIFY_TLS=false` | Defender client secret, Wazuh password and JWTs would cross the network with no server verification |
| empty `TRUSTED_HOSTS` | Starlette's `TrustedHostMiddleware` treats an empty allow-list as "allow everything", so Host-header validation would be silently **off** |

All three are scoped to `ENVIRONMENT=production`; development, test and
staging start unchanged. A test also asserts that every Step 31 production
guard still refuses what it refused before.

### 21.2 Secret redaction now covers every log record

The Step 31 redacting filter lived on the root log handler. That was
insufficient: `uvicorn` and `uvicorn.access` are configured by uvicorn's own
`dictConfig` with `propagate: False` and private handlers, and uvicorn
rewrites them **after** the application imports the app — so their records
never reached the filtered handler, and any filter attached at startup would
have been discarded. A password logged through `uvicorn.error` would therefore
have reached stdout or stderr in cleartext.

A redacting `LogRecord` factory is now installed at startup. It runs before
any handler, logger filter or formatter, so no handler configuration can
bypass it. It chains (rather than replaces) any pre-existing factory, is
idempotent, and never raises: a logging call with a broken format string
still cannot fail the request.

Also fixed: the credential-in-URL pattern consumed the `@` of a DSN, turning
`postgresql://user:secret@db:5432` into `postgresql://user:***db:5432`. It
now uses a lookahead, so the redacted DSN stays readable.

### 21.3 The deployed Compose surface is narrower

| Change | Before | After |
|---|---|---|
| API port | `${API_PORT}:8000` — **every host interface** | `${API_BIND:-127.0.0.1}:${API_PORT}:8000` |
| Frontend port | `${FRONTEND_PORT}:80` — every host interface | `${FRONTEND_BIND:-127.0.0.1}:${FRONTEND_PORT}:80` |
| Backend root filesystem | writable | `read_only: true` |

The database was already loopback-only; the API and frontend were not, so the
stack's only authenticated-but-reachable-everywhere services were its two
public entry points. `API_BIND` / `FRONTEND_BIND` are the documented opt-in
for a real deployment behind a TLS terminator, and both are recorded in
`.env.example`.

`read_only: true` applies the option Step 31 documented but did not enable.
It was verified compatible by inspection: the image sets
`PYTHONDONTWRITEBYTECODE=1`, binds an unprivileged port, runs no migration at
startup, and the application contains no file-write path (its single `open()`
is a read of a file-source connector). `/tmp` is already a tmpfs, and all
three healthchecks are unchanged.

### 21.4 Deliberately NOT changed

* **No `cap_drop` on the database or the frontend.** Both images need
  privileges their entrypoints use before dropping them; adding `cap_drop`
  would stop them starting, and that cannot be verified here (no Docker
  engine). Documented instead, as Step 31 did.
* **No read-only frontend filesystem.** nginx writes to
  `/var/cache/nginx` and `/var/run` at startup, so this needs a reconfigured
  image and tmpfs mounts — an unverifiable change.
* **No shared rate-limit store.** See 21.5.
* **No new dependency, no Redis, no migration, no model change.**

### 21.5 In-process state: precise multi-replica limitation

Five pieces of state are per-process and are **not** shared between replicas:

| State | Location | Effect with N > 1 replicas |
|---|---|---|
| Rate-limit buckets (login, recompute, poll, response, scan) | `core/ratelimit.py` | Budgets multiply by N; a limit of 5 becomes 5 per replica |
| Connector poll health, per-source overlap locks, failure cooldowns | `services/connector_polling.py` | Two replicas can poll the same source simultaneously; each holds its own cooldown |
| Connector runtime health, last-success, fetch counters | `services/connectors.py` | Health is whichever replica answered last; counters are per-replica |
| Ingestion queue depth and per-source metrics | `services/ingestion.py` | Queue metrics describe one replica only |
| Login failure counters | `core/ratelimit.py` | Brute-force protection is per-replica |

Everything that must be correct under concurrency is **already** in the
database and already transactional: audit rows, incidents, correlations,
risk assessments and response actions. Only advisory counters are in-process.

The supported answers are therefore, in order of preference: run a **single
replica** (what this repository's Compose does), or place a shared store
(Redis/Postgres) behind the same interfaces before scaling out. Introducing
that store is out of scope here and was **not** approximated by pretending
the in-process state is shared.

### 21.6 Audit append-only status

Audit tables are append-only by convention and by code path: no endpoint
updates or deletes an audit row. There is no database-level enforcement (no
trigger, no `REVOKE`), so a direct SQL writer with database credentials could
modify history. Adding that enforcement is a migration and is not done here.
For a deployment that requires tamper-evident audit, enable database-level
audit and restrict write access to the application's database role.

### 21.7 What still requires external infrastructure

* **TLS termination** — the API speaks plain HTTP; put it behind a proxy.
* **A real secret store** — `SECRET_KEY`, `POSTGRES_PASSWORD` and connector
  credentials come from the environment.
* **A shared rate-limit store** if more than one replica runs (21.5).
* **Database-level audit immutability** if tamper-evidence is required (21.6).
* **A log shipper** — logs go to stdout only; redaction is guaranteed
  in-process, not by the collector.
* **Live Wazuh / Defender connectivity is still unverified.** No Wazuh or
  Defender instance was ever contacted; every connector test uses
  `httpx.MockTransport`. LIVE state is only ever reported by a real
  successful call, so a deployment that has not configured a connector
  reports `NOT_CONFIGURED`.
* **Docker runtime behaviour is unverified.** The Docker engine is not
  running in this environment. `docker compose config` validates and the
  rendered Compose model was inspected, but no container was started, so the
  read-only root filesystem and the loopback bindings are verified by
  configuration and inspection, not by execution.


## 22. Append-only audit enforcement (Phase 2, Step 11)

Step 10 recorded a precise limitation: audit tables were append-only *by
convention and by code path*, with no enforcement. Step 11 closes the part of
that gap which is reachable from application code.

`app/models/audit_guard.py` registers two SQLAlchemy listeners on the ORM
`Session` at import time (`app/database/session.py`), so the guard applies to
every session in the process — the application's, the test suite's, and any
future entry point.

| Layer | Refuses |
|---|---|
| `before_flush` | An `UPDATE` or `DELETE` of a loaded audit instance |
| `do_orm_execute` | A bulk `UPDATE`/`DELETE` whose target table is an audit table |

Refusal is fail-closed and immediate: the statement never reaches the
database and the caller receives `AuditRecordMutationBlocked` (a
`RuntimeError`, deliberately not an `HTTPException` — it is a consistency
error, never a value a caller could read as success). All eight audit tables
are covered: `auth_audits`, `correlation_audits`, `event_audits`,
`incident_audits`, `response_audit`, `risk_audits`, `scan_audit`,
`vulnerability_audits`.

**Detection is by class name (`*Audit`), not table-name suffix**, because two
audit tables are singular (`response_audit`, `scan_audit`) and a `_audits`
check would have missed them. Models are discovered from the ORM registry, and
a test asserts discovery matches the eight expected tables, so a new audit
model cannot be silently left unprotected.

### 22.1 What the guard does not cover — stated plainly

Verified empirically, not assumed:

| Path | Result |
|---|---|
| Object `UPDATE` / `DELETE` | **Blocked** |
| `Query.delete()` / `Query.update()` | **Blocked** |
| `session.execute(delete(Table))` | **Blocked** |
| `session.execute(text("DELETE FROM ..."))` | Bypasses |
| `session.connection().execute(...)` | Bypasses |
| Migration or external SQL client | Bypasses |

Raw and Core statements executed outside the ORM unit of work do not pass
through these listeners. This is the boundary, not an oversight: the durable
answer for tamper-evident audit is **database-level enforcement plus a
restricted database role** (see 21.7), which is a migration and a DBA
decision, not an application concern.

### 22.2 Test-only purge scope

The suite truncates every table between tests, which genuinely requires
deleting audit rows. `allow_audit_purge_for_tests()` is an explicit, narrow,
scoped capability rather than a global exemption:

* It **refuses to arm unless `ENVIRONMENT=test`**, so a production or staging
  process has no working escape hatch at all.
* It is a depth counter released on exit, so nesting unwinds correctly and
  the guard re-arms the moment the scope closes.
* It lives in the guard module so the exemption is auditable in one place.

It uses a plain module-level counter, not a thread-local, because Step 31
forbids application modules from importing `threading`, `asyncio`, `sched` or
`multiprocessing`. That control — which is what guarantees no background or
autonomous machinery can be introduced by accident — was kept, and the guard
was written to fit inside it.

### 22.3 Preserved behaviour

Inserts and reads are untouched. Updating ordinary tables is untouched.
Step 11 added no endpoint, model, migration, dependency, background worker,
timer or capability; it can only refuse to destroy history.


## 23. Database-level audit immutability (Phase 2, Step 12)

Step 11 enforced append-only audit history at the ORM unit of work and
documented the boundary honestly: raw `text()` SQL, a raw connection, a
migration, or any external client bypasses the ORM entirely. Step 12 closes
that boundary at the database.

`alembic/versions/phase2_step12_audit_immutability.py` (revision
`phase2_step12_audit_immutability`, chained from `step31_hardening`) installs
one `BEFORE UPDATE OR DELETE ... FOR EACH ROW` trigger on each of the eight
audit tables. The shared `audit_append_only_guard()` PL/pgSQL function raises
`restrict_violation` and names both the table and the refused operation.
`INSERT` is untouched, so audit recording is completely unaffected.

### 23.1 Design decisions

| Decision | Reason |
|---|---|
| **Frozen table list**, not imported from the models | A migration must be an immutable snapshot; deriving it from live model code would silently rewrite the meaning of an already-applied migration. A test asserts the list still matches `audit_guard.audit_table_names()` so they cannot drift |
| **PostgreSQL only; no-op elsewhere** | The suite runs on SQLite, where PL/pgSQL does not exist. The dialect is checked before any DDL is issued, so `upgrade()` succeeds and changes nothing on SQLite |
| **Pure DDL builder** | `build_upgrade_statements(dialect)` / `build_downgrade_statements(dialect)` return SQL strings with no connection and no Alembic context, which is what makes the logic testable without a server |
| **`DROP TRIGGER IF EXISTS` before `CREATE`** | Idempotent: re-running `upgrade()` cannot fail on "trigger already exists" |
| **Reversible, rewrites no rows** | `downgrade()` drops only the triggers and function this migration created, so a rollback cannot lose audit history |

### 23.2 Two layers, deliberately aligned

The Step 11 ORM guard and these triggers cover different paths and neither
replaces the other:

| Path | ORM guard (Step 11) | Database trigger (Step 12) |
|---|---|---|
| Object `UPDATE`/`DELETE` | Blocked | Blocked (unreached) |
| `Query.delete()` / `Query.update()` | Blocked | Blocked (unreached) |
| `session.execute(delete(Table))` | Blocked | Blocked (unreached) |
| `text("DELETE ...")` | Bypasses | **Blocked** |
| `session.connection().execute(...)` | Bypasses | **Blocked** |
| Migration or external SQL client | Bypasses | **Blocked** |
| Application `INSERT` | Allowed | Allowed |

### 23.3 Deliberate scope boundary

The trigger covers DML only. **`TRUNCATE`, `DROP TABLE` and a superuser are
not blocked.** `TRUNCATE` protection was considered and rejected as out of
scope: it changes operational behaviour for deliberate data-purge procedures,
and "append-only" is about rows not being modified or removed by normal DML.
A superuser can always disable triggers, which is why 21.7's restricted
database role remains the durable answer rather than this trigger alone.

One operational consequence to be aware of: **any future migration that
rewrites audit data will now be refused** by the trigger. Such a migration
must drop the trigger, run, and re-create it.

### 23.4 Verification status — read this before trusting it

**Verified by execution against PostgreSQL 16.15** (see §24.5). The DDL is
accepted, all eight triggers are created and enabled, and each one refuses a
write.

* **Verified by execution** — the full Alembic chain runs against PostgreSQL:
  `step31_hardening -> phase2_step12_audit_immutability` applies, `alembic_version`
  records `phase2_step12_guard_sqlstate_fix`, and all eight audit tables carry an
  **enabled** `BEFORE UPDATE OR DELETE` trigger wired to
  `audit_append_only_guard`. Both an `UPDATE` and a `DELETE` against each of the
  eight are refused with SQLSTATE `23001`, and an `INSERT` is still accepted.
  Earlier, against SQLite, the same migration was confirmed to be a clean
  no-op (26 tables, 0 trigger objects), reversible, and never blocking
  `INSERT`.
* **Defect found by this run and fixed** — the guard's error message was
  malformed and it raised `22023` instead of `23001`. See §24.6.

To apply it: `alembic upgrade head` with `DATABASE_URL` pointing at
PostgreSQL. On SQLite it is a no-op by design.

## 24. Runtime verification harness (Phase 2, Step 13)

Step 13's scope was runtime verification of Steps 10 and 12 — the two steps
whose guarantees were asserted statically but had never been executed. The
harness was delivered while the environment could not run it; §24.5 records the
run that has since closed that gap, and §24.6 the application defect it found.

### 24.1 The environment at delivery time

At the time this step was written the harness could not be executed, and it was
delivered recording that gap rather than claiming a pass:

| Prerequisite | State at delivery |
|---|---|
| Docker engine | Not running. Only a standalone CLI (29.8.0) was installed |
| Docker Desktop | **Not installed**; WSL reported a stale `docker-desktop` distribution |
| PostgreSQL server | None: no `psql`/`pg_ctl`/`postgres`/`initdb`, nothing listening on 5432 |
| Privilege | The session was not elevated, so no service could be started |

Installing a database server or a container runtime is a system-level change
that was not authorised, so no substitute was attempted at the time.

That gap is now closed (§24.5). The harness itself has no such dependency: it
reports whatever runtime it is handed, and its tests manufacture the
nothing-reachable state rather than assuming it.

### 24.2 The harness

`scripts/verify_runtime.py` performs exactly the checks that were blocked:

* **Step 10 container hardening**, read from `docker inspect` and never by
  changing anything: non-root execution, read-only root filesystem,
  `cap_drop: ALL`, `no-new-privileges`, loopback-only published ports, and
  preserved healthchecks.
* **Step 12 audit triggers**, against the running PostgreSQL: that all eight
  audit tables carry an **enabled** `BEFORE UPDATE OR DELETE` trigger wired to
  `audit_append_only_guard`, and that each one actually refuses both an `UPDATE`
  and a `DELETE` with SQLSTATE `23001`.
* **Health and readiness**, that `/api/v1/health` and `/api/v1/ready` answer.

It is non-destructive, and never inserts. Each write probe is a single-row
`UPDATE`/`DELETE` scoped by `ctid`, run inside an explicit transaction that is
rolled back, so at most one row can be touched and none can be lost whether the
trigger fires or not: if it fires the transaction aborts, and if it did not the
`ROLLBACK` still discards the write. An empty table is reported `SKIP` for the
behavioural probe, never `PASS`. No `rm`, `prune`, `down`, `stop` or `exec` is
ever issued against Docker.

### 24.3 It reports absence of evidence, never a false pass

A check that cannot run is reported `SKIP`, never `PASS`. When neither Docker
nor PostgreSQL is reachable the harness prints *"NOTHING COULD BE VERIFIED …
This is not a pass - it is an absence of evidence"* and exits **2**. Exit **1**
means a check genuinely failed; only exit **0** means everything applicable
passed. In the environment where the harness was written it reported 3 skips,
0 passes, exit 2.

### 24.4 How to run it

```bash
docker compose up -d --build
docker compose exec -T backend alembic upgrade head
python scripts/verify_runtime.py \
    --base-url http://localhost:8000 \
    --database-url "postgresql://secuser:<password>@127.0.0.1:5432/security_platform"
```

The migration must be applied first: with no `phase2_step12_audit_immutability`
revision in the database, the trigger checks fail for a reason that has nothing
to do with the trigger.

### 24.5 The verification run — executed, and what it found

Docker Desktop 4.92.0 (engine 29.8.0) is now installed and running, so the gap
this step recorded has been closed. With the compose stack up, the migration
applied, and PostgreSQL 16.15 reachable on loopback, the harness reports:

```text
36 passed, 0 failed, 0 skipped        (exit 0)
```

All eight Step 10 container-hardening guarantees are confirmed from
`docker inspect`: the backend runs as `appuser` (not root), its root filesystem
is read-only, `CapDrop` is `ALL`, `no-new-privileges` is set, its healthcheck
is preserved, and all three published ports are bound to `127.0.0.1` only.

All eight Step 12 audit triggers are confirmed present, enabled (`tgenabled =
O`), and wired to `audit_append_only_guard` for both `UPDATE` and `DELETE`. Each
table is probed with a real one-row `UPDATE` and a real one-row `DELETE`, and
both are refused with SQLSTATE `23001`:

```text
[PASS] auth_audits: refuses an UPDATE - audit_append_only: auth_audits is append-only; UPDATE is not permitted on audit history [sqlstate=23001]
[PASS] auth_audits: refuses a DELETE - audit_append_only: auth_audits is append-only; DELETE is not permitted on audit history [sqlstate=23001]
```

Running the harness also exposed **four defects in the harness itself**, which
had never executed before and so had never been exercised. None was a safety
defect — none could have made a real failure look like a pass — but three
suppressed evidence and one crashed:

1. `_server_version()` used `with connection`, which **closes** the connection in
   psycopg 3; the caller then raised `OperationalError: the connection is closed`.
2. `docker compose ps --quiet --format json` returns bare container ids with no
   service name, so container discovery always came back empty and reported
   `SKIP` for every Step 10 check — an absence of evidence reported as nothing
   to do. The JSON format (no `--quiet`) carries `Service` and `ID`.
3. The trigger bitmask tested `tgtype & 4` for `DELETE`. Bit 4 is `INSERT`; the
   `DELETE` bit is **8**. Every table looked like it lacked a delete guard
   despite having a correct one.
4. `HostConfig.PortBindings` values are **lists** of bindings, not dicts, so the
   port-binding loop raised `AttributeError`.

Four further problems were found while fixing those, each of which had made a
check weaker or a verdict wrong:

5. **Engine detection read a merged stream.** `_run` returned `stdout + stderr`
   concatenated, so a warning on stderr could be read as the version, and the
   reported server version was whatever the last line happened to be. `_run_split`
   now keeps the streams apart, and the engine counts as reachable only if the
   CLI exits zero *and* prints something on stdout that is actually a version.
   The failure reason is the CLI's own message, not an assumed "daemon not
   running".
6. **Results accumulated in a module-level list**, so a second run in the same
   interpreter saw the first run's verdicts mixed into its own. Results now
   belong to the `Report` they were recorded on.
7. **The write probe judged refusal by message text** (`"append-only" in
   message`), which let any error that happened to contain that phrase pass as
   enforcement. It now requires `sqlstate == '23001'`.
8. **The probe was unscoped.** `DELETE FROM <table>` with no `WHERE` would have
   targeted every row had the trigger not fired. Each probe is now scoped by
   `ctid` and touches at most one row, and both `UPDATE` and `DELETE` are probed
   rather than `DELETE` alone.

Tests that encoded "Docker is unreachable" as a premise rather than a condition
now manufacture that state (a `PATH` whose `docker` always fails), so they assert
the intended behaviour in any environment. Tests that need a real server decide
whether to run by **connecting**, not by inspecting configuration, and skip when
nothing is reachable — so the suite asserts the same thing on a laptop and on a
CI runner with a service container.

### 24.6 One application defect found, and fixed

The trigger **worked** — every write was refused — but the guard function's
error message was malformed. `audit_append_only_guard` built its message with
`format(...)`, and the format string contained bare `%` characters that
PostgreSQL interprets as conversion specifiers:

```sql
RAISE EXCEPTION USING
    ERRCODE = 'restrict_violation',
    MESSAGE = format(
        'audit_append_only: % is append-only; % is not permitted on audit history',
        TG_TABLE_NAME, TG_OP);
```

The literal `% is` is read as a specifier (`% i` — an unknown type), so the
statement failed while *formatting the message*, before the intended
`restrict_violation` was ever raised. Observed on every one of the eight tables:

```text
ERROR:  unrecognized format() type specifier " "
HINT:  For a single "%" use "%%".
CONTEXT: PL/pgSQL function audit_append_only_guard() line 3 at RAISE
SQLSTATE: 22023     <-- invalid_parameter_value, not 23001 restrict_violation
```

Why this mattered, stated plainly: the append-only guarantee held — the
transaction aborted and no row was modified. What was wrong was the *error*. A
caller saw a generic parameter-formatting error naming neither the table nor the
operation, under SQLSTATE `22023` instead of the intended `23001`. That made a
deliberate, correct refusal indistinguishable from a bug, and defeated any
monitoring, alerting or retry logic keyed on the SQLSTATE.

**The fix** is revision `phase2_step12_guard_sqlstate_fix`
(`backend/alembic/versions/phase2_step12_guard_sqlstate_fix.py`), which
`CREATE OR REPLACE FUNCTION`s the guard with `%s` in place of the bare `%`:

```text
ERROR:  audit_append_only: auth_audits is append-only; DELETE is not permitted on audit history
SQLSTATE: 23001
```

Scope of the change, deliberately minimal:

* Only the function body is replaced. The eight triggers are untouched and still
  point at the same function name, so no table DDL is involved at all.
* `ERRCODE` remains `restrict_violation` (**23001**). The protection is not
  weakened; only the template is corrected.
* `INSERT` remains untouched, so audit recording is unaffected.
* Step 12's own migration is **not** edited. It is already applied, so rewriting
  it would make the recorded history disagree with the database it describes.
  `downgrade()` reinstates its exact previous body, which is inherent to
  reversing to it.
* The dialect gate is unchanged: a no-op on SQLite, MySQL and SQL Server.

Verified by execution against PostgreSQL 16.15 — `UPDATE` and `DELETE` are
refused with `23001` on all eight tables, the message names both the table and
the refused operation, and `INSERT` is still accepted (the probe rows are
written inside a transaction that is rolled back, since an append-only table
cannot be cleaned afterwards). A test installs the *old* body and asserts it
reproduces `22023`, so the migration cannot end up "fixing" a defect that never
existed.

The harness now judges refusal on `sqlstate == '23001'` rather than on message
wording, which is the stricter check: any other error — a missing table, a
broken connection, a foreign-key violation — can no longer pass as
"append-only enforced".

### 24.7 Running the PostgreSQL-gated concurrency tests (Step 42)

Step 41's response-approval hardening covers two properties, and they are
deliberately kept apart.

* The **state-machine** guard — a second decision made after the first has
  committed is refused — is asserted on the default SQLite fixture and passes
  everywhere.
* The **row-lock** guard — two decisions that genuinely *overlap* cannot both
  be accepted — needs a database that honours `SELECT ... FOR UPDATE`. SQLite
  silently drops the clause, so on that fixture the property is **measured and
  skipped, never claimed**. A test asserts the compiled SQL really contains no
  `FOR UPDATE`, so the limitation cannot quietly become false confidence.

To execute the row-lock tests for real, point `VERIFY_RUNTIME_DATABASE_URL` at a
reachable PostgreSQL and run the Step 41 suite:

```bash
# from backend/
export VERIFY_RUNTIME_DATABASE_URL="postgresql://secuser:<password>@127.0.0.1:5432/security_platform"
python -m pytest tests/test_response_approval_step41.py -v
```

Expected result: the two `test_postgres_overlapping_*` tests run instead of
skipping. With no `VERIFY_RUNTIME_DATABASE_URL` — or no reachable server — both
skip with an explicit reason, exactly like the harness in A24.3. The tests never
pass on the strength of a database that is not there.

Isolation is structural, not incidental. Each run creates a schema named from
`risk_race_test_<pid>_<random>`, creates the application tables inside it, and
drops that schema on teardown. Nothing outside that name — no table, row or
schema in `public` or anywhere else — is written, altered or dropped, and the
application's own engine is never touched. The driver is normalized to
`postgresql+psycopg` so the documented plain `postgresql://` URL works with the
installed driver.

The race is driven by events rather than sleeps. The first decision is suspended
after it has read the row and is holding its lock; the competing decision then
blocks on that lock, and the suite waits for the *observable* fact of a blocked
`pg_locks.transactionid` entry before releasing the first. The verdict is then
checked against the stored row and the audit records, not only the return value.

The same suite on SQLite (no `VERIFY_RUNTIME_DATABASE_URL`) reports:

```text
21 passed, 4 skipped
```

where the skips are the two `FOR UPDATE` documentation tests and the two
PostgreSQL-gated tests.

## 25. Read-only response audit history (Step 42A)

Step 42A exposes one action's audit history as its own bounded, read-only
surface and shows it in the response workspace.

The endpoint is `GET /api/v2/responses/{action_id}/audit`. It requires
`READ_RESPONSES` (the permission every existing role already holds), and it
reuses no new permission. It reads one action at a time — there is no global
or cross-action feed — and returns:

```json
{
  "action_id": "...",
  "incident_id": "...",
  "entries": [],
  "total": 0,
  "limit": 50,
  "offset": 0,
  "truncated": false
}
```

`limit` defaults to 50 and is capped at 200; `offset` defaults to 0.
`entries` are ordered by `created_at` then `id` so the order is stable when
two rows share a timestamp. `total` counts every audit row for the action,
and `truncated` is true exactly when `offset + len(entries) < total`. An
unknown action id returns 404 with code `RESPONSE_NOT_FOUND`.

Reading the history changes nothing: the handler performs no state
transition, calls nothing like `expire_due()`, and writes no audit row. It
exposes only the stored `actor` — no `request_id` and no identity
enrichment — and each entry's optional `detail` is present only where the
database already recorded one, which is a rejection. An approval,
cancellation or execution entry therefore never carries a rationale, so the
execute path cannot surface a reason it never had.

This is the first endpoint on a new `/api/v2` prefix. Mounting it leaves v1
untouched: v1 still serves every route it served before, and v2 carries only
this one. There is no schema or migration change.

In the frontend, the workspace audit section loads this endpoint rather than
the detail payload, showing `loading`, `denied` (403), `error` and `ready`
states and Previous/Next controls for pages beyond the first. The section is
display-only; it adds no approve, reject, cancel, execute or delete control.

Focused tests:

```powershell
# from backend/
python -m pytest tests/test_response_audit_step42.py -v
```

```text
19 passed
```

and, in `frontend/`:

```text
npx vitest run src/pages/Step42_audit_history.test.tsx
```

## 26. Audit integrity, response timeline and accountability (Phase 4, Steps 43-45)

Steps 43-45 verify, harden and surface the controlled-response audit trail.
None of them adds storage or a write path: every surface here reads rows the
platform already wrote.

### 26.1 Step 43 - audit integrity (verification, no behaviour change)

Step 43 shipped no production change. It is a regression suite that pins the
integrity properties the response audit already depends on: the event
vocabulary is closed (`RESPONSE_AUDIT_EVENTS`), transitions record only
vocabulary events with a consistent `previous_status -> new_status` chain,
rejection reasons are trimmed and sanitized (a blank reason becomes absent,
an overlong reason is a 422), a rationale is attached only to a rejection, a
refused transition writes no row and leaks no traceback, `request_id` is
never returned, an unsafe inbound `X-Request-ID` is replaced with a fresh
opaque id, and audit reads are incident-scoped and repeatable.

`backend/tests/test_audit_integrity_step43.py`:

```text
17 passed
```

### 26.2 Step 44 - response lifecycle in the incident timeline

`GET /api/v1/incidents/{id}/timeline` now interleaves the action lifecycle
with the existing observation and event entries. `TimelineEntry` gained
optional `action_id`, `action_type`, `event`, `actor`, `previous_status` and
`new_status`; response entries carry `kind: "response"`. They are appended
only for callers who hold `READ_RESPONSES`, bounded to the most recent
`max_entries`, with the `action_type` resolved in a single batched lookup so
the timeline stays free of N+1 queries. Ordering is a deterministic total
order, so repeated reads agree. The frontend renders these with an `info`
badge, the action type and the action id as plain text - no new deep link and
no new control.

Focused tests:

```text
python -m pytest tests/test_incident_timeline_response_step44.py   # 12 passed
npx vitest run src/pages/Step44_timeline_response.test.tsx         # 3 passed
```

### 26.3 Step 45 - incident accountability feed

`GET /api/v1/incidents/{id}/activity` is the accountability view: the
append-only controlled-response lifecycle rows for one incident, ordered by
`created_at` then `id`. It requires both `READ_INCIDENTS` and
`READ_RESPONSES`, returns 404 `INCIDENT_NOT_FOUND` for an unknown incident,
and is strictly read-only - no state transition, no expiry sweep, no audit
write.

```json
{
  "incident_id": "...",
  "incident_key": "...",
  "items": [],
  "total": 0,
  "limit": 50,
  "offset": 0,
  "truncated": false,
  "filters": { "event": null, "actor": null }
}
```

Filters are exact matches applied server-side and echoed back in `filters`:
`event` (validated against the closed vocabulary, otherwise 422), `actor`
(<=128), `action_id` (<=64), and `since`/`until` (naive UTC). `limit`
defaults to 50 and is capped at 200; `offset` defaults to 0; `truncated` is
true exactly when `offset + len(items) < total`. Each item exposes only the
stored fields - `id`, `action_id`, `action_type`, `event`, `actor`,
`previous_status`, `new_status`, `policy_version`, `created_at` and the
optional rejection `detail` - never `request_id`.

In the workspace the "Accountability activity" section shows the rows in a
bounded table with the event, actor, action type/id and status transition,
plus exact-match event/actor/time filters and Previous/Next paging. It adds
no write control.

Focused tests:

```text
python -m pytest tests/test_incident_activity_step45.py   # 18 passed
npx vitest run src/pages/Step45_incident_activity.test.tsx # 6 passed
```

### 26.4 Step 46 - operational readiness

Step 46 re-ran the whole surface and recorded the result rather than
asserting it: backend `1082 passed, 14 skipped, 0 failed`; frontend
`231 passed` with the one long-standing parallel-load flake
(`Step33_workspace_foundation.test.tsx`) passing in isolation; `ruff check`
clean apart from two pre-existing errors in `test_risk_consistency.py`; and a
clean production build. No migration, no schema change and no write path was
added by Steps 43-45.

## 27. Incident accountability operations (Phase 4, Steps 47-51)

Steps 42-46 delivered three read-only views over the append-only controlled
response audit. Steps 47-49 then hardened and *verified* those contracts
(parameter bounds, cross-surface consistency, incident lifecycle integrity),
and Step 51 records how they are operated. Nothing here adds a write path, a
migration or a schema change: every surface reads the same `response_audit`
rows that Steps 41-42 already wrote, and the incident trail reads the
`incident_audit` rows from Step 17.

### 27.1 The three accountability read surfaces

| Surface | Endpoint | Permission | Scope | Ordering |
| --- | --- | --- | --- | --- |
| Per-action audit (v2) | `GET /api/v2/responses/{action_id}/audit` | `READ_RESPONSES` | one response action | `created_at, id` |
| Incident timeline | `GET /api/v1/incidents/{id}/timeline` | `READ_INCIDENTS` (+`READ_RESPONSES` for response entries) | one incident, all entry kinds | `at`, then a fixed rank tiebreak |
| Incident activity | `GET /api/v1/incidents/{id}/activity` | `READ_INCIDENTS` **and** `READ_RESPONSES` | one incident's response lifecycle | `created_at, id` |

All three are strictly read-only: they transition nothing, run no expiry
sweep and write no audit row of their own. Pagination defaults to `limit=50`
capped at `200` with `offset>=0`; `truncated` is `true` exactly when
`offset + len(page) < total`, and `total` is computed before pagination.
Unknown ids reuse the stored conventions (`RESPONSE_NOT_FOUND`,
`INCIDENT_NOT_FOUND`). No entry exposes the internal `request_id`.

### 27.2 One source, verified consistent

The per-action audit, the timeline's `kind == "response"` entries and the
activity feed are three projections of the *same* `response_audit` table, so a
row must read identically everywhere. Step 48 pins that: the shared fields
(`event`, `actor`, `previous_status`, `new_status`, `policy_version`,
`created_at`, `detail`) and the order are identical between the v2 feed and the
activity feed, the timeline agrees field-for-field, no surface invents a
transition a still-pending action never had, and a rejection rationale is
byte-identical between the v2 audit and the activity feed while being
deliberately *not* duplicated onto the timeline (its `detail` is a derived
`actor: old -> new` string). The rationale stays on the per-action audit and
the activity feed only.

### 27.3 Query-contract hardening (Step 47)

Step 47 adds regression tests for the activity endpoint's boundaries and
precedence rather than changing it: `actor<=128` and `action_id<=64` accept the
exact maximum and reject one more with a `422 VALIDATION_ERROR`; a malformed
`since`/`until` is a `422`; a timezone-carrying window is normalised to naive
UTC before comparison, so an offset instant filters correctly; several filters
combine and narrow both `items` and `total`; and an unknown incident is a `404`
even when the filter itself is invalid (the incident lookup precedes filter
validation).

### 27.4 Incident lifecycle trail (Step 49)

Alongside the response audit, the incident's own trail (`incident_audit`) is
covered adversarially: opening an incident appends exactly one attributed,
incident-scoped `OPENED` row and no row is visible under another incident; an
accepted status sequence appends a coherent `STATUS_CHANGED` chain with no gap;
a refused transition (unknown status or a forbidden edge) is a `422
INVALID_TRANSITION` that writes no row and leaves the incident untouched; a
no-op edit appends nothing; the stored actor is bounded to the column and
defaults to `system`; reading the timeline is inert and repeatable; and an
unrecognised stored action still renders as the generic `audit` kind with the
full entry contract. Both trails are append-only at the ORM layer (Step 11)
and, on PostgreSQL, at the database layer (Step 12).

### 27.5 Operating the surfaces

Read the per-action audit (`/api/v2/.../audit`) when a reviewer needs the full
rationale for one decision - it is the only surface that carries the stored
rejection `detail`. Read the incident activity feed when reconstructing what
happened across an incident's actions: filter by exact `event`, `actor`,
`action_id` and a `since`/`until` window, then page. Read the incident timeline
for a single merged chronology of observations, evidence events, incident
lifecycle changes and (for callers who may read responses) response lifecycle
entries. Access is split so a caller may see incidents without thereby seeing
controlled-response history.

### 27.6 Verification

```text
python -m pytest tests/test_incident_activity_contract_step47.py   # 7 passed
python -m pytest tests/test_audit_history_consistency_step48.py    # 5 passed
python -m pytest tests/test_incident_audit_integrity_step49.py     # 7 passed
```

Steps 47-49 are test-only; the related audit/incident/timeline suites remain
green and `ruff check` is clean. Step 50 (frontend accountability refinement)
was later delivered: once the Node 26 toolchain became available, `vitest`,
`tsc` and the production build all ran and pass, so the refinement shipped
(see §9 for the current totals and §28 for the recorded baseline).

### 27.7 Boundaries, stated plainly

- These read surfaces are read-only views. They are not themselves
  tamper-evidence: append-only enforcement comes from the ORM guard (Step 11)
  and the PostgreSQL triggers plus a restricted role (Step 12), and the
  documented `TRUNCATE`/`DROP TABLE`/superuser boundary there still applies.
- There is no global or cross-incident response feed, and no free-text search
  or identity enrichment - filters are exact matches on stored values only.
- Same-second audit rows share `created_at`; the returned order then falls to
  the `id` (UUID) tiebreak, so *insertion* order is not recoverable when
  timestamps collide. The order is deterministic, but not insertion-ordered.

## 28. Release verification baseline (Phase 4, Steps 52-55; historical snapshot)

This section records the repeatable verification that establishes the release
baseline for the Network Scanner at the close of Phase 4, together with the
results observed when it was run for this step. Re-run the blocks top to bottom;
a release is checked against the recorded results.

The counts below are a **historical snapshot** captured at Steps 52-55, before
Steps 56-64. Those later steps added tests without changing this method, so the
current totals differ: see §9 for the live figures (backend 1,131 passed /
14 skipped / 0 failed; frontend 246 passed across 39 files). The commands, the
ruff note and the Node 26 caveat below remain current.

Backend (from `backend/`):

```bash
python -m ruff check app tests     # 2 pre-existing findings only (see note)
python -m pytest                   # 1116 passed, 14 skipped, 0 failed
```

Frontend (from `frontend/`), with the Node 26 flag below:

```bash
$env:NODE_OPTIONS="--no-experimental-webstorage"   # PowerShell
npm run test                       # 233 passed across 38 files
npm run lint                       # tsc --noEmit, exit 0
npm run build                      # tsc + vite build, exit 0
```

Recorded baseline (recorded at Steps 52-55):

- `python -m pytest` - **1116 passed, 14 skipped, 0 failed**. The 14 skips are
  environment-gated: they require a live PostgreSQL (for example the Step 42
  concurrency checks, §24.7), and they pass when the compose database is present.
- `python -m ruff check app tests` - **two pre-existing findings only**, both in
  `backend/tests/test_risk_consistency.py` (an unused `select` import and an
  import block flagged for order). Both predate Phase 4 and are untouched by it;
  they are left as-is rather than masked, so the gate stays honest.
- `npm run test` - **233 tests across 38 files, 0 failed** (Vitest, jsdom).
- `npm run lint` and `npm run build` - **exit 0** (`tsc --noEmit`, then
  `tsc --noEmit && vite build`).

Node 26 caveat (read before running the frontend block): Node 26 defines an
experimental global `localStorage` that is `undefined` and shadows jsdom's, so
`window.localStorage.clear()` throws in `src/pages/Step20.test.tsx`. Run the
suite with `NODE_OPTIONS=--no-experimental-webstorage`; the flag removes only the
shadowing global and changes no test. On older Node it is unnecessary.

Deployment baseline: the container + PostgreSQL harness of §24 remains the
deployment-level release check (`python scripts/verify_runtime.py ...` - 36
passed). It and the PostgreSQL-gated concurrency tests need the compose stack and
are not part of the unit-suite baseline above.

Phase 4 close: Steps 47-49 and 52-54 are verification-only (they add tests or
documentation and change no production behaviour); Step 50 refined the incident
accountability UI (§27.6 recorded it as deferred for lack of a Node runtime - that
blocker was resolved and the refinement shipped); Step 51 documented operations
(§27). This section is the snapshot a future release diff is measured against.
#   N e t w o r k - S c a n n e r  
 