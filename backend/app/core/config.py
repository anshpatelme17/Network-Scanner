"""Environment-based application configuration.

All settings are read from environment variables (and an optional ``.env``
file in development). No secrets are hardcoded. See ``.env.example``.

Step 31 hardening: the settings surface itself is a security boundary, so
parsing is deterministic and fail-closed. Unknown environment names are
rejected, the CORS list may never contain a wildcard, and
``validate_production`` refuses to let a deployment start with
development assumptions (placeholder or short secrets, debug on, wildcard
or dev-origin CORS, unbounded database pool). Secret *values* are never
included in any error message — only the name of the offending variable.
"""

import json
from functools import lru_cache

from pydantic import Field, ValidationInfo, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Step 31: closed vocabulary for ENVIRONMENT. An unrecognised value is a
# configuration mistake, and silently coercing it to something else is how
# a production deployment ends up running with development defaults.
ENV_DEVELOPMENT = "development"
ENV_TEST = "test"
ENV_STAGING = "staging"
ENV_PRODUCTION = "production"
ENVIRONMENTS = (ENV_DEVELOPMENT, ENV_TEST, ENV_STAGING, ENV_PRODUCTION)

# Development-only CORS defaults. Production must not fall back to them.
DEV_CORS_ORIGINS = ("http://localhost:5173", "http://localhost:3000", "http://localhost")


MIN_SECRET_KEY_LENGTH = 32
PLACEHOLDER_SECRETS = frozenset(
    {"", "CHANGE_ME_dev_only", "changeme", "secret", "change_me", "changeme_in_env"}
)


class Settings(BaseSettings):
    """Application settings loaded from the environment."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        # Step 31: accept a plain comma-separated value for the list
        # settings instead of requiring JSON. Without this, an operator
        # writing `TRUSTED_HOSTS=` (an empty value) would get a
        # SettingsError before the validators below ever run. JSON is
        # still accepted, because a JSON list is decoded first and then
        # handed to the same validator.
        enable_decoding=False,
    )

    app_name: str = Field(default="Security Platform", description="Application name")
    environment: str = Field(default="development", description="deployment environment")
    debug: bool = Field(default=False, description="Enable debug mode")
    api_host: str = Field(default="0.0.0.0", description="API bind host")  # noqa: S104
    api_port: int = Field(default=8000, description="API bind port")
    api_v1_prefix: str = Field(default="/api/v1", description="Versioned API prefix")

    database_url: str = Field(
        default="postgresql+psycopg://secuser:changeme_in_env@db:5432/security_platform",
        description="SQLAlchemy database URL",
    )

    log_level: str = Field(default="INFO", description="Logging level")

    # Used for future auth/session signing. No default secret in code paths
    # that matter: production refuses to start with the placeholder.
    secret_key: str = Field(default="CHANGE_ME_dev_only", description="Secret key")

    backend_cors_origins: list[str] = Field(
        default_factory=lambda: list(DEV_CORS_ORIGINS),
        description="Allowed CORS origins (never a wildcard)",
    )

    # Step 31: optional Host header allow-list. Empty (the default) keeps
    # the current behaviour so the development workflow is unchanged;
    # setting it enables strict Host validation. Production deployments
    # behind a known hostname should set it.
    trusted_hosts: list[str] = Field(
        default_factory=list,
        description="Allowed Host header values (empty disables Host validation)",
    )

    # Step 14: explicit scan authorization scope. Comma-separated CIDRs;
    # a scan target must fall inside one of them. Default is loopback
    # only — widen deliberately per deployment, never by default.
    scan_allowed_networks: str = Field(
        default="127.0.0.1/32,::1/128",
        description="CIDR allow-list for Nmap scan targets",
    )

    # Step 21: configurable maximum discovery scope (addresses per
    # request). Conservative default: a /24 (256 addresses) is the
    # largest single discovery. Lower per deployment, never raise
    # without authorization to cover the wider scope.
    discovery_max_addresses: int = Field(default=256, description="Max addresses per discovery")

    # Step 24: configurable cap on correlation rule windows (minutes).
    # Effective window = min(rule window, this cap), hard-ceiled at 7
    # days so history scans stay bounded. Conservative default equals
    # the widest rule window (vuln-exposure, 24 h).
    correlation_max_window_minutes: int = Field(
        default=1440, description="Max correlation rule window in minutes"
    )

    # Step 26: live event-connector configuration. All empty by default
    # (secure default: nothing is connected). File paths point at local
    # EVE/log files the operator provisions; API credentials come only
    # from the environment and are never returned by any endpoint.
    suricata_eve_path: str = Field(default="", description="Local Suricata EVE JSON file")
    zeek_log_path: str = Field(default="", description="Local Zeek JSON log file")
    wazuh_api_url: str = Field(default="", description="Wazuh API base URL")
    wazuh_username: str = Field(default="", description="Wazuh API username")
    wazuh_password: str = Field(default="", description="Wazuh API password")
    defender_tenant_id: str = Field(default="", description="Defender tenant ID")
    defender_client_id: str = Field(default="", description="Defender client ID")
    defender_client_secret: str = Field(default="", description="Defender client secret")

    # Step 27: controlled live-API connector foundation. Conservative
    # defaults everywhere; every destination is derived from these
    # settings (never from client input) and enforced by the shared HTTP
    # layer's host allow-list. Empty credentials = NOT_CONFIGURED; the
    # server never attempts a connection for an unconfigured connector.
    defender_api_endpoint: str = Field(
        default="https://graph.microsoft.com/v1.0",
        description="Microsoft Graph base URL for Defender alert retrieval",
    )
    defender_authority: str = Field(
        default="https://login.microsoftonline.com",
        description="OAuth2 authority used for the client-credentials token",
    )
    connector_timeout_seconds: float = Field(
        default=10.0, ge=1.0, le=60.0, description="Per-request timeout for connector HTTP calls"
    )
    connector_max_response_bytes: int = Field(
        default=1_048_576, ge=1024, description="Hard cap on a single connector HTTP response body"
    )
    connector_max_pages: int = Field(
        default=3, ge=1, le=20, description="Maximum pages per connector poll"
    )
    connector_max_events: int = Field(
        default=100, ge=1, le=1000, description="Maximum events retrieved per connector poll"
    )
    connector_retry_max: int = Field(
        default=1, ge=0, le=3, description="Safe retries (GET only) on 429/503/timeout"
    )
    connector_verify_tls: bool = Field(
        default=True, description="Verify TLS certificates for connector HTTPS calls"
    )

    # Phase 2 Step 5: controlled polling policy. Disabled by default and
    # still scheduler-free: nothing here starts a thread, timer or daemon.
    # `connector_auto_poll_enabled` only permits an operator-invoked
    # "poll whatever is due" pass (see app/services/connector_polling.py);
    # with it false, every poll remains an explicit human action.
    connector_auto_poll_enabled: bool = Field(
        default=False,
        description="Permit the due-poll pass to run; off by default, never schedules itself",
    )
    connector_poll_interval_seconds: float = Field(
        default=300.0,
        ge=30.0,
        le=86400.0,
        description="Minimum spacing between two polls of the same connector",
    )
    connector_failure_cooldown_seconds: float = Field(
        default=60.0,
        ge=0.0,
        le=3600.0,
        description="Cool-down applied after a failed poll so a failing source is not hammered",
    )

    # Step 28: bounded ingestion pipeline. Every poll is a deterministic
    # upper bound: at most connector_max_pages pages / connector_max_events
    # records, split into batches of ingestion_max_batch_size, offered to an
    # in-process queue capped at ingestion_queue_max (overflow rejects the
    # new record and is audited — never silent). Transient fetch failures
    # (timeout/connection) are retried at most ingestion_retry_max extra
    # times with linear backoff; authentication and configuration failures
    # are never retried. No scheduler, no daemon, no automatic polling.
    ingestion_max_batch_size: int = Field(
        default=50, ge=1, le=500, description="Max records processed per ingestion batch"
    )
    ingestion_queue_max: int = Field(
        default=500, ge=1, le=10_000, description="Max records held in the in-process ingest queue"
    )
    ingestion_retry_max: int = Field(
        default=1, ge=0, le=3, description="Extra bounded attempts for transient fetch failures"
    )
    ingestion_retry_backoff_seconds: float = Field(
        default=0.25, ge=0.0, le=5.0, description="Linear backoff between ingest fetch retries"
    )
    # File sources: offset resume is OFF by default so repeated bounded
    # polls keep re-reading the window (Step 26/27 idempotent replay,
    # dedup absorbs repeats). Rotation/truncation detection is active in
    # both modes; enabling resume only changes where the read starts.
    connector_file_resume: bool = Field(
        default=False, description="Resume file-source polls at the stored byte offset"
    )

    # Step 29: deterministic incident-intelligence bounds. Every value is
    # a server-side ceiling — never accepted from a client: the three
    # Step 29 rule windows (temporal chain, cross-source group, same
    # entity) plus the hard caps on events considered per analysis
    # operation, relationships stored per incident, relationship
    # evidence entries, evidence entries and timeline entries returned.
    # correlation_disabled_rules is a server-side CSV of rule ids
    # (existing Step 24 and Step 29 catalogs); unknown ids are ignored.
    correlation_temporal_window_minutes: int = Field(
        default=60, ge=1, le=10080, description="Max window between temporal chain events"
    )
    correlation_cross_source_window_minutes: int = Field(
        default=60, ge=1, le=10080, description="Max window for cross-source observation groups"
    )
    correlation_entity_window_minutes: int = Field(
        default=5, ge=1, le=1440, description="Max window for same-entity (source+target) pairs"
    )
    correlation_max_events_per_operation: int = Field(
        default=200, ge=1, le=5000, description="Max events considered per analysis operation"
    )
    correlation_relationship_max: int = Field(
        default=200, ge=1, le=5000, description="Max relationships stored per incident"
    )
    correlation_relationship_evidence_max: int = Field(
        default=20, ge=1, le=200, description="Max evidence event ids stored per relationship"
    )
    correlation_evidence_max: int = Field(
        default=200, ge=1, le=2000, description="Max evidence entries returned per incident"
    )
    correlation_timeline_max_entries: int = Field(
        default=500, ge=10, le=5000, description="Max timeline entries returned per incident"
    )
    correlation_disabled_rules: str = Field(
        default="", description="CSV of correlation rule ids disabled by the operator"
    )

    # Step 20: authentication foundation. Enforcement activates once at
    # least one user exists; with an empty user table the API runs in
    # documented bootstrap mode (legacy open access) so the first ADMIN
    # can be created. REQUIRE_AUTH disables bootstrap mode entirely.
    require_auth: bool = Field(default=False, description="Disable auth bootstrap mode")
    access_token_minutes: int = Field(default=15, description="JWT access-token lifetime")

    # Step 30: controlled defensive response governance. Every value is a
    # server-side ceiling or policy switch — never accepted from a client.
    # Defensive actions are temporary by default: an approved action may
    # never outlive response_max_ttl_minutes, and response_default_ttl_
    # minutes is the TTL a request gets when the caller does not ask for
    # one. There is no unlimited-TTL option and no permanent-block mode.
    # response_provider names the single registry entry used for
    # execution; "MOCK" is the only value that performs anything at all,
    # and what it performs is a platform-side record (never an external
    # system change). "NOT_CONFIGURED" refuses every consequential action
    # with an explicit reason, which is the default posture for any real
    # Microsoft Defender / firewall / endpoint / cloud integration.
    response_max_ttl_minutes: int = Field(
        default=1440, ge=1, le=10080, description="Hard ceiling on a defensive action TTL"
    )
    response_default_ttl_minutes: int = Field(
        default=60, ge=1, le=10080, description="TTL applied when a request does not specify one"
    )
    response_allow_self_approval: bool = Field(
        default=False, description="Allow the requester to also approve a consequential action"
    )
    response_max_actions_per_incident: int = Field(
        default=50, ge=1, le=500, description="Max controlled responses stored per incident"
    )
    response_target_evidence_required: bool = Field(
        default=True, description="Require stored incident evidence to support a target"
    )
    response_provider: str = Field(
        default="MOCK", description="Registry name of the provider allowed to execute responses"
    )

    # Step 31: bounded connection pool. Every value is a server-side
    # ceiling. pool_size is steady-state connections, max_overflow is the
    # hard burst ceiling (so total connections can never exceed
    # pool_size + max_overflow), pool_timeout is how long a caller waits
    # for a connection before failing with a controlled error, and
    # pool_recycle retires connections before an intermediary can drop
    # them. These are ignored for SQLite (single-file, no pool).
    db_pool_size: int = Field(
        default=10, ge=1, le=200, description="Steady-state database pool size"
    )
    db_max_overflow: int = Field(
        default=10, ge=0, le=200, description="Extra connections allowed beyond the pool"
    )
    db_pool_timeout_seconds: float = Field(
        default=10.0, ge=1.0, le=120.0, description="Seconds to wait for a pooled connection"
    )
    db_pool_recycle_seconds: int = Field(
        default=1800, ge=60, le=86400, description="Recycle connections after this age"
    )
    db_connect_timeout_seconds: int = Field(
        default=10, ge=1, le=120, description="Seconds to wait when opening a new connection"
    )
    db_statement_timeout_ms: int = Field(
        default=15000, ge=0, le=600000, description="Per-statement timeout in ms (0 = off)"
    )

    # Step 31: bounded HTTP resource protection. max_request_bytes caps
    # the declared request body before it is buffered (0 disables the
    # check, which only makes sense behind a proxy that already caps it).
    max_request_bytes: int = Field(
        default=1_048_576, ge=0, le=67_108_864, description="Max request body size in bytes"
    )
    # Deterministic fixed-window request budgets for the expensive
    # operations (correlation recompute, incident analysis, risk
    # calculation, connector polling, controlled response governance,
    # scan/discovery starts).
    # Expressed as requests per window, per calling identity.
    rate_limit_window_seconds: int = Field(
        default=60, ge=1, le=3600, description="Fixed rate-limit window length"
    )
    rate_limit_recompute: int = Field(
        default=120, ge=0, description="Correlation recompute requests per window per identity"
    )
    rate_limit_recalculate: int = Field(
        default=120, ge=0, description="Incident recalculate requests per window per identity"
    )
    rate_limit_risk_calculate: int = Field(
        default=120, ge=0, description="Risk calculate requests per window per identity"
    )
    rate_limit_connector_poll: int = Field(
        default=60, ge=0, description="Connector poll requests per window per identity"
    )
    rate_limit_response_governance: int = Field(
        default=300, ge=0, description="Controlled response writes per window per identity"
    )
    rate_limit_scan_start: int = Field(
        default=60, ge=0, description="Scan/discovery start requests per window per identity"
    )
    # Failed logins are counted, not attempts: a correct password must never
    # be throttled, so legitimate operators and services are unaffected while
    # password guessing is bounded.
    rate_limit_login_failures: int = Field(
        default=5, ge=0, description="Failed login attempts per window per caller before 429"
    )
    # How many distinct caller/window buckets are remembered. Bounded so
    # the limiter's own memory is a fixed ceiling, not a function of
    # attacker-supplied keys.
    rate_limit_max_buckets: int = Field(
        default=10_000, ge=16, le=1_000_000, description="Max tracked rate-limit buckets"
    )

    @field_validator("environment")
    @classmethod
    def _normalize_environment(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in ENVIRONMENTS:
            raise ValueError(f"environment must be one of {', '.join(ENVIRONMENTS)}")
        return normalized

    @field_validator("backend_cors_origins", "trusted_hosts", mode="before")
    @classmethod
    def _reject_wildcard_and_empty(cls, value: object, info: ValidationInfo) -> object:
        """A wildcard or blank entry is always a mistake, in any environment.

        Rejecting it here (not only in production) means a bad value fails
        at parse time with a clear message rather than quietly widening the
        policy to every origin. Accepts a JSON list, a Python list, or a
        comma-separated string, so both `["https://a"]` and
        `https://a,https://b` are valid in a `.env` file.
        """
        if value is None:
            return []
        if isinstance(value, str):
            raw = value.strip()
            if not raw:
                return []
            if raw.startswith("["):
                try:
                    parsed = json.loads(raw)
                except ValueError:
                    raise ValueError(
                        f"{info.field_name} is not valid JSON. Use a comma-separated list "
                        "such as https://a.example,https://b.example"
                    ) from None
            else:
                parsed = [item for item in raw.split(",") if item.strip()]
        elif isinstance(value, list | tuple | set):
            parsed = list(value)
        else:
            raise ValueError(f"{info.field_name} must be a list or a comma-separated string.")
        entries = [str(item).strip() for item in parsed]
        for entry in entries:
            if entry in ("*", "null"):
                raise ValueError(f"{info.field_name} must list explicit origins, never a wildcard.")
            if not entry:
                raise ValueError(f"{info.field_name} entries must not be blank.")
        return entries

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        level = value.strip().upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if level not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}")
        return level

    @property
    def is_production(self) -> bool:
        return self.environment == ENV_PRODUCTION

    def validate_production(self) -> None:
        """Fail fast on unsafe production configuration (Step 31 hardened).

        Every message names the *variable* to fix and never echoes the
        offending value, so a misconfiguration cannot leak a secret into
        a log aggregator, a crash report, or a terminal scrollback.
        """
        if not self.is_production:
            return
        if self.debug:
            raise RuntimeError("DEBUG must be false in production.")
        if self.secret_key.strip().lower() in PLACEHOLDER_SECRETS:
            raise RuntimeError("SECRET_KEY must be set to a strong random value in production.")
        if len(self.secret_key) < MIN_SECRET_KEY_LENGTH:
            raise RuntimeError(
                f"SECRET_KEY must be at least {MIN_SECRET_KEY_LENGTH} characters in production."
            )
        if "changeme" in self.database_url.lower():
            raise RuntimeError("DATABASE_URL still contains a placeholder password.")
        # A production deployment must not silently inherit the
        # development browser origins.
        if not self.backend_cors_origins:
            raise RuntimeError(
                "BACKEND_CORS_ORIGINS must list the deployed frontend origins in production."
            )
        dev_only = {origin for origin in DEV_CORS_ORIGINS}
        if dev_only.issubset(set(self.backend_cors_origins)):
            raise RuntimeError(
                "BACKEND_CORS_ORIGINS still contains only development origins in production."
            )
        # Unbounded fan-out is a production incident waiting to happen. The
        # per-field Field bounds (le=200 each) already cap the sum at 400;
        # this documents the intent explicitly rather than duplicating it.
        if self.db_pool_size + self.db_max_overflow > 400:  # pragma: no cover
            raise RuntimeError(
                "DB_POOL_SIZE + DB_MAX_OVERFLOW must not exceed 400 total connections."
            )
        if self.max_request_bytes == 0:
            raise RuntimeError(
                "MAX_REQUEST_BYTES must be set in production (0 disables the body cap)."
            )
        # Step 10. With REQUIRE_AUTH left false, bootstrap mode stays open:
        # the first unauthenticated caller may create the first ADMIN user. That
        # is a deliberate development convenience and must never reach
        # production, where it is an unauthenticated privilege-escalation path.
        if not self.require_auth:
            raise RuntimeError(
                "REQUIRE_AUTH must be true in production (it disables the unauthenticated "
                "bootstrap that can create the first administrator)."
            )
        # Step 10. Connector credentials (Defender client secret, Wazuh
        # password, JWT tokens) travel over this connection. Disabling
        # verification turns every one of them into plaintext on the network,
        # so it is refused outright rather than merely discouraged.
        if not self.connector_verify_tls:
            raise RuntimeError(
                "CONNECTOR_VERIFY_TLS must be true in production (connector credentials are "
                "sent to third-party APIs and TLS verification must not be disabled)."
            )
        # Step 10. An empty TRUSTED_HOSTS list makes TrustedHostMiddleware a
        # no-op, which silently disables Host-header validation. Failing fast
        # is safer than running with the protection quietly off.
        if not self.trusted_hosts:
            raise RuntimeError(
                "TRUSTED_HOSTS must list the deployed hostnames in production (an empty list "
                "disables Host header validation)."
            )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    settings.validate_production()
    return settings
