"""Step 28 ingestion audit vocabulary (shared, dependency-free).

One place for the ``INGESTION_*`` actions emitted by the Step 28
pipeline. Kept in a leaf module so both ``services/connectors.py`` and
``services/ingestion.py`` can use them without an import cycle.

All actions fit the ``event_audits.action`` column (≤ 32 characters)
and are recorded through the existing append-only
``event_service.record_event_audit`` — no parallel audit system. Audit
details carry source names, counters, categories and bounds only:
never credentials, tokens, authorization headers, cookies, or response
bodies.
"""

# Ingestion lifecycle (emitted by the pipeline in services/ingestion.py).
AUDIT_INGESTION_STARTED = "INGESTION_STARTED"
AUDIT_INGESTION_BATCH_STARTED = "INGESTION_BATCH_STARTED"
AUDIT_INGESTION_BATCH_COMPLETED = "INGESTION_BATCH_COMPLETED"
AUDIT_INGESTION_BATCH_FAILED = "INGESTION_BATCH_FAILED"
AUDIT_INGESTION_CHECKPOINT_ADVANCED = "INGESTION_CHECKPOINT_ADVANCED"
AUDIT_INGESTION_CHECKPOINT_REJECTED = "INGESTION_CHECKPOINT_REJECTED"
AUDIT_INGESTION_REPLAY = "INGESTION_REPLAY"
AUDIT_INGESTION_BACKPRESSURE = "INGESTION_BACKPRESSURE"

# Fetch-level conditions (emitted by services/connectors.py, which owns
# the bounded read itself: transient retries and file-identity changes).
AUDIT_INGESTION_RETRY = "INGESTION_RETRY"
AUDIT_INGESTION_ROTATION_DETECTED = "INGESTION_ROTATION_DETECTED"

INGESTION_AUDIT_ACTIONS = (
    AUDIT_INGESTION_STARTED,
    AUDIT_INGESTION_BATCH_STARTED,
    AUDIT_INGESTION_BATCH_COMPLETED,
    AUDIT_INGESTION_BATCH_FAILED,
    AUDIT_INGESTION_CHECKPOINT_ADVANCED,
    AUDIT_INGESTION_CHECKPOINT_REJECTED,
    AUDIT_INGESTION_RETRY,
    AUDIT_INGESTION_BACKPRESSURE,
    AUDIT_INGESTION_ROTATION_DETECTED,
    AUDIT_INGESTION_REPLAY,
)

__all__ = [
    "AUDIT_INGESTION_BACKPRESSURE",
    "AUDIT_INGESTION_BATCH_COMPLETED",
    "AUDIT_INGESTION_BATCH_FAILED",
    "AUDIT_INGESTION_BATCH_STARTED",
    "AUDIT_INGESTION_CHECKPOINT_ADVANCED",
    "AUDIT_INGESTION_CHECKPOINT_REJECTED",
    "AUDIT_INGESTION_REPLAY",
    "AUDIT_INGESTION_RETRY",
    "AUDIT_INGESTION_ROTATION_DETECTED",
    "AUDIT_INGESTION_STARTED",
    "INGESTION_AUDIT_ACTIONS",
]
