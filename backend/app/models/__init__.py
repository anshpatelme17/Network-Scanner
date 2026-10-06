"""ORM models package.

Step 1: no domain tables (``Base`` only).
Step 2: asset inventory (``Asset``, ``DiscoveredService``) and controlled
Nmap scan jobs (``ScanJob``). Step 3: normalized security events
(``SecurityEvent``). Step 9: deterministic correlations over events
(``Correlation``). Step 10: deterministic risk assessments over assets,
findings and correlations (``RiskAssessment``). Step 11: incident records
over correlations/risk (``Incident``). Step 12: dry-run response proposals
and audit trail (``ResponseAction``, ``ResponseAudit``). Future stages
will add users and audit logs — one bounded context (and one migration)
at a time.

Import every model here so ``Base.metadata`` stays complete for Alembic.
"""

from app.database.base import Base  # noqa: F401
from app.models.assets import Asset, DiscoveredService  # noqa: F401
from app.models.auth import AuthAudit, RevokedToken, User  # noqa: F401
from app.models.correlations import Correlation, CorrelationAudit, CorrelationEvidence  # noqa: F401
from app.models.event_enums import Severity, SourceType  # noqa: F401
from app.models.events import SecurityEvent  # noqa: F401
from app.models.incidents import (  # noqa: F401
    Incident,
    IncidentAudit,
    IncidentEvidence,
    IncidentRelationship,
)
from app.models.ingestion import IngestionCheckpoint  # noqa: F401
from app.models.responses import (  # noqa: F401
    ResponseAction,
    ResponseAudit,
    ResponseExecution,
    ResponseRollback,
)
from app.models.risk import RiskAssessment, RiskAudit  # noqa: F401
from app.models.scans import SCAN_TYPE_NMAP, ScanAudit, ScanEvent, ScanJob, ScanStatus  # noqa: F401
from app.models.vulnerabilities import Vulnerability, VulnerabilityAudit  # noqa: F401

__all__ = [
    "Asset",
    "AuthAudit",
    "Base",
    "Correlation",
    "CorrelationAudit",
    "CorrelationEvidence",
    "DiscoveredService",
    "Incident",
    "IncidentAudit",
    "IncidentEvidence",
    "IncidentRelationship",
    "IngestionCheckpoint",
    "ResponseAction",
    "ResponseAudit",
    "ResponseExecution",
    "ResponseRollback",
    "RiskAssessment",
    "RiskAudit",
    "RevokedToken",
    "ScanAudit",
    "ScanEvent",
    "SCAN_TYPE_NMAP",
    "ScanJob",
    "ScanStatus",
    "User",
    "Vulnerability",
    "VulnerabilityAudit",
    "SecurityEvent",
    "Severity",
    "SourceType",
]
