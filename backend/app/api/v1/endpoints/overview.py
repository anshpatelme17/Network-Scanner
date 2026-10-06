"""SOC overview endpoint (Phase 2, Step 9).

Read-only dashboard roll-up. Adds no detection, scoring or correlation
logic: it aggregates rows the platform already stores, and derives priority
with the existing Step 25 band function. See
:mod:`app.services.soc_overview` for the guarantees.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.v1.auth_deps import require_permission
from app.database.session import get_db
from app.schemas.soc import SocOverviewResponse
from app.services import soc_overview
from app.services.auth_service import AuthContext

router = APIRouter(prefix="/overview", tags=["overview"])


@router.get("", response_model=SocOverviewResponse, summary="SOC overview (read-only)")
def get_soc_overview(
    limit: int = Query(
        default=soc_overview.DEFAULT_ITEMS,
        ge=1,
        le=soc_overview.MAX_ITEMS,
        description="Maximum rows per list in the overview. Capped server-side.",
    ),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_permission("READ_INCIDENTS")),
):
    """Aggregate stored security state for a dashboard.

    The only caller-supplied value is ``limit``, which is validated and then
    clamped again server-side. Identity, permissions, severity, priority and
    ordering are decided on the server; the response is counts, identifiers,
    enums, scores and timestamps only.
    """
    return soc_overview.build_overview(db, limit=limit)
