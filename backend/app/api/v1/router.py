"""Versioned router aggregation."""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    assets,
    auth,
    connectors,
    correlations,
    defender,
    events,
    health,
    incidents,
    ingestion,
    network,
    overview,
    responses,
    risk,
    suricata,
    users,
    vuln_assessment,
    vulnerabilities,
    wazuh,
    zeek,
)

v1_router = APIRouter()
v1_router.include_router(auth.router)
v1_router.include_router(users.router)
v1_router.include_router(health.router)
v1_router.include_router(network.router)
v1_router.include_router(assets.router)
v1_router.include_router(connectors.router)
v1_router.include_router(ingestion.router)
v1_router.include_router(events.router)
v1_router.include_router(suricata.router)
v1_router.include_router(zeek.router)
v1_router.include_router(wazuh.router)
v1_router.include_router(defender.router)
v1_router.include_router(vulnerabilities.router)
v1_router.include_router(correlations.router)
v1_router.include_router(risk.router)
v1_router.include_router(incidents.router)
v1_router.include_router(responses.router)
v1_router.include_router(overview.router)
v1_router.include_router(vuln_assessment.router)
