"""Asset inventory models (Step 2).

An ``Asset`` is one row per observed IP address — a continuously updated
inventory, never one row per scan. ``DiscoveredService`` rows describe the
asset's *current known* open ports; each scan replaces the asset's service
set so the inventory reflects the latest observation instead of
accumulating stale rows. First-observation timestamps are preserved for
historical understanding.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base


def _utcnow() -> datetime:
    # Naive UTC preserves the existing column semantics; timezone-aware
    # values would compare unpredictably against SQLite-stored datetimes.
    return datetime.now(UTC).replace(tzinfo=None)


class Asset(Base):
    """A known host identified by IP address."""

    __tablename__ = "assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    mac_address: Mapped[str | None] = mapped_column(String(17), nullable=True)
    operating_system: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Host state as reported by Nmap: "up" / "down".
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="up", index=True)
    # Asset classification. Nmap cannot determine this, so it stays
    # "UNKNOWN" unless a future stage classifies it — never guessed.
    asset_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="UNKNOWN", index=True
    )
    # Where this asset was learned from ("nmap") and which scan found it.
    discovery_source: Mapped[str | None] = mapped_column(String(32), nullable=True)
    discovery_scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=_utcnow
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, default=_utcnow, onupdate=_utcnow
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    services: Mapped[list[DiscoveredService]] = relationship(
        "DiscoveredService",
        back_populates="asset",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class DiscoveredService(Base):
    """One open port/service currently known on an asset.

    Uniqueness on ``(asset_id, port, protocol)`` guarantees repeated
    identical scans can never create duplicate rows.
    """

    __tablename__ = "discovered_services"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="open")
    service_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    extra_info: Mapped[str | None] = mapped_column(Text, nullable=True)
    discovery_scan_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("scan_jobs.id", ondelete="SET NULL"), nullable=True
    )

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), nullable=False, server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=False),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )

    asset: Mapped[Asset] = relationship("Asset", back_populates="services")

    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_service_asset_port_proto"),
        Index("ix_service_asset_port", "asset_id", "port"),
    )
