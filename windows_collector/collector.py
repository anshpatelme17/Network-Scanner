"""Collector orchestration with fail-closed checkpoint semantics."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from .checkpoint import CheckpointStore
from .client import BackendClient
from .config import CollectorConfig
from .errors import AuthenticationError, CollectorError, SourceUnavailableError
from .models import CollectionStatus, utc_now_iso
from .normalizer import normalize_event
from .source import PowerShellEventSource

logger = logging.getLogger(__name__)


@dataclass
class WindowsEventCollector:
    config: CollectorConfig
    source: PowerShellEventSource
    client: BackendClient
    checkpoint: CheckpointStore
    status: CollectionStatus = field(init=False)

    def __post_init__(self) -> None:
        self.status = CollectionStatus(channel=self.config.channel)

    def collect_once(self) -> CollectionStatus:
        state = self.checkpoint.load()
        self.status.checkpoint = state.record_id
        try:
            batch = self.source.read_batch(state.record_id, self.config.batch_size)
        except SourceUnavailableError:
            self.status.source_available = False
            raise
        self.status.source_available = True
        self.status.last_source_read_at = utc_now_iso()
        self.status.checkpoint_reset = batch.reset_detected
        self.status.events_read += len(batch.events)
        payloads = [normalize_event(event, self.config.source_name) for event in batch.events]
        if not batch.events:
            if batch.reset_detected:
                saved = self.checkpoint.save(0)
                self.status.checkpoint = saved.record_id
            self.status.clear_error()
            self.status.authenticated = self.client.authenticated
            return self.status
        try:
            for payload in payloads:
                result = self.client.ingest_event(payload)
                if result.created:
                    self.status.events_uploaded += 1
                else:
                    self.status.events_duplicate += 1
        except AuthenticationError:
            self.status.authenticated = False
            raise
        self.status.authenticated = True
        self.status.last_upload_success_at = utc_now_iso()
        saved = self.checkpoint.save(max(event.record_id for event in batch.events))
        self.status.checkpoint = saved.record_id
        self.status.clear_error()
        return self.status

    def run_forever(
        self,
        sleep_fn: Callable[[float], None] = time.sleep,
        stop_fn: Callable[[], bool] | None = None,
        max_iterations: int | None = None,
    ) -> CollectionStatus:
        iterations = 0
        while max_iterations is None or iterations < max_iterations:
            if stop_fn is not None and stop_fn():
                break
            before_read = self.status.events_read
            before_uploaded = self.status.events_uploaded
            before_duplicate = self.status.events_duplicate
            try:
                self.collect_once()
            except CollectorError as exc:
                self.status.record_error(str(exc))
                logger.error("Collector poll failed: %s", exc)
            except Exception:
                self.status.record_error("Unexpected collector failure.")
                logger.error("Collector poll failed unexpectedly.")
            else:
                logger.info(
                    "Collector poll completed: channel=%s read=%d uploaded=%d duplicate=%d checkpoint=%d",
                    self.status.channel,
                    self.status.events_read - before_read,
                    self.status.events_uploaded - before_uploaded,
                    self.status.events_duplicate - before_duplicate,
                    self.status.checkpoint,
                )
            iterations += 1
            if max_iterations is not None and iterations >= max_iterations:
                break
            if stop_fn is not None and stop_fn():
                break
            sleep_fn(self.config.poll_interval_seconds)
        return self.status


__all__ = ["WindowsEventCollector"]
