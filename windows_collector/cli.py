"""Command-line entry point for the Windows Event Log collector."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections.abc import Sequence

from .checkpoint import CheckpointStore
from .client import BackendClient
from .collector import WindowsEventCollector
from .config import CollectorConfig
from .errors import CollectorError, ConfigError
from .models import COLLECTOR_VERSION, CollectionStatus
from .source import PowerShellEventSource
from .transport import HttpTransport, UrllibTransport

logger = logging.getLogger(__name__)


def build_collector(
    config: CollectorConfig, transport: HttpTransport | None = None
) -> WindowsEventCollector:
    source = PowerShellEventSource(
        channel=config.channel,
        powershell_path=config.powershell_path,
        timeout_seconds=config.source_timeout_seconds,
    )
    client = BackendClient(config=config, transport=transport or UrllibTransport())
    checkpoint = CheckpointStore(config.checkpoint_path, config.channel)
    return WindowsEventCollector(
        config=config,
        source=source,
        client=client,
        checkpoint=checkpoint,
    )


def _status_payload(config: CollectorConfig, status: CollectionStatus) -> dict:
    payload = status.to_dict()
    payload["checkpoint_path"] = str(config.checkpoint_path)
    return payload


def _print_status(config: CollectorConfig, status: CollectionStatus) -> None:
    print(json.dumps(_status_payload(config, status), indent=2, sort_keys=True))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m windows_collector",
        description="Collect Windows Event Log records into the SOC backend.",
    )
    parser.add_argument("--version", action="version", version=COLLECTOR_VERSION)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--status",
        action="store_true",
        help="print local collector status without reading events or contacting the backend",
    )
    mode.add_argument(
        "--once",
        action="store_true",
        help="run one collection cycle and exit instead of polling",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = _parser().parse_args(argv)
    try:
        config = CollectorConfig.from_env(require_credentials=not args.status)
    except ConfigError as exc:
        logger.error("Configuration error: %s", exc)
        return 2
    collector = build_collector(config)
    if args.status:
        status = collector.status
        try:
            status.checkpoint = collector.checkpoint.load().record_id
        except CollectorError as exc:
            status.record_error(str(exc))
            _print_status(config, status)
            return 1
        _print_status(config, status)
        return 0
    if args.once:
        try:
            status = collector.collect_once()
        except CollectorError as exc:
            collector.status.record_error(str(exc))
            _print_status(config, collector.status)
            return 1
        _print_status(config, status)
        return 0
    try:
        collector.run_forever()
    except KeyboardInterrupt:
        logger.info("Collector stopped.")
        return 0
    return 0


__all__ = ["build_collector", "main"]


if __name__ == "__main__":
    sys.exit(main())
