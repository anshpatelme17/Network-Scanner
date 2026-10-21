# Windows Event Log Collector

Standalone collector that reads Windows Event Log records and submits them to the existing SOC backend event-ingestion API.

This first foundation is intentionally narrow. It does not install a Windows service, change audit policy, enable Sysmon, perform autonomous response, or contact external threat-intelligence services. The backend ingestion mode remains `FIXTURE`; the collector records its own provenance inside `raw_event`.

## Requirements

- Windows 10 or Windows 11.
- Windows PowerShell 5.1 (`powershell.exe`).
- Read permission for the selected event channel.
- A backend account with the `MANAGE_EVENTS` permission.
- The backend must expose `POST /api/v1/auth/login` and `POST /api/v1/events`.

The collector uses only the Python standard library. It is not embedded in the backend container and does not require `pywin32`.

## Configuration

All configuration is read from environment variables.

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `SOC_BACKEND_URL` | Yes | none | Backend origin, for example `https://soc.example.test` or `http://localhost:8000`. HTTPS is required except for loopback addresses. |
| `SOC_BACKEND_USERNAME` | Yes | none | Collector account. Not required for `--status`. |
| `SOC_BACKEND_PASSWORD` | Yes | none | Collector password. Not required for `--status`. Never written to the checkpoint or logs. |
| `SOC_WINDOWS_EVENT_CHANNEL` | Yes | none | Exact channel name, for example `Security`, `System`, or `Application`. |
| `SOC_WINDOWS_CHECKPOINT_PATH` | No | `%LOCALAPPDATA%\SOCWindowsCollector\checkpoint.json` | Local checkpoint file. |
| `SOC_WINDOWS_BATCH_SIZE` | No | `50` | Records per read; `1` to `500`. |
| `SOC_WINDOWS_POLL_INTERVAL_SECONDS` | No | `30` | Poll interval; `5` to `3600`. |
| `SOC_WINDOWS_REQUEST_TIMEOUT_SECONDS` | No | `10` | Backend request timeout; `1` to `120`. |
| `SOC_WINDOWS_SOURCE_TIMEOUT_SECONDS` | No | `30` | PowerShell source timeout; `5` to `300`. |
| `SOC_WINDOWS_SOURCE_NAME` | No | `windows-event-collector` | Value sent as `source_name`; at most 128 characters. |
| `SOC_WINDOWS_POWERSHELL` | No | `powershell.exe` | PowerShell executable path. |

The backend URL must not contain credentials, query parameters, fragments, or an API path.

## Usage

Use PowerShell to set the environment for the current process (run these commands from the repository root):

```powershell
$env:SOC_BACKEND_URL = "http://localhost:8000"
$env:SOC_BACKEND_USERNAME = "collector"
$env:SOC_BACKEND_PASSWORD = "replace-with-a-secret"
$env:SOC_WINDOWS_EVENT_CHANNEL = "Security"
```

Show local status without reading events or contacting the backend:

```powershell
python -m windows_collector --status
```

Run one collection cycle:

```powershell
python -m windows_collector --once
```

Run continuously in the foreground:

```powershell
python -m windows_collector
```

`--once` and `--status` print a status JSON object. The polling mode logs safe summaries and errors; it does not log credentials, tokens, request bodies, or raw event XML.

## Collection Behavior

- The collector queries records with `EventRecordID` greater than the checkpoint and reads oldest-first.
- A batch is normalized completely before any upload begins. A malformed record fails the batch closed instead of silently skipping data.
- Events are uploaded individually through `POST /api/v1/events`.
- `201 Created` counts as a new event; `200 OK` counts as a backend idempotent replay.
- The checkpoint advances only after every event in the batch uploads successfully.
- A failed upload leaves the checkpoint unchanged, so the next poll retries the batch. Delivery is at-least-once; the backend performs deduplication through `external_event_id`.
- A malformed event or a backend schema rejection blocks that batch until the data or collector configuration is corrected. There is no automatic skip path in this foundation.
- If the event log was cleared or its newest record ID is below the checkpoint, the collector rereads from zero and advances to the new record set.
- A cleared log with no remaining records resets the checkpoint to zero.

## Normalization

Each record becomes a bounded `WINDOWS` ingestion envelope:

- `source_type`: `WINDOWS`
- `event_type`: `WINDOWS_EVENT_<event_id>`
- `external_event_id`: deterministic channel/record/timestamp identity, hashed when it would exceed 255 characters
- `severity`: Windows levels map to `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO`
- Optional fields are emitted only when present: `hostname`, `username`, `process_name`, `source_ip`, `source_port`

`raw_event` contains collector provenance and an allowlist of event metadata. It does not contain the full event XML or the rendered message.

## Security Notes

- The backend URL must use HTTPS unless it targets `localhost`, `127.0.0.1`, or `::1`.
- TLS certificate verification remains enabled.
- HTTP redirects are not followed.
- Backend credentials are held in memory only. They are excluded from object representations and checkpoint files.
- The PowerShell subprocess receives a sanitized environment. Backend credentials are not passed to it.
- Event channel values are passed to PowerShell through environment variables, not interpolated into a command string.
- Run the collector under a dedicated account with read access to the selected channel. Do not grant write or audit-policy permissions unless separately required.
- Use one collector process per checkpoint file. The checkpoint write is atomic, but there is no cross-process lock.
- The collector is a foreground process in this phase; it does not install or manage a Windows service.

## Status and Troubleshooting

`--status` reports the channel, checkpoint, checkpoint reset flag, source availability, authentication state, counters, and the last safe error message. The status command does not require backend credentials and does not read events.

Common cases:

- `Windows event source is unavailable`: PowerShell or the requested channel is not accessible to the current account.
- `Collector lacks permission to ingest events`: the account is missing `MANAGE_EVENTS`.
- `Backend rejected the event as invalid`: the normalized envelope does not satisfy the backend schema.
- `Checkpoint belongs to a different event channel`: use a separate checkpoint path for each channel or remove the old checkpoint.
- `Checkpoint file could not be read`: inspect or replace the local checkpoint file; no backend data is affected.

## Tests

The collector tests use mocked PowerShell and HTTP responses. They do not require a backend, credentials, or live Windows event access:

```powershell
python -m pytest windows_collector/tests -q
```

Live collection and live backend authentication have not been verified by these mocked tests.
