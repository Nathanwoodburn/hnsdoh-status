# HNSDoH Status

HNSDoH Status is a Flask service that discovers HNSDoH nodes from DNS A records for `hnsdoh.com` and continuously checks each node for:

- DNS over UDP on port 53
- DNS over TCP on port 53
- DNS over HTTPS (DoH) on port 443 at `/dns-query`
- DNS over TLS (DoT) on port 853

For DoH and DoT, TLS certificates are validated with hostname `hnsdoh.com`.

## How It Works

1. Resolve `hnsdoh.com` A records to discover active node IP addresses.
2. Probe each discovered node for all four protocols.
3. Keep current status and short in-memory history.
4. Expose results through a web dashboard and JSON API.

## Run

```bash
uv sync
uv run python main.py
```

The app runs on `0.0.0.0:8000` by default.

## API Endpoints

- `GET /`: HTML status page
- `GET /api/status`: current snapshot and history
- `GET /api/health`: service health (503 if stale or no checks yet)

## Configuration

Environment variables:

- `HNSDOH_DOMAIN` (default: `hnsdoh.com`)
- `HNSDOH_DOH_PATH` (default: `/dns-query`)
- `HNSDOH_CHECK_INTERVAL_SECONDS` (default: `300`)
- `HNSDOH_UI_REFRESH_SECONDS` (default: `30`)
- `HNSDOH_HISTORY_SIZE` (default: `12`)
- `HNSDOH_STALE_AFTER_SECONDS` (default: `900`)
- `HNSDOH_DNS_TIMEOUT_SECONDS` (default: `5`)
- `HNSDOH_DOH_TIMEOUT_SECONDS` (default: `10`)
- `HNSDOH_DOT_TIMEOUT_SECONDS` (default: `10`)

## Notes

- Discovery uses DNS A records only.
- DoH check uses RFC8484 DNS wireformat (`application/dns-message`) to each node IP while sending SNI/Host as `hnsdoh.com` for strict certificate hostname verification.
- History is in-memory and resets on process restart.
