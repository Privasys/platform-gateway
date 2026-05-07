# Platform Gateway

SNI-based L4 TCP gateway for routing `*.apps.privasys.org` traffic to the correct enclave machine.

## Overview

The gateway inspects the TLS ClientHello SNI extension to determine the target hostname, looks up the backend address from an in-memory routing table, and splices the raw TCP connection to the upstream enclave — **without terminating TLS**. This preserves the end-to-end encryption between client and enclave.

### Architecture

```
Client                    Gateway                     Enclave
  │                         │                           │
  │── TLS ClientHello ─────→│                           │
  │   (SNI: myapp.apps.)    │                           │
  │                         │── lookup routing table ──→│
  │                         │   myapp.apps.privasys.org │
  │                         │   → 141.94.219.130:8445   │
  │                         │                           │
  │←─────── TCP splice (bidirectional) ────────────────→│
  │         (TLS terminates at the enclave)             │
```

### Route Sync

The gateway periodically polls the management service `GET /api/v1/internal/routes` to build its routing table. ETag-based conditional requests minimise bandwidth.

## Configuration

| Flag | Env | Default | Description |
|---|---|---|---|
| `-listen` | `GATEWAY_LISTEN` | `:443` | TCP listen address for client connections |
| `-health` | `GATEWAY_HEALTH` | `:9090` | HTTP listen address for health/metrics |
| `-management-url` | `GATEWAY_MANAGEMENT_URL` | — | Management service base URL (required) |
| `-auth-token` | `GATEWAY_AUTH_TOKEN` | — | Bearer token for route sync |
| `-poll-interval` | `GATEWAY_POLL_INTERVAL` | `5s` | Route sync polling interval |
| `-dial-timeout` | `GATEWAY_DIAL_TIMEOUT` | `2s` | Timeout for connecting to upstream |
| `-idle-timeout` | `GATEWAY_IDLE_TIMEOUT` | `300s` | Close connections idle longer than this |
| `-buffer-size` | `GATEWAY_BUFFER_SIZE` | `32768` | TCP splice buffer size in bytes |

## Build

```bash
go build -o gateway ./cmd/gateway
```

With version info:

```bash
go build -ldflags="-X main.Version=v1.0.0 -X main.GitCommit=$(git rev-parse --short HEAD) -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o gateway ./cmd/gateway
```

## Docker

```bash
docker build -t platform-gateway .
docker run -p 443:443 -p 9090:9090 \
  -e GATEWAY_MANAGEMENT_URL=https://api.developer.privasys.org \
  -e GATEWAY_AUTH_TOKEN=<token> \
  platform-gateway
```

## Endpoints

### Health & metrics (`:9090`)

| Path | Description |
|---|---|
| `/healthz` | Health check with route count, version, sync status |
| `/readyz` | Returns 503 until first successful route sync |
| `/metrics` | Prometheus metrics |

### Prometheus Metrics

| Metric | Type | Description |
|---|---|---|
| `gateway_connections_total` | Counter | Total connections accepted |
| `gateway_connections_active` | Gauge | Currently active connections |
| `gateway_connection_errors_total` | Counter | Errors by reason (`client_read`, `sni_parse`, `no_route`, `dial_upstream`, `write_upstream`) |
| `gateway_bytes_total` | Counter | Bytes transferred by direction (`client_to_upstream`, `upstream_to_client`) |

## Deployment

The gateway is designed to run as a systemd service on bare-metal or VM hosts. See `deploy/gateway.service` for the systemd unit file.

For HA, deploy two instances behind DNS round-robin:
- Gateway 1: OVH (Europe)
- Gateway 2: GCP (Europe)

Both gateways independently poll routes and operate identically.

## License

AGPL-3.0 — see [LICENSE](LICENSE).
