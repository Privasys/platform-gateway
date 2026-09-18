# Platform Gateway

SNI-based L4 TCP gateway for routing `*.apps.privasys.org` traffic to the correct enclave machine.

## Overview

The gateway inspects the TLS ClientHello SNI extension to determine the target hostname, looks up the backend address from an in-memory routing table, and splices the raw TCP connection to the upstream enclave, **without terminating TLS**. This preserves the end-to-end encryption between client and enclave. When a public certificate is configured (`-tls-cert`), clients that do not advertise the `privasys-ratls/1` ALPN (browsers, curl) are served in terminate mode instead: the gateway presents the public certificate and opens an internal RA-TLS connection to the enclave on their behalf.

The gateway also enforces the platform's trusted-time quarantine. Every enclave runtime checks its host clock against the platform monitor (`platform-monitoring`, an instance of [container-app-service-monitoring](https://github.com/Privasys/container-app-service-monitoring/blob/main/docs/platform-clock.md)) and NTS servers; when an enclave's host clock is wrong, or the monitor cannot check it, its routes arrive `quarantined` and the gateway refuses them until the monitor releases the enclave. See [Route States](#route-states).

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

### Route States

A route entry may carry an optional `state`. A missing `state` means the route is active, so feeds and gateways that predate the field keep working. Unknown values are treated as active.

```json
{ "sni": "myapp.apps.privasys.org", "upstream": "141.94.219.130:8445", "state": "quarantined" }
```

`quarantined` means the management service has withdrawn the route's enclave from service, today at the request of the platform clock monitor when the enclave's host clock is wrong or cannot be checked. The gateway keeps the route, never dials the upstream, and refuses clients with a clear reason instead of the 404 an unknown host gets:

- **Terminate mode** answers every request, sealed WebSocket upgrades included, with `503 Service Unavailable`, `Retry-After: 300` and `Cache-Control: no-store`. API clients get a JSON body:

  ```json
  {"error":"enclave_quarantined","message":"This application is temporarily unavailable while its enclave's clock is checked."}
  ```

  Clients that ask for `text/html` first (browsers loading a page) get a short HTML page with the same message. CORS preflights are still answered and the refusal carries the CORS headers, so a cross-origin SDK can read it. The live table is checked before each request, so a keep-alive connection opened before the quarantine is refused from its next request on.
- **Splice mode** (`privasys-ratls/1` clients) cannot answer in HTTP because the TLS session belongs to the enclave. The gateway answers the ClientHello with a fatal TLS `handshake_failure` alert and closes the connection.

Traffic already open to a host is cut the moment a route sync marks it quarantined, since RA-TLS SDKs and sealed WebSockets hold long-lived connections: spliced connections are closed, in-flight terminated requests (streamed responses included) and WebSockets tunnelled to the enclave are closed on both legs, and sealed WebSocket streams on the enclave mux are closed with status `1013` (try again later) after the enclave is told to drop them. Idle keep-alive terminate connections stay open and get the 503 on their next request.

Each refusal is logged and counted in `gateway_quarantine_refusals_total`, and each cut in `gateway_quarantine_cuts_total`. When the `state` disappears from the feed (release), the next sync serves the route again. The management route of an enclave (`<enclave>-mgr`) is not quarantined, so the clock monitor and operators can still reach it.

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
| `/healthz` | Health check with route count, quarantined route count, version, sync status |
| `/readyz` | Returns 503 until first successful route sync |
| `/metrics` | Prometheus metrics |

### Prometheus Metrics

| Metric | Type | Description |
|---|---|---|
| `gateway_connections_total` | Counter | Total connections accepted |
| `gateway_connections_active` | Gauge | Currently active connections |
| `gateway_connection_errors_total` | Counter | Errors by reason (`client_read`, `sni_parse`, `no_route`, `dial_upstream`, `write_upstream`) |
| `gateway_bytes_total` | Counter | Bytes transferred by direction (`client_to_upstream`, `upstream_to_client`) |
| `gateway_quarantine_refusals_total` | Counter | Requests (terminate) and connections (splice) refused because their route is quarantined, by `host` and `mode` (`terminate`, `splice`) |
| `gateway_quarantine_cuts_total` | Counter | Open connections and streams closed because their route became quarantined, by `host` and `mode` (`splice`, `http`, `websocket`, `sealed_ws`) |

## Deployment

The gateway is designed to run as a systemd service on bare-metal or VM hosts. See `deploy/gateway.service` for the systemd unit file.

For HA, deploy two instances behind DNS round-robin:
- Gateway 1: OVH (Europe)
- Gateway 2: GCP (Europe)

Both gateways independently poll routes and operate identically.

## License

AGPL-3.0: see [LICENSE](LICENSE).
