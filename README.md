# Platform Gateway

The stateless edge in front of Privasys enclaves. It reads each TLS ClientHello (SNI and ALPN), looks the hostname up in a route table synced from the control plane, and then either splices the TCP connection to the enclave, so TLS ends inside the enclave, or, for the platform's own hostnames, terminates TLS with the platform's public certificate and opens an RA-TLS connection to the enclave on the client's behalf.

The gateway also enforces the platform's trusted-time quarantine. Every enclave runtime checks its host clock against the platform monitor (`platform-monitoring`, an instance of [container-app-service-monitoring](https://github.com/Privasys/container-app-service-monitoring/blob/main/docs/platform-clock.md)) and NTS servers; when an enclave's host clock is wrong, or the monitor cannot check it, its routes arrive `quarantined` and the gateway refuses them until the monitor releases the enclave. See [Route States](#route-states).

## Transport selection

Decided once per connection, from the ClientHello and the route (`internal/proxy`):

| Hostname | ClientHello | Path |
|---|---|---|
| any routed name | ALPN offers `privasys-ratls/1` | **Splice**: L4 relay, RA-TLS ends in the enclave. The gateway sees only the SNI. |
| platform hostname | anything else | **Terminate** with the platform certificate (`-tls-cert`), then an RA-TLS connection inward, verified against the route's `attestation_policy`. |
| adopter hostname, `mode: direct` | any | **Splice** every connection. The enclave holds its own publicly trusted certificate for the name (and serves its RA-TLS leaf to `privasys-ratls/1` clients). |
| adopter hostname, `mode: direct-pending` | ALPN is exactly `acme-tls/1` | **Splice**, so the enclave can answer its ACME TLS-ALPN-01 challenge. |
| adopter hostname, `mode: direct-pending` | anything else | Refused. |
| adopter hostname without a direct mode | any | Refused. |

The gateway never terminates an adopter's hostname and never obtains a certificate for one: an adopter's domain is always served in direct mode, end to end to the enclave. The certificate resolver serves the platform certificate only.

Two further paths:

- **Egress tunnels** (`-tunnels`): an enclave that accepts no inbound connections dials out to the gateway with ALPN `privasys-tunnel/1`; routes whose upstream is `tunnel:<enclave id>` are carried over that tunnel.
- **No route**: a 404 page.

### PROXY protocol on direct splices

With `-direct-proxy-protocol`, the gateway writes a PROXY protocol v2 header carrying the real client address before the client's bytes, on direct splices only, so the enclave can rate-limit per client. It is off by default. Enable it only once every enclave runtime behind the gateway is configured to accept the header from the gateway's address: a runtime that does not expect it fails the TLS handshake on every direct name. The header is never sent through an egress tunnel.

### Architecture

```
Client                    Gateway                       Enclave
  │                         │                             │
  │── TLS ClientHello ─────→│                             │
  │   (SNI, ALPN)           │── look up the route ────────│
  │                         │                             │
  │←───── splice: TCP relay, TLS ends in the enclave ────→│
  │                         │                             │
  │←─ terminate: platform ─→│←──── RA-TLS (verified) ────→│
  │   certificate           │                             │
```

### Route sync

The gateway polls the control plane's `GET /api/v1/internal/routes` (`-poll-interval`, ETag-conditional) and swaps its table atomically.

```json
{
  "routes": [
    { "sni": "myapp.apps.privasys.org", "upstream": "203.0.113.10:8445" },
    { "sni": "shop.example.com", "upstream": "203.0.113.20:443",
      "canonical": "shop.apps.privasys.org", "mode": "direct" }
  ],
  "version": "sha256:..."
}
```

| Field | Meaning |
|---|---|
| `sni` | The hostname. |
| `upstream` | `host:port`, or `tunnel:<enclave id>` for a tunnel-connected enclave. |
| `attestation_policy` | What the terminate path verifies on its RA-TLS connection to the enclave. |
| `state` | `quarantined`, or absent (active). |
| `canonical` | On an adopter hostname: the app's platform hostname. |
| `mode` | On an adopter hostname: `direct` or `direct-pending`. |

A change of upstream, canonical name or mode retires the route: its cached proxy and connection pools are dropped.

### Route States

A route entry may carry an optional `state`. A missing `state` means the route is active, so feeds and gateways that predate the field keep working. Unknown values are treated as active.

```json
{ "sni": "myapp.apps.privasys.org", "upstream": "203.0.113.10:8445", "state": "quarantined" }
```

`quarantined` means the control plane has withdrawn the route's enclave from service, today at the request of the platform clock monitor when the enclave's host clock is wrong or cannot be checked. The gateway keeps the route, never dials the upstream, and refuses clients with a clear reason instead of the 404 an unknown host gets:

- **Terminate mode** answers every request, sealed WebSocket upgrades included, with `503 Service Unavailable`, `Retry-After: 300` and `Cache-Control: no-store`. API clients get a JSON body:

  ```json
  {"error":"enclave_quarantined","message":"This application is temporarily unavailable while its enclave's clock is checked."}
  ```

  Clients that ask for `text/html` first (browsers loading a page) get a short HTML page with the same message. CORS preflights are still answered and the refusal carries the CORS headers, so a cross-origin SDK can read it. The live table is checked before each request, so a keep-alive connection opened before the quarantine is refused from its next request on.
- **Splice mode** (RA-TLS clients and direct names) cannot answer in HTTP because the TLS session belongs to the enclave. The gateway answers the ClientHello with a fatal TLS `handshake_failure` alert and closes the connection.

Traffic already open to a host is cut the moment a route sync marks it quarantined, since RA-TLS SDKs and sealed WebSockets hold long-lived connections: spliced connections are closed, in-flight terminated requests (streamed responses included) and WebSockets tunnelled to the enclave are closed on both legs, and sealed WebSocket streams on the enclave mux are closed with status `1013` (try again later) after the enclave is told to drop them. Idle keep-alive terminate connections stay open and get the 503 on their next request.

Each refusal is logged and counted in `gateway_quarantine_refusals_total`, and each cut in `gateway_quarantine_cuts_total`. When the `state` disappears from the feed (release), the next sync serves the route again. The management route of an enclave (`<enclave>-mgr`) is not quarantined, so the clock monitor and operators can still reach it.

## Configuration

| Flag | Env | Default | Description |
|---|---|---|---|
| `-listen` | `GATEWAY_LISTEN` | `:443` | TCP listen address for client connections |
| `-health` | `GATEWAY_HEALTH` | `:9090` | HTTP listen address for health and metrics |
| `-management-url` | `GATEWAY_MANAGEMENT_URL` | none | Control plane base URL (required) |
| `-auth-token` | `GATEWAY_AUTH_TOKEN` | none | Bearer token for route sync |
| `-poll-interval` | `GATEWAY_POLL_INTERVAL` | `5` (s) | Route sync polling interval |
| `-dial-timeout` | `GATEWAY_DIAL_TIMEOUT` | `2` (s) | Timeout for connecting to an upstream |
| `-idle-timeout` | `GATEWAY_IDLE_TIMEOUT` | `300` (s) | Close connections idle longer than this |
| `-buffer-size` | `GATEWAY_BUFFER_SIZE` | `32768` | Splice buffer size in bytes |
| `-tls-cert`, `-tls-key` | `GATEWAY_TLS_CERT`, `GATEWAY_TLS_KEY` | none | Platform certificate and key; enable terminate mode (reloaded on SIGHUP) |
| `-upstream-ca` | `GATEWAY_UPSTREAM_CA` | none | Optional CA bundle for the enclaves' RA-TLS chains on the terminate path |
| `-cors-origins` | `GATEWAY_CORS_ORIGINS` | none | Allowed CORS origins for terminate-mode routes (exact origins or `*.suffix`) |
| `-tunnels` | `GATEWAY_TUNNELS` | off | Accept egress tunnels from enclaves (requires `-tls-cert`) |
| `-direct-proxy-protocol` | `GATEWAY_DIRECT_PROXY_PROTOCOL` | off | Send a PROXY protocol v2 header on direct splices (see above) |
| `-acme-cache`, `-acme-email`, `-acme-directory` | `GATEWAY_ACME_*` | none | Ignored. They configured per-host certificates for adopter hostnames, which the gateway no longer obtains; `-acme-cache` logs a line at start-up. |

## Build

The Go toolchain is pinned in `go.mod`.

```bash
go build -o gateway ./cmd/gateway
go test ./...
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
| `/readyz` | Returns 503 until the first successful route sync |
| `/metrics` | Prometheus metrics |

### Prometheus Metrics

| Metric | Type | Description |
|---|---|---|
| `gateway_connections_total` | Counter | Total connections accepted |
| `gateway_connections_active` | Gauge | Currently active connections |
| `gateway_connection_errors_total` | Counter | Errors by reason (`client_read`, `sni_parse`, `no_route`, `dial_upstream`, `write_upstream`, `adopter_not_direct`, ...) |
| `gateway_bytes_total` | Counter | Bytes transferred by direction (`client_to_upstream`, `upstream_to_client`) |
| `gateway_quarantine_refusals_total` | Counter | Requests (terminate) and connections (splice) refused because their route is quarantined, by `host` and `mode` (`terminate`, `splice`) |
| `gateway_quarantine_cuts_total` | Counter | Open connections and streams closed because their route became quarantined, by `host` and `mode` (`splice`, `http`, `websocket`, `sealed_ws`) |

## Deployment

The gateway runs as a systemd service on VM or bare-metal hosts; see `deploy/gateway.service` for the unit file. Run two or more instances behind DNS round-robin: each polls the routes independently and they operate identically. An adopter hostname in direct mode works through any instance, so its DNS can point at all of them.

## License

AGPL-3.0: see [LICENSE](LICENSE).
