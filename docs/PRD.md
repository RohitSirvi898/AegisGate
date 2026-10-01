# AegisGate: Product Requirements Document (PRD)

| | |
|---|---|
| **Document version** | 2.1.0-Draft (hardened spec) |
| **Project lead** | Rohit Sirvi |
| **Repository** | https://github.com/RohitSirvi898/AegisGate |
| **Status** | In development / architecture review |
| **Supersedes** | 2.0.0-Core |

**How to read this document.** Everything here is a *requirement*, not a claim about what is already built or measured. Section 9 tracks each requirement through *Specified → Implemented → Tested*. No performance figures are claimed anywhere in this document; performance objectives will be set only after the baseline benchmark in section 9.3 has been run.

### Revision history

| Version | Summary |
|---|---|
| 2.0.0-Core | Scoped the project as a learning-focused proxy; added limitations section, pre-queue redaction, per-target breaker, SSRF rules. |
| 2.1.0-Draft | Reordered the pipeline so tenant identity is established before caching; two-tier rate limiting; precise abuse-scoring semantics; connect-time SSRF enforcement; synthetic half-open probe and per-upstream in-flight cap; hardened cache rules; telemetry queue bounds and allowlist-based redaction; specified admin plane; separate Redis roles; observability and lifecycle; verification plan. |

---

## 1. Overview and Scope

AegisGate is a lightweight reverse-proxy API gateway written in Node.js and TypeScript. It centralizes common perimeter concerns for small microservice deployments: rate limiting, API-key and JWT verification, coarse request filtering, safe response caching, and upstream failure isolation. It is both a learning-focused system-design implementation and a usable edge proxy for small projects.

### 1.1 Target users
Small internal projects, student microservices, and prototype environments that need an easy-to-run edge proxy without deploying Kong, Envoy, or a full Nginx configuration.

### 1.2 Non-goals (explicit)
- Not a replacement for Nginx, Traefik, Envoy, Kong, or Cloudflare in high-scale commercial infrastructure.
- Not a Web Application Firewall. The regex tripwire (section 4.6) is a coarse signal only; backend services remain responsible for input safety (parameterized queries, output encoding).
- No compliance claims (GDPR, HIPAA, PCI). Redaction reduces sensitive data in logs; it is not a compliance mechanism.
- No high-availability guarantee in v2.x (single instance of each dependency; see section 8).
- No TLS termination. TLS must be terminated by an upstream component (Caddy, ALB, Cloudflare) in any non-local environment.

### 1.3 Design principle: availability vs. correctness
Controls are split into two classes, and each failure mode in section 7 follows this rule:

- **Abuse controls** (IP jail, rate limiting, caching, telemetry) **fail open**. Losing them degrades protection but keeps legitimate traffic flowing.
- **Identity and isolation controls** (API-key auth, tenant resolution, SSRF validation, tenant config) **fail closed**. Losing them must never expose data or reach forbidden targets.

---

## 2. Problem Statement

Small teams running several services face three recurring problems:

1. **Perimeter code duplication.** Rate limiting, API-key handling, and token verification get re-implemented in each service, causing drift and inconsistent security behavior.
2. **Cascading failures.** When one downstream service degrades or hangs, intermediaries keep connections open, exhausting sockets and memory across the system.
3. **Wasted backend capacity.** Injection probes and high-frequency bots reach deep application and database layers for requests that could have been rejected at the perimeter.

---

## 3. Pipeline Architecture

Requests to port `8080` pass through a deterministic, short-circuiting pipeline ordered so that each step can rely on what earlier steps established: cheap checks first, tenant identity before any tenant-scoped state (limits, cache), and cache lookup only after authentication and filtering.

```
[ Client Request ]
       │
       ▼
[ 1. Ingress Limits ] ────(Content-Length or streamed bytes > cap)───► 413
       │
       ▼
[ 2. Client IP Derivation ]   (socket address; XFF only via trusted CIDRs)
       │
       ▼
[ 3. Redis IP-Jail Check ] ───(jailed)──────────────────────────────► 403 ip_jailed
       │
       ▼
[ 4. Pre-Auth IP Rate Limit ] ─(over limit)─────────────────────────► 429
       │
       ▼
[ 5. Tenant Resolution & Auth ]  API key → project; JWT if route requires it
       │                       ─(missing / invalid)─────────────────► 401
       ▼
[ 6. Tenant Rate Limiter ] ───(over limit)──────────────────────────► 429
       │
       ▼
[ 7. Regex Tripwire ] ────────(signature match)─────────────────────► 403 request_blocked
       │
       ▼
[ 8. Cache Lookup (whitelisted public GET routes) ]
       │ (hit) ──────────────────────────────────────────────────────► cached response
       │ (miss / bypass)
       ▼
[ 9. Upstream Guard: circuit breaker + in-flight cap ]
       │                       ─(OPEN or saturated)─────────────────► 503
       ▼
[ 10. Reverse Proxy ] ─────────► Upstream microservice
                       ─(timeout)──────────────────────────────────► 504

Off the request path, from any rejecting step and from proxy errors:
  event → redaction → bounded in-process buffer → RabbitMQ → audit worker → MongoDB
```

### 3.1 Error contract

All gateway-generated errors return JSON `{ "error": "<code>", "requestId": "<id>" }` and an `X-Request-Id` header.

| Status | Code | Cause |
|---|---|---|
| 401 | `invalid_or_missing_credentials` | Step 5 |
| 403 | `ip_jailed` | Step 3 |
| 403 | `request_blocked` | Step 7 |
| 413 | `payload_too_large` | Step 1 |
| 429 | `rate_limited` (with `Retry-After`) | Steps 4 and 6 |
| 503 | `upstream_unavailable` | Breaker OPEN |
| 503 | `upstream_saturated` | In-flight cap reached |
| 503 | `auth_backend_unavailable` | Tenant config unreadable (section 7) |
| 504 | `upstream_timeout` | Upstream did not respond within timeout |

---

## 4. Functional Specifications

### 4.1 Ingress limits and body handling (Step 1)

- If `Content-Length` exceeds `MAX_BODY_BYTES` (default 100 KB), respond `413` immediately without reading the body.
- For chunked requests (no `Content-Length`), a byte-counting transform aborts the stream with `413` once the cap is exceeded.
- **Scannable bodies.** Only bodies with content types in `SCAN_BODY_CONTENT_TYPES` (`application/json`, `application/x-www-form-urlencoded`, `text/plain`) are buffered (up to the cap) so the tripwire can inspect them. The proxy layer must forward the exact bytes that were buffered (for `http-proxy-middleware`, this means re-attaching the consumed body, e.g. `fixRequestBody`, and adjusting `Content-Length`). All other content types are streamed through the byte counter without inspection (see limitation L6).
- Runtime: Node.js 20 LTS or later, relying on the built-in HTTP parser's request-smuggling protections. Requests with conflicting `Content-Length` and `Transfer-Encoding` are rejected.

### 4.2 Client IP derivation (Step 2)

- **Default:** use `req.socket.remoteAddress`. IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are normalized to IPv4. Native IPv6 addresses are truncated to their `/64` prefix for jail and rate-limit keys, so a client rotating addresses within a `/64` cannot evade bans.
- **Behind a trusted proxy:** `TRUSTED_PROXY_CIDRS` lists the proxy/load-balancer networks. `X-Forwarded-For` is honored only if the socket peer is inside those CIDRs. The list is walked right to left, skipping trusted entries; the first untrusted address is the client. Otherwise the header is ignored.

### 4.3 Rate limiting (Steps 4 and 6)

Two tiers, both Redis-backed, both fixed-window counters executed atomically in a Lua script:

| Tier | Key | Purpose | Default |
|---|---|---|---|
| Pre-auth | `rl:pre:{ip}` | Protect credential lookups and verification from unauthenticated floods | 120 / 60 s |
| Tenant | `rl:{projectId}:{ip}` | Per-tenant fairness and abuse signal | 60 / 60 s (per-project override) |

```lua
-- KEYS[1] = counter key, ARGV[1] = window in ms
local n = redis.call('INCR', KEYS[1])
if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return { n, redis.call('PTTL', KEYS[1]) }
```

- A request is over the limit when `n > limit`. `Retry-After` is derived from the returned TTL.
- **Violation event:** the first over-limit request in a window (`n == limit + 1`) emits exactly one *rate-limit violation* event for that tier and window. Later rejected requests in the same window do not emit more.
- **Known trade-off:** a fixed window allows up to 2x the nominal rate across a window boundary. Accepted for v2.x; a sliding-window counter or token bucket is on the roadmap (section 10).
- **Redis unavailable:** fail open, but switch to a per-process in-memory fixed-window limiter with the same limits so the gateway is not entirely unthrottled.

### 4.4 Abuse scoring and IP jail (Step 3)

**Scoring.** Each abuse event adds points to `abuse:{ip}` within a fixed 60-second window:

| Event | Points |
|---|---|
| Rate-limit violation (once per tier per window, per 4.3) | 1 |
| Regex tripwire match (4.6) | 1 |

When the score reaches the threshold (default 3) the IP is jailed. One Lua script performs the increment, sets the window expiry only when the counter is new (fixed window, not sliding, and not refreshed on each event), and sets the jail:

```lua
-- KEYS[1]=abuse:{ip}  KEYS[2]=jail:{ip}
-- ARGV: points, windowSec, threshold, jailTtlSec
local s = redis.call('INCRBY', KEYS[1], ARGV[1])
if redis.call('TTL', KEYS[1]) < 0 then redis.call('EXPIRE', KEYS[1], ARGV[2]) end
if s >= tonumber(ARGV[3]) then
  redis.call('SET', KEYS[2], 'banned', 'EX', ARGV[4])
end
return s
```

**Jail.** `jail:{ip}` has a 10-minute TTL. Step 3 is a single `EXISTS`; a jailed IP gets `403 ip_jailed` with no further processing.

**Scope and limits.**
- Jails are global across tenants, keyed by the derived client IP (IPv6 by `/64`).
- Shared NAT (office, campus): several users behind one IP share one score. Mitigated by requiring multiple events before a ban, not eliminated (limitation L3).
- Escalating ban durations for repeat offenders are on the roadmap.
- Redis unavailable: jail checks fail open; scoring is skipped.

### 4.5 Tenant resolution and authentication (Step 5)

Tenant identity is always derived from validated credentials, never from unauthenticated input.

**API key.**
- Every request must carry `x-aegis-api-key`. Keys are 32 random bytes (base64url) with a short prefix; only a SHA-256 hash and the prefix are stored. A fast hash is correct here because keys are high-entropy; slow password hashes (bcrypt/argon2) are not used on the request path.
- Lookup is by hash → project. The header is **stripped** before forwarding upstream.
- The key authorizes *use of the gateway for a project*. It is a server-side credential. If embedded in a browser client it is effectively an identifier, and the project's rate limits are the only protection (limitation L8).

**JWT (per-route, optional).**
- Routes declare `authMode: none | jwt`. The gateway only *verifies* tokens; it never issues them.
- Per project, exactly one algorithm is configured: `RS256` (public key, recommended) or `HS256` (shared secret). `alg` is pinned to that configuration; `none` and any other algorithm are rejected.
- Required claims: valid `exp`; `iss` and `aud` are checked when configured. Clock skew tolerance: 30 s. `kid` supports rotation with up to two active keys.
- HS256 secrets are encrypted at rest (AES-256-GCM, master key from environment). Because HS256 requires the gateway to hold the signing secret, RS256 is preferred.
- The `Authorization` header is forwarded upstream unchanged.

**Tenant config caching and revocation.**
- Validated project config is cached in Redis (`TENANT_CONFIG_REDIS_TTL_SEC`, default 300) and in a per-process LRU (`TENANT_CONFIG_LOCAL_TTL_SEC`, default 15).
- Any key revocation or config change performs Redis `DEL` and clears the local cache on the instance that handled the admin call. Other instances converge within the local TTL (default 15 s). Revocation latency is therefore bounded by that TTL, not 5 minutes.
- Cache miss or Redis outage falls back to MongoDB. If config cannot be loaded from any source, respond `503 auth_backend_unavailable` (fail closed).

### 4.6 Regex tripwire (Step 7)

A coarse signature check, explicitly not a WAF (section 1.2).

- **Inputs scanned:** URL-decoded path, query string (names and values), selected headers (`User-Agent`, `Referer`), and scannable bodies (4.1). JSON bodies are parsed and scanned over keys and string values.
- **Normalization:** URL-decode up to two passes, Unicode NFKC, lowercase, collapse whitespace.
- **Engine:** RE2 (linear-time, no backtracking) to eliminate ReDoS risk on the event loop. Patterns therefore cannot use backreferences or lookaround.
- **Initial signature set** (each with a rule ID recorded in telemetry):
  - SQLi: boolean tautologies (`or 1=1` style), `union select`, stacked-query keywords after `;`, time-based functions such as `sleep(n)`.
  - XSS: `<script`, `javascript:`, inline event-handler attributes.
  - Path traversal: `../` sequences after decoding.
- **Not signatures:** bare `--`, `#`, single quotes, and other tokens that appear in legitimate text (Markdown, prose, CLI snippets). Earlier drafts included bare `--`; it was removed to avoid false positives.
- **Action:** respond `403 request_blocked`, emit a telemetry event, and add 1 abuse point (4.4). A single match never jails on its own.
- Known evasions (hex/char-code encodings, comment splitting, exotic encodings) are documented in limitation L4.

### 4.7 Response caching (Step 8)

**Eligibility** (all must hold):
- Method is `GET`, the project has enabled caching for the matching route, and the route is in the tenant's explicit whitelist.
- The request has no `Authorization` header and no `Cookie` header. Client `Cache-Control` request headers are ignored (honoring `no-cache` would let clients bypass the cache at will).
- All query parameters are in the route's `allowedQueryParams`. A request with any other parameter bypasses the cache (it is proxied but not stored), which prevents cache-busting via random parameters.

**Key.** `cache:{projectId}:{routeId}:GET:{normalizedPath}?{sortedAllowedQuery}`
- `projectId` comes from step 5, so it is always a validated tenant.
- Path normalization: decode unreserved percent-escapes, remove dot segments, collapse duplicate slashes; paths containing encoded slashes (`%2f`) bypass the cache.
- Allowed query parameters are sorted by name (stable for repeated names).
- Keys longer than `CACHE_MAX_KEY_BYTES` (512) bypass the cache.

**Storing.**
- Only `200` responses are stored. Not stored: responses with `Set-Cookie`, `Cache-Control: no-store` or `private`, bodies over `CACHE_MAX_BODY_BYTES` (256 KB), and responses with a `Vary` header other than `Accept-Encoding`.
- For cacheable routes the gateway requests `Accept-Encoding: identity` from the upstream so one stored representation serves all clients.
- TTL defaults to 60 s with ±10% jitter to avoid synchronized expiry.
- Responses carry `X-Aegis-Cache: HIT | MISS | BYPASS`.

**Stampede protection.** Per-process single-flight: concurrent misses for one key share a single upstream request. (A cross-instance lock is on the roadmap.)

**Isolation.** The cache runs on a separate Redis instance (section 6) so eviction pressure on cached bodies can never evict jail, abuse, or rate-limit keys.

**Redis unavailable:** bypass the cache (fail open).

### 4.8 Upstream target security / SSRF (registration time and connect time)

Tenants supply `targetUrl`, and the gateway connects to it from inside your network, so validation must hold at *connection* time, not only at registration.

**At registration:**
- Scheme must be `http` or `https`. URLs with userinfo (`user:pass@`) are rejected.
- Port must not be in `BLOCKED_UPSTREAM_PORTS` (defaults cover the gateway's own dependencies and common infrastructure ports, e.g. 22, 25, 5432, 5672, 6379, 9200, 15672, 27017).

**At connect time (every connection):**
- The HTTP(S) agents use a custom DNS `lookup` that resolves the hostname, validates every returned address against the denylist below, and connects to the *validated IP* (no second resolution), preserving `Host`/SNI. This closes the DNS-rebinding gap.
- Denylist IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16` (includes the cloud metadata address), `172.16.0.0/12`, `192.0.0.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `224.0.0.0/4`, `240.0.0.0/4`.
- Denylist IPv6: `::/128`, `::1/128`, `fc00::/7`, `fe80::/10`, `ff00::/8`, and IPv4-mapped/translated forms (`::ffff:0:0/96`, `64:ff9b::/96`), where the embedded IPv4 address is checked against the IPv4 list.
- **Redirects are not followed.** Upstream `3xx` responses pass through to the client unchanged.

**Operator override for private backends.** Because the target audience often runs backends on localhost or a private network, the **operator** (not tenants) may set `ALLOW_PRIVATE_UPSTREAMS=true` or an explicit `ALLOWED_PRIVATE_CIDRS` list in deployment configuration. Tenants can never set or modify this. Default: disabled.

### 4.9 Reverse proxy behavior (Step 10)

- **Connection pooling:** one `http.Agent`/`https.Agent` per upstream origin with `keepAlive: true` and `maxSockets: 100`.
- **Forwarded headers:** remove hop-by-hop headers (`Connection`, `Keep-Alive`, `Proxy-*`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade`) and `x-aegis-api-key`; append `X-Forwarded-For` (derived client IP), set `X-Forwarded-Proto` and `X-Request-Id`; rewrite `Host` to the upstream.
- **Timeouts:** connect timeout `UPSTREAM_CONNECT_TIMEOUT_MS` (2000) and response timeout `UPSTREAM_TIMEOUT_MS` (5000, overridable per route, max 30000). Expiry aborts the upstream request and returns `504`.
- **Bulkhead:** at most `MAX_INFLIGHT_PER_UPSTREAM` (100) concurrent requests per upstream origin. Excess requests are rejected immediately with `503 upstream_saturated` instead of queuing in the agent. This, together with timeouts, is what actually bounds socket and memory use during a slow-upstream incident.
- **Unsupported in v2.x:** WebSocket, SSE, and HTTP/2 upstreams (limitation L7).

### 4.10 Circuit breaker (Step 9)

- **Scope:** one breaker per upstream origin (scheme + host + port). Projects that target different origins never affect each other.
- **Failures counted:** responses with status `>= 500`, upstream timeouts, and connection errors (refused, reset, DNS failure). **Not counted:** `4xx`, client aborts (the client disconnected first), and gateway-generated rejections (including `upstream_saturated`).
- **CLOSED:** traffic flows; consecutive failures are counted and reset by any success.
- **OPEN:** after `BREAKER_FAILURE_THRESHOLD` (5) consecutive failures, all requests to that origin fail immediately with `503 upstream_unavailable` without touching the network, for `BREAKER_COOLDOWN_MS` (30 s).
- **HALF-OPEN:** when the cooldown timer fires, the gateway sends **one synthetic probe**, `GET {healthCheckPath}` (per-project, default `/`), with the normal timeout. Real client requests continue to receive `503` while the probe runs, so user traffic (including non-idempotent requests) is never used as a probe. The "only one probe" rule is guaranteed by setting the `probeInFlight` flag synchronously in the same event-loop tick as the state check (no `await` between check and set). Probe result `< 500` within the timeout closes the circuit; anything else re-opens it for another cooldown.
- **State lives in process memory** (limitation L1).
- **Out of scope for v2.x:** rolling error-rate windows and minimum-volume thresholds (roadmap).

### 4.11 Telemetry pipeline (off the request path)

**Events.** Emitted for every gateway-side rejection (jail, rate limit, tripwire, auth failure, breaker/saturation) and proxy errors. Health and metrics endpoints are excluded.

**Redaction before enqueue (allowlist-based).**
- Stored fields: request ID, timestamp, project ID, API-key *ID* (never the key), derived client IP, method, path, rule/decision code, status, and upstream origin.
- Headers: only an allowlist (`host`, `user-agent`, `content-type`, `content-length`, `referer`) is ever recorded. `Authorization`, `Cookie`, and `x-aegis-api-key` are never recorded.
- Query strings: values of parameters with sensitive names are replaced with a placeholder.
- Bodies: truncated to `TELEMETRY_BODY_MAX_BYTES` (2 KB). JSON bodies are redacted recursively by key name (case-insensitive: `password`, `passwd`, `secret`, `token`, `api_key`, `authorization`, `card_number`, `cvv`, `ssn`, `email`, and similar); non-JSON bodies get pattern-based masking (Luhn-valid card numbers, SSN and email patterns). Redaction is best effort; bodies are kept only for flagged events.

**Publishing.**
- The request path only pushes the event onto a bounded in-process buffer (`TELEMETRY_BUFFER_MAX`, 1000, **drop-oldest**). A separate publisher loop drains it to RabbitMQ over a confirm channel using persistent messages. `setImmediate` is not relied upon for correctness; what matters is that enqueue is cheap and broker slowness or blocking (`connection.blocked`) fills the buffer rather than the request path.
- Every dropped event increments `telemetry_dropped_total`.

**Broker configuration.**
- Durable queue `aegis.audit` with `x-max-length` (`AUDIT_QUEUE_MAX_LENGTH`, 100000) and `drop-head` overflow, so a long database outage degrades into bounded log loss instead of broker memory or disk alarms.
- Dead-letter exchange and queue `aegis.audit.dlq` for malformed/poison messages (rejected with `requeue=false`).

**Worker.**
- Consumes with `prefetch(50)` and accumulates up to `WORKER_BATCH_SIZE` (20) messages or `WORKER_BATCH_FLUSH_MS` (500 ms), then performs `insertMany({ ordered: false })` and acknowledges the batch (`multiple: true`). (`prefetch` bounds in-flight messages; batching is application logic.)
- On MongoDB failure: stop consuming, retry with exponential backoff, resume. Unacknowledged messages are redelivered.
- Webhook alerts (Slack/Discord) are rate-limited and payloads are escaped and truncated, because logged content is attacker-controlled.

**Storage.** MongoDB audit collection with a 30-day TTL index on `createdAt` and a `{ projectId, createdAt }` index.

**Display.** The admin console renders all telemetry fields as plain text (no raw HTML injection).

**Delivery guarantee.** Telemetry is best effort. Loss is possible under sustained outages and is observable via `telemetry_dropped_total` and queue depth.

### 4.12 Admin plane

- **Separate listener** on `ADMIN_BIND` (default `127.0.0.1:9090`), never on port 8080 and not published by default.
- **Authentication:** admin accounts with argon2id password hashes. Short-lived access token (15 min) sent in the `Authorization` header and held in memory (not `localStorage`); rotating refresh token in an `HttpOnly; Secure; SameSite=Strict` cookie. CORS restricted to the console origin. Login attempts are rate-limited separately from the data plane.
- **Roles:** `tenant` (manages own projects, keys, routes, upstreams; sees own telemetry) and `operator` (global settings, jail management, private-upstream allowlist).
- **Unban is an operator action**, because jails are global across tenants. Tenants see jail events affecting their project but cannot release IPs.
- Every state-changing admin action (key create/revoke, config change, unban) is written to an admin audit log.

### 4.13 Observability and lifecycle

- **Endpoints (admin listener):** `/healthz` (process up), `/readyz` (state Redis reachable, config loadable), `/metrics` (Prometheus text format).
- **Metrics:** requests by result code, rejections by reason, cache hit/miss/bypass, breaker state per upstream, in-flight per upstream, Redis and Mongo errors, `telemetry_dropped_total`, and a latency histogram for gateway overhead (total time minus upstream time).
- **Logs:** structured JSON with `requestId`; `X-Request-Id` is generated if absent and forwarded upstream.
- **Graceful shutdown:** on `SIGTERM`, stop accepting connections, drain in-flight requests up to `SHUTDOWN_GRACE_MS` (10 s), flush the telemetry buffer, then close Redis/AMQP/Mongo connections.

---

## 5. Data Model (summary)

```jsonc
// projects
{
  "_id": "...", "ownerId": "...", "name": "...",
  "apiKeys": [{ "id": "...", "prefix": "ag_ab12", "hash": "<sha256>", "status": "active|revoked", "createdAt": "...", "revokedAt": null }],
  "upstream": { "targetUrl": "https://...", "healthCheckPath": "/", "timeoutMs": 5000 },
  "jwt": { "alg": "RS256|HS256", "publicKey": "...", "secretEnc": "...", "iss": "...", "aud": "...", "keys": [{ "kid": "..." }] },
  "rateLimit": { "perMinute": 60 },
  "routes": [{
    "id": "...", "pathPattern": "/api/v1/products", "authMode": "none|jwt",
    "cache": { "enabled": true, "ttlSec": 60, "allowedQueryParams": ["page", "limit"] }
  }]
}
// indexes: projects.apiKeys.hash (unique), projects.ownerId
// audit_logs: { projectId, apiKeyId, ip, method, path, rule, status, createdAt, ... }
// indexes: createdAt (TTL 30d), { projectId, createdAt }
```

---

## 6. Technology Stack and Deployment Topology

| Component | Technology | Role |
|---|---|---|
| Gateway (data plane) | Node.js 20+, TypeScript, Express, `http-proxy-middleware`, RE2 | Pipeline, proxying, breaker, per-origin agents |
| Redis: **state** | Redis 7, `maxmemory-policy noeviction`, memory alerting | Jail, abuse scores, rate limits, tenant config cache. All keys are small and TTL-bound. |
| Redis: **cache** | Redis 7, `maxmemory` set, `allkeys-lru` | Response cache only. Eviction here can never affect security state. |
| Message broker | RabbitMQ 3 | Durable, bounded audit queue with DLQ. Chosen over Redis Streams for independent broker isolation and native DLQ/confirm semantics, at the cost of one more service to operate. |
| Audit worker | Node.js daemon | Batch consumer and MongoDB writer, webhook alerts |
| Store | MongoDB Atlas | Projects, hashed keys, admin accounts, audit logs (30-day TTL) |
| Admin console | React 18, Vite, Tailwind CSS | Tenant management, telemetry view, operator unban |
| Orchestration | Docker Compose (bridge network) | Local/prototype deployment. TLS terminated externally (section 1.2). |

---

## 7. Failure Modes and Reliability Matrix

| Failure | Policy | Behavior and trade-off |
|---|---|---|
| **Redis (state) down** | Abuse controls fail open; identity fails closed | Jail checks and scoring are skipped. Rate limiting falls back to a per-process in-memory limiter. Tenant config is read from local LRU, then MongoDB. If config is unavailable everywhere: `503 auth_backend_unavailable`. |
| **Redis (cache) down** | Fail open | Cache bypassed; all requests proxied. Upstream sees higher load; rate limits still apply. |
| **MongoDB down** | Identity: cached config only; telemetry: buffered | Requests whose tenant config is in local/Redis cache continue until it expires. Uncached tenants get `503`. The audit worker stops consuming and retries with backoff; the queue absorbs events up to its max length (oldest dropped beyond it). |
| **RabbitMQ down** | Fail open for traffic | Events accumulate in the in-process buffer (1000, drop-oldest). Proxy traffic is unaffected. On reconnect the buffer drains. |
| **Audit worker down** | Fail open | Queue grows to `x-max-length`, then drops oldest. |
| **Upstream down or slow** | Breaker + timeout + bulkhead | Timeouts return `504` and count as failures; after 5 consecutive failures the breaker opens and requests get immediate `503`. The in-flight cap bounds sockets and memory while the breaker is still CLOSED. |
| **Admin plane down** | Isolated | Data plane is unaffected; already-cached tenant config keeps working. |
| **Gateway process crash** | Not handled in v2.x | Single instance; restart policy in Compose. See L2. |

---

## 8. Threat Model and Known Limitations

**In scope (what AegisGate attempts to handle):** brute-force/bot request floods, basic injection probes reaching backends, upstream failure propagation, cross-tenant cache or rate-limit interference, tenant-supplied-URL SSRF, secret leakage into logs.

**Out of scope:** application-layer logic flaws, sophisticated WAF-grade evasion, volumetric L3/L4 DDoS, compromised host/container, malicious operators.

| # | Limitation |
|---|---|
| L1 | **Per-process circuit breaker.** With several gateway replicas each instance tracks upstream health independently. |
| L2 | **Single points of failure.** One instance each of gateway, both Redis instances, RabbitMQ, and the worker. No replication, Sentinel, or multi-node broker. "High availability" is not a v2.x goal. |
| L3 | **IP-based abuse control.** Shared NAT users share a score; attackers with many IPs evade bans. The jail is a cheap first line, not authentication. |
| L4 | **Regex evasion.** Hex/char-code encodings, comment splitting, and unusual encodings bypass the tripwire. Backends must never assume inputs are safe because the gateway passed them. |
| L5 | **Fixed-window rate limits** permit up to 2x the nominal rate across a boundary. |
| L6 | **Body coverage.** Only JSON, urlencoded, and text bodies up to the size cap are inspected. Multipart uploads and other types above the cap are rejected or passed uninspected; large file uploads are not supported through the gateway. |
| L7 | **Protocol coverage.** No WebSocket, SSE, or HTTP/2-to-upstream support. |
| L8 | **API key in browsers.** A key embedded in a browser app is an identifier, not a secret; protection relies on rate limits and per-route JWTs. |
| L9 | **Telemetry is best-effort.** Events can be dropped under sustained broker or database outages. |
| L10 | **No stale-if-error.** When an upstream is down, only still-fresh cache entries (up to 60 s old) are served. |
| L11 | **TLS is external.** The gateway speaks plain HTTP; API keys travel in clear text if deployed without a TLS terminator. |
| L12 | **Redaction is best effort.** Pattern-based masking of free-text bodies can miss sensitive data; the allowlist approach for headers and fields is the primary control. |

---

## 9. Verification Plan

### 9.1 Status tracking

Each requirement is tracked through three states. Only mark Implemented/Tested when it is true. Unchecked boxes are the honest default.

| ID | Requirement (section) | Implemented | Tested |
|---|---|---|---|
| R1 | Body cap incl. chunked streams (4.1) | ☐ | ☐ |
| R2 | Client-IP derivation, trusted CIDRs, IPv6 /64 (4.2) | ☐ | ☐ |
| R3 | Two-tier atomic rate limiting, one violation per window (4.3) | ☐ | ☐ |
| R4 | Abuse scoring and jail semantics (4.4) | ☐ | ☐ |
| R5 | API-key hashing, stripping, revocation bound (4.5) | ☐ | ☐ |
| R6 | JWT alg pinning and claim checks (4.5) | ☐ | ☐ |
| R7 | Tripwire on path/query/body, RE2 (4.6) | ☐ | ☐ |
| R8 | Cache eligibility, key, bypass rules, single-flight (4.7) | ☐ | ☐ |
| R9 | SSRF at registration and connect time (4.8) | ☐ | ☐ |
| R10 | Proxy header handling, timeouts, in-flight cap (4.9) | ☐ | ☐ |
| R11 | Circuit breaker with synthetic probe (4.10) | ☐ | ☐ |
| R12 | Redaction before enqueue, bounded queues, DLQ (4.11) | ☐ | ☐ |
| R13 | Admin plane auth, roles, separate listener (4.12) | ☐ | ☐ |
| R14 | Health, metrics, graceful shutdown (4.13) | ☐ | ☐ |

### 9.2 Automated tests (minimum set)

| Test | Expected result |
|---|---|
| Send `X-Forwarded-For: <victim>` from an untrusted peer | Header ignored; jail/limits apply to the socket IP |
| Same, from a trusted-CIDR peer | XFF honored per right-to-left rule |
| Exceed rate limit 50x in one window | Exactly 1 abuse point per tier for that window |
| 3 tripwire hits in 60 s from one IP | IP jailed 600 s; 4th request gets `403 ip_jailed` |
| 1 tripwire hit, then 61 s idle | Score expired; not jailed |
| Markdown body containing `--` | Not blocked |
| SQLi probe in query string of a GET | Blocked (`request_blocked`) |
| JWT with `alg: none`, wrong alg, expired, wrong `aud` | `401` in every case |
| Revoke API key | Rejected within the local-cache TTL at most |
| Register upstream `http://127.0.0.1:6379`, `http://169.254.169.254`, `http://[::1]/` | Rejected at registration |
| Hostname resolving to public IP at registration, private IP at request time | Connection refused at connect time |
| Upstream returns `302 Location: http://10.0.0.5/` | Returned to client; not followed |
| 100 concurrent requests during half-open | Exactly one probe sent; all client requests get `503` |
| Upstream delayed beyond timeout ×5 | `504` ×5, then breaker OPEN, then immediate `503` |
| Upstream returns `404` repeatedly | Breaker stays CLOSED |
| Cache: `?a=1&b=2` vs `?b=2&a=1` | Same key, single stored entry |
| Cache: `?random=xyz` on a route without that param allowed | `BYPASS`; no new entry |
| Response with `Set-Cookie`, `no-store`, or foreign `Vary` | Never stored |
| Request with `Authorization` or `Cookie` on whitelisted route | `BYPASS` |
| 50 concurrent misses for one key | One upstream request (single-flight) |
| Log a JSON body with `password`, `email`, Luhn-valid card number | Values masked in RabbitMQ message and in MongoDB |
| Request with `Authorization` and `x-aegis-api-key` headers | Neither appears in telemetry |

### 9.3 Benchmark methodology (no results claimed yet)

- Tool: `autocannon` or `k6`. Record hardware, Node version, Redis/Mongo topology, and whether services run on one host.
- Scenarios: (a) direct to upstream (baseline), (b) through gateway with full pipeline, cache miss, (c) cache hit, (d) jailed-IP rejection, (e) rate-limited rejection.
- Report: requests/s and **p50/p95/p99** latency at stated concurrency levels; gateway overhead = (b) minus (a) at the same load.
- Publish results and raw data in `docs/benchmarks.md`. Update this PRD's performance objectives from measured data only.

### 9.4 Failure-injection scenarios (results to be recorded)

| Scenario | Method | Expected behavior |
|---|---|---|
| Upstream killed | Stop container | Timeouts/refusals → breaker OPEN → fast `503`; recovery through probe after upstream returns |
| Upstream slow | Toxiproxy latency > timeout | `504`s, in-flight cap enforced, sockets bounded |
| Redis (state) killed | Stop container | Traffic continues; local limiter active; jail skipped; uncached-tenant behavior per matrix |
| Redis (cache) killed | Stop container | All requests `BYPASS`; no errors to clients |
| RabbitMQ killed | Stop container | Proxy traffic unaffected; buffer fills to 1000 then drops oldest; drains on reconnect |
| RabbitMQ blocked (disk/memory alarm) | Force alarm | Buffer absorbs; `telemetry_dropped_total` increases; no request latency impact |
| MongoDB killed | Network cut | Worker backs off; queue grows to max length; cached tenants keep working |
| Gateway SIGTERM under load | `kill -TERM` | In-flight requests complete; buffer flushed; clean exit |

---

## 10. Roadmap

**v2.2 (depth)**
- Sliding-window counter or token-bucket limiter, with a written comparison against the fixed window.
- `stale-if-error` cache serving while the breaker is OPEN.
- Rolling error-rate breaker with minimum request volume.
- Escalating jail durations for repeat offenders.
- Cross-instance single-flight (Redis `SET NX` lock).

**v3.0 (scale)**
- Shared breaker state via Redis, or documented per-instance semantics with health aggregation.
- Redis Sentinel/replication and multi-instance deployment behind a load balancer.
- WebSocket and SSE passthrough.
- Honest comparison write-up versus Nginx, Traefik, and Kong.

Explicitly **not** planned: Kubernetes, Kafka, or ML-based detection. None of them addresses a current gap.

---

## Appendix A: Configuration Defaults

These are initial defaults, to be tuned after the section 9.3 benchmark. All are environment-configurable unless noted.

| Variable | Default |
|---|---|
| `MAX_BODY_BYTES` | 102400 |
| `SCAN_BODY_CONTENT_TYPES` | `application/json,application/x-www-form-urlencoded,text/plain` |
| `TRUSTED_PROXY_CIDRS` | (empty: no proxies trusted) |
| `PRE_AUTH_RATE_LIMIT` | 120 per 60 s per IP |
| `DEFAULT_TENANT_RATE_LIMIT` | 60 per 60 s per (project, IP) |
| `ABUSE_WINDOW_SEC` / `ABUSE_THRESHOLD` / `JAIL_TTL_SEC` | 60 / 3 / 600 |
| `TENANT_CONFIG_REDIS_TTL_SEC` / `TENANT_CONFIG_LOCAL_TTL_SEC` | 300 / 15 |
| `UPSTREAM_CONNECT_TIMEOUT_MS` / `UPSTREAM_TIMEOUT_MS` | 2000 / 5000 (route max 30000) |
| `MAX_INFLIGHT_PER_UPSTREAM` | 100 |
| `BREAKER_FAILURE_THRESHOLD` / `BREAKER_COOLDOWN_MS` | 5 / 30000 |
| `CACHE_TTL_SEC` / jitter | 60 / ±10% |
| `CACHE_MAX_BODY_BYTES` / `CACHE_MAX_KEY_BYTES` | 262144 / 512 |
| `TELEMETRY_BUFFER_MAX` / `TELEMETRY_BODY_MAX_BYTES` | 1000 / 2048 |
| `AUDIT_QUEUE_MAX_LENGTH` | 100000 |
| `WORKER_BATCH_SIZE` / `WORKER_BATCH_FLUSH_MS` / `WORKER_PREFETCH` | 20 / 500 / 50 |
| Audit log retention | 30 days (TTL index) |
| `SHUTDOWN_GRACE_MS` | 10000 |
| `ALLOW_PRIVATE_UPSTREAMS` | `false` (operator-only) |
| `ADMIN_BIND` | `127.0.0.1:9090` |