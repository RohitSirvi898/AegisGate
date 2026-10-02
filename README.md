# 🛡️ AegisGate - Resilient API Security Gateway & Reverse Proxy

AegisGate is a lightweight reverse-proxy API gateway written in Node.js and TypeScript, designed to centralize critical perimeter concerns for microservice architectures: rate limiting, authentication verification, request pattern filtering, response caching, and upstream failure isolation.

Built as an educational and practical system-design implementation, it acts as a transparent boundary shield in front of backend containers without requiring application-level code modifications.

---

## 📐 System Architecture (Data & Telemetry Planes)

```mermaid
%%{init: {'flowchart': {'htmlLabels': true, 'curve': 'bump'}, 'theme': 'base', 'themeVariables': { 'primaryColor': '#1e293b', 'primaryTextColor': '#f8fafc', 'primaryBorderColor': '#334155', 'lineColor': '#94a3b8'}}}%%
graph LR
    %% Clients
    Client("🌐 Client API /<br/>HTTP Fetch")
    Console("💻 admin-dashboard<br/>React Console")

    %% Core Data Plane
    subgraph DataPlane ["🔐 Edge Ingress Pipeline (gateway-core :8080)"]
        direction TB
        PayloadCap["1. Ingress 100KB Cap<br/>(Header & Stream Byte Counter)"]
        IPExtract["2. Client IP Derivation<br/>(Socket IP / Trusted CIDRs / IPv6 /64)"]
        IPJail{"3. Redis IP Jail Check<br/>(10-Min Ban / Abuse Scoring)"}
        AuthCheck{"4. Auth & Scope Gate<br/>(Stateless JWT / Hashed ag_live_ Keys)"}
        RateLimit{"5. Atomic Redis Rate Limiter<br/>(O(1) Lua Script)"}
        Tripwire{"6. Security Tripwire<br/>(SQLi / XSS RE2 Pattern Match)"}
        CacheCheck{"7. Response Cache<br/>(Single-Flight / Whitelisted GET)"}
        Breaker{"8. Circuit Breaker & Bulkhead<br/>(100 In-Flight Cap / Health Probe)"}
        Proxy["9. Reverse Proxy Forwarder<br/>(TCP Socket Pooling keepAlive: true)"]
    end

    %% State & Storage
    subgraph StorageLayer ["💾 State & Message Infrastructure"]
        RedisState[("Redis (State)<br/>Jail / Rate Limits / Config")]
        RedisCache[("Redis (Cache)<br/>Response Caching")]
        Queue[["RabbitMQ Broker<br/>(Durable aegis.audit + DLQ)"]]
    end

    %% Async Worker
    subgraph AuditPlane ["⚙️ Async Telemetry Plane"]
        Worker["async-audit-worker<br/>(Prefetch 50 / Batch 20 or 500ms)"]
        Mongo[("MongoDB Atlas<br/>(30-Day TTL Audit Store)")]
    end

    %% Upstream Target
    Upstream[("🎯 Upstream Microservice<br/>(Protected Backend)")]

    %% Ingress Flow
    Client -->|Port 8080| PayloadCap
    PayloadCap --> IPExtract --> IPJail --> AuthCheck --> RateLimit --> Tripwire --> CacheCheck --> Breaker --> Proxy
    Proxy -->|SSRF-Safe Socket| Upstream

    %% Rejections & Telemetry Flow
    PayloadCap -.->|413 Payload Too Large| Client
    IPJail -.->|403 ip_jailed| Client
    AuthCheck -.->|401 Unauthorized| Client
    RateLimit -.->|429 rate_limited| Client
    Tripwire -.->|403 request_blocked| Client
    Breaker -.->|503 upstream_unavailable| Client
    CacheCheck -.->|200 OK (Cache HIT)| Client

    %% Async Telemetry Path
    DataPlane -.->|Pre-Queue Redacted Events<br/>Bounded In-Process Buffer (1000 cap)| Queue
    Queue -.->|AMQP Stream| Worker
    Worker -->|Bulk insertMany| Mongo

    %% Management Connections
    Console -->|Admin Endpoints :8080| DataPlane
    DataPlane <--> RedisState
    DataPlane <--> RedisCache
```

---

## ⚡ Core Engineering Features (PRD v2.1 Hardened)

### 1. Ingress Safeguards & Anti-Spoofing Client IP Derivation
* **100KB Ingress Cap**: Rejects requests with Content-Length > 100KB with 413 `payload_too_large` before buffering bodies. Chunked transfer streams are aborted via a byte-counting transform stream.
* **Anti-Spoofing IP Resolution**: Uses socket IP (`req.socket.remoteAddress`) by default. Parses `X-Forwarded-For` right-to-left only when the peer belongs to configured `TRUSTED_PROXY_CIDRS`.
* **IPv6 /64 Prefix Masking**: Truncates native IPv6 addresses to their /64 subnet prefix, preventing attackers from rotating IPv6 host addresses to evade bans.

### 2. Proactive Redis IP-Jail (Abuse Scoring)
* **Abuse Scoring Tripwire**: Replaces fragile single-hit bans with a 60-second fixed-window abuse score (`abuse:<ip>`).
* **Ban Semantics**: Exceeding 3 abuse points (from repeated rate-limit violations or tripwire hits) sets `jail:<ip>` for 10 minutes (403 `ip_jailed`), dropping abusive clients at the ingress boundary in sub-millisecond time.
* **Operator Unban**: Full unban and manual release controls via React Admin Console (`POST /api/v1/admin/unban`).

### 3. Connect-Time SSRF Defense & DNS Pinning
* **Registration & Connect-Time Verification**: Blocks private RFC 1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local/cloud metadata (`169.254.169.254`), and dangerous ports (22, 25, 5432, 6379, 27017).
* **DNS Pinning**: Uses a custom DNS resolver on HTTP/HTTPS agents that resolves the destination hostname once and pins the validated IP directly to the socket, neutralizing DNS-rebinding (TOCTOU) exploits.

### 4. Per-Upstream Circuit Breaker & Bulkhead
* **Fault Isolation**: State machine (`CLOSED`, `OPEN`, `HALF_OPEN`) isolated per upstream target origin.
* **Bulkhead Concurrency Cap**: Rejects excess requests beyond `MAX_INFLIGHT_PER_UPSTREAM` (default: 100) with 503 `upstream_saturated` to prevent socket exhaustion during slow backend periods.
* **Fail-Fast & Synthetic Probe**: Trips to `OPEN` after 5 consecutive upstream failures (5xx or timeouts > 5,000ms), immediately responding with 503 `upstream_unavailable`. Uses a single synthetic `GET /` probe during `HALF_OPEN` before restoring live traffic.

### 5. Safe Response Caching (Anti-Leakage & Stampede Protection)
* **Strict Bypass Rules**: Bypasses cache if `Authorization` or `Cookie` headers are present, or if the upstream returns `Set-Cookie`, `no-store`, or `private`.
* **Canonical Key Formatting**: `cache:{projectId}:{routeId}:GET:{path}?{sortedQuery}` sorts allowed query parameters alphabetically and bypasses unlisted parameters to prevent cache-busting attacks.
* **Single-Flight Coalescing**: Consolidates concurrent cache misses for the same key into a single upstream request, preventing cache stampedes.

### 6. Pre-Queue Telemetry Redaction & Bounded Buffering
* **Edge PII Redaction**: Sensitive headers (`Authorization`, `Cookie`, `x-aegis-api-key`) and payload fields (`password`, `credit_card`, `ssn`, `email`) are scrubbed before messages reach RabbitMQ.
* **Bounded In-Process Buffer**: Buffers up to 1,000 events in memory during broker disconnects, applying a drop-oldest policy (`telemetry_dropped_total`) to prevent Node.js heap exhaustion.
* **Bulk Worker Ingestion**: Worker consumes via `prefetch(50)` and flushes to MongoDB Atlas in batches of 20 items or every 500ms using `insertMany({ ordered: false })`.

---

## ⚡ 5-Minute Developer Quickstart

AegisGate acts as a drop-in reverse proxy in front of your backend services:

### Step 1: Docker Compose Mesh

```yaml
version: '3.8'

services:
  # Your existing backend (isolated from public internet)
  my-backend-api:
    image: my-sample-api:latest
    expose:
      - "5000"
    networks:
      - aegis_mesh

  # AegisGate Edge Proxy
  aegis-gateway:
    image: rohitsirvi/aegisgate-core:latest
    ports:
      - "8080:8080" # Exposed publicly to clients
    environment:
      - PORT=8080
      - UPSTREAM_TARGET_URL=http://my-backend-api:5000
      - REDIS_URL=redis://aegis-cache:6379
      - RABBITMQ_URL=amqp://aegis-queue:5672
      - MONGO_URI=mongodb+srv://<USER>:<PASS>@cluster.mongodb.net/AegisGate
      - JWT_SECRET=your_jwt_signing_key_here
      - ALLOW_PRIVATE_UPSTREAMS=true
    depends_on:
      - aegis-cache
      - aegis-queue
    networks:
      - aegis_mesh

  # Redis Distributed State & Cache
  aegis-cache:
    image: redis:7-alpine
    networks:
      - aegis_mesh

  # RabbitMQ Broker for Asynchronous Telemetry
  aegis-queue:
    image: rabbitmq:3-management-alpine
    networks:
      - aegis_mesh

networks:
  aegis_mesh:
    driver: bridge
```

### Step 2: Boot Infrastructure

```bash
docker compose up -d --build
```

### Step 3: Route Client Traffic

Point your frontend requests to the proxy host (`http://localhost:8080`), injecting your project API key:

```javascript
fetch('http://localhost:8080/api/v1/orders', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'x-aegis-api-key': 'ag_live_0b4bc02d0c468ad66b49ba4637883edd7c336628d43f3afe'
  },
  body: JSON.stringify({ item: 'Widget', qty: 2 })
})
.then(res => res.json())
.then(data => console.log('Proxied Response:', data))
.catch(err => console.error('Connection error:', err));
```

---

## 📦 Directory Structure

```text
aegis-gate/
├── services/
│   ├── gateway-core/           # Node.js/TS Edge Ingress Proxy & Middlewares (Port 8080)
│   ├── async-audit-worker/     # Node.js/TS RabbitMQ Batch Consumer & MongoDB Persister
│   └── admin-dashboard/        # React/Vite/Tailwind Control Console (Circuit & Jail Manager)
├── scripts/
│   └── vps-setup.sh            # Automated Cloud VPS Provisioning Script
├── docker-compose.yml          # Local Dev Environment Orchestration
├── docker-compose.prod.yml     # Production Mesh Configuration
├── PRD.md                      # Hardened System Design Specification (PRD v2.1)
└── README.md                   # System Operations Manual
```

---

## 🛡️ Standard Error Contract

All gateway-generated rejections return uniform JSON and set the `X-Request-Id` response header:

| Status Code | Error Code (`error`) | Trigger Condition |
| :--- | :--- | :--- |
| **401 Unauthorized** | `invalid_or_missing_credentials` | Missing or invalid `x-aegis-api-key` / JWT |
| **403 Forbidden** | `ip_jailed` | Client IP is currently in 10-minute Redis ban |
| **403 Forbidden** | `request_blocked` | Coarse SQLi / XSS pattern detected by tripwire |
| **413 Payload Too Large** | `payload_too_large` | Body size exceeds 100KB cap |
| **429 Too Many Requests** | `rate_limited` | Rate limit window exceeded (includes `Retry-After`) |
| **503 Service Unavailable** | `upstream_unavailable` | Target circuit breaker is in `OPEN` state |
| **503 Service Unavailable** | `upstream_saturated` | Upstream concurrent in-flight cap (100) reached |
| **503 Service Unavailable** | `auth_backend_unavailable` | Project credentials could not be loaded |
| **504 Gateway Timeout** | `upstream_timeout` | Upstream failed to respond within 5,000ms |

---

## 🧪 Automated Test Suite & Verification

Validate all architectural requirements and failure behaviors locally:

```bash
# gateway-core: Test SSRF, Circuit Breaker, IP Jail, and Caching
cd services/gateway-core && npx tsx src/__tests__/hardening.test.ts

# async-audit-worker: Test Batch Ingestion, DLQ, and Outage Backoff
cd services/async-audit-worker && npx tsx src/__tests__/worker.test.ts

# Production build verification
cd services/gateway-core && npm run build
cd services/async-audit-worker && npm run build
cd services/admin-dashboard && npm run build
```
