# 🛡️ AegisGate: Comprehensive Project & Architecture Documentation

---

## 1. Executive Summary & Project Idea

### 1.1 What is AegisGate?
**AegisGate** is a production-grade, lightweight, and resilient API Security Gateway, Reverse Proxy, and Telemetry Engine written in **Node.js**, **Express**, and **TypeScript**, backed by **Redis 7**, **RabbitMQ**, **MongoDB Atlas**, and an **IBM Plex-styled React 19 Admin Console**.

AegisGate is designed to serve as a **transparent perimeter shield** positioned in front of downstream microservices and APIs. It absorbs, filters, throttles, and audits incoming web traffic without requiring code modifications to the protected backend services.

```
                           ┌────────────────────────────────────────┐
                           │            CLIENT INGRESS              │
                           │   (Public Mobile, Web, API Clients)    │
                           └──────────────────┬─────────────────────┘
                                              │ HTTP(S) Request
                                              ▼
    ┌─────────────────────────────────────────────────────────────────────────────────┐
    │                      AEGISGATE DUAL-PLANE ARCHITECTURE                          │
    │                                                                                 │
    │   ┌─────────────────────────────────────────────────────────────────────────┐   │
    │   │                    SYNCHRONOUS DATA PLANE (PORT 8080)                   │   │
    │   │                                                                         │   │
    │   │  1. Ingress Safeguards: 100KB Limit + Anti-Spoofing Client IP           │   │
    │   │  2. Redis IP-Jail: 60s Abuse Window (>=3 violations = 10-Min Ban)       │   │
    │   │  3. Sliding-Window Rate Limiter: Atomic Redis Lua O(1) Execution        │   │
    │   │  4. Dynamic Tenant Resolution: API Key Lookup (Cached 5 min)            │   │
    │   │  5. Security Filter: RE2 Signature Tripwire (SQLi, XSS, Traversal)      │   │
    │   │  6. Response Cache: Query-Param Normalization + Single-Flight Lock      │   │
    │   │  7. Circuit Breaker & Bulkhead: Closed/Open/Half-Open + 100 Concurrency │   │
    │   │  8. SSRF Defense: Connect-Time IP Denylist + DNS Pinning Socket         │   │
    │   └──────────────────────┬──────────────────────────────────────────────────┘   │
    │                          │                                                      │
    │                          ├─────────────────────────┐                            │
    │            Fast Proxy    │                         │ Asynchronous Out-of-Band   │
    │            (Low Latency) │                         │ Telemetry Events           │
    │                          ▼                         ▼                            │
    │          ┌───────────────────────┐   ┌──────────────────────────────────────┐   │
    │          │  PROTECTED UPSTREAM   │   │     ASYNCHRONOUS TELEMETRY PLANE     │   │
    │          │     MICROSERVICES     │   │                                      │   │
    │          │ (Node/Go/Python/Java) │   │ • Pre-Queue Edge PII Redaction       │   │
    │          └───────────────────────┘   │ • Bounded In-Process Ring Buffer     │   │
    │                                      │ • RabbitMQ Exchange & Queue          │   │
    │                                      │ • Dead-Letter Queue (DLQ Poison Trap)│   │
    │                                      │ • Batch Ingestion Worker (20/500ms)  │   │
    │                                      │ • MongoDB Atlas (30-Day TTL Store)   │   │
    │                                      │ • Real-time Webhook Dispatcher       │   │
    │                                      └──────────────────┬───────────────────┘   │
    │                                                         │                       │
    │                                                         ▼                       │
    │                                      ┌──────────────────────────────────────┐   │
    │                                      │    OPERATOR & OBSERVABILITY PLANE    │   │
    │                                      │       (React 19 Admin Console)       │   │
    │                                      │                                      │   │
    │                                      │ • Live Threat Stream & Inspector     │   │
    │                                      │ • Redis Jailed IP Unban Controls     │   │
    │                                      │ • Upstream Circuit Breaker Monitors  │   │
    │                                      │ • DLQ Poison Message Inspector       │   │
    │                                      │ • Multi-Tenant API Key Provisioning  │   │
    │                                      │ • Security & Webhook Config Editor   │   │
    │                                      └──────────────────────────────────────┘   │
    └─────────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 The Problem AegisGate Solves
Modern distributed systems suffer from several recurring operational risks:
1. **Perimeter Fragility**: Microservices frequently expose unauthenticated or poorly rate-limited endpoints, leaving them vulnerable to volumetric brute-force attacks and credential stuffing.
2. **Cascading Failures**: When one downstream dependency becomes sluggish or unresponsive, upstream connection pools saturate, eventually starving the entire application fleet of sockets (thread pool exhaustion).
3. **SSRF Vulnerabilities**: Applications that accept webhook URLs or proxy target parameters can be tricked into scanning internal private subnets (`10.0.0.0/8`, `192.168.0.0/16`, AWS/GCP metadata at `169.254.169.254`).
4. **Data Privacy Leakage in Audit Trails**: Naive logging engines often write raw HTTP payloads to databases, accidentally persisting passwords, credit card numbers, and authorization tokens into permanent storage.
5. **Slowdown from Synchronous Logging**: Writing security audit trails synchronously within the request-response lifecycle adds tens or hundreds of milliseconds of overhead to every user request.

### 1.3 The AegisGate Solution
AegisGate enforces **Dual-Plane Separation**:
- **Data Plane**: Executes synchronous, sub-millisecond edge validations (anti-spoofing IP resolution, atomic Redis sliding-window throttling, in-memory regex tripwires, single-flight response caching, and bulkhead socket isolation).
- **Telemetry Plane**: Offloads all logging, payload scrubbing, database persistence, and webhook dispatching completely out-of-band via RabbitMQ and an asynchronous batch worker.

---

## 2. Core Features & Capabilities

### 2.1 Ingress Safeguards & Anti-Spoofing IP Resolution
- **100KB Ingress Cap**: Rejects oversized payloads immediately with HTTP `413 Payload Too Large` using both header inspection (`Content-Length`) and raw stream byte-counting before buffering.
- **Anti-Spoofing Client IP**: Parses `X-Forwarded-For` right-to-left only when the direct peer socket IP is verified against configured `TRUSTED_PROXY_CIDRS`. Otherwise, it falls back strictly to the direct socket IP (`req.socket.remoteAddress`).
- **IPv6 /64 Prefix Masking**: Native IPv6 client addresses are truncated to their `/64` subnet prefix, preventing attackers from rotating host addresses within the same subnet to bypass rate limits or jail rules.

### 2.2 Abuse Scoring IP-Jail (Redis 7)
- **Cumulative Abuse Scoring**: Rather than imposing brittle single-hit bans, AegisGate maintains a 60-second fixed sliding abuse score in Redis (`abuse:<ip>`).
- **10-Minute Jailing**: Reaching 3 abuse points (accumulated from rate-limit violations, tripwire hits, or structural anomalies) sets `jail:<ip>` for 10 minutes (`600s TTL`). All subsequent requests from the IP are rejected at the edge with HTTP `403 Forbidden` (`ip_jailed`).
- **Admin Unban**: Operators can inspect jailed IPs, examine remaining TTLs, trigger sources, and last request paths, and instantly release an IP via `POST /api/v1/admin/unban`.

### 2.3 Sliding-Window Rate Limiter
- **Atomic Lua Scripting**: Enforces a sliding-window rate limit using Redis Sorted Sets (`ZADD`, `ZREMRANGEBYSCORE`, `ZCARD`, `EXPIRE`).
- **Zero Race Conditions**: Because the script executes atomically on the Redis master node, concurrent requests cannot bypass the quota.
- **Pre-Auth and Per-Tenant Quotas**: Protects public ingress before authentication, and enforces per-project burst limits once tenant credentials are confirmed.

### 2.4 Security Filter & RE2 Signature Tripwires
- **Injection Pattern Matching**: Scans request query parameters, URL path strings, and JSON request bodies for SQL Injection (`sqli.tautology`, `sqli.union`), Cross-Site Scripting (`xss.script-tag`, `xss.event-handler`), and Directory Traversal (`traversal.dotdot`, `traversal.encoded`).
- **Observation Mode (Dry Run)**: Tenants can configure `dryRun: true`. In observation mode, threats are tagged, header-flagged (`X-Threat-Detected: true`), and forwarded to asynchronous audit telemetry without blocking the user request.
- **Active Enforcement Mode**: When `dryRun: false`, malicious requests are blocked immediately with HTTP `403 Forbidden` (`request_blocked`), saving upstream server compute.

### 2.5 Connect-Time SSRF Defense & DNS Pinning
- **Strict IP Denylist**: Disallows routing to RFC 1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.0/8`), carrier-grade NAT (`100.64.0.0/10`), link-local/cloud metadata (`169.254.169.254`), and dangerous ports (SSH 22, SMTP 25, Redis 6379, MongoDB 27017).
- **DNS Pinning Socket Agent**: Resolves the upstream hostname once at connect time, validates the resolved IP address, and pins the socket directly to that IP address, preventing Time-of-Check to Time-of-Use (TOCTOU) DNS-rebinding attacks.

### 2.6 Per-Upstream Circuit Breaker & Bulkhead
- **State Machine Isolation**: Maintains independent `CLOSED`, `OPEN`, and `HALF_OPEN` states per upstream target origin.
- **Bulkhead Concurrency Cap**: Restricts active in-flight requests to a maximum of 100 per upstream (`MAX_INFLIGHT_PER_UPSTREAM = 100`). Excess concurrent requests fail fast with HTTP `503 Service Unavailable` (`upstream_saturated`).
- **Failure Trips & Synthetic Health Probes**: 5 consecutive upstream timeouts (>5000ms) or 5xx server errors trip the breaker to `OPEN`. During `HALF_OPEN`, a single synthetic probe (`GET /`) verifies upstream health before restoring user traffic.

### 2.7 Safe Response Caching
- **Anti-Leakage Guardrails**: Completely bypasses cache if request contains `Authorization` or `Cookie`, or if upstream response includes `Set-Cookie`, `Cache-Control: no-store`, or `Cache-Control: private`.
- **Deterministic Key Normalization**: Builds canonical cache keys `cache:{projectId}:{routeId}:GET:{path}?{sortedQuery}` with alphabetically sorted query parameters.
- **Single-Flight Coalescing**: Consolidates multiple concurrent requests for the exact same uncached URL into a single in-flight upstream promise, completely mitigating cache stampedes (thundering herd problem).

### 2.8 Pre-Queue PII Scrubbing & Async Audit Pipeline
- **Edge PII Redaction**: Strips sensitive headers (`Authorization`, `Cookie`, `x-aegis-api-key`) and masks sensitive JSON fields (`password`, `credit_card`, `ssn`, `email`) before telemetry is published to RabbitMQ.
- **In-Memory Ring Buffer**: Implements a bounded 1,000-event in-process buffer during RabbitMQ broker reconnects, using a drop-oldest policy to protect Node.js heap stability.
- **High-Throughput Batch Worker**: The worker service consumes messages with `prefetch(50)` and flushes to MongoDB Atlas in batches of 20 items or every 500ms using `insertMany({ ordered: false })`.
- **Outage Recovery**: If MongoDB becomes temporarily unavailable, the worker cancels its consumer, avoids acknowledging messages (leaving them in RabbitMQ), and retries with exponential backoff up to 30 seconds.

### 2.9 Dead-Letter Queue (DLQ) & Poison Message Isolation
- **Dead-Letter Exchange (`aegis_dlx`)**: Messages that fail unmarshalling or processing after 3 retry attempts are automatically isolated to `aegis.audit.dlq` (`aegis_dead_letter`).
- **Admin DLQ Console**: Enables security operators to inspect unprocessable poison messages, view failure reasons, inspect sanitized 2KB payload excerpts, and trigger retries or purges.

### 2.10 Multi-Tenant Self-Service Console (React 19)
- **Tenant Provisioning**: Generate project names, unique IDs, and hashed API keys (`ag_live_...`).
- **Granular Security Controls**: Toggle observation mode (dry-run) and signature filter on a per-tenant basis.
- **Webhook Alert Integrations**: Configure Slack and Discord webhooks with mask/unmask toggles for instant threat notification delivery.
- **Live Observability**: Real-time KPI summary cards, live threat stream table, expandable jailed IP table with countdown progress bars, and circuit breaker status tiles.

---

## 3. Repository Directory Structure

```
aegis-gate/
├── .env.example                                  # Master environment configuration template
├── docker-compose.yml                            # Local development stack (Redis, RabbitMQ, Mongo, App)
├── docker-compose.prod.yml                       # Production-grade hardened container orchestration
├── README.md                                     # System overview and quickstart guide
├── AegisGate_End_to_End_Postman_Testing_Manual.md# Automated API test suite instructions
├── docs/                                         # Architectural documentation & PRD specifications
│   ├── AegisGate_PRD_v2.2.md                     # Comprehensive Product Requirements Document (PRD)
│   ├── PROJECT_DOCUMENTATION.md                  # This master project & file documentation
│   └── PRD.md                                    # Baseline functional specifications
├── infrastructure/                               # Infrastructure-as-code and container definitions
│   └── docker/                                   # Service Dockerfiles and runtime build scripts
├── scripts/                                      # Automation and deployment scripts
│   └── vps-setup.sh                              # Automated Ubuntu VPS host provisioning script
└── services/                                     # Microservice workspace packages
    ├── gateway-core/                             # Core Edge Reverse Proxy & API Gateway (Port 8080)
    │   ├── Dockerfile
    │   ├── package.json
    │   ├── tsconfig.json
    │   └── src/
    │       ├── index.ts                          # Gateway entrypoint & HTTP pipeline configuration
    │       ├── config/                           # External infrastructure drivers
    │       │   ├── queue.ts                      # RabbitMQ connection, channel & ring-buffer publisher
    │       │   └── redis.ts                      # Redis 7 client connection & lifecycle management
    │       ├── middleware/                       # Synchronous Data Plane middleware pipeline
    │       │   ├── authenticate.ts               # API key & JWT authentication and role authorization
    │       │   ├── circuitBreaker.ts             # Per-origin circuit breaker state machine & bulkhead
    │       │   ├── ipJail.ts                     # Redis abuse scoring & IP jail verification middleware
    │       │   ├── rateLimiter.ts                # Sliding-window atomic Lua rate limiter
    │       │   ├── requireAuth.ts                # Route-level bearer token auth guard
    │       │   ├── responseCache.ts              # Canonical query response caching & stampede shield
    │       │   └── securityFilter.ts             # RE2 SQLi, XSS, and Path Traversal tripwire filter
    │       ├── models/                           # Mongoose data schemas for Gateway Core
    │       │   ├── User.ts                       # Admin/operator user credentials schema
    │       │   ├── deadLetter.ts                 # Dead-letter queue record schema
    │       │   ├── project.ts                    # Tenant project configuration schema
    │       │   └── threatLog.ts                  # Threat detection incident log schema
    │       ├── routes/                           # Gateway Core API routing modules
    │       │   ├── admin.ts                      # Admin endpoints (IP unban, circuit breakers, jail status)
    │       │   ├── analytics.ts                  # Telemetry query, stats aggregation & DLQ endpoints
    │       │   ├── auth.ts                       # Operator authentication (login & registration)
    │       │   ├── projects.ts                   # Tenant project CRUD and settings management
    │       │   └── users.ts                      # User management endpoints
    │       └── utils/                            # Core gateway utility functions & security guards
    │           ├── errors.ts                     # Unified RFC 7807 error responses & request IDs
    │           ├── ip.ts                         # Anti-spoofing client IP resolution & IPv6 subnet masking
    │           ├── piiScrubber.ts                # Recursive JSON and header PII redaction
    │           ├── ssrf.ts                       # Connect-time SSRF denylist & DNS pinning agents
    │           └── telemetry.ts                  # Out-of-band audit event emitter
    │
    ├── async-audit-worker/                       # Asynchronous Background Worker Microservice
    │   ├── Dockerfile
    │   ├── package.json
    │   ├── tsconfig.json
    │   └── src/
    │       ├── index.ts                          # Worker microservice entrypoint
    │       ├── worker.ts                         # RabbitMQ consumer, batching & outage recovery logic
    │       ├── models/                           # Worker Mongoose models
    │       │   ├── AuditLog.ts                   # Standardized audit log model (with 30-day TTL)
    │       │   ├── deadLetter.ts                 # Dead-letter record model
    │       │   └── threatLog.ts                  # Threat incident log model
    │       └── utils/                            # Worker utility functions
    │           ├── piiScrubber.ts                # Secondary worker PII scrubber
    │           ├── webhookNotifier.ts            # Webhook dispatcher bridge
    │           └── webhooks.ts                   # Discord and Slack webhook delivery with retries
    │
    └── admin-dashboard/                          # React 19 / TypeScript Operator Console (Vite)
        ├── Dockerfile
        ├── index.html                            # Main HTML with IBM Plex typography
        ├── package.json
        ├── vite.config.ts
        ├── src/
        │   ├── App.css                           # Global CSS resets
        │   ├── App.tsx                           # Route configuration & context providers
        │   ├── index.css                         # Design tokens, typography & prototype utility classes
        │   ├── main.tsx                          # React root initialization
        │   ├── components/                       # Dashboard UI view components
        │   │   ├── DLQMonitor.tsx                # Dead-letter queue inspector component
        │   │   ├── Dashboard.tsx                 # Main console (KPIs, Jailed IPs, Breakers, Threats)
        │   │   ├── Icons.tsx                     # Pixel-perfect SVG icon component definitions
        │   │   ├── ProjectSettings.tsx           # Project settings & webhook configuration editor
        │   │   ├── ProtectedRoute.tsx            # Protected authentication route guard
        │   │   └── TenantProvisioning.tsx        # Tenant creation & API key generator component
        │   ├── context/                          # Global React Context providers
        │   │   ├── AuthContext.tsx               # JWT token & active project state management
        │   │   └── ToastContext.tsx              # Auto-dismissing floating toast notification system
        │   ├── hooks/                            # Custom React hooks
        │   │   └── useThreatTelemetry.ts         # Polling hook for live threat telemetry stream
        │   ├── pages/                            # Full-page view layouts
        │   │   └── AuthScreen.tsx                # Operator Sign-in & Account Registration screen
        │   └── services/                         # Client API integration layer
        │       └── api.ts                        # Backend HTTP client, JWT injection & API wiring
```

---

## 4. Exhaustive File-by-File Breakdown & Functionality

### 4.1 Root Workspace Configuration Files

| File Path | Functionality & Key Responsibilities |
| :--- | :--- |
| **[.env.example](file:///d:/aegis-gate/.env.example)** | Defines all required environment variables across microservices: database URIs (`MONGO_URI`), broker URLs (`RABBITMQ_URL`), cache settings (`REDIS_URL`), ports (`PORT`), security secrets (`JWT_SECRET`), and trusted proxy subnets (`TRUSTED_PROXY_CIDRS`). |
| **[docker-compose.yml](file:///d:/aegis-gate/docker-compose.yml)** | Multi-container development orchestration defining services: `gateway-core` (8080), `async-audit-worker`, `admin-dashboard` (5173), `redis` (6379), `rabbitmq` (5672/15672), and `mongo` (27017) with internal Docker networking and persistent volumes. |
| **[docker-compose.prod.yml](file:///d:/aegis-gate/docker-compose.prod.yml)** | Production deployment configuration with resource constraints (CPU/RAM limits), restart policies (`always`), health checks, isolated production subnets, and hardened security options. |
| **[README.md](file:///d:/aegis-gate/README.md)** | Developer documentation featuring system architecture diagrams, quickstart commands, engineering specifications, and verification workflows. |
| **[scripts/vps-setup.sh](file:///d:/aegis-gate/scripts/vps-setup.sh)** | Shell script for automated VPS host preparation: installs Docker, Docker Compose, Git, UFW firewall configurations (ports 80, 443, 8080, 22), and sets up swap space and kernel networking tweaks. |

---

### 4.2 Gateway Core (`services/gateway-core`)

#### Entrypoint & Infrastructure Configuration
| File Path | Description & Functions |
| :--- | :--- |
| **[src/index.ts](file:///d:/aegis-gate/services/gateway-core/src/index.ts)** | The primary application entrypoint. Initializes Express, binds the global SSRF-safe HTTP/HTTPS socket agents, registers request ID generation, enforces the 100KB ingress cap, derives client IP, evaluates IP-jail status, mounts sub-routers (`/api/v1/auth`, `/api/v1/projects`, `/api/v1/analytics`, `/api/v1/users`, `/api/v1/admin`), resolves dynamic tenant configurations from Redis/MongoDB, and forwards traffic to upstreams via `http-proxy-middleware`. |
| **[src/config/redis.ts](file:///d:/aegis-gate/services/gateway-core/src/config/redis.ts)** | Manages the `ioredis` client instance. Handles reconnection exponential backoff, cluster/standalone event logging (`connect`, `error`, `close`), and exports `redisClient` used across the rate limiter, IP jail, response cache, and project caching. |
| **[src/config/queue.ts](file:///d:/aegis-gate/services/gateway-core/src/config/queue.ts)** | Manages RabbitMQ broker connections using `amqplib`. Declares primary exchange `aegis.audit`, dead-letter exchange `aegis_dlx`, and dead-letter queue `aegis.audit.dlq`. Maintains an in-memory 1,000-event ring buffer with drop-oldest eviction to ensure zero request-path blocking during message broker disconnects. |

#### Middleware Layer (`src/middleware/`)
| File Path | Description & Functions |
| :--- | :--- |
| **[src/middleware/ipJail.ts](file:///d:/aegis-gate/services/gateway-core/src/middleware/ipJail.ts)** | Evaluates incoming client IP against `jail:<ip>` in Redis. Rejects banned IPs instantly with HTTP 403 `ip_jailed`. Implements `recordAbusePoint(ip, points, reason)` to increment `abuse:<ip>` within a 60-second sliding window, triggering an automatic 10-minute ban upon reaching 3 points. |
| **[src/middleware/rateLimiter.ts](file:///d:/aegis-gate/services/gateway-core/src/middleware/rateLimiter.ts)** | Enforces sliding-window rate limits using atomic Redis Lua scripts over Sorted Sets. Tracks hits against `rate_limit:<ip>` or `rate_limit:<projectId>:<ip>`. Exceeding limits records abuse points, injects `X-RateLimit-*` headers, and returns HTTP 429 `rate_limit_exceeded`. |
| **[src/middleware/authenticate.ts](file:///d:/aegis-gate/services/gateway-core/src/middleware/authenticate.ts)** | Dual authentication verification. Validates either `x-aegis-api-key` (hashed comparison against tenant project store) or Bearer JWT tokens (`Authorization: Bearer <jwt>`). Implements role-based access control (RBAC) to restrict routes by role (`admin`, `developer`, `user`). |
| **[src/middleware/requireAuth.ts](file:///d:/aegis-gate/services/gateway-core/src/middleware/requireAuth.ts)** | Route-level authentication guard ensuring requests possess a valid signed JWT token containing operator user ID and role claims. |
| **[src/middleware/securityFilter.ts](file:///d:/aegis-gate/services/gateway-core/src/middleware/securityFilter.ts)** | RE2-compliant regular expression tripwire inspection. Scans query strings, URL paths, and JSON bodies for SQLi, XSS, and directory traversal patterns. If `dryRun: true`, tags and logs the threat; if `dryRun: false`, blocks immediately with HTTP 403 `request_blocked` and emits audit telemetry. |
| **[src/middleware/responseCache.ts](file:///d:/aegis-gate/services/gateway-core/src/middleware/responseCache.ts)** | High-performance response caching middleware. Generates deterministic cache keys sorted by query parameter. Enforces strict bypass rules for authenticated or cookie-bearing requests. Implements single-flight promise coalescing to eliminate cache stampedes. |
| **[src/middleware/circuitBreaker.ts](file:///d:/aegis-gate/services/gateway-core/src/middleware/circuitBreaker.ts)** | Implements per-upstream fault tolerance. Manages `CLOSED`, `OPEN`, and `HALF_OPEN` state transitions based on consecutive failure counters. Enforces a bulkhead limit of 100 concurrent in-flight connections per upstream origin. Dispatches synthetic health probes before re-opening closed circuits. |

#### Routing Layer (`src/routes/`)
| File Path | Description & Functions |
| :--- | :--- |
| **[src/routes/auth.ts](file:///d:/aegis-gate/services/gateway-core/src/routes/auth.ts)** | Operator identity endpoints (`POST /api/v1/auth/login`, `POST /api/v1/auth/register`). Manages bcrypt password hashing, JWT token issuance (24-hour expiration), and initial administrative bootstrap. |
| **[src/routes/projects.ts](file:///d:/aegis-gate/services/gateway-core/src/routes/projects.ts)** | Tenant project management (`GET /`, `POST /`, `PUT /:id`, `DELETE /:id`). Generates secure cryptographically randomized API keys (`ag_live_...`), invalidates Redis project caches on updates, and synchronizes upstream target URLs. |
| **[src/routes/analytics.ts](file:///d:/aegis-gate/services/gateway-core/src/routes/analytics.ts)** | Telemetry and monitoring endpoints (`GET /telemetry`, `GET /stats`, `GET /dlq`, `POST /dlq/:id/retry`, `DELETE /dlq/:id`). Queries MongoDB for tenant threat logs, calculates aggregate KPI metrics, and provides management operations for poison messages in the Dead-Letter Queue. |
| **[src/routes/admin.ts](file:///d:/aegis-gate/services/gateway-core/src/routes/admin.ts)** | Core gateway administration (`GET /jailed-ips`, `POST /unban`, `GET /circuit-breakers`). Queries Redis for all active `jail:*` keys and TTLs, removes IP ban keys on demand, and returns live status for all upstream circuit breakers. |
| **[src/routes/users.ts](file:///d:/aegis-gate/services/gateway-core/src/routes/users.ts)** | Administrative user identity and role assignment endpoints. |

#### Models (`src/models/`)
| File Path | Description & Schema Details |
| :--- | :--- |
| **[src/models/project.ts](file:///d:/aegis-gate/services/gateway-core/src/models/project.ts)** | Mongoose schema for tenant projects: `projectName`, `apiKey` (indexed), `targetUrl`, `dryRun`, `enableLLMAudit`, `slackWebhookUrl`, `discordWebhookUrl`, and timestamps. |
| **[src/models/User.ts](file:///d:/aegis-gate/services/gateway-core/src/models/User.ts)** | Mongoose schema for administrative console operators: `email`, `password` (bcrypt hash), and `role` (`admin` / `developer`). |
| **[src/models/threatLog.ts](file:///d:/aegis-gate/services/gateway-core/src/models/threatLog.ts)** | Mongoose schema for blocked and flagged threats: `projectId`, `clientIp`, `endpoint`, `method`, `attackVector`, `severity`, `rawBody`, `timestamp`, and 30-day TTL indexing. |
| **[src/models/deadLetter.ts](file:///d:/aegis-gate/services/gateway-core/src/models/deadLetter.ts)** | Mongoose schema for unprocessable poison messages: `projectId`, `clientIp`, `endpoint`, `method`, `timestamp`, `rawBody`, `errorReason`, and `retryCount`. |

#### Utility Layer (`src/utils/`)
| File Path | Description & Key Functions |
| :--- | :--- |
| **[src/utils/ip.ts](file:///d:/aegis-gate/services/gateway-core/src/utils/ip.ts)** | Secure anti-spoofing client IP resolution. Validates peer socket addresses against `TRUSTED_PROXY_CIDRS`. Parses `X-Forwarded-For` from right to left. Normalizes IPv4-mapped IPv6 strings (`::ffff:192.0.2.1`) and truncates IPv6 addresses to `/64` subnets. |
| **[src/utils/ssrf.ts](file:///d:/aegis-gate/services/gateway-core/src/utils/ssrf.ts)** | Connect-time Server-Side Request Forgery (SSRF) defense. Evaluates targets against RFC 1918, loopback, link-local metadata, and dangerous port denylists. Creates custom HTTP and HTTPS agents with single-resolution DNS pinning to neutralize DNS rebinding. |
| **[src/utils/errors.ts](file:///d:/aegis-gate/services/gateway-core/src/utils/errors.ts)** | Standardizes RFC 7807 problem details error responses (`type`, `title`, `status`, `detail`, `instance`, `requestId`). Manages unique request ID assignment (`X-Request-Id`). |
| **[src/utils/piiScrubber.ts](file:///d:/aegis-gate/services/gateway-core/src/utils/piiScrubber.ts)** | Recursively scrubs Personally Identifiable Information (PII) and sensitive fields (`password`, `token`, `secret`, `credit_card`, `ssn`, `authorization`, `cookie`) from request bodies and headers before queuing. |
| **[src/utils/telemetry.ts](file:///d:/aegis-gate/services/gateway-core/src/utils/telemetry.ts)** | Telemetry publishing layer. Assembles standardized audit events, runs edge PII redaction, and pushes events into RabbitMQ or the fallback in-memory ring buffer. |

---

### 4.3 Asynchronous Audit Worker (`services/async-audit-worker`)

| File Path | Description & Functionality |
| :--- | :--- |
| **[src/index.ts](file:///d:/aegis-gate/services/async-audit-worker/src/index.ts)** | Microservice entrypoint. Connects to MongoDB Atlas and boots the RabbitMQ audit consumer. |
| **[src/worker.ts](file:///d:/aegis-gate/services/async-audit-worker/src/worker.ts)** | Core ingestion worker. Connects to `aegis.audit` queue with `prefetch(50)`. Collects messages into an in-memory batch. Flushes batches to MongoDB using `AuditLogModel.insertMany(docs, { ordered: false })` when batch size reaches 20 or after a 500ms timeout. Acknowledges batches upon successful write. Handles MongoDB connection outages by pausing the consumer, retaining unacknowledged messages in RabbitMQ, and retrying with exponential backoff up to 30s. |
| **[src/models/AuditLog.ts](file:///d:/aegis-gate/services/async-audit-worker/src/models/AuditLog.ts)** | Mongoose schema for persistent audit logs with a 30-day automatic Time-To-Live (TTL) index: `requestId`, `projectId`, `ip`, `method`, `path`, `rule`, `status`, `upstreamOrigin`, `headers`, and `body`. |
| **[src/models/deadLetter.ts](file:///d:/aegis-gate/services/async-audit-worker/src/models/deadLetter.ts)** | Mongoose schema representing messages rejected to the Dead-Letter Queue. |
| **[src/models/threatLog.ts](file:///d:/aegis-gate/services/async-audit-worker/src/models/threatLog.ts)** | Mongoose schema representing specific security threat events. |
| **[src/utils/webhooks.ts](file:///d:/aegis-gate/services/async-audit-worker/src/utils/webhooks.ts)** | Real-time security webhook delivery engine. Formats rich JSON embed alerts for Discord and blocks for Slack. Dispatches notifications whenever a critical threat or 403 block is detected. |
| **[src/utils/webhookNotifier.ts](file:///d:/aegis-gate/services/async-audit-worker/src/utils/webhookNotifier.ts)** | Clean export bridge for webhook alerting functions. |
| **[src/utils/piiScrubber.ts](file:///d:/aegis-gate/services/async-audit-worker/src/utils/piiScrubber.ts)** | Secondary deep-traversal PII sanitizer validating payloads prior to database insertion. |

---

### 4.4 Admin Dashboard (`services/admin-dashboard`)

#### Configuration & Styling
| File Path | Description & Functionality |
| :--- | :--- |
| **[index.html](file:///d:/aegis-gate/services/admin-dashboard/index.html)** | Single-page application HTML template. Imports Google Fonts `IBM Plex Sans` (400, 500, 600) and `IBM Plex Mono` (400), and sets document title to "AegisGate". |
| **[src/index.css](file:///d:/aegis-gate/services/admin-dashboard/src/index.css)** | Master design token definition. Configures color palette variables (`--bg`, `--card`, `--inset`, `--hover`, `--bd`, `--t1`, `--t2`, `--ac`, `--ok`, `--crit`, `--hi`, `--med`), typography (`font-variant-numeric: tabular-nums`), and custom prototype classes (`.mono`, `.card`, `.p`, `.tr`, `.bar`, `.ch`, `.tg`, `.fld`, `.kv`, `.toast`, `.ov`). |
| **[src/App.css](file:///d:/aegis-gate/services/admin-dashboard/src/App.css)** | Application reset stylesheet ensuring clean isolation from Vite starter defaults. |

#### Contexts & Hooks
| File Path | Description & Functionality |
| :--- | :--- |
| **[src/context/AuthContext.tsx](file:///d:/aegis-gate/services/admin-dashboard/src/context/AuthContext.tsx)** | React context managing operator authentication state: JWT token storage in `localStorage`, active project selection (`activeProjectId`), and `login` / `logout` actions. |
| **[src/context/ToastContext.tsx](file:///d:/aegis-gate/services/admin-dashboard/src/context/ToastContext.tsx)** | React context providing an auto-dismissing floating toast system (`showToast(msg)`). Renders temporary 3-second notification bubbles centered at the bottom of the screen. |
| **[src/hooks/useThreatTelemetry.ts](file:///d:/aegis-gate/services/admin-dashboard/src/hooks/useThreatTelemetry.ts)** | Custom React hook that polls Gateway Core analytics endpoints (`/api/v1/analytics/telemetry`) every 5 seconds with tenant headers (`X-Project-Id`), providing reactive threat logs, block statistics, and manual refetch capabilities. |

#### Components (`src/components/`)
| File Path | Description & Component Functionality |
| :--- | :--- |
| **[src/components/Icons.tsx](file:///d:/aegis-gate/services/admin-dashboard/src/components/Icons.tsx)** | Crisp SVG icon definitions matching the prototype: `ShieldIcon`, `CaretDownIcon`, `ChevronRightIcon`, `CloseIcon`, `CopyIcon`, `EyeIcon`, `MailIcon`, `LockIcon`, `WarningIcon`, `CheckIcon`, `ShieldCheckIcon`. |
| **[src/components/Dashboard.tsx](file:///d:/aegis-gate/services/admin-dashboard/src/components/Dashboard.tsx)** | Main administrative interface coordinating the top command header, project dropdown, navigation tabs, and Screen 1 (Analytics Console). Includes 4 KPI cards, expandable Jailed IPs table with unban confirmation modal, upstream circuit breaker monitors, live threat stream with severity filter chips, and interactive payload inspector with collapsible headers. |
| **[src/components/TenantProvisioning.tsx](file:///d:/aegis-gate/services/admin-dashboard/src/components/TenantProvisioning.tsx)** | Screen 2 (Tenant Provisioning). Renders an 800px centered card for registering tenant projects. Calls `api.createProject`, displays provisioned project ID and API key with copy buttons, and shows security warning notice. |
| **[src/components/ProjectSettings.tsx](file:///d:/aegis-gate/services/admin-dashboard/src/components/ProjectSettings.tsx)** | Screen 3 (Project Settings). Renders a 960px centered card for project configuration: observation mode (dry-run) toggle, signature filter toggle, regex-validated upstream URL, and optional Slack/Discord webhook inputs with eye visibility toggles. |
| **[src/components/DLQMonitor.tsx](file:///d:/aegis-gate/services/admin-dashboard/src/components/DLQMonitor.tsx)** | Screen 4 (DLQ Monitor). Displays poison message counts with status pills, a centered healthy empty-state graphic, and an inspection split-view for failed messages with error reasons, retry metrics, and 2KB truncated payload viewers. |
| **[src/components/ProtectedRoute.tsx](file:///d:/aegis-gate/services/admin-dashboard/src/components/ProtectedRoute.tsx)** | Route wrapper verifying authentication before rendering protected administrative views. |

#### Pages & API Services
| File Path | Description & Functionality |
| :--- | :--- |
| **[src/pages/AuthScreen.tsx](file:///d:/aegis-gate/services/admin-dashboard/src/pages/AuthScreen.tsx)** | Authentication screen featuring a centered 440px card with 28px shield icon, segmented control for "Sign in" vs "Create account", password confirmation validation, eye visibility toggles, and live wiring to backend authentication endpoints with graceful offline simulation fallback. |
| **[src/services/api.ts](file:///d:/aegis-gate/services/admin-dashboard/src/services/api.ts)** | Backend HTTP client layer. Exports functions and an `api` client object for `fetchProjects`, `createProject`, `updateProjectSettings`, `fetchDeadLetterLogs`, `retryDeadLetterMessage`, `purgeDeadLetterMessage`, `fetchJailedIps`, `unbanClientIp`, `fetchCircuitBreakers`, `login`, and `register`. Injects JWT bearer headers and project identifiers. |

---

## 5. Data Models, Database Schemas & Storage Design

### 5.1 MongoDB Collections & Schemas

#### 1. Projects Collection (`projects`)
```typescript
{
  _id: ObjectId,
  projectName: string,          // e.g. "Production Payment Portal"
  apiKey: string,               // e.g. "ag_live_7Hq2Zx9Kc4..." (indexed, unique)
  targetUrl?: string,           // Downstream backend origin (e.g. "https://api.internal/payments")
  dryRun: boolean,              // Observation mode toggle (default: false)
  enableLLMAudit: boolean,      // Signature filter toggle (default: true)
  slackWebhookUrl?: string,     // Optional Slack alert endpoint
  discordWebhookUrl?: string,   // Optional Discord alert endpoint
  createdAt: Date
}
```

#### 2. Audit Logs Collection (`audit_logs`)
```typescript
{
  _id: ObjectId,
  requestId: string,            // Unique UUIDv4 assigned at ingress
  projectId: string,            // Associated tenant project ID (indexed)
  ip: string,                   // Normalized, anti-spoofed client IP or IPv6 /64 prefix
  method: string,               // GET, POST, PUT, DELETE, etc.
  path: string,                 // Request URI path
  rule?: string,                // Rule triggered (e.g. "sqli.tautology", "rate_limit_exceeded")
  status: number,               // HTTP response status code (e.g. 200, 403, 429, 503)
  upstreamOrigin?: string,      // Target backend origin resolved for proxying
  headers?: Record<string, string>, // Allowlisted, sanitized HTTP headers
  body?: string,                // Redacted JSON request payload
  createdAt: Date               // Indexed with 30-day automatic MongoDB TTL expiration
}
```

#### 3. Dead-Letter Queue Collection (`dead_letters`)
```typescript
{
  _id: ObjectId,
  projectId: string,            // Tenant project ID
  clientIp: string,             // Origin client IP
  endpoint: string,             // Destination path
  method: string,               // HTTP method
  timestamp: Date,              // Original message timestamp
  rawBody: string,              // Poison message payload excerpt (up to 2KB)
  errorReason: string,          // Processing exception detail (e.g. "Schema validation failed")
  retryCount: number,           // Number of failed delivery attempts (typically 3)
  createdAt: Date
}
```

### 5.2 Redis Key Schema & TTL Lifecycle

| Key Pattern | Data Structure | TTL | Purpose |
| :--- | :--- | :--- | :--- |
| `abuse:<ip>` | String (Integer) | 60 seconds | Tracks accumulated abuse points for an IP. Exceeding 3 points triggers an automatic ban. |
| `jail:<ip>` | String ("1") | 600 seconds (10 min) | Active IP jail flag. Evaluated at ingress boundary to immediately drop traffic with 403. |
| `rate_limit:<ip>` | Sorted Set (ZSET) | 60 seconds | Sliding-window timestamp log for pre-auth global rate limiting. |
| `rate_limit:<projId>:<ip>` | Sorted Set (ZSET) | 60 seconds | Sliding-window timestamp log for per-tenant authenticated rate limiting. |
| `project:<apiKey>` | String (JSON) | 300 seconds (5 min) | Cached tenant metadata (target URL, dry-run state, webhooks) to avoid MongoDB lookups. |
| `cache:<projId>:<route>:GET:<url>` | String (Cached Response) | Configurable (e.g. 60s) | Cached upstream HTTP response body and headers with single-flight stampede protection. |

---

## 6. End-to-End Request Lifecycle & Execution Flows

### 6.1 Normal Allowed Proxy Request
1. **Client** issues `POST /api/v1/payments/checkout` with header `x-aegis-api-key: ag_live_...`.
2. **Ingress Cap Check**: Body size confirmed `< 100KB`.
3. **IP Derivation**: Socket verified against `TRUSTED_PROXY_CIDRS`; client IP resolved to `198.51.100.8`.
4. **IP-Jail Check**: Evaluates `jail:198.51.100.8` in Redis. Returns `nil` (not jailed).
5. **Rate Limiting**: Sliding-window Lua script logs current timestamp and confirms hits < limit.
6. **Tenant Resolution**: Redis query `project:ag_live_...` hits cache; resolves `targetUrl = https://payments.internal`.
7. **Security Filter**: RE2 regex scans payload. No injection signatures matched.
8. **Circuit Breaker Check**: Breaker for `payments.internal` is `CLOSED`. Active in-flight requests < 100.
9. **Proxy Dispatch**: `http-proxy-middleware` connects to `https://payments.internal` using DNS-pinned socket agent.
10. **Telemetry Emission**: Ingress metadata, status code (200), and redacted payload published out-of-band to RabbitMQ `aegis.audit`.
11. **Client Response**: Downstream response returned to client with `X-Shielded-By: AegisGate-Core`.

### 6.2 Malicious Request Blocked by Tripwire
1. **Client** issues `POST /api/v1/auth/login` containing `{"username": "admin' OR '1'='1 --"}`.
2. **IP Derivation**: Client IP resolved to `45.227.254.12`.
3. **IP-Jail Check**: IP is currently unjailed.
4. **Security Filter**: RE2 signature tripwire matches `sqli.tautology`.
5. **Abuse Point Increment**: Gateway calls `recordAbusePoint("45.227.254.12", 1, "sqli.tautology")`.
6. **Enforcement**: Project setting `dryRun === false`. Gateway halts request pipeline immediately.
7. **Client Error Response**: Returns HTTP `403 Forbidden` (`request_blocked`).
8. **Asynchronous Audit**: Enqueues redacted threat event to RabbitMQ.
9. **Webhook Alert**: `async-audit-worker` consumes event, detects 403 status, and dispatches real-time Discord/Slack webhook alert.

### 6.3 Third Violation & Automatic Jailing
1. **Client** at `45.227.254.12` commits a 3rd violation within 60 seconds.
2. **Abuse Threshold Reached**: `abuse:45.227.254.12` reaches 3 points.
3. **Redis Jail Created**: Gateway executes `SETEX jail:45.227.254.12 600 1`.
4. **Subsequent Traffic Dropped**: For the next 10 minutes, all requests from `45.227.254.12` are rejected in `<1ms` at Pipeline Step 3 with HTTP `403 Forbidden` (`ip_jailed`).
5. **Operator Release**: Operator opens the AegisGate Admin Console, inspects the Jailed IPs table, clicks "Unban", confirms the modal dialog, and Gateway Core deletes `jail:45.227.254.12`.

---

## 7. Verification & Production Build Validation

All microservices within the AegisGate repository compile and build cleanly without warnings or errors:

- **Gateway Core**:
  ```bash
  cd services/gateway-core
  npm run build    # Compiles TypeScript via tsc into dist/
  ```
- **Async Audit Worker**:
  ```bash
  cd services/async-audit-worker
  npm run build    # Compiles worker TypeScript via tsc into dist/
  ```
- **Admin Dashboard**:
  ```bash
  cd services/admin-dashboard
  npm run build    # Executes tsc -b && vite build (0 errors)
  ```
- **Containerized Stack**:
  ```bash
  docker compose up -d --build
  ```

---
*Documentation maintained by AegisGate Core Engineering.*
