# AegisGate: V2.2 Design Specification

| | |
|---|---|
| **Document version** | 2.2.0-Draft |
| **Project lead** | Rohit Sirvi |
| **Repository** | https://github.com/RohitSirvi898/AegisGate |
| **Baseline** | PRD v2.1 (current project) |
| **Status** | **Design only. Nothing in this document is implemented.** Work is paused while the underlying technologies are studied. |

**How to read this document.** V2.2 is a set of changes on top of v2.1. Each change was reviewed against v2.1 for flaws and the specs below are the corrected versions. Where a number is given (rates, thresholds, sizes) it is an *initial value to tune*, not a measured result. No performance claims are made.

---

## 0. Pause Checkpoint (read this first when resuming)

### 0.1 Verify the v2.1 baseline before building anything

Some v2.1 statements did not match the repository when last checked. Confirm each one, and fix or re-document it, before starting V2.2.

| Item | v2.1 spec says | Repo / README at last check | Action |
|---|---|---|---|
| Redis topology | Two roles: state (`noeviction`) and cache (`allkeys-lru`) | `docker-compose.yml` runs one Redis (`aegis-cache`) | Add `aegis-state` and `aegis-cache` containers |
| Admin plane | Separate listener on `ADMIN_BIND` (`:9090`) | Diagram shows console calling admin endpoints on `:8080` | Move admin routes to their own listener |
| Private upstreams | Operator-controlled override | Quickstart sets `ALLOW_PRIVATE_UPSTREAMS=true` | Replace with host allowlist (3.1) |
| README API key | n/a | Quickstart contains a real-looking `ag_live_...` key | Rotate if ever issued; use `ag_live_REPLACE_ME` |
| README latency claim | No unmeasured claims | "sub-millisecond" jail drop | Remove until benchmarked |
| Circuit breaker wording | Passive failure counter | README says it checks backend health | Reword (3.9) |

### 0.2 Recommended implementation order

1. **Step 1:** SSRF host allowlist, API key checksum and negative cache, 401 abuse handling, README fixes (3.1 to 3.3, 3.9). These are independent of everything else.
2. **Step 2:** Token-bucket limiter with client and project tiers, edge-triggered abuse scoring, `Retry-After` (3.4, 3.5). Ship as **one** change; the scoring rule depends on the limiter.
3. **Step 3:** Telemetry priority/aggregation, then circuit breaker rework (3.6, 3.7).
4. **Step 4:** Admin listener, dual Redis in compose, README alignment (3.8, 3.9).

---

## 1. Goals and Non-Goals

**Goals**
- Close the abuse and security gaps found in review of v2.1.
- Replace the fixed-window limiter with a token bucket without creating new ban traps.
- Make documentation match the implementation exactly.

**Non-goals (unchanged from v2.1)**
- Not a WAF; not a replacement for Nginx/Traefik/Envoy/Kong/Cloudflare.
- No compliance claims; no high-availability guarantee; no TLS termination.
- No Kubernetes, Kafka, or ML.

---

## 2. Change Summary

| # | Change | Why | Priority |
|---|---|---|---|
| 3.1 | SSRF: exact-host allowlist replaces `ALLOW_PRIVATE_UPSTREAMS` | The boolean disabled SSRF protection entirely, and let tenants reach Redis/RabbitMQ | P0 |
| 3.2 | API key checksum + bounded in-process invalid-key cache | Random keys caused a cache miss and a MongoDB query per request | P0 |
| 3.3 | 401 abuse handling | Credential probing earned no abuse score | P0 |
| 3.4 | Token-bucket limiter: client tier + project tier, atomic | Fixed window allows boundary bursts; per-(project, IP) limits do not cap a project's aggregate traffic | P1 |
| 3.5 | Edge-triggered abuse scoring (latch) | Without windows, per-rejection points would jail a briefly bursting client | P1 (ships with 3.4) |
| 3.6 | Telemetry: per-class caps and aggregation | Drop-oldest discards the earliest, most useful events during a flood | P1 |
| 3.7 | Breaker: failure-rate and slow-call triggers | "5 consecutive failures" never trips a backend failing ~40% of calls | P1 |
| 3.8 | Admin listener, dual Redis | Match v2.1 spec to the code | P2 |
| 3.9 | Documentation alignment | Remove overclaims | P2 |

---

## 3. Specifications

### 3.1 SSRF: exact-host allowlist

**Removed:** `ALLOW_PRIVATE_UPSTREAMS` (code, README, compose).

**Added**
- `ALLOWED_UPSTREAM_HOSTS`: operator-only config, comma-separated exact `host:port` entries (for example `my-backend-api:5000,api.local:3000`).
- Per-project flag `privateUpstreamApproved` (settable by operators only).

**Rules**
- A tenant-registered upstream resolving to a private, loopback, link-local, or metadata range is rejected at registration **and** at connect time, unless the exact `host:port` is in `ALLOWED_UPSTREAM_HOSTS` **and** the project has `privateUpstreamApproved = true`. This stops one tenant pointing at another tenant's or the operator's private host.
- An upstream defined by env (`UPSTREAM_TARGET_URL`) is trusted operator configuration. The quickstart therefore needs no flag.
- **Always-deny set.** At startup, resolve the hosts in `REDIS_URL`, `RABBITMQ_URL`, and `MONGO_URI` and add their IPs to a deny set that **overrides** the allowlist. The port denylist (22, 25, 5432, 5672, 6379, 15672, 27017, and so on) stays as defense in depth, but ports alone are not relied on because dependencies can run on any port.
- Connect-time enforcement via a custom DNS `lookup` on the HTTP/HTTPS agents:
  - Support both callback shapes. On Node 20, `net.connect` can call `lookup` with `options.all === true` and expects an array of addresses.
  - Connect only to the validated IP, but keep TLS server name and certificate verification against the **original hostname**.
  - Do not follow redirects; pass `3xx` responses through.

### 3.2 API key format and negative caching

**Key format (new keys):** `ag_live_<32 random bytes, base64url><checksum>` where `checksum` is the first 4 bytes of `HMAC-SHA256(API_KEY_CHECKSUM_SECRET, "ag_live_" + body)`, base64url-encoded (6 characters).

**Lookup order in the auth step**
1. Syntax and checksum check (constant-time compare). A bad checksum returns `401` with **zero** Redis or MongoDB calls. Keys in the legacy format skip this check until rotated.
2. Bounded in-process LRU of key hashes known to be invalid (`INVALID_KEY_LRU_MAX` = 10,000 entries, `INVALID_KEY_TTL_SEC` = 30). A hit returns `401` immediately.
3. Tenant config from Redis cache, then MongoDB.

**Rules**
- **Do not store negative entries in the state Redis.** It runs `noeviction`; a botnet could fill it, writes would start failing, and the limiter would then fail open.
- Creating or restoring a key clears any matching invalid-cache entry.
- Checksum secret rotation: accept a current and a previous secret (`API_KEY_CHECKSUM_SECRETS`).
- The checksum only avoids lookups for malformed keys. It is not authentication; the hashed-key lookup remains the authority.

### 3.3 401 abuse handling

- Count failed authentications per IP in `authfail:{ip}`, a fixed 60 s window (expiry set only when the counter is new).
- At `AUTH_FAIL_THRESHOLD` (default 20) add `AUTH_FAIL_POINTS` (default 3) abuse points through the abuse-scoring script (3.5), with a latch so the penalty applies at most once per window.
- Do **not** add one point per 401. The jail is global, so a misconfigured job or an expired key behind a shared NAT would otherwise jail an entire office after three failures.

### 3.4 Token-bucket rate limiting

#### Tiers

| Tier | Key | Protects | Initial values (to tune) |
|---|---|---|---|
| Pre-auth | `rl:pre:{ip}` | Credential checks from unauthenticated floods | 2 tokens/s, burst 30 |
| Client | `rl:client:{projectId}:{ip}` | Fairness per client | 10 tokens/s, burst 20 |
| Project | `rl:project:{projectId}` | Backend protection against distributed traffic | 100 tokens/s, burst 150 |

Per-project overrides are allowed. Each limit is configured as `{ratePerSec, burst}` rather than "N per window".

The client and project tiers run in **one atomic script** so tokens are consumed only if **both** allow the request. Otherwise a noisy client could drain the project bucket, or spend a client token on a request the project tier then rejects. The pre-auth tier uses the same algorithm as a single-bucket call.

#### Algorithm rules
- **Time source:** Redis `TIME` inside the script, never the gateway's `Date.now()`, so clock skew between gateway instances cannot corrupt balances. Requires Redis 5 or later.
- **Integer arithmetic:** tokens are stored as micro-tokens (1 token = 1,000,000 units). Refill per millisecond is `ratePerSec x 1000` units, an integer for rates with up to three decimals. This avoids floating-point drift and also supports slow rates (for example 0.1 tokens/s).
- **Retry-After:** wait in ms is `ceil((1,000,000 - units) / refillPerMs)`. For two tiers use the larger wait. The HTTP header is whole seconds: `max(1, ceil(waitMs / 1000))`.
- **TTL:** each bucket expires after the time needed to refill from empty to full (the default state of a missing bucket).
- Clock moving backwards is treated as zero elapsed time.
- GCRA gives equivalent behavior with a single stored timestamp and is an acceptable alternative implementation.

#### Reference script (sketch; test before use)

```lua
-- KEYS: 1=client bucket, 2=project bucket
-- ARGV: 1=clientBurst 2=clientRefillPerMs 3=projectBurst 4=projectRefillPerMs
-- Returns { denied, waitMs }  denied: 0=allowed, 1=client tier, 2=project tier
local UNIT = 1000000
local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)

local function load(key, burst, refill)
  local d = redis.call('HMGET', key, 'u', 'ts')
  local capU = burst * UNIT
  local u = tonumber(d[1]) or capU
  local ts = tonumber(d[2]) or now
  return math.min(capU, u + math.max(0, now - ts) * refill)
end

local cr, pr = tonumber(ARGV[2]), tonumber(ARGV[4])
local cu = load(KEYS[1], tonumber(ARGV[1]), cr)
local pu = load(KEYS[2], tonumber(ARGV[3]), pr)
local cw = cu >= UNIT and 0 or math.ceil((UNIT - cu) / cr)
local pw = pu >= UNIT and 0 or math.ceil((UNIT - pu) / pr)

local denied = 0
if cw > 0 then denied = 1 elseif pw > 0 then denied = 2 end
if denied == 0 then cu = cu - UNIT; pu = pu - UNIT end

redis.call('HSET', KEYS[1], 'u', cu, 'ts', now)
redis.call('PEXPIRE', KEYS[1], math.max(1, math.ceil(tonumber(ARGV[1]) * UNIT / cr)))
redis.call('HSET', KEYS[2], 'u', pu, 'ts', now)
redis.call('PEXPIRE', KEYS[2], math.max(1, math.ceil(tonumber(ARGV[3]) * UNIT / pr)))
return { denied, math.max(cw, pw) }
```

#### Redis unavailable
Fail open to an in-process limiter using the **same algorithm**. It is per instance, so with N replicas the effective limit is up to N times larger. Document this.

### 3.5 Abuse scoring with an edge-triggered latch

In a token bucket there are no windows, so v2.1's "one point per window" rule cannot be used. Awarding a point per rejected request would jail a client after three rejected requests in a second.

**Rule:** award a point on the *allowed to rejected transition*, at most once per latch period (default 10 s) per bucket key.

**Which events score**

| Event | Scores? | Points |
|---|---|---|
| Client-tier rejection (pre-auth or client bucket), latched | Yes | 1 |
| **Project-tier rejection** | **No** | 0 (during a distributed flood the project bucket empties; scoring would jail innocent users) |
| Tripwire match | Yes | 1 |
| 401 threshold crossing (3.3) | Yes | 3 |

When both client and project tiers deny, the rejection is attributed to the client tier.

#### Abuse script (one script for all scoring; latch optional)

```lua
-- KEYS: 1=latch key (ignored if latchTtl = 0)  2=abuse:{ip}  3=jail:{ip}
-- ARGV: 1=latchTtlSec 2=points 3=windowSec 4=threshold 5=jailTtlSec
if tonumber(ARGV[1]) > 0 then
  if not redis.call('SET', KEYS[1], '1', 'NX', 'EX', ARGV[1]) then return -1 end
end
local s = redis.call('INCRBY', KEYS[2], ARGV[2])
if redis.call('TTL', KEYS[2]) < 0 then redis.call('EXPIRE', KEYS[2], ARGV[3]) end
if s >= tonumber(ARGV[4]) then
  redis.call('SET', KEYS[3], 'banned', 'EX', ARGV[5])
end
return s
```

All key names are passed in `KEYS`; none are built inside the script. A raw `INCRBY` outside this script is never used, because it would set no expiry and never reach the jail threshold.

### 3.6 Telemetry: class caps and aggregation

**Event classes**

| Class | Examples | Notes |
|---|---|---|
| P0 security | `request_blocked`, auth-failure aggregates, SSRF rejections, admin actions | Highest value |
| P1 operational | breaker state changes, upstream errors, `upstream_saturated` | |
| P2 high volume | `rate_limited` 429s, `ip_jailed` 403s | Dropped first |

**Rules**
- Each class has its **own bounded buffer** with drop-oldest inside the class. A flood of P2 events can never evict P0 events. Every class increments its own `telemetry_dropped_total{class}` counter.
- **Aggregation:** events are merged by `(class, ip, projectId, rule)` over `TELEMETRY_AGG_WINDOW_MS` (default 5000) into one event with `count`, `firstSeen`, `lastSeen`, and one sample. A one-second window is too short to help.
- Bound the aggregation map (`TELEMETRY_AGG_MAX_KEYS`, default 5000). Overflow merges into a single catch-all event ("many sources") with a count, so distributed attacks cannot grow memory.
- 401 events are attacker-controlled and high volume, so they use the same aggregation and the same per-class cap. "Always protect" never means "unbounded".

### 3.7 Circuit breaker rework

**Definitions**
- *Failure:* response status `>= 500`, upstream timeout, or connection error.
- *Slow call:* a successful response slower than `SLOW_CALL_MS` (default 2000). This must be **below** the upstream timeout; a threshold equal to the timeout adds nothing.
- Not counted: `4xx`, client aborts, gateway-generated rejections (including `upstream_saturated`).

**CLOSED to OPEN triggers (either one)**
1. `BREAKER_FAILURE_THRESHOLD` (default 5) consecutive failures.
2. Over a rolling **time window** (`BREAKER_WINDOW_SEC`, default 30) with at least `BREAKER_MIN_CALLS` (default 20) calls: failure rate `>= 40%`, or slow-call rate `>= 60%` (initial values).

Implement the window as per-second buckets of `{calls, failures, slow}`. A window of "the last 20 requests" is not used because at low traffic it can span hours.

**OPEN / HALF-OPEN** are unchanged from v2.1: 30 s cooldown, one synthetic probe `GET {healthCheckPath}`, probe result `< 500` closes the circuit, client requests receive `503` while probing.

**503 responses** carry `Retry-After` equal to the *remaining* cooldown in whole seconds, not a fixed 30.

State remains per process (see section 6).

### 3.8 Admin listener and topology

- Admin routes bind to a dedicated listener: `ADMIN_BIND` (default `127.0.0.1:9090` outside containers). Port `8080` serves only ingress proxying.
- **Inside Docker**, binding `127.0.0.1` in the container makes the port unreachable from the host and from other containers. Bind `0.0.0.0:9090` in the container and either publish it as `127.0.0.1:9090:9090` or leave it unpublished and let the console reach it over the internal network.
- Be honest about isolation: a separate *listener* in the same process separates the network surface, not failure domains. Failure isolation requires a separate process or container. Document whichever is actually true.
- **Compose:** two Redis containers: `aegis-state` (`maxmemory-policy noeviction`, small, TTL-bound keys, memory alerting) and `aegis-cache` (`maxmemory` set, `allkeys-lru`, response bodies only).
- Update the architecture diagram so the console points at the admin listener.

### 3.9 Documentation alignment

| Topic | Wording to use |
|---|---|
| Circuit breaker | "Passive failure and slow-call counters on live traffic; an active synthetic health probe only in HALF-OPEN." |
| Multi-instance semantics | "Rate limits and the jail are shared across instances via Redis. Circuit breaker state, single-flight, and the fallback limiter are local to each instance." |
| Admin plane | State the actual listener and process model (3.8). |
| SSRF | "Validated at registration and at connect time; private upstreams require an operator allowlist." |
| Latency | No figures until benchmarked. |

---

## 4. Pipeline (changes only)

The v2.1 order is unchanged. Differences inside the steps:

```
[ 4. Pre-Auth IP Rate Limit ]   token bucket, key rl:pre:{ip}
[ 5. Tenant Resolution & Auth ] checksum check (no I/O) -> invalid-key LRU
                                -> config cache -> MongoDB; 401s counted in authfail:{ip}
[ 6. Rate Limiter ]             client + project buckets, one atomic script;
                                client-tier rejections score once per latch period
```

---

## 5. Configuration Additions

Initial defaults, to be tuned after the baseline benchmark.

| Variable | Default |
|---|---|
| `ALLOWED_UPSTREAM_HOSTS` | (empty) |
| `API_KEY_CHECKSUM_SECRETS` | required |
| `INVALID_KEY_LRU_MAX` / `INVALID_KEY_TTL_SEC` | 10000 / 30 |
| `AUTH_FAIL_THRESHOLD` / `AUTH_FAIL_POINTS` | 20 / 3 |
| `RL_PRE_AUTH` (ratePerSec / burst) | 2 / 30 |
| `RL_CLIENT` (ratePerSec / burst) | 10 / 20 |
| `RL_PROJECT` (ratePerSec / burst) | 100 / 150 |
| `RL_VIOLATION_LATCH_SEC` | 10 |
| `TELEMETRY_AGG_WINDOW_MS` / `TELEMETRY_AGG_MAX_KEYS` | 5000 / 5000 |
| `SLOW_CALL_MS` | 2000 |
| `BREAKER_WINDOW_SEC` / `BREAKER_MIN_CALLS` | 30 / 20 |
| `ADMIN_BIND` | `127.0.0.1:9090` |

Removed: `ALLOW_PRIVATE_UPSTREAMS`.

---

## 6. Known Limitations (carried forward and new)

- Circuit breaker state is per process; the fallback limiter and single-flight are per process.
- Regex tripwire is coarse and evadable; it can false-positive on routes carrying HTML, SQL snippets, or `../`.
- IP-based abuse controls are weak against distributed attackers and shared NAT.
- Everything keyed by IP degrades if `TRUSTED_PROXY_CIDRS` is not configured behind a proxy (all clients share the proxy's IP).
- Telemetry is best effort, even with class caps.
- Single instance of each dependency; TLS terminated externally.
- Token bucket permits an initial burst up to its capacity by design.

---

## 7. Test Plan for V2.2

| Area | Test | Expected |
|---|---|---|
| SSRF | Private host not allowlisted | Rejected |
| SSRF | Allowlisted host, project not approved | Rejected |
| SSRF | Dependency IP (Redis/RabbitMQ/Mongo) even if allowlisted | Rejected |
| SSRF | Hostname resolves public at registration, private at connect | Connection refused |
| SSRF | `lookup` called with `all: true` | Works; validated IP used |
| SSRF | Upstream `302` to a private address | Passed through, not followed |
| API keys | Bad checksum | `401` with zero DB/Redis calls |
| API keys | Repeated unknown valid-format key | Second request served from LRU, not MongoDB |
| API keys | Create a key after it was cached as invalid | Works immediately |
| 401 scoring | 19 vs 20 failures in 60 s | Not jailed vs penalty applied |
| 401 scoring | Penalty path | Uses the abuse script; score expires |
| Limiter | Burst to capacity, then sustained rate | Allowed up to burst, then limited to refill rate |
| Limiter | Slow rate (for example 0.1 tokens/s) | Refills correctly (integer math) |
| Limiter | Clock skew between two gateway instances | No corruption (Redis `TIME`) |
| Limiter | Client denied by project tier | Client token not consumed |
| Limiter | `Retry-After` | Whole seconds, at least 1, larger of the two waits |
| Scoring | 100 rejections within 10 s | Exactly 1 abuse point |
| Scoring | Project-tier-only rejection | 0 points |
| Scoring | 3 latched violations across 3 latch periods inside the window | Jailed |
| Distributed | 1000 IPs under their client limits, aggregate above project limit | Project bucket limits backend traffic; no IP jailed |
| Telemetry | Flood of 429/403 events | P0 events still present; P2 dropped first; aggregation produces counts |
| Telemetry | Distinct-key overflow | Catch-all event; memory bounded |
| Breaker | 40% failures interleaved with successes | Trips on rate window |
| Breaker | Slow successes above `SLOW_CALL_MS` | Trips on slow-call rate |
| Breaker | Low traffic below `BREAKER_MIN_CALLS` | Does not trip on rate |
| Breaker | `503` `Retry-After` | Equals remaining cooldown |
| Admin | Port `8080` | No admin routes reachable |
| Admin | Container bind | Reachable via published or internal route as documented |

---

## 8. Open Decisions

1. Final default rates and bursts: decide after the first baseline benchmark.
2. Do API keys have scopes (the README mentions an "Auth & Scope Gate")? If yes, caching must be limited to routes with `authMode: none`, or the key scope must be part of the cache key.
3. Process model for the admin plane: separate listener only, or separate process/container.
4. Where operators set `privateUpstreamApproved` (admin API only, or configuration file).
5. Whether to keep both token bucket and GCRA as options, or choose one.

### Deferred backlog (recommended, not part of the V2.2 core)
- Per-route tripwire modes `block | monitor | off`; monitor hits do not score.
- Startup and runtime warning when behind a proxy without `TRUSTED_PROXY_CIDRS`.
- Cache eligibility tied to route `authMode`.
- Sliding-window or shared breaker state, `stale-if-error`, Redis replication (v3.0).

---

## 9. Concepts to Study Before Resuming

| Topic | Be able to explain | Used in |
|---|---|---|
| Redis Lua scripting | Why scripts are atomic; why all keys go in `KEYS`; `TIME` and replication behavior | 3.4, 3.5 |
| Token bucket vs fixed window vs GCRA | Burst behavior, boundary problem, memory cost | 3.4 |
| Rate-limit abuse design | Why per-rejection scoring jails bursty clients; latching | 3.5 |
| SSRF and DNS rebinding | Resolve-then-connect races; why validation must be at connect time; IPv6 and mapped addresses | 3.1 |
| Node networking | Custom `lookup`, `autoSelectFamily`, agents, TLS server name | 3.1 |
| HMAC and key design | Checksum vs authentication; constant-time compare; key rotation | 3.2 |
| Circuit breaker patterns | Count vs rate windows, slow-call rate, half-open probing | 3.7 |
| RabbitMQ | Publisher confirms, durable queues, DLQ, backpressure | 3.6 |
| Docker networking | Container loopback vs published ports; internal networks | 3.8 |
| Load/failure testing | `autocannon`/`k6`; failure injection with Toxiproxy | Verification |
