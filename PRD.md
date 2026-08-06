# Product Requirement Document (PRD)

## Project Name: AegisGate (Codename)
**Target Start Date:** May 2026  
**Author:** Rohit Sirvi (Project Lead)  
**Status:** Draft / Approved  

---

## 1. Executive Summary & Objective
AegisGate is an open-source, high-performance API Gateway designed specifically for microservice architectures. Unlike traditional gateways (like Nginx or Kong) which require complex configuration files and custom scripts for advanced security features, AegisGate provides an out-of-the-box, zero-config reverse proxy packed with distributed rate-limiting, JWT validation, and intelligent local anomaly detection. 

The ultimate goal is to offer developers a plug-and-play security boundary that stops malicious payloads at the edge without degrading system latency or incurring heavy API costs.

## 2. Target Audience & Personas
*   **The Startup Backend Engineer:** Needs to secure their rapidly growing microservices but doesn't have a dedicated DevOps team to manage complex enterprise gateway clusters.
*   **The Open-Source Contributor:** Looking for a highly modular, clean Node.js/TypeScript and Python codebase to contribute security plugins and performance optimizations.

## 3. Core Features & Scope (MVP)

### 3.1 Data Plane (High Throughput / Low Latency Critical Path)
*   **Reverse Proxy & Routing:** Intercepts incoming HTTP requests and forwards them to target microservices based on dynamic path rules. Utilizes `http.Agent` TCP connection pooling (`keepAlive: true`, `maxSockets: 100`) to reuse sockets between the gateway and upstream targets.
*   **Redis Hot-Path Lookup Caching:** Caches API key validations and project metadata (`targetUrl`, `dryRun`, `enableLLMAudit`, webhook URLs) in Redis (`aegis-cache`) with a 300s TTL, eliminating direct MongoDB reads from middleware hot paths.
*   **Atomic Distributed Rate Limiting:** Implements an atomic O(1) Redis rate limiter (`INCR` + `EXPIRE` Lua script) to prevent DDoS and brute-force attempts under high concurrency.
*   **Identity Edge Validation:** Cryptographically verifies incoming JWTs and validates Role-Based Access Control (RBAC) scopes before proxying.
*   **Inline Anomaly Filtering:** Routes request metadata through an embedded, ultra-fast Machine Learning model (Inference time under 2ms) to block structural anomalies.

### 3.2 Control & Analytics Plane (Asynchronous Background Path)
*   **Asynchronous Non-Blocking Telemetry Pipeline:** Offloads request telemetry and flagged threat payloads asynchronously via RabbitMQ and the AI Anomaly Engine using non-blocking execution (`setImmediate`) to maintain minimal HTTP response latency.
*   **Asynchronous AI Audit Worker:** A background service that consumes events from the queue, batches them, and triggers an LLM to categorize attack vectors and generate human-readable security summaries.
*   **Admin Analytics Dashboard:** A web interface providing real-time telemetry, visual metrics on blocked IPs, and searchable AI threat analysis reports.

## 4. Non-Functional Requirements (NFRs)
*   **Performance:** The gateway must bring response times under 100ms during high-concurrency rate-limit testing (introducing less than 5ms overhead to the raw request lifecycle).
*   **Resilience:** If the background message queue or local AI service goes down, core routing and security features (JWT, Rate Limiting) must gracefully degrade fail-open, continuing to route legitimate traffic.
*   **Portability:** The entire environment must be completely containerized using Docker Compose for instant local reproduction.

## 5. Out of Scope (Future Releases)
*   Support for gRPC or GraphQL native parsing (MVP will strictly handle REST/HTTP).
*   Dynamic configuration reloads without service restarts.