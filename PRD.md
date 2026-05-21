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
*   **Reverse Proxy & Routing:** Intercepts incoming HTTP requests and forwards them to target microservices based on dynamic path rules.
*   **Distributed Rate Limiting:** Implements a sliding-window rate limiter utilizing an in-memory Redis store to prevent DDoS and brute-force attempts.
*   **Identity Edge Validation:** Cryptographically verifies incoming JWTs and validates Role-Based Access Control (RBAC) scopes before proxying.
*   **Inline Anomaly Filtering:** Routes request metadata through an embedded, ultra-fast Machine Learning model (Inference time under 2ms) to block structural anomalies.

### 3.2 Control & Analytics Plane (Asynchronous Background Path)
*   **Asynchronous Event Pipeline:** Offloads flagged malicious payloads to a message queue (RabbitMQ) to maintain low latency on live threads.
*   **Asynchronous AI Audit Worker:** A background service that consumes events from the queue, batches them, and triggers an LLM to categorize the attack vectors and generate human-readable security summaries.
*   **Admin Analytics Dashboard:** A web interface providing real-time telemetry, visual metrics on blocked IPs, and searchable AI threat analysis reports.

## 4. Non-Functional Requirements (NFRs)
*   **Performance:** The gateway must introduce less than 5ms of total overhead overhead to the raw request lifecycle (excluding background tasks).
*   **Resilience:** If the background message queue or the local AI service goes down, the core routing and security features (JWT, Rate Limiting) must gracefully degrade, logging errors but continuing to route legitimate traffic.
*   **Portability:** The entire environment must be completely containerized using Docker Compose for instant local reproduction.

## 5. Out of Scope (Future Releases)
*   Support for gRPC or GraphQL native parsing (MVP will strictly handle REST/HTTP).
*   Dynamic configuration reloads without service restarts.