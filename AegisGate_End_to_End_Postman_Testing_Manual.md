# AegisGate End-to-End Postman Testing Manual

This document provides step-by-step instructions and exact request definitions for manually testing the AegisGate Edge Security Shield & AI Firewall using **Postman**.

---

## 🛠 Global Setup & Environment Variables

Create a Postman Environment named `AegisGate-Local` with the following variables:

| Variable | Initial / Current Value | Description |
| :--- | :--- | :--- |
| `baseUrl` | `http://localhost:8080` | AegisGate Gateway Core base URL |
| `jwtToken` | `eyJhbGciOiJIUzI1NiIsInR5c...` | Developer JWT token received from Auth registration |
| `projectId` | `6a72eb17a286892a9f1c72d2` | MongoDB `_id` of the provisioned project |
| `apiKey` | `ag_live_0b4bc02d0c468ad66b49ba46...` | Provisioned tenant API key prefixed with `ag_live_` |

---

## 📋 Test 1: User Registration & Project API Key Provisioning

### 1.1 Developer Registration / Login
- **Method**: `POST`
- **URL**: `{{baseUrl}}/api/v1/auth/register`
- **Headers**:
  - `Content-Type`: `application/json`
- **Body** (raw JSON):
  ```json
  {
    "email": "developer@aegisgate.io",
    "password": "SecurePassword123!"
  }
  ```
- **Expected Response**: `HTTP 201 Created`
  ```json
  {
    "message": "User registered successfully",
    "token": "eyJhbGciOiJIUzI1NiIsInR..."
  }
  ```
  *> Copy the returned `token` into your Postman environment as `jwtToken`.*

---

### 1.2 Tenant Project Provisioning
- **Method**: `POST`
- **URL**: `{{baseUrl}}/api/v1/projects`
- **Headers**:
  - `Content-Type`: `application/json`
  - `Authorization`: `Bearer {{jwtToken}}`
- **Body** (raw JSON):
  ```json
  {
    "name": "SmartBill Shield",
    "targetUrl": "http://ai-anomaly-engine:8000/docs",
    "dryRun": true,
    "enableLLMAudit": true
  }
  ```
- **Expected Response**: `HTTP 201 Created`
  ```json
  {
    "_id": "6a72eb17a286892a9f1c72d2",
    "projectName": "SmartBill Shield",
    "apiKey": "ag_live_0b4bc02d0c468ad66b49ba4637883edd7c336628d43f3afe",
    "targetUrl": "http://ai-anomaly-engine:8000/docs",
    "dryRun": true,
    "enableLLMAudit": true
  }
  ```
  *> Copy `_id` to `projectId` and `apiKey` to `apiKey` in Postman Environment.*

---

## 📋 Test 2: Ingress Proxy Routing & Invalid API Key Rejection

### 2.1 Valid API Key Ingress Request
- **Method**: `GET`
- **URL**: `{{baseUrl}}/api/v1/orders`
- **Headers**:
  - `x-aegis-api-key`: `{{apiKey}}`
- **Expected Response**: `HTTP 200 OK` (Proxied downstream to target backend)

---

### 2.2 Invalid API Key Request Rejection
- **Method**: `GET`
- **URL**: `{{baseUrl}}/api/v1/orders`
- **Headers**:
  - `x-aegis-api-key`: `invalid_key_12345`
- **Expected Response**: `HTTP 401 Unauthorized`
  ```json
  {
    "error": "Unauthorized",
    "message": "API key is missing or invalid."
  }
  ```

---

## 📋 Test 3: Observation / Dry-Run Mode (`dryRun: true`)

### 3.1 Ensure Project is in Dry-Run Mode
- **Method**: `PUT`
- **URL**: `{{baseUrl}}/api/v1/projects/{{projectId}}`
- **Headers**:
  - `Content-Type`: `application/json`
  - `Authorization`: `Bearer {{jwtToken}}`
- **Body**:
  ```json
  {
    "targetUrl": "http://ai-anomaly-engine:8000/docs",
    "dryRun": true
  }
  ```

---

### 3.2 Send Anomaly Payload in Dry-Run Mode
- **Method**: `POST`
- **URL**: `{{baseUrl}}/api/v1/orders`
- **Headers**:
  - `x-aegis-api-key`: `{{apiKey}}`
  - `Content-Type`: `application/json`
- **Body** (raw JSON):
  ```json
  {
    "username": "admin' OR 1=1 --"
  }
  ```
- **Expected Response**: Request is **NOT** blocked with 403. Returns HTTP 200/404 from proxied target.
- **Header Check**: Response Headers include:
  ```http
  X-Aegis-Threat-Detected: true
  ```

---

## 📋 Test 4: Active AI Firewall Enforcement (`dryRun: false`)

### 4.1 Switch Project to Active Blocking Mode
- **Method**: `PUT`
- **URL**: `{{baseUrl}}/api/v1/projects/{{projectId}}`
- **Headers**:
  - `Content-Type`: `application/json`
  - `Authorization`: `Bearer {{jwtToken}}`
- **Body**:
  ```json
  {
    "dryRun": false
  }
  ```

---

### 4.2 Send Anomaly Payload in Active Enforcement Mode
- **Method**: `POST`
- **URL**: `{{baseUrl}}/api/v1/orders`
- **Headers**:
  - `x-aegis-api-key`: `{{apiKey}}`
  - `Content-Type`: `application/json`
- **Body** (raw JSON):
  ```json
  {
    "username": "admin' OR 1=1 --"
  }
  ```
- **Expected Response**: `HTTP 403 Forbidden`
  ```json
  {
    "error": "AI Threat Detection Blocked Request",
    "message": "Security boundary blocked request due to structural anomalies."
  }
  ```

---

## 📋 Test 5: PII Redaction & LLM Privacy Opt-Out

### 5.1 Disable External LLM Auditing
- **Method**: `PUT`
- **URL**: `{{baseUrl}}/api/v1/projects/{{projectId}}`
- **Headers**:
  - `Content-Type`: `application/json`
  - `Authorization`: `Bearer {{jwtToken}}`
- **Body**:
  ```json
  {
    "dryRun": true,
    "enableLLMAudit": false
  }
  ```

---

### 5.2 Submit Sensitive PII Payload
- **Method**: `POST`
- **URL**: `{{baseUrl}}/api/v1/login`
- **Headers**:
  - `x-aegis-api-key`: `{{apiKey}}`
  - `Content-Type`: `application/json`
- **Body** (raw JSON):
  ```json
  {
    "email": "user@example.com",
    "password": "SuperSecretPassword123!",
    "credit_card": "4111222233334444",
    "ssn": "000-12-3456",
    "query": "SELECT * FROM users--"
  }
  ```

---

### 5.3 Verify Scrubbed Audit Log
- **Method**: `GET`
- **URL**: `{{baseUrl}}/api/v1/analytics/telemetry`
- **Headers**:
  - `X-Project-Id`: `{{projectId}}`
  - `Authorization`: `Bearer {{jwtToken}}`
- **Expected Response**: `HTTP 200 OK`
- **Assertions**:
  - `category` is `"UNANALYZED_PRIVACY_OPT_OUT"`.
  - `rawBody` displays masked PII:
    ```json
    {
      "email": "[REDACTED_EMAIL]",
      "password": "[REDACTED]",
      "credit_card": "[REDACTED]",
      "ssn": "[REDACTED]",
      "query": "SELECT * FROM users--"
    }
    ```

---

## 📋 Test 6: Webhook Alerting & Dead-Letter Queue (DLQ) Management

### 6.1 Configure Webhook URLs
- **Method**: `PUT`
- **URL**: `{{baseUrl}}/api/v1/projects/{{projectId}}`
- **Headers**:
  - `Content-Type`: `application/json`
  - `Authorization`: `Bearer {{jwtToken}}`
- **Body**:
  ```json
  {
    "slackWebhookUrl": "https://hooks.slack.com/services/T000/B000/XXXX",
    "discordWebhookUrl": "https://discord.com/api/webhooks/123456/XXXX"
  }
  ```

---

### 6.2 Fetch Dead-Letter Queue (DLQ) Logs
- **Method**: `GET`
- **URL**: `{{baseUrl}}/api/v1/analytics/dlq`
- **Headers**:
  - `X-Project-Id`: `{{projectId}}`
  - `Authorization`: `Bearer {{jwtToken}}`
- **Expected Response**: `HTTP 200 OK` (Returns array of dead-lettered poison message records)
  ```json
  [
    {
      "_id": "6a72eb...",
      "projectId": "6a72eb17a286892a9f1c72d2",
      "errorReason": "Exceeded maximum retries (3/3)",
      "retryCount": 3,
      "rawBody": "..."
    }
  ]
  ```

---

### 6.3 Re-queue DLQ Message Back to Pipeline
- **Method**: `POST`
- **URL**: `{{baseUrl}}/api/v1/analytics/dlq/{{messageId}}/retry`
- **Headers**:
  - `Authorization`: `Bearer {{jwtToken}}`
- **Expected Response**: `HTTP 200 OK`
  ```json
  {
    "success": true,
    "message": "Message re-queued successfully."
  }
  ```

---

### 6.4 Permanently Purge DLQ Message
- **Method**: `DELETE`
- **URL**: `{{baseUrl}}/api/v1/analytics/dlq/{{messageId}}`
- **Headers**:
  - `Authorization`: `Bearer {{jwtToken}}`
- **Expected Response**: `HTTP 200 OK`
  ```json
  {
    "success": true,
    "message": "Message purged successfully."
  }
  ```

---

## 🎯 Verification Summary Matrix

| Test ID | Test Name | Key Postman Headers | Expected Status Code | Validation Indicator |
| :--- | :--- | :--- | :--- | :--- |
| **Test 1** | Project & Key Provisioning | `Authorization: Bearer <jwtToken>` | `201 Created` | Response contains `ag_live_` API key |
| **Test 2** | Ingress Proxy Routing | `x-aegis-api-key: <apiKey>` vs `invalid` | `200 OK` / `401 Unauthorized` | 200 for valid key, 401 JSON for invalid |
| **Test 3** | Observation / Dry-Run | `x-aegis-api-key: <apiKey>` (`dryRun: true`) | `200/404` | `X-Aegis-Threat-Detected: true` header present |
| **Test 4** | Active AI Firewall Block | `x-aegis-api-key: <apiKey>` (`dryRun: false`) | `403 Forbidden` | `{"error": "AI Threat Detection Blocked Request"}` |
| **Test 5** | PII Redaction & LLM Opt-Out | `x-aegis-api-key: <apiKey>` (`enableLLMAudit: false`)| `200 OK` | `[REDACTED]`, `[REDACTED_EMAIL]`, `UNANALYZED_PRIVACY_OPT_OUT` |
| **Test 6** | DLQ Monitoring & Actions | `X-Project-Id: <projectId>` | `200 OK` | Returns DLQ list; retry & purge return `{ success: true }` |
