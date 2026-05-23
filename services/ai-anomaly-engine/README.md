# AegisGate - AI Anomaly Engine

This microservice acts as the local edge machine learning boundary for **AegisGate**, performing high-speed, inline anomaly detection on incoming request payloads. It is built using **FastAPI** for low-overhead routing and **scikit-learn**'s `IsolationForest` for robust, unsupervised outlier detection.

---

## Architecture & Logic

1. **Automatic Initialization**: On startup, the service initializes and pseudo-trains an `IsolationForest` model on baseline synthetic normal traffic data.
2. **In-Memory Inference**: The trained model resides in-memory, avoiding disk reads or external database hops during predictions.
3. **Resiliency & Fault Tolerance**: If prediction fails (due to shape mismatch, empty values, or core model issues), the service gracefully logs the failure and defaults to `is_anomaly = False`, ensuring live traffic is never blocked.

---

## Installation & Setup

### 1. Prerequisites
Ensure you have **Python 3.10** or higher installed.

### 2. Create a Virtual Environment
Navigate to this service directory and spin up a local virtual environment:

```bash
cd services/ai-anomaly-engine
python -m venv .venv
```

Activate the environment:
* **Windows (PowerShell)**:
  ```powershell
  .venv\Scripts\Activate.ps1
  ```
* **macOS / Linux**:
  ```bash
  source .venv/bin/activate
  ```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## Running the Application

Start the FastAPI application on port `8000`:

```bash
python main.py
```

Or run via Uvicorn with auto-reload:
```bash
uvicorn main:app --port 8000 --reload
```

---

## API Documentation

Once the server is running, you can explore the interactive documentation:
* **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
* **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## Verification & Testing

Verify that the model successfully classifies normal vs anomalous traffic:

### 1. Normal Payload Request (Within Baseline)
```bash
curl -X POST "http://localhost:8000/api/v1/analyze" \
     -H "Content-Type: application/json" \
     -d '{"metrics": [0.1, -0.2, 0.4, 0.05]}'
```
**Expected Response**:
```json
{
  "is_anomaly": false,
  "score": 0.384218
}
```

### 2. Anomalous Payload Request (Significant Outlier)
```bash
curl -X POST "http://localhost:8000/api/v1/analyze" \
     -H "Content-Type: application/json" \
     -d '{"metrics": [20.0, -45.0, 99.0, 88.0]}'
```
**Expected Response**:
```json
{
  "is_anomaly": true,
  "score": -0.320491
}
```
