# pyrefly: ignore [missing-import]
from fastapi import FastAPI, HTTPException
# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field, ConfigDict
from contextlib import asynccontextmanager
import logging
from utils.model import detector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("ai-anomaly-engine")

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load and pseudo-train the in-memory isolation forest model upon startup
    try:
        detector.train_baseline()
    except Exception as e:
        logger.error(f"Critical startup training failure: {e}")
    yield
    # Cleanup if needed (none required)

app = FastAPI(
    title="AegisGate Anomaly Engine",
    description="Lightweight local edge anomaly detection engine powered by FastAPI & scikit-learn.",
    version="1.0.0",
    lifespan=lifespan
)

class PayloadMetrics(BaseModel):
    metrics: list[float] = Field(
        ...,
        description="A list of numerical features representing the telemetry of the payload to analyze."
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "metrics": [0.12, 0.45, -0.21, 0.05]
            }
        }
    )

@app.post("/api/v1/analyze", response_model=dict)
async def analyze_payload(payload: PayloadMetrics):
    """
    Highly optimized inference endpoint evaluating telemetry for structural anomalies.
    Returns:
        dict: { "is_anomaly": bool, "score": float }
    """
    try:
        # Perform scikit-learn Isolation Forest prediction
        is_anomaly, score = detector.predict(payload.metrics)
        return {
            "is_anomaly": is_anomaly,
            "score": score
        }
    except Exception as e:
        # Fault Resilience: Gracefully degrade, logging the error and defaulting to safe/non-anomalous state
        logger.error(f"[Inference Tier Failure] Degrading gracefully, defaulting to non-anomaly: {e}")
        return {
            "is_anomaly": False,
            "score": 0.0
        }

@app.get("/health", response_model=dict)
async def health_check():
    """
    Liveness & readiness probe check.
    """
    return {
        "status": "healthy",
        "model_fitted": detector.is_fitted
    }

if __name__ == "__main__":
    # pyrefly: ignore [missing-import]
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
