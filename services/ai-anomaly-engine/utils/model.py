import numpy as np
from sklearn.ensemble import IsolationForest
import logging

logger = logging.getLogger("ai-anomaly-engine")

FEATURE_DIM = 4

class AnomalyDetector:
    def __init__(self) -> None:
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.is_fitted = False

    def train_baseline(self) -> None:
        """
        Pseudo-train the Isolation Forest model on synthetic baseline traffic data.
        Generates 90% very clean, small objects and 10% extreme, messy injection profiles.
        """
        logger.info("Initializing baseline training for Isolation Forest...")
        
        np.random.seed(42)
        # 90% clean, normal JSON objects (length ~ 50, injection chars ~ 0, colons ~ 2, depth ~ 1)
        clean_samples = np.random.normal(loc=[50.0, 0.0, 2.0, 1.0], scale=[20.0, 0.2, 1.0, 0.5], size=(90, FEATURE_DIM))
        clean_samples = np.maximum(clean_samples, 0.0)
        
        # 10% extreme, messy injection profiles (e.g., [500, 20, 12, 6])
        messy_samples = np.random.normal(loc=[500.0, 20.0, 12.0, 6.0], scale=5.0, size=(10, FEATURE_DIM))
        messy_samples = np.maximum(messy_samples, 0.0)
        
        # Combine clean and messy traffic data
        normal_samples = np.vstack([clean_samples, messy_samples])
        
        self.model.fit(normal_samples)
        self.is_fitted = True
        logger.info("Isolation Forest successfully trained on baseline synthetic data.")

    def predict(self, metrics: list[float]) -> tuple[bool, float]:
        """
        Predict if the given metrics represent an anomaly.
        Returns:
            tuple: (is_anomaly: bool, score: float)
        """
        if not self.is_fitted:
            raise RuntimeError("Model is not fitted. Call train_baseline() first.")
        
        if len(metrics) != FEATURE_DIM:
            raise ValueError(f"Expected {FEATURE_DIM} features, but received {len(metrics)}.")

        # Reshape input for prediction
        x = np.array(metrics).reshape(1, -1)
        
        # predict() returns 1 for normal, -1 for anomaly
        prediction = self.model.predict(x)[0]
        is_anomaly = bool(prediction == -1)
        
        # Heuristic enhancement: Flag request as anomaly if injection-sensitive character count >= 3.0
        if len(metrics) > 1 and metrics[1] >= 3.0:
            is_anomaly = True

        # decision_function score (negative value indicates anomaly)
        score = float(self.model.decision_function(x)[0])
        
        return is_anomaly, score

# Instantiate a global ready-to-use in-memory detector
detector = AnomalyDetector()
