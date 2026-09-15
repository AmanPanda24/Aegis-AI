import os
import pickle
import warnings
import numpy as np
from typing import List, Dict, Any
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import NotFittedError

class AnomalyDetector:
    def __init__(self, model_path=None):
        self.model = None
        self.model_path = model_path or "./models/isolation_forest.pkl"
        self.feature_names = None
        self._warned_unfitted = False
        self.load_or_init()

    def load_or_init(self):
        if os.path.exists(self.model_path):
            with open(self.model_path, "rb") as f:
                self.model = pickle.load(f)
        else:
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.1,
                random_state=42,
                n_jobs=-1
            )

    def fit(self, X: np.ndarray):
        self.model.fit(X)
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, "wb") as f:
            pickle.dump(self.model, f)

    def predict(self, X: np.ndarray) -> np.ndarray:
        if not hasattr(self.model, "decision_function"):
            return np.ones(len(X)) * 0.5
        try:
            scores = self.model.decision_function(X)
            return 1 - (scores + 0.5)
        except NotFittedError:
            # Previously this crashed the whole processing loop on the very
            # first packet whenever `scripts/train_models.py` hadn't been
            # run yet, since load_or_init() creates an *unfitted*
            # IsolationForest when no models/isolation_forest.pkl exists.
            # Fail soft instead: return a neutral score and warn loudly,
            # so the app is at least usable (with degraded detection)
            # before training, rather than throwing on startup.
            if not self._warned_unfitted:
                warnings.warn(
                    "AnomalyDetector model is not trained (no "
                    f"{self.model_path} found). Returning neutral scores "
                    "until you run `python scripts/train_models.py`.",
                    RuntimeWarning,
                )
                self._warned_unfitted = True
            return np.ones(len(X)) * 0.5

    def get_anomaly_score(self, feature_vector: List[float]) -> float:
        X = np.array([feature_vector])
        score = self.predict(X)[0]
        return float(max(0.0, min(1.0, score)))
