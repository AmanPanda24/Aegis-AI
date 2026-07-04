import os
import pickle
import numpy as np
from typing import List, Dict, Any
from sklearn.ensemble import RandomForestClassifier

try:
    import xgboost as xgb
    XGBOOST_AVAILABLE = True
except ImportError:
    XGBOOST_AVAILABLE = False

class AttackClassifier:
    def __init__(self, model_path=None, use_xgboost=False):
        self.model = None
        self.model_path = model_path or "./models/classifier.pkl"
        self.use_xgboost = use_xgboost and XGBOOST_AVAILABLE
        self.classes = ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce", "WebAttack", "Bot", "Infiltration"]
        self.load_or_init()

    def load_or_init(self):
        if os.path.exists(self.model_path):
            with open(self.model_path, "rb") as f:
                data = pickle.load(f)
                self.model = data.get("model")
                self.classes = data.get("classes", self.classes)
        else:
            if self.use_xgboost and XGBOOST_AVAILABLE:
                self.model = xgb.XGBClassifier(
                    n_estimators=100,
                    max_depth=6,
                    learning_rate=0.1,
                    random_state=42,
                    eval_metric="mlogloss"
                )
            else:
                self.model = RandomForestClassifier(
                    n_estimators=100,
                    max_depth=10,
                    random_state=42,
                    n_jobs=-1
                )

    def fit(self, X: np.ndarray, y: np.ndarray):
        self.model.fit(X, y)
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, "wb") as f:
            pickle.dump({"model": self.model, "classes": self.classes}, f)

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        if hasattr(self.model, "predict_proba"):
            return self.model.predict_proba(X)
        else:
            preds = self.model.predict(X)
            proba = np.zeros((len(preds), len(self.classes)))
            for i, p in enumerate(preds):
                idx = list(self.classes).index(p) if p in self.classes else 0
                proba[i, idx] = 1.0
            return proba

    def classify(self, feature_vector: List[float]) -> Dict[str, Any]:
        X = np.array([feature_vector])
        prediction = self.predict(X)[0]
        probabilities = self.predict_proba(X)[0]

        confidence = float(np.max(probabilities))
        class_idx = int(np.argmax(probabilities))

        if isinstance(prediction, (int, np.integer)) and 0 <= int(prediction) < len(self.classes):
            attack_type = str(self.classes[int(prediction)])
        elif 0 <= class_idx < len(self.classes):
            attack_type = str(self.classes[class_idx])
        else:
            attack_type = str(prediction)

        return {
            "attack_type": attack_type,
            "confidence": confidence,
            "class_index": class_idx,
            "all_probabilities": {
                cls: float(prob) 
                for cls, prob in zip(self.classes, probabilities)
            }
        }
