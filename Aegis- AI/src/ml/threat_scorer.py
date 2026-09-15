import numpy as np
from typing import List, Dict, Any
from src.ml.anomaly_detector import AnomalyDetector
from src.ml.classifier import AttackClassifier
from src.ml.lstm_detector import LSTMDetector

class ThreatScorer:
    def __init__(self, config=None):
        self.config = config or {}
        self.anomaly_detector = AnomalyDetector()
        self.classifier = AttackClassifier(use_xgboost=self.config.get("use_xgboost", False))
        self.lstm_detector = LSTMDetector(sequence_window=self.config.get("sequence_window", 10))
        self.threat_threshold = self.config.get("threat_threshold", 75)

    def score_flow(self, feature_vector: List[float], flow: Dict[str, Any]) -> Dict[str, Any]:
        anomaly_score = self.anomaly_detector.get_anomaly_score(feature_vector)
        classification = self.classifier.classify(feature_vector)
        attack_type = classification["attack_type"]
        classification_confidence = classification["confidence"]

        self.lstm_detector.update_sequence(feature_vector)
        sequence_score = self.lstm_detector.detect()

        if attack_type == "BENIGN":
            classification_component = (1 - classification_confidence) * 30
        else:
            classification_component = classification_confidence * 100

        anomaly_component = anomaly_score * 100
        sequence_component = sequence_score * 100

        # The 0.20 weight on sequence_component is only justified when
        # it comes from a genuinely trained LSTM. In every default
        # install (no tensorflow, no trained model - see
        # lstm_detector.py) it's an unscaled heuristic, not a learned
        # signal, and previously still carried a fixed 20% of every
        # single threat score regardless. Redistribute its weight to the
        # two components that ARE backed by real trained models
        # (anomaly_detector / classifier) whenever the LSTM isn't ready,
        # keeping their relative proportions (0.30 : 0.50 -> 0.375 : 0.625).
        if self.lstm_detector.is_trained():
            weights = (0.30, 0.50, 0.20)
        else:
            weights = (0.375, 0.625, 0.0)

        threat_score = (
            anomaly_component * weights[0] +
            classification_component * weights[1] +
            sequence_component * weights[2]
        )

        threat_score = min(100, max(0, threat_score))

        if threat_score >= self.threat_threshold:
            risk_level = "HIGH RISK / ATTACK"
        elif threat_score >= self.threat_threshold * 0.6:
            risk_level = "MEDIUM RISK"
        elif threat_score >= self.threat_threshold * 0.3:
            risk_level = "LOW RISK"
        else:
            risk_level = "BENIGN"

        if risk_level == "HIGH RISK / ATTACK":
            action = "Immediate investigation required. Block source IP and isolate affected systems."
        elif risk_level == "MEDIUM RISK":
            action = "Monitor closely. Verify traffic legitimacy and check for compromise indicators."
        elif risk_level == "LOW RISK":
            action = "Log for review. No immediate action required."
        else:
            action = "Normal traffic. Continue monitoring."

        return {
            "threat_score": round(threat_score, 2),
            "risk_level": risk_level,
            "attack_type": attack_type,
            "anomaly_score": round(anomaly_score, 4),
            "classification_confidence": round(classification_confidence, 4),
            "sequence_score": round(sequence_score, 4),
            "recommended_action": action,
            "component_breakdown": {
                "anomaly": round(anomaly_component, 2),
                "classification": round(classification_component, 2),
                "sequence": round(sequence_component, 2),
                "weights_used": {"anomaly": weights[0], "classification": weights[1], "sequence": weights[2]},
                "lstm_trained": self.lstm_detector.is_trained(),
            }
        }
