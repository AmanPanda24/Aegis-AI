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

        threat_score = (
            anomaly_component * 0.30 +
            classification_component * 0.50 +
            sequence_component * 0.20
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
                "sequence": round(sequence_component, 2)
            }
        }
