import warnings
import numpy as np

from src.ml.anomaly_detector import AnomalyDetector
from src.ml.classifier import AttackClassifier
from src.ml.threat_scorer import ThreatScorer


def test_anomaly_detector_does_not_crash_when_untrained(tmp_path):
    # Regression test: previously calling get_anomaly_score() on a fresh
    # AnomalyDetector (no isolation_forest.pkl on disk) raised
    # sklearn.exceptions.NotFittedError and crashed the whole flow
    # processing loop in src/api/main.py.
    detector = AnomalyDetector(model_path=str(tmp_path / "does_not_exist.pkl"))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        score = detector.get_anomaly_score([0.0] * 53)
        assert any(issubclass(w.category, RuntimeWarning) for w in caught)
    assert 0.0 <= score <= 1.0


def test_anomaly_detector_works_after_fit(tmp_path):
    detector = AnomalyDetector(model_path=str(tmp_path / "iso.pkl"))
    X = np.random.randn(50, 5)
    detector.fit(X)
    score = detector.get_anomaly_score([0.0] * 5)
    assert 0.0 <= score <= 1.0


def test_classifier_defaults_to_benign_when_untrained(tmp_path):
    # Regression test: previously .classify() raised NotFittedError before
    # scripts/train_models.py had ever been run.
    clf = AttackClassifier(model_path=str(tmp_path / "does_not_exist.pkl"))
    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        result = clf.classify([0.0] * 53)
    assert result["attack_type"] == "BENIGN"


def test_threat_scorer_end_to_end_does_not_crash_untrained(tmp_path):
    scorer = ThreatScorer(config={})
    scorer.anomaly_detector = AnomalyDetector(model_path=str(tmp_path / "iso2.pkl"))
    scorer.classifier = AttackClassifier(model_path=str(tmp_path / "clf2.pkl"))

    flow = {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "TCP"}
    result = scorer.score_flow([0.0] * 53, flow)

    assert 0.0 <= result["threat_score"] <= 100.0
    assert result["risk_level"] in ("BENIGN", "LOW RISK", "MEDIUM RISK", "HIGH RISK / ATTACK")
