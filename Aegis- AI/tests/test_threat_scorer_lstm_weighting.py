from src.ml.threat_scorer import ThreatScorer
from src.ml.lstm_detector import LSTMDetector


def test_sequence_weight_is_zero_when_lstm_untrained():
    # Regression test: previously the LSTM fallback's meaningless
    # intra-vector-variance number always carried a fixed 20% weight in
    # every threat score, even though every default install (no
    # tensorflow) never has a genuinely trained model.
    scorer = ThreatScorer()
    assert scorer.lstm_detector.is_trained() is False

    result = scorer.score_flow([1.0] * 55, {})
    weights = result["component_breakdown"]["weights_used"]
    assert weights["sequence"] == 0.0
    assert weights["anomaly"] + weights["classification"] + weights["sequence"] == 1.0
    assert result["component_breakdown"]["lstm_trained"] is False


def test_sequence_weight_is_nonzero_when_lstm_trained():
    scorer = ThreatScorer()
    scorer.lstm_detector._is_trained = True  # simulate a trained model without needing TF
    result = scorer.score_flow([1.0] * 55, {})
    weights = result["component_breakdown"]["weights_used"]
    assert weights["sequence"] == 0.20
    assert weights["anomaly"] == 0.30
    assert weights["classification"] == 0.50


def test_lstm_fallback_uses_temporal_not_intravector_variance():
    # Regression test: the fallback used to compute variance WITHIN one
    # feature vector (across differently-scaled features), not across
    # time. A flow with an identical feature vector repeated every
    # timestep (i.e. genuinely stable/non-bursty over time) should score
    # near zero even if the vector itself has wildly different-scale
    # values within it.
    d = LSTMDetector()
    stable_vector = [1.0, 5000.0, 0.02, 300.0] + [0.0] * 51
    for _ in range(5):
        d.update_sequence(stable_vector)
    score = d.detect()
    assert score == 0.0, "identical vectors over time should show zero temporal variance"


def test_lstm_fallback_detects_genuine_temporal_change():
    d = LSTMDetector()
    for v in [0.1, 5.0, 0.1, 5.0, 0.1]:
        d.update_sequence([v] * 55)
    score = d.detect()
    assert score > 0.0
