import math
from src.processing.feature_extraction import FeatureExtractor


def _packet(src_ip, dst_ip, ts, length, flags="", entropy=0.0):
    return {
        "timestamp": ts, "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": 1234, "dst_port": 80, "length": length,
        "flags": flags, "payload_entropy": entropy, "payload": b"",
    }


def test_empty_flow_returns_empty_features():
    fe = FeatureExtractor()
    assert fe.extract_features({"packets": []}) == {}


def test_basic_flow_duration_and_byte_counts():
    fe = FeatureExtractor()
    flow = {
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "TCP",
        "packets": [
            _packet("10.0.0.1", "10.0.0.2", 0.0, 100, flags="S"),
            _packet("10.0.0.2", "10.0.0.1", 0.5, 200, flags="SA"),
            _packet("10.0.0.1", "10.0.0.2", 1.0, 50, flags="A"),
        ],
    }
    features = fe.extract_features(flow)

    assert features["total_fwd_packets"] == 2  # src_ip == 10.0.0.1
    assert features["total_bwd_packets"] == 1
    assert features["total_fwd_bytes"] == 150
    assert features["total_bwd_bytes"] == 200
    assert math.isclose(features["flow_duration"], 1.0)
    assert features["syn_flag_count"] == 2  # "S" and "SA"


def test_feature_vector_length_matches_declared_names():
    fe = FeatureExtractor()
    flow = {
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "TCP",
        "packets": [_packet("10.0.0.1", "10.0.0.2", 0.0, 100)],
    }
    features = fe.extract_features(flow)
    vector = fe.get_feature_vector(features)
    assert len(vector) == len(fe.feature_names)
    assert all(isinstance(v, (int, float)) for v in vector)


def test_missing_feature_defaults_to_zero_in_vector():
    fe = FeatureExtractor()
    vector = fe.get_feature_vector({})  # no keys at all
    assert vector == [0.0] * len(fe.feature_names)


def test_zero_packet_flow_duration_does_not_divide_by_zero():
    # A single-packet flow has flow_duration == 0 by construction (max==min);
    # extract_features must clamp this before dividing bytes/sec by it.
    fe = FeatureExtractor()
    flow = {
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "UDP",
        "packets": [_packet("10.0.0.1", "10.0.0.2", 5.0, 64)],
    }
    features = fe.extract_features(flow)
    assert features["flow_duration"] > 0
    assert math.isfinite(features["flow_bytes_per_sec"])
