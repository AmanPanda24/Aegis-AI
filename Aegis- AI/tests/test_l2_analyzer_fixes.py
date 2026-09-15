import time

from src.processing.l2_analyzer import L2Analyzer
from src.capture.l2_capture import L2Capture


def test_stp_hijack_still_alerts_immediately():
    a = L2Analyzer()
    now = time.time()
    a._check_stp({"type": "STP", "timestamp": now, "src_mac": "aa:bb:cc:00:00:01", "root_id": "8000aabbccddeeff"})
    alert = a._check_stp({"type": "STP", "timestamp": now + 1, "src_mac": "de:ad:be:ef:00:66", "root_id": "0001deadbeef0066"})
    assert alert is not None
    assert alert["category"] == "STP_ROOT_HIJACK"


def test_stp_baseline_recovers_after_legit_reconvergence():
    # Regression test: previously, once an attacker's forged (lower) root
    # id became the baseline, a real switch re-electing a legitimate but
    # numerically HIGHER root id could never be relearned - the baseline
    # stayed permanently poisoned.
    a = L2Analyzer(config={"thresholds": {"stp_recovery_confirmations": 3}})
    now = time.time()
    a._check_stp({"type": "STP", "timestamp": now, "src_mac": "aa:bb:cc:00:00:01", "root_id": "8000aabbccddeeff"})
    a._check_stp({"type": "STP", "timestamp": now + 1, "src_mac": "de:ad:be:ef:00:66", "root_id": "0001deadbeef0066"})
    assert a.stp_root_id == "0001deadbeef0066"  # poisoned

    for i in range(3):
        alert = a._check_stp({"type": "STP", "timestamp": now + 2 + i, "src_mac": "aa:bb:cc:00:00:01", "root_id": "8000aabbccddeeff"})
        assert alert is None  # reconvergence isn't attack behavior, no alert

    assert a.stp_root_id == "8000aabbccddeeff"  # recovered


def test_stp_single_stray_bpdu_does_not_reset_baseline():
    a = L2Analyzer(config={"thresholds": {"stp_recovery_confirmations": 3}})
    now = time.time()
    a._check_stp({"type": "STP", "timestamp": now, "src_mac": "aa:bb:cc:00:00:01", "root_id": "8000aabbccddeeff"})
    # One-off higher root id, not sustained - should NOT become baseline
    a._check_stp({"type": "STP", "timestamp": now + 1, "src_mac": "zz", "root_id": "9000ffffffffffff"})
    assert a.stp_root_id == "8000aabbccddeeff"


def test_known_macs_are_pruned_and_stay_bounded():
    # Regression test: _known_macs/_cdp_events used to grow forever,
    # exactly under the flood traffic they exist to detect.
    a = L2Analyzer(config={"thresholds": {"state_retention_seconds": 100}})
    a._prune_interval_seconds = 0  # force pruning to actually run each call
    now = time.time()
    for i in range(50):
        a.analyze({"type": "CDP", "timestamp": now, "src_mac": f"aa:bb:cc:00:00:{i:02x}"})
    assert len(a._known_macs) == 50

    # Jump far into the future - old entries should be pruned away
    for i in range(50, 100):
        a.analyze({"type": "CDP", "timestamp": now + 1000, "src_mac": f"aa:bb:cc:00:00:{i:02x}"})
    assert len(a._known_macs) == 50  # old 50 pruned, new 50 present
    assert all(m not in a._known_macs for m in [f"aa:bb:cc:00:00:{i:02x}" for i in range(50)])


def test_bpdu_parses_correctly_through_single_vlan_tag():
    # Regression test: BPDU/SNAP parsing hardcoded offset 14 (bare
    # Ethernet), which misaligned on any 802.1Q-tagged trunk frame -
    # exactly where STP traffic matters most.
    from scapy.all import Ether, Dot1Q, Raw

    llc = bytes([0x42, 0x42, 0x03])
    bpdu_body = bytes([0, 0, 0, 0, 0]) + bytes.fromhex("8000aabbccddeeff") + (100).to_bytes(4, "big") + bytes.fromhex("8000aabbccddeeff") + bytes(10)

    tagged = Ether(src="aa:bb:cc:00:00:01", dst="01:80:c2:00:00:00") / Dot1Q(vlan=10) / Raw(llc + bpdu_body)
    l2 = L2Capture(state=None)
    result = l2._parse_frame(tagged)
    assert result is not None
    assert result["type"] == "STP"
    assert result["root_id"] == "8000aabbccddeeff"
    assert result["root_cost"] == 100
