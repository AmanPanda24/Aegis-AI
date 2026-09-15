import time

from src.processing.scan_detector import ScanDetector


def _flow(src_ip, dst_ip, dst_port, ts, protocol="TCP"):
    return {"src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port,
            "protocol": protocol, "timestamp": ts}


def test_no_alert_for_normal_traffic():
    sd = ScanDetector(config={"distinct_ports_threshold": 15, "window_seconds": 10})
    now = time.time()
    for i in range(5):
        assert sd.observe(_flow("10.0.0.5", "10.0.0.9", 443, now + i * 0.1)) is None


def test_port_scan_triggers_alert():
    # Regression test for the core detection gap: a port scan is
    # inherently cross-flow (one source, many distinct ports), which no
    # single flow's stats or per-flow DPI heuristic can see.
    sd = ScanDetector(config={"distinct_ports_threshold": 15, "window_seconds": 10})
    now = time.time()
    alert = None
    for port in range(20):
        alert = sd.observe(_flow("10.0.0.66", "10.0.0.9", 1000 + port, now + port * 0.01)) or alert
    assert alert is not None
    assert alert["category"] == "PORT_SCAN"
    assert alert["layer"] == "L3"
    assert alert["src_ip"] == "10.0.0.66"


def test_host_sweep_triggers_alert_on_distinct_hosts_not_ports():
    sd = ScanDetector(config={"distinct_ports_threshold": 100, "distinct_hosts_threshold": 10, "window_seconds": 10})
    now = time.time()
    alert = None
    for i in range(15):
        alert = sd.observe(_flow("10.0.0.66", f"10.0.0.{100+i}", 445, now + i * 0.01)) or alert
    assert alert is not None
    assert alert["category"] == "HOST_SWEEP"


def test_alert_cooldown_prevents_spam_for_same_source():
    sd = ScanDetector(config={"distinct_ports_threshold": 5, "window_seconds": 10, "alert_cooldown_seconds": 10})
    now = time.time()
    alerts = []
    for port in range(10):
        a = sd.observe(_flow("10.0.0.66", "10.0.0.9", 1000 + port, now + port * 0.01))
        if a:
            alerts.append(a)
    assert len(alerts) == 1  # not one per qualifying flow


def test_activity_outside_window_is_pruned_and_does_not_count():
    sd = ScanDetector(config={"distinct_ports_threshold": 10, "window_seconds": 5})
    now = time.time()
    for port in range(9):
        sd.observe(_flow("10.0.0.66", "10.0.0.9", 1000 + port, now + port * 0.1))
    # Long gap - old activity should fall out of the window
    late_alert = sd.observe(_flow("10.0.0.66", "10.0.0.9", 2000, now + 30))
    assert late_alert is None


def test_different_sources_tracked_independently():
    sd = ScanDetector(config={"distinct_ports_threshold": 10, "window_seconds": 10})
    now = time.time()
    for port in range(5):
        assert sd.observe(_flow("10.0.0.1", "10.0.0.9", 1000 + port, now + port * 0.01)) is None
        assert sd.observe(_flow("10.0.0.2", "10.0.0.9", 1000 + port, now + port * 0.01)) is None
