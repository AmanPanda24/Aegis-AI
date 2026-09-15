"""
Cross-flow reconnaissance detector (L3 counterpart to L2Analyzer).

A port scan's defining signature is *one source touching many distinct
destination ports/hosts in a short window* - that's inherently a
cross-flow property. No single flow's packet/byte statistics can express
it, so per-flow ML features (FeatureExtractor) and per-flow DPI
heuristics (dpi_engine.DPIEngine._flag_anomalies's PORT_SCAN_PATTERN)
structurally cannot detect it: they only ever see one 5-tuple at a time.

This module tracks, per source IP, a sliding window of (dst_ip, dst_port)
pairs contacted, plus overall connection attempt rate, and raises an
alert when either crosses a threshold - the same stateful/rule-based
approach L2Analyzer uses for ARP/STP/etc., because "many distinct
destinations from one source in a short time" is a well-known, well-
defined signature (this is how real tools like Zeek's scan.bro /
Suricata's stream-based scan detection work), not something you'd train
a per-flow classifier to see.

Fed one flow record at a time from main.py's processing_loop, right
alongside feature_extractor/dpi_engine/threat_scorer.
"""

import time
from collections import defaultdict, deque


class ScanDetector:
    def __init__(self, config=None):
        self.config = config or {}
        self.window_seconds = self.config.get("window_seconds", 10)
        self.port_threshold = self.config.get("distinct_ports_threshold", 15)
        self.host_threshold = self.config.get("distinct_hosts_threshold", 15)
        self.conn_rate_threshold = self.config.get("connection_rate_threshold", 30)
        self.alert_cooldown = self.config.get("alert_cooldown_seconds", self.window_seconds)

        # src_ip -> deque[(timestamp, dst_ip, dst_port)]
        self._activity = defaultdict(deque)
        # src_ip -> last time we alerted for it, to avoid re-firing every
        # single flow while a scan is still ongoing (mirrors
        # L2Analyzer's _mac_flood_last_alert / _stp_tc_last_alert pattern)
        self._last_alert = {}

    def observe(self, flow: dict):
        """Feed one completed flow record. Returns an alert dict (same
        shape as L2Analyzer's alerts, tagged layer='L3') if this source's
        recent activity now looks like a scan, else None.
        """
        src_ip = flow.get("src_ip")
        dst_ip = flow.get("dst_ip")
        dst_port = flow.get("dst_port")
        protocol = flow.get("protocol")
        ts = flow.get("timestamp", time.time())
        if not src_ip or src_ip == dst_ip:
            return None

        window = self._activity[src_ip]
        window.append((ts, dst_ip, dst_port))
        while window and ts - window[0][0] > self.window_seconds:
            window.popleft()

        distinct_ports = {(d, p) for _, d, p in window if p is not None}
        distinct_port_count = len({p for _, _, p in window if p is not None})
        distinct_host_count = len({d for _, d, _ in window})
        conn_count = len(window)

        is_scan = (
            distinct_port_count >= self.port_threshold
            or distinct_host_count >= self.host_threshold
            or conn_count >= self.conn_rate_threshold
        )
        if not is_scan:
            return None

        last = self._last_alert.get(src_ip, 0)
        if ts - last < self.alert_cooldown:
            return None
        self._last_alert[src_ip] = ts

        if distinct_port_count >= self.port_threshold:
            category, title = "PORT_SCAN", "Port Scan Detected (Multi-Port Reconnaissance)"
        elif distinct_host_count >= self.host_threshold:
            category, title = "HOST_SWEEP", "Host Sweep Detected (Multi-Host Reconnaissance)"
        else:
            category, title = "CONNECTION_FLOOD", "High-Rate Connection Attempts (Possible DoS/Brute-Force Spray)"

        return {
            "layer": "L3",
            "category": category,
            "attack_type": title,
            "threat_score": 85,
            "risk_level": "HIGH RISK / ATTACK",
            "timestamp": ts,
            "src_ip": src_ip,
            "dst_ip": None,
            "recommended_action": (
                "Investigate source host for scanning/reconnaissance tooling "
                "(nmap, masscan, etc.); consider temporary blocking or rate-"
                "limiting at the perimeter."
            ),
            "description": (
                f"{src_ip} contacted {distinct_port_count} distinct destination "
                f"ports across {distinct_host_count} distinct hosts "
                f"({conn_count} connection attempts) within {self.window_seconds}s "
                f"- consistent with automated network scanning (e.g. nmap/masscan) "
                f"rather than normal application traffic."
            ),
            "details": {
                "distinct_ports": distinct_port_count,
                "distinct_hosts": distinct_host_count,
                "connection_attempts": conn_count,
                "window_seconds": self.window_seconds,
                "protocol": protocol,
            },
        }
