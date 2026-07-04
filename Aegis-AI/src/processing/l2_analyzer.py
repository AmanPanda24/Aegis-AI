"""
Layer 2 threat analyzer.

L3 attacks (port scans, DoS, brute force...) get flagged by statistics
over a flow -- packet counts, timing, entropy. L2 attacks don't work that
way: there's no "flow" to a broadcast ARP reply or a spoofed BPDU. Instead
each protocol has its own, well-known abuse pattern, so this module is
rule-based/stateful rather than ML-based -- which mirrors how real NIDS
(Snort/Suricata/arpwatch/etc.) actually catch these:

  - ARP spoofing      -> an IP suddenly maps to a second, conflicting MAC
  - MAC flooding       -> a burst of unseen source MACs (CAM table overflow)
  - STP manipulation   -> a new/foreign node claims to be root bridge, or
                          topology-change floods
  - CDP flood          -> abnormal rate of Cisco Discovery Protocol frames
  - DTP negotiation     -> any end host asking to trunk = switch spoofing
  - VTP attack          -> a suspicious jump in VTP configuration revision
  - VLAN hopping        -> a frame carrying two stacked 802.1Q tags
"""

import time
from collections import defaultdict, deque


class L2Analyzer:
    def __init__(self, config=None):
        self.config = config or {}
        t = self.config.get("thresholds", {})

        self.mac_flood_window = t.get("mac_flood_window_seconds", 10)
        self.mac_flood_new_macs = t.get("mac_flood_new_macs_per_window", 40)
        self.cdp_flood_window = t.get("cdp_flood_window_seconds", 10)
        self.cdp_flood_count = t.get("cdp_flood_count_per_window", 20)
        self.stp_tc_window = t.get("stp_topology_change_window_seconds", 10)
        self.stp_tc_count = t.get("stp_topology_change_count", 5)

        # ARP: trusted ip -> mac bindings we've observed
        self.arp_table = {}
        # MAC flood: rolling window of (timestamp, mac) seen
        self._mac_events = deque()
        self._known_macs = set()
        self._mac_flood_last_alert = 0
        # STP: baseline root bridge id, once learned
        self.stp_root_id = None
        self.stp_root_mac = None
        self._stp_tc_events = deque()
        # CDP: rolling window of timestamps per source mac
        self._cdp_events = defaultdict(deque)
        # DTP: macs already alerted on recently, to avoid spamming
        self._dtp_last_alert = {}
        # VTP: last known configuration revision
        self.vtp_last_revision = None

    def analyze(self, event):
        etype = event.get("type")
        if etype == "ARP":
            return self._check_arp(event)
        if etype == "STP":
            return self._check_stp(event)
        if etype == "CDP":
            return self._check_mac_flood(event) or self._check_cdp(event)
        if etype == "DTP":
            return self._check_dtp(event)
        if etype == "VTP":
            return self._check_vtp(event)
        if etype == "VLAN_DOUBLE_TAG":
            return self._check_vlan_hop(event)
        return None

    # ---------------------------------------------------------------- ARP

    def _check_arp(self, event):
        flood_alert = self._check_mac_flood(event)
        if flood_alert:
            return flood_alert

        if event.get("op") != "reply":
            return None

        ip = event.get("src_ip")
        mac = event.get("src_hw") or event.get("src_mac")
        if not ip or ip == "0.0.0.0" or not mac:
            return None

        known_mac = self.arp_table.get(ip)
        if known_mac and known_mac != mac:
            self.arp_table[ip] = mac
            return self._alert(
                category="ARP_SPOOFING",
                title="ARP Spoofing / Cache Poisoning Detected",
                severity=92,
                event=event,
                description=(
                    f"IP {ip} was bound to MAC {known_mac}, but a new ARP "
                    f"reply now claims it belongs to {mac}. This is the "
                    f"signature of ARP cache poisoning (e.g. arpspoof, "
                    f"Ettercap, Yersinia) used to redirect traffic for a "
                    f"man-in-the-middle attack."
                ),
                recommended_action=(
                    "Verify the legitimate MAC for this IP, isolate the "
                    "offending host, and consider enabling Dynamic ARP "
                    "Inspection (DAI) / static ARP entries on critical hosts."
                ),
                details={"ip": ip, "previous_mac": known_mac, "new_mac": mac},
            )

        self.arp_table[ip] = mac
        return None

    # ---------------------------------------------------------------- MAC

    def _check_mac_flood(self, event):
        mac = event.get("src_mac")
        ts = event.get("timestamp", time.time())
        if not mac:
            return None

        self._mac_events.append((ts, mac))
        while self._mac_events and ts - self._mac_events[0][0] > self.mac_flood_window:
            self._mac_events.popleft()

        is_new = mac not in self._known_macs
        self._known_macs.add(mac)

        if not is_new:
            return None

        new_macs_in_window = len({m for _, m in self._mac_events})
        if new_macs_in_window >= self.mac_flood_new_macs:
            if ts - self._mac_flood_last_alert < self.mac_flood_window:
                return None
            self._mac_flood_last_alert = ts
            return self._alert(
                category="MAC_FLOODING",
                title="MAC Flooding / CAM Table Overflow Attempt",
                severity=88,
                event=event,
                description=(
                    f"{new_macs_in_window} distinct source MAC addresses "
                    f"seen within {self.mac_flood_window}s. This matches "
                    f"tools like macof/Yersinia flooding a switch's CAM "
                    f"table so it fails open and starts broadcasting all "
                    f"traffic, enabling passive sniffing."
                ),
                recommended_action=(
                    "Enable port security (max MAC count per port) on "
                    "access switches and investigate the source segment."
                ),
                details={"distinct_macs_in_window": new_macs_in_window,
                         "window_seconds": self.mac_flood_window},
            )
        return None

    # ---------------------------------------------------------------- STP

    def _check_stp(self, event):
        root_id = event.get("root_id")
        ts = event.get("timestamp", time.time())

        alert = None
        if root_id:
            if self.stp_root_id is None:
                self.stp_root_id = root_id
                self.stp_root_mac = event.get("src_mac")
            elif root_id != self.stp_root_id and root_id < self.stp_root_id:
                alert = self._alert(
                    category="STP_ROOT_HIJACK",
                    title="STP Root Bridge Hijack (BPDU Manipulation)",
                    severity=90,
                    event=event,
                    description=(
                        f"A BPDU claiming a superior (lower) bridge ID "
                        f"{root_id} was seen from {event.get('src_mac')}, "
                        f"displacing the previously observed root "
                        f"{self.stp_root_id}. This is the classic Yersinia/"
                        f"STP root-takeover attack, which lets the attacker "
                        f"reroute traffic through itself."
                    ),
                    recommended_action=(
                        "Enable BPDU Guard / Root Guard on access ports so "
                        "end hosts can never become the STP root."
                    ),
                    details={"claimed_root_id": root_id, "previous_root_id": self.stp_root_id},
                )
                self.stp_root_id = root_id
                self.stp_root_mac = event.get("src_mac")

        if event.get("topology_change"):
            self._stp_tc_events.append(ts)
            while self._stp_tc_events and ts - self._stp_tc_events[0] > self.stp_tc_window:
                self._stp_tc_events.popleft()
            if not alert and len(self._stp_tc_events) >= self.stp_tc_count:
                return self._alert(
                    category="STP_TC_FLOOD",
                    title="STP Topology Change Flood",
                    severity=70,
                    event=event,
                    description=(
                        f"{len(self._stp_tc_events)} topology-change BPDUs "
                        f"seen within {self.stp_tc_window}s, well above "
                        f"normal. Repeated forced topology changes are used "
                        f"to keep MAC tables flushing and disrupt switching."
                    ),
                    recommended_action="Investigate the source port for rogue STP participation.",
                    details={"tc_count_in_window": len(self._stp_tc_events)},
                )
        return alert

    # ---------------------------------------------------------------- CDP

    def _check_cdp(self, event):
        mac = event.get("src_mac")
        ts = event.get("timestamp", time.time())
        window = self._cdp_events[mac]
        window.append(ts)
        while window and ts - window[0] > self.cdp_flood_window:
            window.popleft()

        if len(window) >= self.cdp_flood_count:
            window.clear()
            return self._alert(
                category="CDP_FLOOD",
                title="CDP Flood (Recon / Table Exhaustion)",
                severity=55,
                event=event,
                description=(
                    f"Abnormal rate of Cisco Discovery Protocol frames from "
                    f"{mac}. CDP floods are used for network reconnaissance "
                    f"(harvesting device/IOS info) or to exhaust a switch's "
                    f"neighbor table, as done by Yersinia's CDP flood mode."
                ),
                recommended_action="Disable CDP on access ports facing untrusted hosts.",
                details={"window_seconds": self.cdp_flood_window},
            )
        return None

    # ---------------------------------------------------------------- DTP

    def _check_dtp(self, event):
        mac = event.get("src_mac")
        ts = event.get("timestamp", time.time())
        last = self._dtp_last_alert.get(mac, 0)
        if ts - last < 30:
            return None
        self._dtp_last_alert[mac] = ts

        return self._alert(
            category="DTP_SWITCH_SPOOFING",
            title="DTP Trunk Negotiation from Untrusted Host (Switch Spoofing)",
            severity=85,
            event=event,
            description=(
                f"Host {mac} sent a DTP frame attempting to negotiate a "
                f"trunk link. A legitimate end host has no reason to speak "
                f"DTP -- this is the setup step for VLAN hopping via switch "
                f"spoofing (as automated by Yersinia's DTP mode): if the "
                f"port complies, the attacker gains a trunk and can see "
                f"every VLAN."
            ),
            recommended_action=(
                "Set access ports to 'switchport mode access' and disable "
                "DTP ('switchport nonegotiate') so trunking can never be "
                "negotiated from an end host."
            ),
            details={},
        )

    # ---------------------------------------------------------------- VTP

    def _check_vtp(self, event):
        revision = event.get("revision")
        if revision is None:
            return None

        if self.vtp_last_revision is not None and revision > self.vtp_last_revision + 50:
            prev = self.vtp_last_revision
            self.vtp_last_revision = revision
            return self._alert(
                category="VTP_ATTACK",
                title="VTP Configuration Revision Attack",
                severity=85,
                event=event,
                description=(
                    f"VTP configuration revision jumped from {prev} to "
                    f"{revision}. An attacker who joins a VTP domain with a "
                    f"higher revision number than the real server can push "
                    f"an (often empty) VLAN database to every switch in the "
                    f"domain, wiping out VLANs network-wide -- a well-known "
                    f"VTP attack replicated by Yersinia's VTP mode."
                ),
                recommended_action=(
                    "Set switches to VTP transparent mode or use VTP "
                    "passwords/version 3 authentication; never trust "
                    "revision numbers from untrusted ports."
                ),
                details={"previous_revision": prev, "new_revision": revision},
            )

        self.vtp_last_revision = revision
        return None

    # -------------------------------------------------------------- VLAN

    def _check_vlan_hop(self, event):
        return self._alert(
            category="VLAN_DOUBLE_TAGGING",
            title="VLAN Hopping via 802.1Q Double Tagging",
            severity=95,
            event=event,
            description=(
                f"Frame from {event.get('src_mac')} carries two stacked "
                f"802.1Q tags (outer VLAN {event.get('outer_vlan')}, inner "
                f"VLAN {event.get('inner_vlan')}). A switch that strips "
                f"only the outer (native VLAN) tag will forward the inner-"
                f"tagged frame onto a VLAN the sender was never authorized "
                f"to reach -- a one-way VLAN hop that needs no trunk "
                f"negotiation at all."
            ),
            recommended_action=(
                "Never use VLAN 1 as the native VLAN on trunks, and tag the "
                "native VLAN explicitly so double-tagged frames are dropped."
            ),
            details={"outer_vlan": event.get("outer_vlan"), "inner_vlan": event.get("inner_vlan")},
        )

    # -------------------------------------------------------------- shared

    @staticmethod
    def _alert(category, title, severity, event, description, recommended_action, details):
        if severity >= 75:
            risk_level = "HIGH RISK / ATTACK"
        elif severity >= 45:
            risk_level = "MEDIUM RISK"
        elif severity >= 20:
            risk_level = "LOW RISK"
        else:
            risk_level = "BENIGN"

        return {
            "layer": "L2",
            "category": category,
            "attack_type": title,
            "threat_score": severity,
            "risk_level": risk_level,
            "timestamp": event.get("timestamp", time.time()),
            "src_mac": event.get("src_mac"),
            "dst_mac": event.get("dst_mac"),
            "src_ip": event.get("src_ip"),
            "dst_ip": event.get("dst_ip"),
            "description": description,
            "recommended_action": recommended_action,
            "details": details,
        }
