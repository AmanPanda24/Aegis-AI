"""
Layer 2 capture module.

Everything in packet_capture.py only sees IP/TCP/UDP/ICMP. This module
captures (or simulates) the non-IP frame types that L2 attack tools like
Yersinia operate on: ARP, STP BPDUs, Cisco CDP/DTP/VTP (SNAP-encapsulated),
and 802.1Q VLAN tags -- including illegally double-stacked tags used for
VLAN-hopping.

Each captured/simulated frame is normalized into a small "l2_event" dict
and handed to L2Analyzer (see src/processing/l2_analyzer.py) for stateful
detection. This module does not decide what's malicious; it only parses
and reports what's on the wire.
"""

import time
import random
import threading
from collections import deque

try:
    from scapy.all import sniff, Ether, ARP, Dot1Q
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    Ether = ARP = Dot1Q = None

STP_MULTICAST = "01:80:c2:00:00:00"
CISCO_MULTICAST = "01:00:0c:cc:cc:cc"

# SNAP protocol IDs used inside Cisco's 01:00:0c:cc:cc:cc multicast frames
CISCO_SNAP_PROTO = {
    0x2000: "CDP",
    0x2003: "VTP",
    0x2004: "DTP",
    0x2005: "PAGP",
    0x0111: "UDLD",
}


class L2Capture:
    def __init__(self, state, mode="simulation", interface="eth0"):
        self.state = state
        self.mode = mode
        self.interface = interface
        self.events = deque(maxlen=5000)
        self.running = False
        self.thread = None
        self._lock = threading.Lock()

    def start(self):
        self.running = True
        if self.mode == "live" and SCAPY_AVAILABLE:
            self.thread = threading.Thread(target=self._live_capture, daemon=True)
        else:
            self.thread = threading.Thread(target=self._simulation_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    # ---------------------------------------------------------------- live

    def _live_capture(self):
        if not SCAPY_AVAILABLE:
            print("[L2-CAPTURE] Scapy not available. Switching to simulation.")
            self._simulation_loop()
            return

        def handler(pkt):
            if not self.running:
                return
            event = self._parse_frame(pkt)
            if event:
                self._push(event)

        try:
            # No BPF filter here on purpose: BPF can't easily select
            # "ARP or STP or Cisco-SNAP or double-tagged 802.1Q" in one
            # expression, and these are all low-volume control-plane
            # frame types, so sniffing all L2 traffic on the interface
            # is cheap.
            sniff(iface=self.interface, prn=handler, store=0)
        except Exception as e:
            print(f"L2 live capture error: {e}")
            self.state.config["l2_capture_error"] = str(e)

    def _parse_frame(self, pkt):
        if Ether not in pkt:
            return None
        eth = pkt[Ether]
        now = time.time()

        # Double-tagged 802.1Q (VLAN hopping / QinQ abuse on an access port)
        if Dot1Q in pkt:
            tags = []
            layer = pkt
            while Dot1Q in layer:
                tags.append(layer[Dot1Q].vlan)
                layer = layer[Dot1Q].payload
            if len(tags) >= 2:
                return {
                    "type": "VLAN_DOUBLE_TAG", "timestamp": now,
                    "src_mac": eth.src, "dst_mac": eth.dst,
                    "outer_vlan": tags[0], "inner_vlan": tags[1],
                }

        if ARP in pkt:
            arp = pkt[ARP]
            return {
                "type": "ARP", "timestamp": now,
                "src_mac": eth.src, "dst_mac": eth.dst,
                "op": "reply" if arp.op == 2 else "request",
                "src_ip": arp.psrc, "src_hw": arp.hwsrc,
                "dst_ip": arp.pdst, "dst_hw": arp.hwdst,
            }

        if eth.dst.lower() == STP_MULTICAST:
            raw = bytes(pkt)
            bpdu = self._parse_bpdu(raw)
            if bpdu:
                bpdu.update({"type": "STP", "timestamp": now,
                             "src_mac": eth.src, "dst_mac": eth.dst})
                return bpdu

        if eth.dst.lower() == CISCO_MULTICAST:
            raw = bytes(pkt)
            proto = self._parse_snap_proto(raw)
            if proto:
                return {
                    "type": proto, "timestamp": now,
                    "src_mac": eth.src, "dst_mac": eth.dst,
                }

        return None

    @staticmethod
    def _parse_bpdu(raw):
        """Best-effort manual BPDU parse (LLC/SNAP + 802.1D BPDU body)."""
        try:
            # Ethernet(14) + LLC(3, DSAP/SSAP/CTRL=42/42/03) -> BPDU body
            idx = 14 + 3
            if len(raw) < idx + 35:
                return None
            body = raw[idx:]
            flags = body[4]
            root_id = body[5:13].hex()
            root_cost = int.from_bytes(body[13:17], "big")
            bridge_id = body[17:25].hex()
            topology_change = bool(flags & 0x01)
            topology_change_ack = bool(flags & 0x80)
            return {
                "root_id": root_id, "root_cost": root_cost,
                "bridge_id": bridge_id,
                "topology_change": topology_change,
                "topology_change_ack": topology_change_ack,
            }
        except Exception:
            return None

    @staticmethod
    def _parse_snap_proto(raw):
        try:
            # Ethernet(14) + LLC(3) + SNAP OUI(3) + SNAP PID(2)
            idx = 14 + 3 + 3
            if len(raw) < idx + 2:
                return None
            pid = int.from_bytes(raw[idx:idx + 2], "big")
            return CISCO_SNAP_PROTO.get(pid)
        except Exception:
            return None

    # --------------------------------------------------------- simulation

    def _simulation_loop(self):
        scenarios = [
            "normal_l2", "arp_spoof", "mac_flood", "stp_attack",
            "cdp_flood", "dtp_negotiation", "vtp_attack", "vlan_double_tag",
        ]
        weights = [55, 8, 8, 8, 7, 6, 4, 4]

        legit_ip_mac = {
            "192.168.100.1": "aa:bb:cc:00:00:01",   # gateway
            "192.168.100.10": "aa:bb:cc:00:00:10",  # victim/host
            "192.168.100.11": "aa:bb:cc:00:00:11",
        }
        attacker_mac = "de:ad:be:ef:00:66"
        legit_root_bridge = "8000." + "aa:bb:cc:00:00:01".replace(":", "")

        while self.running:
            scenario = random.choices(scenarios, weights=weights)[0]
            for event in self._gen_scenario(scenario, legit_ip_mac, attacker_mac, legit_root_bridge):
                if not self.running:
                    break
                self._push(event)
                time.sleep(0.02)
            time.sleep(random.uniform(0.8, 2.2))

    def _gen_scenario(self, scenario, legit_ip_mac, attacker_mac, legit_root_bridge):
        now = time.time()
        events = []

        if scenario == "normal_l2":
            ip, mac = random.choice(list(legit_ip_mac.items()))
            events.append({
                "type": "ARP", "timestamp": now, "src_mac": mac,
                "dst_mac": "ff:ff:ff:ff:ff:ff", "op": "request",
                "src_ip": ip, "src_hw": mac, "dst_ip": "192.168.100.1", "dst_hw": "00:00:00:00:00:00",
            })
            # Legitimate switch's periodic STP hello, so the analyzer has a
            # real baseline root bridge to compare forged BPDUs against.
            events.append({
                "type": "STP", "timestamp": now, "src_mac": legit_ip_mac["192.168.100.1"],
                "dst_mac": STP_MULTICAST, "root_id": legit_root_bridge, "root_cost": 4,
                "bridge_id": legit_root_bridge,
                "topology_change": False, "topology_change_ack": False,
            })

        elif scenario == "arp_spoof":
            # Attacker sends gratuitous ARP replies claiming to be the
            # gateway, poisoning victims' ARP caches (classic MITM setup).
            gateway_ip = "192.168.100.1"
            for _ in range(random.randint(4, 10)):
                events.append({
                    "type": "ARP", "timestamp": now + random.uniform(0, 0.5),
                    "src_mac": attacker_mac, "dst_mac": "ff:ff:ff:ff:ff:ff",
                    "op": "reply", "src_ip": gateway_ip, "src_hw": attacker_mac,
                    "dst_ip": gateway_ip, "dst_hw": "00:00:00:00:00:00",
                })

        elif scenario == "mac_flood":
            # Flood random source MACs to overflow a switch's CAM table.
            for _ in range(random.randint(60, 150)):
                fake_mac = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
                events.append({
                    "type": "ARP", "timestamp": now + random.uniform(0, 1.0),
                    "src_mac": fake_mac, "dst_mac": "ff:ff:ff:ff:ff:ff",
                    "op": "request", "src_ip": f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                    "src_hw": fake_mac, "dst_ip": "0.0.0.0", "dst_hw": "00:00:00:00:00:00",
                })

        elif scenario == "stp_attack":
            # Attacker announces itself as root with a superior (lower) ID.
            fake_root = "0001." + attacker_mac.replace(":", "")
            for _ in range(random.randint(3, 8)):
                events.append({
                    "type": "STP", "timestamp": now + random.uniform(0, 0.5),
                    "src_mac": attacker_mac, "dst_mac": STP_MULTICAST,
                    "root_id": fake_root, "root_cost": 0,
                    "bridge_id": fake_root,
                    "topology_change": True, "topology_change_ack": False,
                })

        elif scenario == "cdp_flood":
            for _ in range(random.randint(25, 60)):
                events.append({
                    "type": "CDP", "timestamp": now + random.uniform(0, 1.0),
                    "src_mac": attacker_mac, "dst_mac": CISCO_MULTICAST,
                })

        elif scenario == "dtp_negotiation":
            # An end host sending DTP is trying to talk a switch port into
            # trunking (switch spoofing) so it can see every VLAN.
            for _ in range(random.randint(2, 5)):
                events.append({
                    "type": "DTP", "timestamp": now + random.uniform(0, 0.5),
                    "src_mac": attacker_mac, "dst_mac": CISCO_MULTICAST,
                })

        elif scenario == "vtp_attack":
            events.append({
                "type": "VTP", "timestamp": now,
                "src_mac": attacker_mac, "dst_mac": CISCO_MULTICAST,
                "revision": random.randint(9000, 9999),
            })

        elif scenario == "vlan_double_tag":
            events.append({
                "type": "VLAN_DOUBLE_TAG", "timestamp": now,
                "src_mac": attacker_mac, "dst_mac": "ff:ff:ff:ff:ff:ff",
                "outer_vlan": 1, "inner_vlan": random.choice([10, 20, 99]),
            })

        return events

    # --------------------------------------------------------------- misc

    def _push(self, event):
        with self._lock:
            self.events.append(event)

    def drain_events(self):
        with self._lock:
            events = list(self.events)
            self.events.clear()
        return events
