import time
import random
import threading
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    IP = TCP = UDP = ICMP = None

class PacketCapture:
    def __init__(self, state, mode="simulation", interface="eth0", filter_exp="tcp or udp or icmp"):
        self.state = state
        self.mode = mode
        self.interface = interface
        self.filter_exp = filter_exp
        self.packet_buffer = []
        self.flows = defaultdict(list)
        self.running = False
        self.thread = None

    def start(self):
        self.running = True
        if self.mode == "live" and SCAPY_AVAILABLE:
            self.thread = threading.Thread(target=self._live_capture)
            self.thread.daemon = True
            self.thread.start()
        elif self.mode == "simulation":
            self.thread = threading.Thread(target=self._simulation_loop)
            self.thread.daemon = True
            self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def _live_capture(self):
        if not SCAPY_AVAILABLE:
            print("[CAPTURE] Scapy not available. Switching to simulation.")
            self._simulation_loop()
            return

        def packet_handler(pkt):
            if not self.running:
                return
            if IP in pkt:
                packet_info = self._extract_packet_info(pkt)
                self._process_packet(packet_info)

        try:
            sniff(iface=self.interface, filter=self.filter_exp, prn=packet_handler, store=0)
        except Exception as e:
            print(f"Live capture error: {e}")
            self.state.config["capture_error"] = str(e)

    def _simulation_loop(self):
        """Generate synthetic traffic simulating VM environment"""
        scenarios = ["normal", "port_scan", "dos", "brute_force", "data_exfil", "slow_apt"]
        scenario_weights = [60, 8, 8, 8, 8, 8]

        victim_ips = ["192.168.100.10", "192.168.100.11"]
        attacker_ip = "192.168.100.20"
        external_ips = ["10.0.0.5", "172.16.0.8", "8.8.8.8"]

        while self.running:
            scenario = random.choices(scenarios, weights=scenario_weights)[0]
            packets = self._generate_scenario(scenario, attacker_ip, victim_ips, external_ips)

            for pkt in packets:
                if not self.running:
                    break
                self._process_packet(pkt)
                time.sleep(0.01)

            time.sleep(random.uniform(0.5, 2.0))

    def _generate_scenario(self, scenario, attacker, victims, externals):
        packets = []
        now = time.time()
        victim = random.choice(victims)
        external = random.choice(externals)

        if scenario == "normal":
            for _ in range(random.randint(3, 8)):
                proto = random.choice(["TCP", "UDP", "ICMP"])
                if proto == "TCP":
                    src_port = random.randint(40000, 60000)
                    dst_port = random.choice([80, 443, 22, 8080])
                    size = random.randint(60, 1500)
                    flags = random.choice(["SA", "PA", "FA", "S"])
                elif proto == "UDP":
                    src_port = random.randint(40000, 60000)
                    dst_port = random.choice([53, 123, 161])
                    size = random.randint(40, 800)
                    flags = ""
                else:
                    src_port = 0
                    dst_port = 0
                    size = random.randint(28, 100)
                    flags = ""

                packets.append({
                    "timestamp": now + random.uniform(0, 0.1),
                    "src_ip": random.choice([victim, external]),
                    "dst_ip": random.choice([victim, external]),
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "length": size,
                    "flags": flags,
                    "payload_entropy": random.uniform(0.1, 7.5)
                })

        elif scenario == "port_scan":
            for port in random.sample(range(1, 1000), random.randint(10, 50)):
                packets.append({
                    "timestamp": now + random.uniform(0, 0.5),
                    "src_ip": attacker,
                    "dst_ip": victim,
                    "src_port": random.randint(40000, 60000),
                    "dst_port": port,
                    "protocol": "TCP",
                    "length": 40,
                    "flags": "S",
                    "payload_entropy": 0.0
                })

        elif scenario == "dos":
            for _ in range(random.randint(100, 500)):
                packets.append({
                    "timestamp": now + random.uniform(0, 0.1),
                    "src_ip": attacker,
                    "dst_ip": victim,
                    "src_port": random.randint(40000, 60000),
                    "dst_port": 80,
                    "protocol": "TCP",
                    "length": random.randint(40, 60),
                    "flags": "S",
                    "payload_entropy": 0.0
                })

        elif scenario == "brute_force":
            for _ in range(random.randint(20, 60)):
                packets.append({
                    "timestamp": now + random.uniform(0, 2.0),
                    "src_ip": attacker,
                    "dst_ip": victim,
                    "src_port": random.randint(40000, 60000),
                    "dst_port": 22,
                    "protocol": "TCP",
                    "length": random.randint(60, 200),
                    "flags": "PA",
                    "payload_entropy": random.uniform(4.0, 6.0)
                })

        elif scenario == "data_exfil":
            for _ in range(random.randint(50, 150)):
                packets.append({
                    "timestamp": now + random.uniform(0, 1.0),
                    "src_ip": victim,
                    "dst_ip": external,
                    "src_port": random.randint(40000, 60000),
                    "dst_port": 443,
                    "protocol": "TCP",
                    "length": random.randint(1000, 1500),
                    "flags": "PA",
                    "payload_entropy": random.uniform(7.0, 7.9)
                })

        elif scenario == "slow_apt":
            for _ in range(random.randint(5, 15)):
                packets.append({
                    "timestamp": now + random.uniform(0, 5.0),
                    "src_ip": victim,
                    "dst_ip": external,
                    "src_port": random.randint(40000, 60000),
                    "dst_port": 53,
                    "protocol": "UDP",
                    "length": random.randint(40, 100),
                    "flags": "",
                    "payload_entropy": random.uniform(5.0, 7.5)
                })

        return packets

    def _extract_packet_info(self, pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto_num = pkt[IP].proto
            length = len(pkt)

            if proto_num == 6 and TCP in pkt:
                protocol = "TCP"
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                flags = str(pkt[TCP].flags)
            elif proto_num == 17 and UDP in pkt:
                protocol = "UDP"
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                flags = ""
            elif proto_num == 1 and ICMP in pkt:
                protocol = "ICMP"
                src_port = 0
                dst_port = 0
                flags = str(pkt[ICMP].type)
            else:
                protocol = "OTHER"
                src_port = 0
                dst_port = 0
                flags = ""

            payload = bytes(pkt[IP].payload) if hasattr(pkt[IP], 'payload') else b''
            entropy = self._calculate_entropy(payload)

            return {
                "timestamp": time.time(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "length": length,
                "flags": flags,
                "payload_entropy": entropy
            }
        return None

    def _calculate_entropy(self, data):
        if not data:
            return 0.0
        from math import log2
        prob = [float(data.count(c)) / len(data) for c in set(data)]
        entropy = -sum([p * log2(p) for p in prob if p > 0])
        return round(entropy, 2)

    def _process_packet(self, packet_info):
        if not packet_info:
            return
        self.state.stats["total_packets"] += 1
        self.state.stats["total_bytes"] += packet_info["length"]

        flow_key = (
            packet_info["src_ip"], packet_info["dst_ip"],
            packet_info["src_port"], packet_info["dst_port"],
            packet_info["protocol"]
        )
        self.flows[flow_key].append(packet_info)

        if len(self.flows) > 1000:
            self._flush_old_flows()

    def _flush_old_flows(self):
        now = time.time()
        to_remove = []
        for key, packets in self.flows.items():
            if packets and now - packets[-1]["timestamp"] > 60:
                to_remove.append(key)
        for key in to_remove:
            del self.flows[key]

    def get_current_flows(self):
        flows = []
        for key, packets in list(self.flows.items()):
            if len(packets) >= 2:
                src_ip, dst_ip, src_port, dst_port, protocol = key
                flows.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "packets": packets
                })
        return flows

    def clear_processed_flows(self, flow_keys):
        for key in flow_keys:
            if key in self.flows:
                del self.flows[key]
