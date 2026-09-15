import time
import random
import threading
from collections import defaultdict

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    IP = IPv6 = TCP = UDP = ICMP = None

class PacketCapture:
    def __init__(self, state, mode="simulation", interface="eth0", filter_exp="tcp or udp or icmp or ip6",
                 idle_timeout=2.0):
        self.state = state
        self.mode = mode
        self.interface = interface
        self.filter_exp = filter_exp
        # How long a flow with only a single packet is held before being
        # finalized/reported anyway. Without this, a flow only ever left
        # the buffer once it had >=2 packets - which silently discarded
        # every single-packet flow (a lone SYN to a port that never
        # replied, a single DNS query, one ICMP ping...) once it aged out
        # via _flush_old_flows(). That's exactly the traffic shape of a
        # port scan (many single-SYN flows to many ports) and low-and-slow
        # beaconing, so those attack classes were reaching the ML/DPI
        # pipeline at a ~0% rate. Now: a flow is "ready" either once it
        # has >=2 packets (fast path, no reason to wait) or once it has
        # been idle for `idle_timeout` seconds (so a genuinely one-shot
        # packet still gets scored, just with a small, bounded delay).
        self.idle_timeout = idle_timeout
        self.packet_buffer = []
        self.flows = defaultdict(list)
        # `self.flows` is written by the capture thread (_process_packet,
        # spawned in start()) and read/deleted by the asyncio event loop
        # thread (get_current_flows()/clear_processed_flows(), called from
        # main.py's processing_loop()) - two genuinely different OS threads
        # touching the same plain dict with no synchronization. In
        # particular, inserting a brand-new flow key (defaultdict's
        # implicit __missing__) while the other thread is mid-iteration
        # over self.flows.items() can raise "RuntimeError: dictionary
        # changed size during iteration". That's most likely to fire right
        # after switch_mode() spins up a fresh capture thread that starts
        # inserting many new flow keys in a burst, which lands
        # processing_loop() in its broad except-and-retry branch every
        # single cycle - so no new flow/alert ever gets appended to
        # state.flows, and the dashboard's gauge/"Threats Detected" appear
        # frozen exactly when switching capture modes. This lock (RLock so
        # _flush_old_flows can be called from the already-locked
        # _process_packet without deadlocking) closes that race. L2Capture
        # already had an equivalent lock for its own event queue; this
        # brings PacketCapture in line with it.
        self.lock = threading.RLock()
        self.running = False
        self.thread = None
        self.last_error = None

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

    def test_live_capture(self, interface=None, timeout=0.5):
        """Synchronously verify that live capture would actually work on
        this interface, before committing to it. This is exactly the same
        sniff() call _live_capture() makes, just bounded by a short
        timeout - so it surfaces the real permission/interface errors
        (PermissionError for missing CAP_NET_RAW, OSError for an interface
        that doesn't exist, etc.) synchronously, instead of the caller
        finding out later from a background thread that silently died or
        fell back to simulation while a UI kept showing "Live" as active.

        Returns (ok: bool, error: Optional[str]).
        """
        if not SCAPY_AVAILABLE:
            return False, "scapy is not installed in this environment."

        target_iface = interface or self.interface
        try:
            sniff(iface=target_iface, filter=self.filter_exp, timeout=timeout, count=1, store=0)
            return True, None
        except PermissionError:
            return False, (
                f"Permission denied opening a raw socket on '{target_iface}'. "
                "Live capture needs root, or CAP_NET_RAW/CAP_NET_ADMIN "
                "(e.g. `docker run --cap-add=NET_RAW --cap-add=NET_ADMIN ...`)."
            )
        except OSError as e:
            return False, f"Could not capture on interface '{target_iface}': {e}"
        except Exception as e:
            return False, f"Live capture check failed: {e}"

    def switch_mode(self, mode, interface=None):
        """Actually switch capture mode at runtime, with real verification.

        Unlike a UI toggle that just relabels itself, this:
          1. Pre-flight-checks live mode before tearing anything down, so a
             failed switch leaves the current (working) capture untouched.
          2. Cleanly stops the old capture thread before starting a new one.
          3. Returns a real (ok, error) result the caller must surface,
             instead of assuming success.
        """
        if mode not in ("simulation", "live"):
            return False, f"Unknown capture mode '{mode}'."

        if mode == "live":
            ok, err = self.test_live_capture(interface)
            if not ok:
                self.last_error = err
                return False, err

        self.stop()
        self.mode = mode
        if interface:
            self.interface = interface
        self.last_error = None
        # Clear whatever was left mid-flight in the old mode. Without this,
        # the first few seconds after a switch mix leftover
        # simulation-mode (or live-mode) flows into the new mode's
        # processing, which looks like the gauge/alerts "aren't syncing"
        # with the mode you just switched to.
        with self.lock:
            self.flows.clear()
        self.start()
        return True, None

    def _live_capture(self):
        if not SCAPY_AVAILABLE:
            print("[CAPTURE] Scapy not available. Switching to simulation.")
            self._simulation_loop()
            return

        def packet_handler(pkt):
            if not self.running:
                return
            # Was `if IP in pkt` only - IPv6 traffic was silently invisible
            # to live capture entirely (no error, just never handed to
            # _extract_packet_info). IPv6 is real production traffic, not
            # an edge case, so an attacker (or just normal dual-stack
            # hosts) using it would leave zero trace here.
            if IP in pkt or (IPv6 is not None and IPv6 in pkt):
                packet_info = self._extract_packet_info(pkt)
                self._process_packet(packet_info)

        try:
            sniff(iface=self.interface, filter=self.filter_exp, prn=packet_handler, store=0)
        except Exception as e:
            print(f"Live capture error: {e}")
            self.last_error = str(e)
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

    # ---- realistic payload builders (simulation mode) -------------------
    # These exist so DPIEngine has actual bytes to parse in simulation
    # mode too, not just in live capture. Without this, running Aegis-AI
    # without root/raw-socket access would never exercise the real DPI
    # code path at all.

    _SIM_HOSTS = ["example.com", "api.example.com", "cdn.example.net", "updates.example.org"]
    _SIM_URIS = ["/", "/index.html", "/api/v1/status", "/login", "/assets/app.js"]
    _SIM_SUSPICIOUS_URIS = ["/login?id=1' UNION SELECT * FROM users--", "/../../etc/passwd", "/search?q=<script>alert(1)</script>"]

    def _build_http_payload(self, suspicious=False):
        host = random.choice(self._SIM_HOSTS)
        uri = random.choice(self._SIM_SUSPICIOUS_URIS) if suspicious else random.choice(self._SIM_URIS)
        req = (
            f"GET {uri} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (X11; Linux x86_64) AegisSim/1.0\r\n"
            f"Accept: */*\r\n\r\n"
        )
        return req.encode("latin-1")

    def _build_dns_payload(self, domain=None, tunneling=False):
        import struct as _struct
        if tunneling:
            # Overly long subdomain, a classic DNS-tunneling tell.
            domain = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9.tunnel.example.net"
        elif domain is None:
            domain = random.choice(self._SIM_HOSTS)

        txid = random.randint(0, 0xFFFF)
        header = _struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)  # standard query, 1 question
        qname = b""
        for label in domain.split("."):
            qname += bytes([len(label)]) + label.encode("latin-1")
        qname += b"\x00"
        question = qname + _struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
        return header + question

    def _build_tls_client_hello(self, sni=None):
        import struct as _struct
        if sni is None:
            sni = random.choice(self._SIM_HOSTS)
        sni_bytes = sni.encode("latin-1")

        server_name = _struct.pack(">H", len(sni_bytes)) + b"\x00" + _struct.pack(">H", len(sni_bytes)) + sni_bytes
        # server_name extension: type 0, length, server_name_list
        ext_sni = _struct.pack(">HH", 0x0000, len(server_name)) + server_name
        extensions = ext_sni
        exts_block = _struct.pack(">H", len(extensions)) + extensions

        session_id = b"\x00"
        cipher_suites = _struct.pack(">H", 2) + b"\x13\x01"  # one TLS 1.3 cipher
        compression = b"\x01\x00"
        client_version = b"\x03\x03"
        random_bytes = bytes(32)

        body = client_version + random_bytes + session_id + cipher_suites + compression + exts_block
        handshake = bytes([0x01]) + _struct.pack(">I", len(body))[1:] + body  # type=ClientHello, 3-byte length
        record = bytes([0x16]) + b"\x03\x01" + _struct.pack(">H", len(handshake)) + handshake
        return record

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

                payload = b""
                if proto == "TCP" and dst_port == 80:
                    payload = self._build_http_payload()
                elif proto == "TCP" and dst_port == 443:
                    payload = self._build_tls_client_hello()
                elif proto == "UDP" and dst_port == 53:
                    payload = self._build_dns_payload()

                packets.append({
                    "timestamp": now + random.uniform(0, 0.1),
                    "src_ip": random.choice([victim, external]),
                    "dst_ip": random.choice([victim, external]),
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": proto,
                    "length": size if not payload else max(size, len(payload)),
                    "flags": flags,
                    "payload_entropy": self._calculate_entropy(payload) if payload else random.uniform(0.1, 7.5),
                    "payload": payload,
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
            tls_hello = self._build_tls_client_hello(sni="upload-relay.example.net")
            for i in range(random.randint(50, 150)):
                # First packet of the flow looks like a real TLS handshake
                # (so DPI can report the SNI); the bulk transfer packets
                # that follow are opaque/high-entropy, as real encrypted
                # exfil traffic would be.
                payload = tls_hello if i == 0 else bytes(random.getrandbits(8) for _ in range(64))
                packets.append({
                    "timestamp": now + random.uniform(0, 1.0),
                    "src_ip": victim,
                    "dst_ip": external,
                    "src_port": random.randint(40000, 60000),
                    "dst_port": 443,
                    "protocol": "TCP",
                    "length": random.randint(1000, 1500),
                    "flags": "PA",
                    "payload_entropy": random.uniform(7.0, 7.9) if i > 0 else self._calculate_entropy(payload),
                    "payload": payload,
                })

        elif scenario == "slow_apt":
            for _ in range(random.randint(5, 15)):
                # Slow, low-and-slow APT beaconing modeled as DNS
                # tunneling: overlong subdomains carrying exfiltrated data
                # encoded into the query name, which DPI flags via
                # POSSIBLE_DNS_TUNNELING.
                payload = self._build_dns_payload(tunneling=True)
                packets.append({
                    "timestamp": now + random.uniform(0, 5.0),
                    "src_ip": victim,
                    "dst_ip": external,
                    "src_port": random.randint(40000, 60000),
                    "dst_port": 53,
                    "protocol": "UDP",
                    "length": max(40, len(payload)),
                    "flags": "",
                    "payload_entropy": self._calculate_entropy(payload),
                    "payload": payload,
                })

        return packets

    def _extract_packet_info(self, pkt):
        ip_layer = None
        is_v6 = False
        if IP in pkt:
            ip_layer = pkt[IP]
        elif IPv6 is not None and IPv6 in pkt:
            ip_layer = pkt[IPv6]
            is_v6 = True

        if ip_layer is not None:
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            # IPv4's `proto` and IPv6's `nh` (next header) are the same
            # IANA protocol-number field, just named differently by scapy.
            proto_num = ip_layer.nh if is_v6 else ip_layer.proto
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
            elif proto_num == 58:
                # ICMPv6 - scapy splits this across several classes
                # (echo request/reply, ND, RA...) rather than one generic
                # ICMPv6 class, so we don't try to pull a sub-type flag
                # the way ICMPv4 does; still reported distinctly rather
                # than falling into the generic "OTHER" bucket.
                protocol = "ICMPv6"
                src_port = 0
                dst_port = 0
                flags = ""
            else:
                protocol = "OTHER"
                src_port = 0
                dst_port = 0
                flags = ""

            payload = bytes(ip_layer.payload) if hasattr(ip_layer, 'payload') else b''
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
                "payload_entropy": entropy,
                # Raw application-layer bytes, needed by DPIEngine to do real
                # payload inspection instead of guessing the protocol from
                # the port number. Previously computed for entropy and then
                # discarded.
                "payload": payload,
            }
        return None

    def _calculate_entropy(self, data):
        if not data:
            return 0.0
        from math import log2
        prob = [float(data.count(c)) / len(data) for c in set(data)]
        entropy = -sum([p * log2(p) for p in prob if p > 0])
        return round(entropy, 2)

    @staticmethod
    def _canonical_flow_key(src_ip, dst_ip, src_port, dst_port, protocol):
        """Direction-independent bucket key so a request and its response
        land in the *same* flow instead of two separate ones.

        The previous key was literally (src_ip, dst_ip, src_port, dst_port,
        protocol) taken straight from each packet. A response packet has
        src/dst swapped and (for TCP/UDP) different port roles, so it can
        never match the request's key - every flow was structurally
        one-directional. That silently zeroed out every "backward"
        feature (total_bwd_packets, bwd_packet_length_*, down_up_ratio...)
        for every flow, live or simulated, which is a real mismatch
        against the bidirectional CICFlowMeter-style features the shipped
        model was actually trained on.

        Sorting the two (ip, port) endpoints gives a stable bucket for
        both directions while leaving the original per-packet src/dst
        untouched, so direction can still be recovered later from
        whichever packet arrived first.
        """
        a = (src_ip, src_port)
        b = (dst_ip, dst_port)
        if a <= b:
            return (a[0], a[1], b[0], b[1], protocol)
        return (b[0], b[1], a[0], a[1], protocol)

    def _process_packet(self, packet_info):
        if not packet_info:
            return
        self.state.stats["total_packets"] += 1
        self.state.stats["total_bytes"] += packet_info["length"]

        flow_key = self._canonical_flow_key(
            packet_info["src_ip"], packet_info["dst_ip"],
            packet_info["src_port"], packet_info["dst_port"],
            packet_info["protocol"]
        )
        with self.lock:
            self.flows[flow_key].append(packet_info)
            flow_count = len(self.flows)

        if flow_count > 1000:
            self._flush_old_flows()

    def _flush_old_flows(self):
        now = time.time()
        with self.lock:
            to_remove = [
                key for key, packets in self.flows.items()
                if packets and now - packets[-1]["timestamp"] > 60
            ]
            for key in to_remove:
                del self.flows[key]

    def get_current_flows(self):
        """A flow is returned once it's "ready": either it already has
        >=2 packets (no reason to wait), or it's been idle for
        `idle_timeout` seconds (so a genuine one-packet flow - a lone
        scan probe, a single DNS query - still gets scored instead of
        silently expiring in _flush_old_flows() unseen).

        Direction (src_ip/dst_ip/src_port/dst_port reported on the flow)
        is taken from whichever packet arrived first, since `self.flows`
        is now keyed by a canonical (direction-independent) tuple -
        see _canonical_flow_key. That first packet is treated as the
        flow's "forward" direction, matching the convention
        FeatureExtractor already assumes (fwd = packets whose src_ip
        matches flow['src_ip']).
        """
        now = time.time()
        with self.lock:
            ready = [
                (key, list(packets)) for key, packets in self.flows.items()
                if packets and (len(packets) >= 2 or now - packets[-1]["timestamp"] >= self.idle_timeout)
            ]

        flows = []
        for key, packets in ready:
            first = packets[0]
            flows.append({
                "src_ip": first["src_ip"],
                "dst_ip": first["dst_ip"],
                "src_port": first["src_port"],
                "dst_port": first["dst_port"],
                "protocol": first["protocol"],
                "packets": packets,
                # Internal bucket key, needed by clear_processed_flows()
                # since self.flows is keyed canonically now, not by the
                # literal (src,dst) pair reported above. Not meant for
                # consumers outside this module/main.py's processing loop.
                "_capture_key": key,
            })
        return flows

    def clear_processed_flows(self, flow_keys):
        with self.lock:
            for key in flow_keys:
                if key in self.flows:
                    del self.flows[key]
