"""
Deep Packet Inspection engine.

The original prototype version of this file didn't inspect payloads at
all - it guessed the application protocol purely from the destination
port number and left every DPI-derived field (http_method, http_host,
tls_sni, dns_query, user_agent...) hardcoded to None. That's port-based
service guessing, not DPI.

This version actually parses the bytes each packet carries:
  - HTTP: request line + Host / User-Agent headers from a plaintext
    request (works because HTTP requests are plaintext).
  - DNS: QNAME/QTYPE from the raw DNS message on port 53.
  - TLS: server_name extension (SNI) out of a ClientHello, without
    needing to decrypt anything - SNI is sent in the clear during the
    TLS handshake.

For this to have anything to inspect, packets need a raw `payload` (bytes)
field. `packet_capture.py` now attaches that for both live capture (already
had the bytes, they were just discarded after computing entropy) and
simulation mode (synthetic but structurally real payload bytes, so this
code path is exercised even without live traffic).
"""

import struct
from typing import Dict, Any, Optional

HTTP_METHODS = (b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH", b"CONNECT", b"TRACE")

DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"}

TLS_HANDSHAKE_CONTENT_TYPE = 0x16
TLS_CLIENT_HELLO = 0x01
SNI_EXTENSION_TYPE = 0x0000


class DPIEngine:
    """Deep Packet Inspection Engine."""

    def inspect(self, flow: Dict[str, Any], features: Dict[str, Any]) -> Dict[str, Any]:
        """Perform DPI on a flow and extract application-layer metadata."""
        dpi_result: Dict[str, Any] = {
            "application_protocol": "UNKNOWN",
            "http_method": None,
            "http_host": None,
            "http_uri": None,
            "http_user_agent": None,
            "dns_query": None,
            "dns_query_type": None,
            "tls_version": None,
            "tls_sni": None,
            "detected_os": None,
            "anomaly_indicators": [],
        }

        packets = flow.get("packets", [])
        dst_port = flow.get("dst_port", 0)
        src_port = flow.get("src_port", 0)

        # Fall back to port-based labeling only as a last resort, when no
        # payload bytes are available to actually inspect (e.g. ICMP, or a
        # capture path that hasn't attached payloads).
        dpi_result["application_protocol"] = self._guess_protocol_by_port(dst_port, src_port)

        for pkt in packets:
            payload = pkt.get("payload")
            if not payload:
                continue

            http_info = self._parse_http(payload)
            if http_info:
                dpi_result["application_protocol"] = "HTTP"
                dpi_result.update({k: v for k, v in http_info.items() if v is not None})

            if dst_port == 53 or src_port == 53:
                dns_info = self._parse_dns(payload)
                if dns_info:
                    dpi_result["application_protocol"] = "DNS"
                    dpi_result.update(dns_info)

            tls_info = self._parse_tls_client_hello(payload)
            if tls_info:
                dpi_result["application_protocol"] = "TLS"
                dpi_result.update(tls_info)

        dpi_result["anomaly_indicators"] = self._flag_anomalies(features, dpi_result)
        return dpi_result

    # ------------------------------------------------------------ helpers

    def _guess_protocol_by_port(self, dst_port: int, src_port: int) -> str:
        port_map = {80: "HTTP", 443: "HTTPS", 53: "DNS", 22: "SSH", 21: "FTP", 25: "SMTP"}
        return port_map.get(dst_port) or port_map.get(src_port) or "UNKNOWN"

    def _parse_http(self, payload: bytes) -> Optional[Dict[str, Any]]:
        if not payload.startswith(HTTP_METHODS):
            return None
        try:
            text = payload.split(b"\r\n\r\n", 1)[0].decode("latin-1", errors="ignore")
            lines = text.split("\r\n")

            # A well-formed request line is "METHOD URI HTTP/x.y" with no
            # spaces in URI or version. A malicious/malformed URI (e.g. a
            # SQLi payload with embedded spaces: "/x?id=1' UNION SELECT...")
            # breaks a naive `.split(" ")`, silently truncating the URI at
            # the first space and losing exactly the content that makes it
            # suspicious. Split from both ends instead: method is
            # everything before the first space, HTTP version is everything
            # after the last space, and the URI is whatever's left between
            # them - spaces and all.
            request_line = lines[0]
            method, _, rest = request_line.partition(" ")
            uri, _, _http_version = rest.rpartition(" ")
            uri = uri or rest or None
            method = method or None

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()

            return {
                "http_method": method,
                "http_uri": uri,
                "http_host": headers.get("host"),
                "http_user_agent": headers.get("user-agent"),
            }
        except Exception:
            return None

    def _parse_dns(self, payload: bytes) -> Optional[Dict[str, Any]]:
        # DNS header is 12 bytes; QR bit (top bit of byte 2) must be 0 for a query.
        if len(payload) < 13:
            return None
        try:
            flags = payload[2]
            is_query = (flags & 0x80) == 0
            if not is_query:
                return None

            qdcount = struct.unpack(">H", payload[4:6])[0]
            if qdcount < 1:
                return None

            offset = 12
            labels = []
            while offset < len(payload):
                length = payload[offset]
                if length == 0:
                    offset += 1
                    break
                offset += 1
                labels.append(payload[offset:offset + length].decode("latin-1", errors="ignore"))
                offset += length

            if offset + 2 > len(payload):
                return None
            qtype = struct.unpack(">H", payload[offset:offset + 2])[0]

            return {
                "dns_query": ".".join(labels) if labels else None,
                "dns_query_type": DNS_QTYPES.get(qtype, str(qtype)),
            }
        except Exception:
            return None

    def _parse_tls_client_hello(self, payload: bytes) -> Optional[Dict[str, Any]]:
        # TLS record: [content_type(1)][version(2)][length(2)][handshake...]
        if len(payload) < 6 or payload[0] != TLS_HANDSHAKE_CONTENT_TYPE:
            return None
        try:
            handshake_type = payload[5]
            if handshake_type != TLS_CLIENT_HELLO:
                return None

            tls_version = f"{payload[1]}.{payload[2]}"

            pos = 5 + 4  # skip handshake header (type[1] + length[3])
            pos += 2 + 32  # client_version(2) + random(32)

            session_id_len = payload[pos]
            pos += 1 + session_id_len

            cipher_suites_len = struct.unpack(">H", payload[pos:pos + 2])[0]
            pos += 2 + cipher_suites_len

            compression_len = payload[pos]
            pos += 1 + compression_len

            if pos + 2 > len(payload):
                return {"tls_version": tls_version, "tls_sni": None}

            extensions_len = struct.unpack(">H", payload[pos:pos + 2])[0]
            pos += 2
            extensions_end = pos + extensions_len

            sni = None
            while pos + 4 <= extensions_end and pos + 4 <= len(payload):
                ext_type = struct.unpack(">H", payload[pos:pos + 2])[0]
                ext_len = struct.unpack(">H", payload[pos + 2:pos + 4])[0]
                ext_data_start = pos + 4

                if ext_type == SNI_EXTENSION_TYPE:
                    # server_name_list: [list_len(2)][type(1)][name_len(2)][name]
                    sp = ext_data_start + 2 + 1
                    if sp + 2 <= len(payload):
                        name_len = struct.unpack(">H", payload[sp:sp + 2])[0]
                        name_start = sp + 2
                        sni = payload[name_start:name_start + name_len].decode("latin-1", errors="ignore")
                    break

                pos = ext_data_start + ext_len

            return {"tls_version": tls_version, "tls_sni": sni}
        except Exception:
            return None

    def _flag_anomalies(self, features: Dict[str, Any], dpi_result: Dict[str, Any]) -> list:
        indicators = []

        if features.get("syn_flag_count", 0) > 50 and features.get("ack_flag_count", 0) < features.get("syn_flag_count", 0) * 0.5:
            indicators.append("SYN_FLOOD_PATTERN")

        if features.get("flow_packets_per_sec", 0) > 1000:
            indicators.append("HIGH_PACKET_RATE")

        if features.get("payload_entropy_mean", 0) > 7.5:
            indicators.append("HIGH_ENTROPY_PAYLOAD")

        if features.get("down_up_ratio", 0) > 10:
            indicators.append("ASYMMETRIC_FLOW")

        if features.get("total_fwd_packets", 0) > 10 and features.get("flow_duration", 0) < 1:
            # NOTE: despite the name, this is a rapid-burst-to-one-
            # destination heuristic (a lot of packets in one 5-tuple flow,
            # fast), not real port-scan detection - a scan is defined by
            # one source touching MANY DIFFERENT ports/hosts, which is a
            # cross-flow property no single-flow check can see. Real
            # cross-flow scan/host-sweep detection lives in
            # src/processing/scan_detector.py. Kept here as a secondary,
            # cheap indicator (catches e.g. a rapid burst of SYNs to one
            # port), not the primary scan detector.
            indicators.append("PORT_SCAN_PATTERN")

        # DPI-informed indicators that a pure port-guess could never produce.
        if dpi_result.get("http_uri") and any(
            token in dpi_result["http_uri"].lower() for token in ("union select", "../", "<script", "%00")
        ):
            indicators.append("SUSPICIOUS_HTTP_URI")

        if dpi_result.get("dns_query") and len(dpi_result["dns_query"]) > 60:
            indicators.append("POSSIBLE_DNS_TUNNELING")

        return indicators
