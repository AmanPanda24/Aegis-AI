import struct

from src.processing.dpi_engine import DPIEngine


def _flow(packets, dst_port=80, src_port=40000, protocol="TCP"):
    return {
        "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
        "src_port": src_port, "dst_port": dst_port, "protocol": protocol,
        "packets": packets,
    }


def _pkt(payload):
    return {"payload": payload}


def test_http_request_parsed_from_raw_payload():
    payload = (
        b"GET /login?user=admin HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: curl/8.0\r\n\r\n"
    )
    dpi = DPIEngine()
    result = dpi.inspect(_flow([_pkt(payload)], dst_port=80), features={})

    assert result["application_protocol"] == "HTTP"
    assert result["http_method"] == "GET"
    assert result["http_host"] == "example.com"
    assert result["http_user_agent"] == "curl/8.0"
    assert result["http_uri"] == "/login?user=admin"


def test_http_sqli_uri_flagged_as_suspicious():
    payload = b"GET /login?id=1' UNION SELECT * FROM users-- HTTP/1.1\r\nHost: example.com\r\n\r\n"
    dpi = DPIEngine()
    result = dpi.inspect(_flow([_pkt(payload)]), features={})
    assert "SUSPICIOUS_HTTP_URI" in result["anomaly_indicators"]


def test_dns_query_parsed_from_raw_payload():
    # Minimal hand-built DNS query: header + QNAME "example.com" + QTYPE=A, QCLASS=IN
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"\x07example\x03com\x00"
    question = qname + struct.pack(">HH", 1, 1)
    payload = header + question

    dpi = DPIEngine()
    result = dpi.inspect(_flow([_pkt(payload)], dst_port=53, protocol="UDP"), features={})

    assert result["application_protocol"] == "DNS"
    assert result["dns_query"] == "example.com"
    assert result["dns_query_type"] == "A"


def test_overlong_dns_query_flagged_as_possible_tunneling():
    long_label = "a" * 63
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = bytes([len(long_label)]) + long_label.encode() + b"\x03net\x00"
    question = qname + struct.pack(">HH", 1, 1)
    payload = header + question

    dpi = DPIEngine()
    result = dpi.inspect(_flow([_pkt(payload)], dst_port=53, protocol="UDP"), features={})
    assert "POSSIBLE_DNS_TUNNELING" in result["anomaly_indicators"]


def test_tls_client_hello_sni_extracted():
    sni = b"secure.example.com"
    server_name = struct.pack(">H", len(sni)) + b"\x00" + struct.pack(">H", len(sni)) + sni
    ext_sni = struct.pack(">HH", 0x0000, len(server_name)) + server_name
    exts_block = struct.pack(">H", len(ext_sni)) + ext_sni

    body = (
        b"\x03\x03" + bytes(32) + b"\x00"  # client_version, random, empty session id
        + struct.pack(">H", 2) + b"\x13\x01"  # 1 cipher suite
        + b"\x01\x00"  # compression methods
        + exts_block
    )
    handshake = bytes([0x01]) + struct.pack(">I", len(body))[1:] + body
    record = bytes([0x16]) + b"\x03\x01" + struct.pack(">H", len(handshake)) + handshake

    dpi = DPIEngine()
    result = dpi.inspect(_flow([_pkt(record)], dst_port=443), features={})

    assert result["application_protocol"] == "TLS"
    assert result["tls_sni"] == "secure.example.com"


def test_no_payload_falls_back_to_port_guess():
    dpi = DPIEngine()
    result = dpi.inspect(_flow([{"payload": b""}], dst_port=443), features={})
    assert result["application_protocol"] == "HTTPS"
    assert result["tls_sni"] is None


def test_flow_anomaly_indicators_from_features_only():
    dpi = DPIEngine()
    features = {
        "syn_flag_count": 100, "ack_flag_count": 5,
        "flow_packets_per_sec": 2000, "payload_entropy_mean": 7.9,
        "down_up_ratio": 15, "total_fwd_packets": 20, "flow_duration": 0.2,
    }
    result = dpi.inspect(_flow([]), features=features)
    for expected in (
        "SYN_FLOOD_PATTERN", "HIGH_PACKET_RATE", "HIGH_ENTROPY_PAYLOAD",
        "ASYMMETRIC_FLOW", "PORT_SCAN_PATTERN",
    ):
        assert expected in result["anomaly_indicators"]
