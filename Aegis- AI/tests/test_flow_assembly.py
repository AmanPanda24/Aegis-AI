import time
from collections import defaultdict

from src.capture.packet_capture import PacketCapture


class FakeState:
    stats = {"total_packets": 0, "total_bytes": 0}


def _pkt(src_ip, dst_ip, src_port, dst_port, protocol, ts, length=64):
    return {
        "timestamp": ts, "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port, "protocol": protocol,
        "length": length, "flags": "", "payload_entropy": 0.0, "payload": b"",
    }


def _pc(idle_timeout=2.0):
    return PacketCapture(state=FakeState(), idle_timeout=idle_timeout)


def test_request_and_response_merge_into_one_bidirectional_flow():
    # Regression test for: flow key used to be the literal per-packet
    # (src,dst,sport,dport,proto), so a response (swapped src/dst, swapped
    # ports) could never land in the same bucket as its request - every
    # flow was structurally one-directional and total_bwd_packets was
    # always 0.
    pc = _pc()
    now = time.time()
    pc._process_packet(_pkt("10.0.0.5", "10.0.0.9", 51000, 80, "TCP", now))
    pc._process_packet(_pkt("10.0.0.9", "10.0.0.5", 80, 51000, "TCP", now + 0.1))

    assert len(pc.flows) == 1, "request and response should share one flow bucket"
    flows = pc.get_current_flows()
    assert len(flows) == 1
    assert len(flows[0]["packets"]) == 2


def test_flow_direction_is_the_first_packet_seen():
    pc = _pc()
    now = time.time()
    pc._process_packet(_pkt("10.0.0.5", "10.0.0.9", 51000, 80, "TCP", now))
    pc._process_packet(_pkt("10.0.0.9", "10.0.0.5", 80, 51000, "TCP", now + 0.1))
    flow = pc.get_current_flows()[0]
    assert flow["src_ip"] == "10.0.0.5"
    assert flow["dst_ip"] == "10.0.0.9"


def test_single_packet_flow_is_not_ready_immediately():
    pc = _pc(idle_timeout=2.0)
    pc._process_packet(_pkt("10.0.0.5", "10.0.0.9", 51000, 80, "TCP", time.time()))
    assert pc.get_current_flows() == []


def test_single_packet_flow_becomes_ready_after_idle_timeout():
    # Regression test for the core bug: single-packet flows (a lone SYN
    # to a port that never replies - exactly the shape of a port scan
    # probe) used to sit forever until _flush_old_flows() silently
    # deleted them, never reaching detection.
    pc = _pc(idle_timeout=2.0)
    old_ts = time.time() - 5.0  # well past idle_timeout
    pc._process_packet(_pkt("10.0.0.5", "10.0.0.9", 51000, 22, "TCP", old_ts))
    flows = pc.get_current_flows()
    assert len(flows) == 1
    assert len(flows[0]["packets"]) == 1


def test_port_scan_shape_all_packets_eventually_processed():
    # 30 single-SYN probes to 30 different ports, each with its own
    # ephemeral source port (the actual shape packet_capture.py's
    # simulator generates for "port_scan"). Every one of them must
    # eventually be returned by get_current_flows(), not silently
    # dropped.
    pc = _pc(idle_timeout=2.0)
    old_ts = time.time() - 5.0
    for port in range(30):
        pc._process_packet(_pkt("10.0.0.5", "10.0.0.9", 40000 + port, 1000 + port, "TCP", old_ts))

    flows = pc.get_current_flows()
    assert len(flows) == 30
    assert sum(len(f["packets"]) for f in flows) == 30


def test_clear_processed_flows_uses_capture_key_correctly():
    # Regression test: get_current_flows()'s canonical bucket key differs
    # from the literal (src_ip,dst_ip,src_port,dst_port,protocol) tuple
    # reported on the flow dict. clear_processed_flows() must be given
    # the actual bucket key (flow["_capture_key"]), or already-processed
    # flows are never removed and get rescored/re-alerted every tick.
    pc = _pc(idle_timeout=2.0)
    old_ts = time.time() - 5.0
    pc._process_packet(_pkt("10.0.0.5", "10.0.0.9", 51000, 80, "TCP", old_ts))

    flows = pc.get_current_flows()
    assert len(flows) == 1
    key = flows[0]["_capture_key"]
    pc.clear_processed_flows([key])
    assert len(pc.flows) == 0
    assert pc.get_current_flows() == []


def test_icmp_uses_zero_ports_and_still_buckets_correctly():
    pc = _pc()
    now = time.time()
    pc._process_packet(_pkt("10.0.0.5", "10.0.0.9", 0, 0, "ICMP", now))
    pc._process_packet(_pkt("10.0.0.9", "10.0.0.5", 0, 0, "ICMP", now + 0.1))
    assert len(pc.flows) == 1
