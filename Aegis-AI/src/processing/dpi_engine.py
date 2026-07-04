from typing import Dict, Any

class DPIEngine:
    """Deep Packet Inspection Engine - Prototype Version"""

    def __init__(self):
        self.http_methods = [b"GET", b"POST", b"PUT", b"DELETE", b"HEAD", b"OPTIONS", b"PATCH"]
        self.dns_query_types = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}

    def inspect(self, flow: Dict[str, Any], features: Dict[str, Any]) -> Dict[str, Any]:
        """Perform DPI on flow and extract application metadata"""
        dpi_result = {
            "application_protocol": "UNKNOWN",
            "http_method": None,
            "http_host": None,
            "http_uri": None,
            "dns_query": None,
            "dns_query_type": None,
            "tls_version": None,
            "tls_sni": None,
            "detected_os": None,
            "user_agent": None,
            "anomaly_indicators": []
        }

        packets = flow.get("packets", [])
        if not packets:
            return dpi_result

        dst_port = flow.get("dst_port", 0)
        src_port = flow.get("src_port", 0)

        if dst_port == 80 or src_port == 80:
            dpi_result["application_protocol"] = "HTTP"
        elif dst_port == 443 or src_port == 443:
            dpi_result["application_protocol"] = "HTTPS"
        elif dst_port == 53 or src_port == 53:
            dpi_result["application_protocol"] = "DNS"
        elif dst_port == 22 or src_port == 22:
            dpi_result["application_protocol"] = "SSH"
        elif dst_port == 21 or src_port == 21:
            dpi_result["application_protocol"] = "FTP"
        elif dst_port == 25 or src_port == 25:
            dpi_result["application_protocol"] = "SMTP"

        if features.get("syn_flag_count", 0) > 50 and features.get("ack_flag_count", 0) < features.get("syn_flag_count", 0) * 0.5:
            dpi_result["anomaly_indicators"].append("SYN_FLOOD_PATTERN")

        if features.get("flow_packets_per_sec", 0) > 1000:
            dpi_result["anomaly_indicators"].append("HIGH_PACKET_RATE")

        if features.get("payload_entropy_mean", 0) > 7.5:
            dpi_result["anomaly_indicators"].append("HIGH_ENTROPY_PAYLOAD")

        if features.get("down_up_ratio", 0) > 10:
            dpi_result["anomaly_indicators"].append("ASYMMETRIC_FLOW")

        if features.get("total_fwd_packets", 0) > 10 and features.get("flow_duration", 0) < 1:
            dpi_result["anomaly_indicators"].append("PORT_SCAN_PATTERN")

        return dpi_result
