import math
import time
from typing import List, Dict, Any

class FeatureExtractor:
    def __init__(self):
        self.feature_names = [
            "flow_duration", "total_fwd_packets", "total_bwd_packets",
            "total_fwd_bytes", "total_bwd_bytes", "fwd_packet_length_mean",
            "fwd_packet_length_std", "bwd_packet_length_mean", "bwd_packet_length_std",
            "flow_bytes_per_sec", "flow_packets_per_sec", "fwd_iat_mean",
            "fwd_iat_std", "bwd_iat_mean", "bwd_iat_std", "fwd_psh_flags",
            "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags", "fwd_header_length",
            "bwd_header_length", "min_packet_length", "max_packet_length",
            "packet_length_mean", "packet_length_std", "packet_length_variance",
            "fin_flag_count", "syn_flag_count", "rst_flag_count", "psh_flag_count",
            "ack_flag_count", "urg_flag_count", "ece_flag_count", "down_up_ratio",
            "avg_packet_size", "avg_fwd_segment_size", "avg_bwd_segment_size",
            "fwd_header_length2", "subflow_fwd_packets", "subflow_fwd_bytes",
            "subflow_bwd_packets", "subflow_bwd_bytes", "init_win_bytes_forward",
            "init_win_bytes_backward", "act_data_pkt_forward", "min_seg_size_forward",
            "active_mean", "active_std", "active_max", "active_min",
            "idle_mean", "idle_std", "idle_max", "idle_min", "payload_entropy_mean"
        ]

    def extract_features(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        packets = flow.get("packets", [])
        if not packets:
            return {}

        src_ip = flow["src_ip"]
        dst_ip = flow["dst_ip"]

        fwd_packets = [p for p in packets if p["src_ip"] == src_ip]
        bwd_packets = [p for p in packets if p["src_ip"] == dst_ip]

        timestamps = [p["timestamp"] for p in packets]
        lengths = [p["length"] for p in packets]
        entropies = [p.get("payload_entropy", 0) for p in packets]

        flow_duration = max(timestamps) - min(timestamps) if len(timestamps) > 1 else 0
        flow_duration = max(flow_duration, 0.0001)

        total_fwd_packets = len(fwd_packets)
        total_bwd_packets = len(bwd_packets)
        total_fwd_bytes = sum(p["length"] for p in fwd_packets)
        total_bwd_bytes = sum(p["length"] for p in bwd_packets)

        fwd_lengths = [p["length"] for p in fwd_packets]
        bwd_lengths = [p["length"] for p in bwd_packets]

        fwd_packet_length_mean = self._mean(fwd_lengths) if fwd_lengths else 0
        fwd_packet_length_std = self._std(fwd_lengths) if fwd_lengths else 0
        bwd_packet_length_mean = self._mean(bwd_lengths) if bwd_lengths else 0
        bwd_packet_length_std = self._std(bwd_lengths) if bwd_lengths else 0

        flow_bytes = sum(lengths)
        flow_bytes_per_sec = flow_bytes / flow_duration
        flow_packets_per_sec = len(packets) / flow_duration

        fwd_timestamps = [p["timestamp"] for p in fwd_packets]
        bwd_timestamps = [p["timestamp"] for p in bwd_packets]

        fwd_iats = self._calculate_iats(fwd_timestamps)
        bwd_iats = self._calculate_iats(bwd_timestamps)

        fwd_iat_mean = self._mean(fwd_iats) if fwd_iats else 0
        fwd_iat_std = self._std(fwd_iats) if fwd_iats else 0
        bwd_iat_mean = self._mean(bwd_iats) if bwd_iats else 0
        bwd_iat_std = self._std(bwd_iats) if bwd_iats else 0

        flags = [p.get("flags", "") for p in packets]
        fwd_flags = [p.get("flags", "") for p in fwd_packets]
        bwd_flags = [p.get("flags", "") for p in bwd_packets]

        fwd_psh_flags = sum(1 for f in fwd_flags if "P" in f)
        bwd_psh_flags = sum(1 for f in bwd_flags if "P" in f)
        fwd_urg_flags = sum(1 for f in fwd_flags if "U" in f)
        bwd_urg_flags = sum(1 for f in bwd_flags if "U" in f)

        fwd_header_length = total_fwd_packets * 20 if flow["protocol"] == "TCP" else total_fwd_packets * 8
        bwd_header_length = total_bwd_packets * 20 if flow["protocol"] == "TCP" else total_bwd_packets * 8

        min_packet_length = min(lengths) if lengths else 0
        max_packet_length = max(lengths) if lengths else 0
        packet_length_mean = self._mean(lengths)
        packet_length_std = self._std(lengths)
        packet_length_variance = packet_length_std ** 2

        fin_flag_count = sum(1 for f in flags if "F" in f)
        syn_flag_count = sum(1 for f in flags if "S" in f)
        rst_flag_count = sum(1 for f in flags if "R" in f)
        psh_flag_count = sum(1 for f in flags if "P" in f)
        ack_flag_count = sum(1 for f in flags if "A" in f)
        urg_flag_count = sum(1 for f in flags if "U" in f)
        ece_flag_count = sum(1 for f in flags if "E" in f)

        down_up_ratio = total_bwd_bytes / max(total_fwd_bytes, 1)
        avg_packet_size = packet_length_mean
        avg_fwd_segment_size = fwd_packet_length_mean
        avg_bwd_segment_size = bwd_packet_length_mean

        subflow_fwd_packets = total_fwd_packets
        subflow_fwd_bytes = total_fwd_bytes
        subflow_bwd_packets = total_bwd_packets
        subflow_bwd_bytes = total_bwd_bytes

        init_win_bytes_forward = 640 if flow["protocol"] == "TCP" else 0
        init_win_bytes_backward = 640 if flow["protocol"] == "TCP" else 0
        act_data_pkt_forward = total_fwd_packets
        min_seg_size_forward = min(fwd_lengths) if fwd_lengths else 0

        active_mean = flow_duration
        active_std = 0
        active_max = flow_duration
        active_min = flow_duration
        idle_mean = 0
        idle_std = 0
        idle_max = 0
        idle_min = 0

        payload_entropy_mean = self._mean(entropies) if entropies else 0

        return {
            "flow_duration": flow_duration,
            "total_fwd_packets": total_fwd_packets,
            "total_bwd_packets": total_bwd_packets,
            "total_fwd_bytes": total_fwd_bytes,
            "total_bwd_bytes": total_bwd_bytes,
            "fwd_packet_length_mean": fwd_packet_length_mean,
            "fwd_packet_length_std": fwd_packet_length_std,
            "bwd_packet_length_mean": bwd_packet_length_mean,
            "bwd_packet_length_std": bwd_packet_length_std,
            "flow_bytes_per_sec": flow_bytes_per_sec,
            "flow_packets_per_sec": flow_packets_per_sec,
            "fwd_iat_mean": fwd_iat_mean,
            "fwd_iat_std": fwd_iat_std,
            "bwd_iat_mean": bwd_iat_mean,
            "bwd_iat_std": bwd_iat_std,
            "fwd_psh_flags": fwd_psh_flags,
            "bwd_psh_flags": bwd_psh_flags,
            "fwd_urg_flags": fwd_urg_flags,
            "bwd_urg_flags": bwd_urg_flags,
            "fwd_header_length": fwd_header_length,
            "bwd_header_length": bwd_header_length,
            "min_packet_length": min_packet_length,
            "max_packet_length": max_packet_length,
            "packet_length_mean": packet_length_mean,
            "packet_length_std": packet_length_std,
            "packet_length_variance": packet_length_variance,
            "fin_flag_count": fin_flag_count,
            "syn_flag_count": syn_flag_count,
            "rst_flag_count": rst_flag_count,
            "psh_flag_count": psh_flag_count,
            "ack_flag_count": ack_flag_count,
            "urg_flag_count": urg_flag_count,
            "ece_flag_count": ece_flag_count,
            "down_up_ratio": down_up_ratio,
            "avg_packet_size": avg_packet_size,
            "avg_fwd_segment_size": avg_fwd_segment_size,
            "avg_bwd_segment_size": avg_bwd_segment_size,
            "fwd_header_length2": fwd_header_length,
            "subflow_fwd_packets": subflow_fwd_packets,
            "subflow_fwd_bytes": subflow_fwd_bytes,
            "subflow_bwd_packets": subflow_bwd_packets,
            "subflow_bwd_bytes": subflow_bwd_bytes,
            "init_win_bytes_forward": init_win_bytes_forward,
            "init_win_bytes_backward": init_win_bytes_backward,
            "act_data_pkt_forward": act_data_pkt_forward,
            "min_seg_size_forward": min_seg_size_forward,
            "active_mean": active_mean,
            "active_std": active_std,
            "active_max": active_max,
            "active_min": active_min,
            "idle_mean": idle_mean,
            "idle_std": idle_std,
            "idle_max": idle_max,
            "idle_min": idle_min,
            "payload_entropy_mean": payload_entropy_mean
        }

    def _mean(self, values):
        return sum(values) / len(values) if values else 0

    def _std(self, values):
        if not values or len(values) < 2:
            return 0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)

    def _calculate_iats(self, timestamps):
        if len(timestamps) < 2:
            return []
        sorted_ts = sorted(timestamps)
        return [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts)-1)]

    def get_feature_vector(self, features: Dict[str, Any]) -> List[float]:
        return [features.get(name, 0.0) for name in self.feature_names]
