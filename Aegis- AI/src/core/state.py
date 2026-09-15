import asyncio
from typing import List, Dict, Any
from dataclasses import dataclass, field

@dataclass
class AegisState:
    flows: List[Dict[str, Any]] = field(default_factory=list)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=lambda: {
        "total_packets": 0,
        "total_bytes": 0,
        "active_flows": 0,
        "alert_count": 0,
        "packets_per_sec": 0,
        "bytes_per_sec": 0,
        "avg_threat_score": 0.0
    })
    config: Dict[str, Any] = field(default_factory=lambda: {
        "threat_threshold": 75,
        "anomaly_threshold": 0.6
    })
    websocket_connections: List = field(default_factory=list)
    flow_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    alert_queue: asyncio.Queue = field(default_factory=asyncio.Queue)
    running: bool = False

state = AegisState()
