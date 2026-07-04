import os
import sys
import json
import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
import yaml

from src.core.state import AegisState
from src.core import database as db
from src.capture.packet_capture import PacketCapture
from src.capture.l2_capture import L2Capture
from src.processing.feature_extraction import FeatureExtractor
from src.processing.dpi_engine import DPIEngine
from src.processing.l2_analyzer import L2Analyzer
from src.ml.threat_scorer import ThreatScorer

CONFIG_PATH = "./config/config.yaml"
config = {}
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f).get("aegis", {})

app = FastAPI(
    title="Aegis-AI API",
    description="Intelligent Network Behavior Analysis System - Prototype",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.get("api", {}).get("cors_origins", ["*"]),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
dashboard_dir = config.get("api", {}).get("dashboard_dir", "./src/dashboard")
if os.path.isdir(dashboard_dir):
    css_dir = os.path.join(dashboard_dir, "css")
    js_dir = os.path.join(dashboard_dir, "js")
    if os.path.isdir(css_dir):
        app.mount("/css", StaticFiles(directory=css_dir), name="css")
    if os.path.isdir(js_dir):
        app.mount("/js", StaticFiles(directory=js_dir), name="js")

# Global state
state = AegisState()
state.config = {
    "threat_threshold": config.get("ml", {}).get("threat_threshold", 75),
    "anomaly_threshold": config.get("ml", {}).get("anomaly_threshold", 0.6),
    "capture_mode": config.get("capture", {}).get("mode", "simulation")
}

# Components
capture = None
feature_extractor = FeatureExtractor()
dpi_engine = DPIEngine()
threat_scorer = ThreatScorer(config=config.get("ml", {}))
dashboard_config = config.get("dashboard", {})
LIVE_PACKET_SAMPLE_SIZE = dashboard_config.get("live_packet_sample_size", 15)

l2_config = config.get("l2", {})
l2_capture = None
l2_analyzer = L2Analyzer(config=l2_config)

# Background tasks
processing_task = None
l2_processing_task = None

@app.on_event("startup")
async def startup():
    global capture, processing_task, l2_capture, l2_processing_task

    db.init_db()

    capture_config = config.get("capture", {})
    capture = PacketCapture(
        state=state,
        mode=capture_config.get("mode", "simulation"),
        interface=capture_config.get("interface", "eth0"),
        filter_exp=capture_config.get("filter", "tcp or udp or icmp")
    )
    capture.start()

    processing_task = asyncio.create_task(processing_loop())
    asyncio.create_task(stats_broadcaster())

    if l2_config.get("enabled", True):
        l2_capture = L2Capture(
            state=state,
            mode=l2_config.get("mode", "simulation"),
            interface=l2_config.get("interface", capture_config.get("interface", "eth0"))
        )
        l2_capture.start()
        l2_processing_task = asyncio.create_task(l2_processing_loop())
        print(f"[AEGIS] L2 monitoring started. Mode: {l2_config.get('mode', 'simulation')}")

    print(f"[AEGIS] Prototype started. Mode: {capture_config.get('mode', 'simulation')}")
    print(f"[AEGIS] Dashboard: http://localhost:{config.get('api', {}).get('port', 8000)}")

@app.on_event("shutdown")
async def shutdown():
    global capture, processing_task, l2_capture, l2_processing_task
    state.running = False
    if capture:
        capture.stop()
    if processing_task:
        processing_task.cancel()
    if l2_capture:
        l2_capture.stop()
    if l2_processing_task:
        l2_processing_task.cancel()

async def processing_loop():
    state.running = True
    while state.running:
        try:
            flows = capture.get_current_flows()
            flow_keys = []

            for flow in flows:
                flow_key = (
                    flow["src_ip"], flow["dst_ip"],
                    flow["src_port"], flow["dst_port"], flow["protocol"]
                )
                flow_keys.append(flow_key)

                features = feature_extractor.extract_features(flow)
                feature_vector = feature_extractor.get_feature_vector(features)

                dpi_result = dpi_engine.inspect(flow, features)

                ml_result = threat_scorer.score_flow(feature_vector, flow)

                flow_record = {
                    "timestamp": time.time(),
                    "src_ip": flow["src_ip"],
                    "dst_ip": flow["dst_ip"],
                    "src_port": flow["src_port"],
                    "dst_port": flow["dst_port"],
                    "protocol": flow["protocol"],
                    "packet_count": len(flow.get("packets", [])),
                    "total_bytes": sum(p["length"] for p in flow.get("packets", [])),
                    "duration": features.get("flow_duration", 0),
                    "threat_score": ml_result["threat_score"],
                    "risk_level": ml_result["risk_level"],
                    "attack_type": ml_result["attack_type"],
                    "anomaly_score": ml_result["anomaly_score"],
                    "classification_confidence": ml_result["classification_confidence"],
                    "features": features,
                    "dpi_result": dpi_result
                }

                flow_id = db.insert_flow(flow_record)
                flow_record["id"] = flow_id

                raw_packets = flow.get("packets", [])
                db.insert_packets_bulk(flow_id, raw_packets)
                # Cap what goes out over the websocket so a DoS burst (hundreds of
                # packets in one flow) can't flood the browser; the full set is
                # still persisted above and reachable via /api/flows/{id}.
                flow_record["packets_sample"] = raw_packets[:LIVE_PACKET_SAMPLE_SIZE]
                flow_record["packets_sample_truncated"] = len(raw_packets) > LIVE_PACKET_SAMPLE_SIZE

                state.flows.insert(0, flow_record)
                if len(state.flows) > 1000:
                    state.flows = state.flows[:1000]

                if ml_result["threat_score"] >= state.config["threat_threshold"]:
                    alert = {
                        "timestamp": time.time(),
                        "flow_id": flow_id,
                        "src_ip": flow["src_ip"],
                        "dst_ip": flow["dst_ip"],
                        "attack_type": ml_result["attack_type"],
                        "threat_score": ml_result["threat_score"],
                        "recommended_action": ml_result["recommended_action"]
                    }
                    db.insert_alert(alert)
                    state.alerts.insert(0, alert)
                    if len(state.alerts) > 500:
                        state.alerts = state.alerts[:500]
                    state.stats["alert_count"] += 1

                    await broadcast_message({
                        "type": "alert",
                        "data": alert
                    })

                await broadcast_message({
                    "type": "flow",
                    "data": flow_record
                })

            if flow_keys:
                capture.clear_processed_flows(flow_keys)

            state.stats["active_flows"] = len(flows)
            if state.flows:
                recent_flows = state.flows[:100]
                state.stats["avg_threat_score"] = (
                    sum(f["threat_score"] for f in recent_flows) / len(recent_flows)
                )

            await asyncio.sleep(0.5)

        except Exception as e:
            print(f"Processing error: {e}")
            await asyncio.sleep(1)

async def l2_processing_loop():
    """Non-IP counterpart to processing_loop(): consumes ARP/STP/CDP/DTP/
    VTP/double-tagged-VLAN events and runs them through the rule-based
    L2Analyzer, since these attacks have no IP flow to build ML features
    from."""
    while state.running:
        try:
            events = l2_capture.drain_events() if l2_capture else []
            for event in events:
                state.stats["total_packets"] += 1
                alert = l2_analyzer.analyze(event)
                if not alert:
                    continue

                alert_id = db.insert_alert(alert)
                alert["flow_id"] = None
                alert["id"] = alert_id

                state.alerts.insert(0, alert)
                if len(state.alerts) > 500:
                    state.alerts = state.alerts[:500]
                state.stats["alert_count"] += 1

                await broadcast_message({"type": "alert", "data": alert})

            await asyncio.sleep(0.5)
        except Exception as e:
            print(f"L2 processing error: {e}")
            await asyncio.sleep(1)

async def stats_broadcaster():
    while state.running:
        try:
            total_packets = state.stats.get("total_packets", 0)
            total_bytes = state.stats.get("total_bytes", 0)

            stats = {
                "type": "stats",
                "data": {
                    "total_packets": total_packets,
                    "total_bytes": total_bytes,
                    "active_flows": state.stats.get("active_flows", 0),
                    "alert_count": state.stats.get("alert_count", 0),
                    "avg_threat_score": round(state.stats.get("avg_threat_score", 0), 2),
                    "packets_per_sec": total_packets,
                    "bytes_per_sec": total_bytes,
                    "timestamp": time.time()
                }
            }
            await broadcast_message(stats)
            await asyncio.sleep(1)
        except Exception as e:
            print(f"Stats broadcast error: {e}")
            await asyncio.sleep(1)

async def broadcast_message(message: dict):
    disconnected = []
    for conn in state.websocket_connections:
        try:
            await conn.send_json(message)
        except:
            disconnected.append(conn)
    for conn in disconnected:
        if conn in state.websocket_connections:
            state.websocket_connections.remove(conn)

class ConfigUpdate(BaseModel):
    threat_threshold: Optional[float] = Field(None, ge=0, le=100)
    anomaly_threshold: Optional[float] = Field(None, ge=0, le=1)

class FlowFilter(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    risk_level: Optional[str] = None
    time_from: Optional[float] = None
    time_to: Optional[float] = None

@app.get("/", response_class=HTMLResponse)
async def root():
    dashboard_path = Path(dashboard_dir) / "index.html"
    if dashboard_path.exists():
        return HTMLResponse(content=dashboard_path.read_text())
    return HTMLResponse("<h1>Aegis-AI API</h1><p>Dashboard not found.</p>")

@app.get("/api/stats")
async def get_stats():
    db_stats = db.get_stats()
    return {
        **db_stats,
        "total_packets": state.stats.get("total_packets", 0),
        "total_bytes": state.stats.get("total_bytes", 0),
        "packets_per_sec": state.stats.get("packets_per_sec", 0),
        "bytes_per_sec": state.stats.get("bytes_per_sec", 0),
        "config": state.config
    }

@app.get("/api/flows")
async def get_flows(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    risk_level: Optional[str] = None
):
    filters = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "risk_level": risk_level
    }
    filters = {k: v for k, v in filters.items() if v is not None}
    return db.get_recent_flows(limit=limit, offset=offset, filters=filters if filters else None)

@app.get("/api/flows/{flow_id}")
async def get_flow_detail(flow_id: int):
    flow = db.get_flow_detail(flow_id)
    if not flow:
        raise HTTPException(status_code=404, detail="Flow not found")
    return flow

@app.get("/api/packets")
async def get_packets(
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    flow_id: Optional[int] = None
):
    filters = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "flow_id": flow_id
    }
    filters = {k: v for k, v in filters.items() if v is not None}
    return db.get_recent_packets(limit=limit, offset=offset, filters=filters if filters else None)

@app.get("/api/network/talkers")
async def get_network_talkers(minutes: int = Query(60, ge=1, le=1440)):
    return db.get_top_talkers(minutes=minutes)

@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    acknowledged: Optional[bool] = None,
    layer: Optional[str] = Query(None, pattern="^(L2|L3)$")
):
    ack = 1 if acknowledged == True else (0 if acknowledged == False else None)
    return db.get_alerts(limit=limit, acknowledged=ack, layer=layer)

@app.get("/api/l2/status")
async def get_l2_status():
    """Live view into the L2 analyzer's internal state, mainly useful for
    debugging/demoing what it currently considers 'known good'."""
    return {
        "enabled": l2_capture is not None,
        "mode": l2_config.get("mode", "simulation"),
        "arp_table_size": len(l2_analyzer.arp_table),
        "known_mac_count": len(l2_analyzer._known_macs),
        "stp_root_id": l2_analyzer.stp_root_id,
        "stp_root_mac": l2_analyzer.stp_root_mac,
        "vtp_last_revision": l2_analyzer.vtp_last_revision,
    }

@app.get("/api/traffic")
async def get_traffic(minutes: int = Query(60, ge=1, le=1440)):
    return db.get_traffic_timeseries(minutes=minutes)

@app.post("/api/config")
async def update_config(update: ConfigUpdate):
    if update.threat_threshold is not None:
        state.config["threat_threshold"] = update.threat_threshold
    if update.anomaly_threshold is not None:
        state.config["anomaly_threshold"] = update.anomaly_threshold
    return {"status": "updated", "config": state.config}

@app.get("/api/export/alerts")
async def export_alerts(format: str = Query("json", pattern="^(json|csv)$")):
    alerts = db.get_alerts(limit=10000)
    if format == "json":
        return JSONResponse(content=alerts)
    else:
        import csv
        import io
        output = io.StringIO()
        if alerts:
            writer = csv.DictWriter(output, fieldnames=alerts[0].keys())
            writer.writeheader()
            writer.writerows(alerts)
        content = output.getvalue()
        output.close()
        return StreamingResponse(
            io.BytesIO(content.encode()),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=aegis_alerts.csv"}
        )

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.websocket_connections.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "ping":
                    await websocket.send_json({"type": "pong"})
                elif msg.get("action") == "get_stats":
                    stats = db.get_stats()
                    await websocket.send_json({"type": "stats", "data": stats})
            except:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in state.websocket_connections:
            state.websocket_connections.remove(websocket)

if __name__ == "__main__":
    port = config.get("api", {}).get("port", 8000)
    host = config.get("api", {}).get("host", "0.0.0.0")
    uvicorn.run(app, host=host, port=port)
