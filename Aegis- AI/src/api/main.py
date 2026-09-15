import os
import sys
import json
import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn
import yaml

from src.core.state import AegisState
from src.core import database as db
from src.core.auth import require_api_key, require_ws_api_key, API_KEY
from src.core.rate_limit import RateLimitMiddleware
from src.capture.packet_capture import PacketCapture, SCAPY_AVAILABLE
from src.capture.l2_capture import L2Capture
from src.processing.feature_extraction import FeatureExtractor
from src.processing.dpi_engine import DPIEngine
from src.processing.l2_analyzer import L2Analyzer
from src.processing.scan_detector import ScanDetector
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

cors_origins = config.get("api", {}).get("cors_origins", ["http://localhost:8000", "http://127.0.0.1:8000"])
# allow_credentials=True is invalid (and rejected by browsers) when combined
# with a wildcard origin - the previous config used allow_origins=["*"] AND
# allow_credentials=True together, which is a real CORS misconfiguration,
# not just a style nit. Only allow credentials when origins are an explicit
# allowlist; never combine credentials with a wildcard.
allow_credentials = "*" not in cors_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=allow_credentials,
    allow_methods=["GET", "POST"],
    allow_headers=["X-API-Key", "Content-Type"],
)

rate_limit_config = config.get("api", {}).get("rate_limit", {})
app.add_middleware(
    RateLimitMiddleware,
    max_requests=rate_limit_config.get("max_requests", 120),
    window_seconds=rate_limit_config.get("window_seconds", 60),
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
scan_detector = ScanDetector(config=config.get("scan_detection", {}))

# Background tasks
processing_task = None
l2_processing_task = None

@app.on_event("startup")
async def startup():
    global capture, processing_task, l2_capture, l2_processing_task

    db.init_db()

    capture_config = config.get("capture", {})
    processing_config = config.get("processing", {})
    capture = PacketCapture(
        state=state,
        mode=capture_config.get("mode", "simulation"),
        interface=capture_config.get("interface", "eth0"),
        filter_exp=capture_config.get("filter", "tcp or udp or icmp or ip6"),
        idle_timeout=processing_config.get("flow_idle_timeout_seconds", 2.0)
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
                # PacketCapture buckets packets by a canonical (direction-
                # independent) key, not the literal (src,dst) reported on
                # the flow - use the key it actually stored under so
                # clear_processed_flows() finds and removes the right
                # bucket instead of silently no-op'ing (which used to leave
                # already-processed flows in the buffer forever, getting
                # re-scored and re-alerted on every 0.5s tick).
                flow_key = flow.pop("_capture_key", None) or (
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

                # db.* calls are synchronous SQLite (new connection, insert,
                # commit) - running them inline here would block the whole
                # asyncio event loop, including broadcast_message() and every
                # other coroutine (WebSocket pings, API requests), for the
                # duration of each disk write. asyncio.to_thread() pushes the
                # blocking work onto a worker thread so the loop stays free
                # to broadcast flows/alerts to the dashboard immediately
                # instead of queuing behind DB I/O.
                flow_id = await asyncio.to_thread(db.insert_flow, flow_record)
                flow_record["id"] = flow_id

                raw_packets = flow.get("packets", [])
                await asyncio.to_thread(db.insert_packets_bulk, flow_id, raw_packets)
                # Cap what goes out over the websocket so a DoS burst (hundreds of
                # packets in one flow) can't flood the browser; the full set is
                # still persisted above and reachable via /api/flows/{id}.
                # Raw payload bytes aren't JSON-serializable and aren't useful
                # to the browser anyway (DPI already extracted the meaningful
                # fields above) - only forward a short hex preview.
                sample = [_sanitize_packet_for_json(p) for p in raw_packets[:LIVE_PACKET_SAMPLE_SIZE]]
                flow_record["packets_sample"] = sample
                flow_record["packets_sample_truncated"] = len(raw_packets) > LIVE_PACKET_SAMPLE_SIZE

                state.flows.insert(0, flow_record)
                if len(state.flows) > 1000:
                    state.flows = state.flows[:1000]

                # Cross-flow recon check: a port scan/host sweep is a
                # property of many flows from one source, not any single
                # flow's stats - see src/processing/scan_detector.py for
                # why this can't be done as a per-flow ML feature or DPI
                # heuristic.
                scan_alert = scan_detector.observe(flow_record)
                if scan_alert:
                    scan_alert_id = await asyncio.to_thread(db.insert_alert, scan_alert)
                    scan_alert["flow_id"] = None
                    scan_alert["id"] = scan_alert_id
                    state.alerts.insert(0, scan_alert)
                    if len(state.alerts) > 500:
                        state.alerts = state.alerts[:500]
                    state.stats["alert_count"] += 1
                    await broadcast_message({"type": "alert", "data": scan_alert})

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
                    await asyncio.to_thread(db.insert_alert, alert)
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

                alert_id = await asyncio.to_thread(db.insert_alert, alert)
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

def _sanitize_packet_for_json(packet: dict) -> dict:
    """Raw payload bytes aren't JSON-serializable; replace with a short hex
    preview (first 32 bytes) so the dashboard can still show *that* a
    payload was inspected without shipping raw bytes over the wire."""
    clean = {k: v for k, v in packet.items() if k != "payload"}
    payload = packet.get("payload")
    clean["payload_preview_hex"] = payload[:32].hex() if payload else None
    clean["payload_length"] = len(payload) if payload else 0
    return clean


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

class CaptureModeUpdate(BaseModel):
    mode: str = Field(..., pattern="^(simulation|live)$")
    interface: Optional[str] = None

class FlowFilter(BaseModel):
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None
    risk_level: Optional[str] = None
    time_from: Optional[float] = None
    time_to: Optional[float] = None

@app.get("/api/capture/status")
async def get_capture_status(_auth: bool = Depends(require_api_key)):
    """The dashboard's mode toggle previously just relabeled itself with no
    backend call at all - clicking 'Live' didn't change what was running,
    it just changed which button looked highlighted. This endpoint (and
    /api/capture/mode below) give the dashboard a real, verifiable source
    of truth for what's actually capturing traffic right now."""
    return {
        "requested_mode": capture.mode if capture else None,
        "interface": capture.interface if capture else None,
        "capture_thread_alive": bool(capture and capture.thread and capture.thread.is_alive()),
        "last_error": capture.last_error if capture else None,
        "l2_requested_mode": l2_capture.mode if l2_capture else None,
        "l2_capture_thread_alive": bool(l2_capture and l2_capture.thread and l2_capture.thread.is_alive()),
        "l2_last_error": l2_capture.last_error if l2_capture else None,
        "scapy_available": SCAPY_AVAILABLE,
    }

@app.post("/api/capture/mode")
async def set_capture_mode(update: CaptureModeUpdate, _auth: bool = Depends(require_api_key)):
    """Actually switch capture mode, with real verification - not just a
    UI relabel. Pre-flight-checks live mode (permissions, interface
    existence) BEFORE tearing down the current, working capture, so a
    failed switch to 'live' leaves simulation running rather than leaving
    nothing running at all. Returns a real error the dashboard must show
    the user on failure, instead of assuming success like the old button did.

    switch_mode() internally calls stop(), which blocks on
    thread.join(timeout=2) waiting for the old capture thread to exit.
    Calling that directly here would block on the single asyncio event
    loop for up to 2 seconds on every switch - freezing stats_broadcaster()
    and processing_loop() too, so the dashboard's gauge/KPIs visibly
    stall (and look "out of sync") for the duration of every mode switch.
    Running it in a worker thread via asyncio.to_thread keeps the event
    loop (and therefore the rest of the dashboard) responsive while the
    old capture thread winds down.
    """
    if not capture:
        raise HTTPException(status_code=503, detail="Capture engine not initialized yet.")

    ok, err = await asyncio.to_thread(capture.switch_mode, update.mode, update.interface)

    if not ok:
        # Don't touch the L2 sidecar if the primary switch failed - a
        # previous version of this endpoint attempted both switches
        # unconditionally, which could leave L2 capture running in "live"
        # mode while the primary capture (and the HTTP response) reported
        # failure. That's the same kind of "looks switched but isn't
        # consistent" state the dashboard button used to produce.
        raise HTTPException(status_code=422, detail=f"Could not switch to '{update.mode}': {err}")

    l2_ok, l2_err = (True, None)
    if l2_capture:
        l2_ok, l2_err = await asyncio.to_thread(l2_capture.switch_mode, update.mode, update.interface)

    state.config["capture_mode"] = capture.mode

    return {
        "status": "switched",
        "mode": capture.mode,
        "interface": capture.interface,
        "l2_switched": l2_ok,
        "l2_warning": l2_err if not l2_ok else None,
    }

@app.post("/api/session/clear")
async def clear_session(_auth: bool = Depends(require_api_key)):
    """Backs the dashboard's 'Clear All' button. This used to be purely
    cosmetic on the frontend (it emptied a few JS arrays and re-rendered
    the tables) while the backend's cumulative counters - alert_count,
    avg_threat_score, and everything in the alerts/flows tables - were
    never touched, so the next stats broadcast a fraction of a second
    later would snap the gauge and 'Threats Detected' right back to their
    old values. This endpoint actually resets the active session:
      - the *current* session's flows/alerts/packets/stats become empty,
        so the dashboard genuinely starts from zero
      - nothing is deleted - every row is archived under its original
        session_id in the database and stays fully retrievable via
        GET /api/sessions (and session_id-scoped queries), matching
        "clear it and start fresh, but keep the old data in the system"
    """
    result = await asyncio.to_thread(db.clear_session)

    # Reset in-memory state (mutated in place, not reassigned, so the
    # background capture/processing threads/tasks - which hold a reference
    # to this same `state` object - keep incrementing the same dict rather
    # than a stale one).
    state.flows.clear()
    state.alerts.clear()
    state.stats.update({
        "total_packets": 0,
        "total_bytes": 0,
        "active_flows": 0,
        "alert_count": 0,
        "packets_per_sec": 0,
        "bytes_per_sec": 0,
        "avg_threat_score": 0.0,
    })

    # Push a zeroed stats frame immediately instead of waiting up to ~1s for
    # the next stats_broadcaster() tick, so every connected dashboard's
    # gauge/KPIs/charts visibly reset right away.
    fresh_stats = {
        **state.stats,
        "total_alerts": 0,
        "total_flows": 0,
        "total_packets_logged": 0,
        "attack_distribution": [],
        "protocol_distribution": [],
        "recent_flows": 0,
        "recent_alerts": 0,
        "config": state.config,
        "timestamp": time.time(),
    }
    await broadcast_message({"type": "stats", "data": fresh_stats})
    await broadcast_message({"type": "session_cleared", "data": result})

    return {"status": "cleared", **result}

@app.get("/api/sessions")
async def list_sessions(limit: int = Query(50, ge=1, le=200), _auth: bool = Depends(require_api_key)):
    """Every past 'Clear All' shows up here with a summary of what it
    archived, so cleared data stays visible/auditable instead of just
    quietly sitting in the database with no way to see it again."""
    return db.get_sessions(limit=limit)

@app.get("/", response_class=HTMLResponse)
async def root():
    dashboard_path = Path(dashboard_dir) / "index.html"
    if dashboard_path.exists():
        html = dashboard_path.read_text()
        # The dashboard is a same-origin, single-user local tool: injecting
        # the key here lets the bundled JS authenticate itself without any
        # manual setup. This is NOT safe if the dashboard is ever exposed
        # to untrusted users/origins - it trades multi-tenant security for
        # zero-config local use, which matches this project's threat model.
        injected = f'<script>window.AEGIS_API_KEY = {json.dumps(API_KEY)};</script>'
        if "</head>" in html:
            html = html.replace("</head>", f"{injected}</head>", 1)
        else:
            html = injected + html
        return HTMLResponse(content=html)
    return HTMLResponse("<h1>Aegis-AI API</h1><p>Dashboard not found.</p>")

@app.get("/api/stats")
async def get_stats(_auth: bool = Depends(require_api_key)):
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
    risk_level: Optional[str] = None,
    _auth: bool = Depends(require_api_key)
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
async def get_flow_detail(flow_id: int, _auth: bool = Depends(require_api_key)):
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
    flow_id: Optional[int] = None,
    _auth: bool = Depends(require_api_key)
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
async def get_network_talkers(minutes: int = Query(60, ge=1, le=1440), _auth: bool = Depends(require_api_key)):
    return db.get_top_talkers(minutes=minutes)

@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    acknowledged: Optional[bool] = None,
    layer: Optional[str] = Query(None, pattern="^(L2|L3)$"),
    _auth: bool = Depends(require_api_key)
):
    ack = 1 if acknowledged == True else (0 if acknowledged == False else None)
    return db.get_alerts(limit=limit, acknowledged=ack, layer=layer)

@app.get("/api/l2/status")
async def get_l2_status(_auth: bool = Depends(require_api_key)):
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
async def get_traffic(minutes: int = Query(60, ge=1, le=1440), _auth: bool = Depends(require_api_key)):
    return db.get_traffic_timeseries(minutes=minutes)

@app.post("/api/config")
async def update_config(update: ConfigUpdate, _auth: bool = Depends(require_api_key)):
    if update.threat_threshold is not None:
        state.config["threat_threshold"] = update.threat_threshold
    if update.anomaly_threshold is not None:
        state.config["anomaly_threshold"] = update.anomaly_threshold
    return {"status": "updated", "config": state.config}

@app.get("/api/export/alerts")
async def export_alerts(format: str = Query("json", pattern="^(json|csv)$"), _auth: bool = Depends(require_api_key)):
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
    # Check the key BEFORE accept() - query params are available on the
    # ASGI scope pre-handshake, so an invalid key can be rejected outright
    # via websocket.close() without ever telling the client "connected".
    # The previous order (accept() then check) meant every unauthenticated
    # client briefly received a successful handshake before being kicked,
    # which contradicted this module's own documented intent
    # (see require_ws_api_key's docstring in src/core/auth.py).
    if not await require_ws_api_key(websocket):
        return  # require_ws_api_key already closed the connection with 4401
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
