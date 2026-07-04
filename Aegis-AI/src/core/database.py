import sqlite3
import json
import os
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path

DB_PATH = "./data/aegis.db"

def _ensure_column(cursor, table, column, coltype):
    """Add a column to an existing table if it's missing (safe migration for DBs created before a schema change)."""
    cursor.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cursor.fetchall()}
    if column not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")

def init_db():
    Path("./data").mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            packet_count INTEGER,
            total_bytes INTEGER,
            duration REAL,
            threat_score REAL,
            risk_level TEXT,
            attack_type TEXT,
            anomaly_score REAL,
            classification_confidence REAL,
            features_json TEXT,
            dpi_json TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            flow_id INTEGER,
            src_ip TEXT,
            dst_ip TEXT,
            attack_type TEXT,
            threat_score REAL,
            recommended_action TEXT,
            acknowledged INTEGER DEFAULT 0,
            layer TEXT DEFAULT 'L3',
            category TEXT,
            src_mac TEXT,
            dst_mac TEXT,
            details_json TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            flow_id INTEGER,
            timestamp REAL,
            src_ip TEXT,
            dst_ip TEXT,
            src_port INTEGER,
            dst_port INTEGER,
            protocol TEXT,
            length INTEGER,
            flags TEXT,
            payload_entropy REAL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp REAL,
            level TEXT,
            component TEXT,
            message TEXT
        )
    """)

    # Migration safety net: if flows/packets tables already existed from a prior
    # version of the schema (before dpi_json / flow_id were added), patch them in
    # place instead of silently dropping the new data.
    _ensure_column(cursor, "flows", "dpi_json", "TEXT")
    _ensure_column(cursor, "packets", "flow_id", "INTEGER")
    _ensure_column(cursor, "alerts", "layer", "TEXT DEFAULT 'L3'")
    _ensure_column(cursor, "alerts", "category", "TEXT")
    _ensure_column(cursor, "alerts", "src_mac", "TEXT")
    _ensure_column(cursor, "alerts", "dst_mac", "TEXT")
    _ensure_column(cursor, "alerts", "details_json", "TEXT")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_flow_id ON packets(flow_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp)")

    conn.commit()
    conn.close()

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def _parse_json(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default

def insert_flow(flow_data: dict) -> int:
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO flows 
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, 
             total_bytes, duration, threat_score, risk_level, attack_type, 
             anomaly_score, classification_confidence, features_json, dpi_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            flow_data.get("timestamp"),
            flow_data.get("src_ip"),
            flow_data.get("dst_ip"),
            flow_data.get("src_port"),
            flow_data.get("dst_port"),
            flow_data.get("protocol"),
            flow_data.get("packet_count"),
            flow_data.get("total_bytes"),
            flow_data.get("duration"),
            flow_data.get("threat_score"),
            flow_data.get("risk_level"),
            flow_data.get("attack_type"),
            flow_data.get("anomaly_score"),
            flow_data.get("classification_confidence"),
            json.dumps(flow_data.get("features", {})),
            json.dumps(flow_data.get("dpi_result", {}))
        ))
        conn.commit()
        return cursor.lastrowid

def insert_alert(alert_data: dict):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts 
            (timestamp, flow_id, src_ip, dst_ip, attack_type, threat_score, recommended_action,
             layer, category, src_mac, dst_mac, details_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_data.get("timestamp"),
            alert_data.get("flow_id"),
            alert_data.get("src_ip"),
            alert_data.get("dst_ip"),
            alert_data.get("attack_type"),
            alert_data.get("threat_score"),
            alert_data.get("recommended_action"),
            alert_data.get("layer", "L3"),
            alert_data.get("category"),
            alert_data.get("src_mac"),
            alert_data.get("dst_mac"),
            json.dumps(alert_data.get("details", {}))
        ))
        conn.commit()
        return cursor.lastrowid

def insert_packets_bulk(flow_id, packets: list):
    """Persist every raw packet that made up a flow, linked back to that flow."""
    if not packets:
        return
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.executemany("""
            INSERT INTO packets
            (flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload_entropy)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            (
                flow_id,
                p.get("timestamp"),
                p.get("src_ip"),
                p.get("dst_ip"),
                p.get("src_port"),
                p.get("dst_port"),
                p.get("protocol"),
                p.get("length"),
                p.get("flags"),
                p.get("payload_entropy"),
            )
            for p in packets
        ])
        conn.commit()

def get_recent_flows(limit=100, offset=0, filters=None):
    with get_db() as conn:
        query = "SELECT * FROM flows WHERE 1=1"
        params = []
        if filters:
            if filters.get("src_ip"):
                query += " AND src_ip LIKE ?"
                params.append(f"%{filters['src_ip']}%")
            if filters.get("dst_ip"):
                query += " AND dst_ip LIKE ?"
                params.append(f"%{filters['dst_ip']}%")
            if filters.get("protocol"):
                query += " AND protocol = ?"
                params.append(filters["protocol"])
            if filters.get("risk_level"):
                query += " AND risk_level = ?"
                params.append(filters["risk_level"])
            if filters.get("time_from"):
                query += " AND timestamp >= ?"
                params.append(filters["time_from"])
            if filters.get("time_to"):
                query += " AND timestamp <= ?"
                params.append(filters["time_to"])
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor = conn.execute(query, params)
        rows = [dict(row) for row in cursor.fetchall()]
        for row in rows:
            row["features"] = _parse_json(row.pop("features_json", None), {})
            row["dpi_result"] = _parse_json(row.pop("dpi_json", None), {})
        return rows

def get_flow_detail(flow_id: int):
    with get_db() as conn:
        cursor = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,))
        row = cursor.fetchone()
        if not row:
            return None
        flow = dict(row)
        flow["features"] = _parse_json(flow.pop("features_json", None), {})
        flow["dpi_result"] = _parse_json(flow.pop("dpi_json", None), {})

        cursor = conn.execute(
            "SELECT * FROM packets WHERE flow_id = ? ORDER BY timestamp ASC", (flow_id,)
        )
        flow["packets"] = [dict(r) for r in cursor.fetchall()]
        return flow

def get_recent_packets(limit=200, offset=0, filters=None):
    with get_db() as conn:
        query = "SELECT * FROM packets WHERE 1=1"
        params = []
        if filters:
            if filters.get("src_ip"):
                query += " AND src_ip LIKE ?"
                params.append(f"%{filters['src_ip']}%")
            if filters.get("dst_ip"):
                query += " AND dst_ip LIKE ?"
                params.append(f"%{filters['dst_ip']}%")
            if filters.get("protocol"):
                query += " AND protocol = ?"
                params.append(filters["protocol"])
            if filters.get("flow_id"):
                query += " AND flow_id = ?"
                params.append(filters["flow_id"])
        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

def get_alerts(limit=50, acknowledged=None, layer=None):
    with get_db() as conn:
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if acknowledged is not None:
            query += " AND acknowledged = ?"
            params.append(acknowledged)
        if layer is not None:
            query += " AND layer = ?"
            params.append(layer)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        cursor = conn.execute(query, params)
        rows = [dict(row) for row in cursor.fetchall()]
        for row in rows:
            row["details"] = _parse_json(row.pop("details_json", None), {})
        return rows

def get_stats():
    with get_db() as conn:
        cursor = conn.execute("SELECT COUNT(*) as total_flows FROM flows")
        total_flows = cursor.fetchone()[0]

        cursor = conn.execute("SELECT COUNT(*) as total_alerts FROM alerts")
        total_alerts = cursor.fetchone()[0]

        cursor = conn.execute("SELECT COUNT(*) as total_packets FROM packets")
        total_packets_logged = cursor.fetchone()[0]

        cursor = conn.execute("SELECT AVG(threat_score) as avg_threat FROM flows")
        avg_threat = cursor.fetchone()[0] or 0

        cursor = conn.execute("""
            SELECT attack_type, COUNT(*) as count 
            FROM flows 
            WHERE attack_type != 'BENIGN' 
            GROUP BY attack_type
        """)
        attack_dist = [dict(row) for row in cursor.fetchall()]

        cursor = conn.execute("""
            SELECT protocol, COUNT(*) as count 
            FROM flows 
            GROUP BY protocol
        """)
        protocol_dist = [dict(row) for row in cursor.fetchall()]

        from time import time
        hour_ago = time() - 3600
        cursor = conn.execute(
            "SELECT COUNT(*) as recent_flows FROM flows WHERE timestamp > ?", 
            (hour_ago,)
        )
        recent_flows = cursor.fetchone()[0]

        cursor = conn.execute(
            "SELECT COUNT(*) as recent_alerts FROM alerts WHERE timestamp > ?", 
            (hour_ago,)
        )
        recent_alerts = cursor.fetchone()[0]

        return {
            "total_flows": total_flows,
            "total_alerts": total_alerts,
            "total_packets_logged": total_packets_logged,
            "avg_threat_score": round(avg_threat, 2),
            "attack_distribution": attack_dist,
            "protocol_distribution": protocol_dist,
            "recent_flows": recent_flows,
            "recent_alerts": recent_alerts
        }

def get_traffic_timeseries(minutes=60):
    with get_db() as conn:
        from time import time
        start = time() - (minutes * 60)
        cursor = conn.execute("""
            SELECT 
                strftime('%Y-%m-%d %H:%M', datetime(timestamp, 'unixepoch')) as minute,
                COUNT(*) as flow_count,
                SUM(total_bytes) as byte_count,
                AVG(threat_score) as avg_threat
            FROM flows
            WHERE timestamp > ?
            GROUP BY minute
            ORDER BY minute
        """, (start,))
        return [dict(row) for row in cursor.fetchall()]

def get_top_talkers(limit=8, minutes=60):
    """Top source/destination IPs by traffic volume, for network-wide visibility."""
    with get_db() as conn:
        from time import time
        start = time() - (minutes * 60)

        cursor = conn.execute("""
            SELECT src_ip as ip, SUM(total_bytes) as bytes, SUM(packet_count) as packets, COUNT(*) as flows
            FROM flows WHERE timestamp > ?
            GROUP BY src_ip ORDER BY bytes DESC LIMIT ?
        """, (start, limit))
        sources = [dict(row) for row in cursor.fetchall()]

        cursor = conn.execute("""
            SELECT dst_port as port, protocol, COUNT(*) as flows, SUM(total_bytes) as bytes
            FROM flows WHERE timestamp > ?
            GROUP BY dst_port, protocol ORDER BY flows DESC LIMIT ?
        """, (start, limit))
        ports = [dict(row) for row in cursor.fetchall()]

        return {"top_sources": sources, "top_ports": ports}
