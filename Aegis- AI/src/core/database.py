import sqlite3
import json
import os
import time as _time
from datetime import datetime
from contextlib import contextmanager
from pathlib import Path

DB_PATH = "./data/aegis.db"


def _connect():
    """Every call site previously did a bare sqlite3.connect(DB_PATH) with
    default journal mode (DELETE) and no busy timeout. Under concurrent
    writers - packet capture, L2 processing, and API requests all hitting
    the same file-based DB simultaneously - that's a real "database is
    locked" risk: DELETE-mode writers block all readers for the duration
    of a write, and sqlite3's default 5s busy timeout can still be too
    short under sustained concurrent load.

    WAL (Write-Ahead Logging) lets readers proceed concurrently with a
    writer instead of blocking, and a longer explicit busy_timeout gives
    genuinely concurrent writers a real chance to retry instead of
    immediately raising OperationalError.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def _ensure_column(cursor, table, column, coltype):
    """Add a column to an existing table if it's missing (safe migration for DBs created before a schema change)."""
    cursor.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cursor.fetchall()}
    if column not in existing:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")

def init_db():
    Path("./data").mkdir(exist_ok=True)
    conn = _connect()
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

    # Sessions: every "Clear All" starts a new session instead of deleting
    # anything. Old flows/alerts/packets keep the session_id they were
    # created under, so historical data is archived (queryable via
    # get_sessions() / a specific session_id) rather than destroyed, while
    # the dashboard's default view only sees the current, just-reset session.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at REAL,
            ended_at REAL,
            label TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
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
    _ensure_column(cursor, "flows", "session_id", "INTEGER")
    _ensure_column(cursor, "alerts", "session_id", "INTEGER")
    _ensure_column(cursor, "packets", "session_id", "INTEGER")

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_flow_id ON packets(flow_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_timestamp ON flows(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_flows_session ON flows(session_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id)")

    # Make sure there's always a current session to tag new rows with -
    # on a brand-new DB this creates session 1; on an existing DB from
    # before sessions existed, this adopts all of that pre-existing data
    # into session 1 rather than leaving it with a NULL session_id that
    # would make it invisible to get_stats()/get_recent_flows() etc.
    cursor.execute("SELECT value FROM meta WHERE key = 'current_session_id'")
    row = cursor.fetchone()
    if row is None:
        cursor.execute(
            "INSERT INTO sessions (started_at, ended_at, label) VALUES (?, NULL, ?)",
            (_time.time(), "Session 1")
        )
        session_id = cursor.lastrowid
        cursor.execute(
            "INSERT INTO meta (key, value) VALUES ('current_session_id', ?)",
            (str(session_id),)
        )
        # Backfill any pre-existing rows (from a DB created before sessions
        # existed) into this first session instead of leaving them orphaned.
        cursor.execute("UPDATE flows SET session_id = ? WHERE session_id IS NULL", (session_id,))
        cursor.execute("UPDATE alerts SET session_id = ? WHERE session_id IS NULL", (session_id,))
        cursor.execute("UPDATE packets SET session_id = ? WHERE session_id IS NULL", (session_id,))

    conn.commit()
    conn.close()

@contextmanager
def get_db():
    conn = _connect()
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

def get_current_session_id(conn=None) -> int:
    """The session new rows get tagged with, and the default scope for every
    read query below. Reassigned by clear_session() whenever the dashboard's
    Clear All is used."""
    if conn is not None:
        cursor = conn.execute("SELECT value FROM meta WHERE key = 'current_session_id'")
        row = cursor.fetchone()
        return int(row[0]) if row else 1
    with get_db() as c:
        return get_current_session_id(c)

def _resolve_session_filter(conn, session_id):
    """session_id="current" (default) -> today's active session only.
    session_id=None -> no filter, i.e. every session ever recorded.
    session_id=<int> -> that specific archived (or current) session."""
    if session_id == "current":
        return get_current_session_id(conn)
    return session_id

def insert_flow(flow_data: dict) -> int:
    with get_db() as conn:
        session_id = get_current_session_id(conn)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO flows 
            (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, packet_count, 
             total_bytes, duration, threat_score, risk_level, attack_type, 
             anomaly_score, classification_confidence, features_json, dpi_json, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            json.dumps(flow_data.get("dpi_result", {})),
            session_id
        ))
        conn.commit()
        return cursor.lastrowid

def insert_alert(alert_data: dict):
    with get_db() as conn:
        session_id = get_current_session_id(conn)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts 
            (timestamp, flow_id, src_ip, dst_ip, attack_type, threat_score, recommended_action,
             layer, category, src_mac, dst_mac, details_json, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            json.dumps(alert_data.get("details", {})),
            session_id
        ))
        conn.commit()
        return cursor.lastrowid

def insert_packets_bulk(flow_id, packets: list):
    """Persist every raw packet that made up a flow, linked back to that flow."""
    if not packets:
        return
    with get_db() as conn:
        session_id = get_current_session_id(conn)
        cursor = conn.cursor()
        cursor.executemany("""
            INSERT INTO packets
            (flow_id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, length, flags, payload_entropy, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                session_id,
            )
            for p in packets
        ])
        conn.commit()

def get_recent_flows(limit=100, offset=0, filters=None, session_id="current"):
    with get_db() as conn:
        sid = _resolve_session_filter(conn, session_id)
        query = "SELECT * FROM flows WHERE 1=1"
        params = []
        if sid is not None:
            query += " AND session_id = ?"
            params.append(sid)
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
    # Flow detail is looked up by its own unique id, so it isn't scoped to
    # the current session - a flow from an archived session is still
    # viewable by id, it just won't show up in the default flow list/table.
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

def get_recent_packets(limit=200, offset=0, filters=None, session_id="current"):
    with get_db() as conn:
        sid = _resolve_session_filter(conn, session_id)
        query = "SELECT * FROM packets WHERE 1=1"
        params = []
        if sid is not None:
            query += " AND session_id = ?"
            params.append(sid)
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

def get_alerts(limit=50, acknowledged=None, layer=None, session_id="current"):
    with get_db() as conn:
        sid = _resolve_session_filter(conn, session_id)
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        if sid is not None:
            query += " AND session_id = ?"
            params.append(sid)
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

def get_stats(session_id="current"):
    with get_db() as conn:
        sid = _resolve_session_filter(conn, session_id)
        flow_where = " WHERE session_id = ?" if sid is not None else ""
        alert_where = " WHERE session_id = ?" if sid is not None else ""
        packet_where = " WHERE session_id = ?" if sid is not None else ""
        p = [sid] if sid is not None else []

        cursor = conn.execute(f"SELECT COUNT(*) as total_flows FROM flows{flow_where}", p)
        total_flows = cursor.fetchone()[0]

        cursor = conn.execute(f"SELECT COUNT(*) as total_alerts FROM alerts{alert_where}", p)
        total_alerts = cursor.fetchone()[0]

        cursor = conn.execute(f"SELECT COUNT(*) as total_packets FROM packets{packet_where}", p)
        total_packets_logged = cursor.fetchone()[0]

        cursor = conn.execute(f"SELECT AVG(threat_score) as avg_threat FROM flows{flow_where}", p)
        avg_threat = cursor.fetchone()[0] or 0

        cursor = conn.execute(f"""
            SELECT attack_type, COUNT(*) as count 
            FROM flows 
            {flow_where}{" AND" if sid is not None else " WHERE"} attack_type != 'BENIGN' 
            GROUP BY attack_type
        """, p)
        attack_dist_map = {row["attack_type"]: row["count"] for row in cursor.fetchall()}

        # L2-layer alerts (ARP spoofing, MAC flooding, STP/CDP/DTP/VTP
        # attacks, VLAN hopping, ...) have no corresponding row in `flows`
        # - that table only tracks IP-layer traffic - so without this, the
        # dashboard's "Attack Distribution" chart was completely blind to
        # every L2 detection, even though the Alerts panel showed them
        # correctly (tagged layer='L2'). Merged in here by attack_type so
        # the chart reflects everything the system has actually detected.
        l2_where = " WHERE layer = 'L2'"
        l2_params = []
        if sid is not None:
            l2_where += " AND session_id = ?"
            l2_params.append(sid)
        cursor = conn.execute(f"SELECT attack_type, COUNT(*) as count FROM alerts{l2_where} GROUP BY attack_type", l2_params)
        for row in cursor.fetchall():
            attack_dist_map[row["attack_type"]] = attack_dist_map.get(row["attack_type"], 0) + row["count"]

        attack_dist = [
            {"attack_type": k, "count": v}
            for k, v in sorted(attack_dist_map.items(), key=lambda kv: -kv[1])
        ]

        cursor = conn.execute(f"""
            SELECT protocol, COUNT(*) as count 
            FROM flows 
            {flow_where}
            GROUP BY protocol
        """, p)
        protocol_dist = [dict(row) for row in cursor.fetchall()]

        from time import time
        hour_ago = time() - 3600
        cursor = conn.execute(
            f"SELECT COUNT(*) as recent_flows FROM flows{flow_where}{' AND' if sid is not None else ' WHERE'} timestamp > ?",
            p + [hour_ago]
        )
        recent_flows = cursor.fetchone()[0]

        cursor = conn.execute(
            f"SELECT COUNT(*) as recent_alerts FROM alerts{alert_where}{' AND' if sid is not None else ' WHERE'} timestamp > ?",
            p + [hour_ago]
        )
        recent_alerts = cursor.fetchone()[0]

        return {
            "session_id": sid,
            "total_flows": total_flows,
            "total_alerts": total_alerts,
            "total_packets_logged": total_packets_logged,
            "avg_threat_score": round(avg_threat, 2),
            "attack_distribution": attack_dist,
            "protocol_distribution": protocol_dist,
            "recent_flows": recent_flows,
            "recent_alerts": recent_alerts
        }

def get_traffic_timeseries(minutes=60, session_id="current"):
    with get_db() as conn:
        sid = _resolve_session_filter(conn, session_id)
        from time import time
        start = time() - (minutes * 60)
        query = """
            SELECT 
                strftime('%Y-%m-%d %H:%M', datetime(timestamp, 'unixepoch')) as minute,
                COUNT(*) as flow_count,
                SUM(total_bytes) as byte_count,
                AVG(threat_score) as avg_threat
            FROM flows
            WHERE timestamp > ?
        """
        params = [start]
        if sid is not None:
            query += " AND session_id = ?"
            params.append(sid)
        query += " GROUP BY minute ORDER BY minute"
        cursor = conn.execute(query, params)
        return [dict(row) for row in cursor.fetchall()]

def get_top_talkers(limit=8, minutes=60, session_id="current"):
    """Top source/destination IPs by traffic volume, for network-wide visibility."""
    with get_db() as conn:
        sid = _resolve_session_filter(conn, session_id)
        from time import time
        start = time() - (minutes * 60)
        session_clause = " AND session_id = ?" if sid is not None else ""
        session_params = [sid] if sid is not None else []

        cursor = conn.execute(f"""
            SELECT src_ip as ip, SUM(total_bytes) as bytes, SUM(packet_count) as packets, COUNT(*) as flows
            FROM flows WHERE timestamp > ?{session_clause}
            GROUP BY src_ip ORDER BY bytes DESC LIMIT ?
        """, [start] + session_params + [limit])
        sources = [dict(row) for row in cursor.fetchall()]

        cursor = conn.execute(f"""
            SELECT dst_port as port, protocol, COUNT(*) as flows, SUM(total_bytes) as bytes
            FROM flows WHERE timestamp > ?{session_clause}
            GROUP BY dst_port, protocol ORDER BY flows DESC LIMIT ?
        """, [start] + session_params + [limit])
        ports = [dict(row) for row in cursor.fetchall()]

        return {"top_sources": sources, "top_ports": ports}


def start_new_session(label=None):
    """Ends the current session and opens a new one. Returns the new session id.
    Nothing is deleted - every row already written keeps the session_id it
    was created under, so it stays fully queryable via get_stats(session_id=...)
    / get_recent_flows(session_id=...) / etc, or by browsing get_sessions()."""
    with get_db() as conn:
        cursor = conn.cursor()
        old_id = get_current_session_id(conn)
        now = _time.time()

        cursor.execute("UPDATE sessions SET ended_at = ? WHERE id = ?", (now, old_id))
        cursor.execute(
            "INSERT INTO sessions (started_at, ended_at, label) VALUES (?, NULL, ?)",
            (now, label)
        )
        new_id = cursor.lastrowid
        cursor.execute(
            "UPDATE meta SET value = ? WHERE key = 'current_session_id'",
            (str(new_id),)
        )
        conn.commit()
        return old_id, new_id


def clear_session():
    """Backs the dashboard's 'Clear All' button. Archives the current
    session (with a summary snapshot of what it contained) and starts a
    fresh, empty one. All of the old session's flows/alerts/packets remain
    in the database under their original session_id - archived, not erased -
    and stay reachable via get_sessions() / the session_id-scoped getters."""
    with get_db() as conn:
        old_id = get_current_session_id(conn)

    # Snapshot what's being archived before rolling over, so the caller can
    # show/return "archived N alerts, M flows" instead of a silent reset.
    archived_summary = get_stats(session_id=old_id)

    old_id, new_id = start_new_session()

    return {
        "archived_session_id": old_id,
        "archived_summary": {
            "total_flows": archived_summary["total_flows"],
            "total_alerts": archived_summary["total_alerts"],
            "total_packets_logged": archived_summary["total_packets_logged"],
            "avg_threat_score": archived_summary["avg_threat_score"],
        },
        "new_session_id": new_id,
        "cleared_at": _time.time(),
    }


def get_sessions(limit=50):
    """List past sessions (most recent first) with a summary of what each
    contains, so archived data from 'Clear All' stays discoverable rather
    than just sitting invisibly in the database."""
    with get_db() as conn:
        cursor = conn.execute(
            "SELECT id, started_at, ended_at, label FROM sessions ORDER BY id DESC LIMIT ?",
            (limit,)
        )
        sessions = [dict(row) for row in cursor.fetchall()]

    for s in sessions:
        stats = get_stats(session_id=s["id"])
        s["total_flows"] = stats["total_flows"]
        s["total_alerts"] = stats["total_alerts"]
        s["total_packets_logged"] = stats["total_packets_logged"]
        s["avg_threat_score"] = stats["avg_threat_score"]
        s["is_current"] = (s["id"] == get_current_session_id())

    return sessions
