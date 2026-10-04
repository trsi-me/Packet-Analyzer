# -*- coding: utf-8 -*-
# SQLite helpers with a re-entrant lock for thread-safe access.
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "packet_analyzer.db")
SETTINGS_PATH = os.path.join(BASE_DIR, "local_settings.json")

_db_lock = threading.RLock()

# Cache heavy aggregations: GROUP BY on large tables can hold the DB lock too long.
_QUERY_CACHE_TTL_S = 3.0
_agg_cache: Optional[Dict[str, Any]] = None
_agg_cache_ts: float = 0.0
_proto_cache: Optional[Dict[str, int]] = None
_proto_cache_ts: float = 0.0

DEFAULT_SETTINGS = {
    "interface": "",
    "max_packets": 100000,
}


def _ensure_settings_file() -> None:
    if not os.path.isfile(SETTINGS_PATH):
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_SETTINGS, f, ensure_ascii=False, indent=2)


def load_settings() -> Dict[str, Any]:
    _ensure_settings_file()
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in DEFAULT_SETTINGS.items():
            data.setdefault(k, v)
        return data
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULT_SETTINGS)


def save_settings(settings: Dict[str, Any]) -> None:
    _ensure_settings_file()
    current = load_settings()
    current.update(settings)
    with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
        json.dump(current, f, ensure_ascii=False, indent=2)


def _apply_pragmas(conn: sqlite3.Connection) -> None:
    # Before any write transaction: prefer WAL so a rollback journal is not used.
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("PRAGMA synchronous=NORMAL")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("PRAGMA busy_timeout=5000")
    except sqlite3.OperationalError:
        pass


@contextmanager
def get_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10.0)
    conn.row_factory = sqlite3.Row
    _apply_pragmas(conn)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def shutdown_wal() -> None:
    """WAL checkpoint on shutdown; no global lock to avoid exit deadlock."""
    try:
        c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=1.0)
        try:
            c.execute("PRAGMA busy_timeout=500")
            _apply_pragmas(c)
            c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        finally:
            c.close()
    except Exception:
        pass


def _remove_stale_rollback_journal_if_wal() -> None:
    jpath = DB_PATH + "-journal"
    if not os.path.isfile(jpath):
        return
    try:
        c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=2.0)
        try:
            _apply_pragmas(c)
            mode = c.execute("PRAGMA journal_mode").fetchone()
        finally:
            c.close()
    except Exception:
        return
    m = (mode[0] or "").lower() if mode else ""
    if m == "wal":
        try:
            os.remove(jpath)
        except OSError:
            pass


def init_db() -> None:
    with _db_lock:
        with get_connection() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    src_port INTEGER,
                    dst_port INTEGER,
                    protocol TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    ttl INTEGER,
                    payload TEXT,
                    raw_summary TEXT
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    start_time DATETIME,
                    end_time DATETIME,
                    total_packets INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'active'
                );
                CREATE TABLE IF NOT EXISTS saved_filters (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    filter_json TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_packets_timestamp ON packets(timestamp);
                CREATE INDEX IF NOT EXISTS idx_packets_src_ip ON packets(src_ip);
                CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
                """
            )
    _ensure_settings_file()
    _remove_stale_rollback_journal_if_wal()


def invalidate_query_cache() -> None:
    global _agg_cache, _proto_cache
    _agg_cache = None
    _proto_cache = None


def get_db_size_bytes() -> int:
    try:
        return os.path.getsize(DB_PATH)
    except OSError:
        return 0


def insert_packet(
    src_ip: str,
    dst_ip: str,
    src_port: Optional[int],
    dst_port: Optional[int],
    protocol: str,
    size: int,
    ttl: Optional[int],
    payload: Optional[str],
    raw_summary: Optional[str],
) -> Optional[int]:
    max_packets = int(load_settings().get("max_packets", 100000))
    with _db_lock:
        with get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO packets (src_ip, dst_ip, src_port, dst_port, protocol, size, ttl, payload, raw_summary)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    size,
                    ttl,
                    payload,
                    raw_summary,
                ),
            )
            pid = cur.lastrowid
            conn.execute(
                """
                UPDATE sessions SET total_packets = total_packets + 1
                WHERE id = (SELECT id FROM sessions WHERE status = 'active' ORDER BY id DESC LIMIT 1)
                """
            )
            _trim_packets_locked(conn, max_packets)
        return pid


def _trim_packets_locked(conn: sqlite3.Connection, max_packets: int) -> None:
    row = conn.execute("SELECT COUNT(*) FROM packets").fetchone()
    count = row[0] if row else 0
    if count <= max_packets:
        return
    excess = count - max_packets
    conn.execute(
        """
        DELETE FROM packets WHERE id IN (
            SELECT id FROM packets ORDER BY timestamp ASC LIMIT ?
        )
        """,
        (excess,),
    )


def create_session() -> int:
    with _db_lock:
        with get_connection() as conn:
            cur = conn.execute(
                """
                INSERT INTO sessions (start_time, end_time, total_packets, status)
                VALUES (datetime('now'), NULL, 0, 'active')
                """
            )
            return int(cur.lastrowid)


def close_active_session() -> None:
    with _db_lock:
        with get_connection() as conn:
            conn.execute(
                """
                UPDATE sessions SET end_time = datetime('now'), status = 'stopped'
                WHERE status = 'active'
                """
            )


def count_packets() -> int:
    with _db_lock:
        with get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) FROM packets").fetchone()
            return int(row[0]) if row else 0


def clear_all_packets() -> None:
    # Deletes packets + sessions; does not remove saved_filters or settings JSON.
    with _db_lock:
        with get_connection() as conn:
            conn.execute("DELETE FROM packets")
            conn.execute("DELETE FROM sessions")
            try:
                conn.execute(
                    "DELETE FROM sqlite_sequence WHERE name IN ('packets', 'sessions')"
                )
            except sqlite3.OperationalError:
                pass
    invalidate_query_cache()


def get_packets_page(
    page: int = 1,
    per_page: int = 50,
    protocol: Optional[str] = None,
    search: Optional[str] = None,
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    port: Optional[str] = None,
    time_from: Optional[str] = None,
    time_to: Optional[str] = None,
    size_min: Optional[int] = None,
    size_max: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    page = max(1, page)
    per_page = max(1, min(200, per_page))
    where: List[str] = []
    params: List[Any] = []

    if protocol and protocol != "all":
        where.append("protocol = ?")
        params.append(protocol)
    if src_ip:
        where.append("src_ip LIKE ?")
        params.append(f"%{src_ip}%")
    if dst_ip:
        where.append("dst_ip LIKE ?")
        params.append(f"%{dst_ip}%")
    if port:
        p = port.strip()
        if p.isdigit():
            pi = int(p)
            where.append("(src_port = ? OR dst_port = ?)")
            params.extend([pi, pi])
        else:
            where.append("(CAST(src_port AS TEXT) LIKE ? OR CAST(dst_port AS TEXT) LIKE ?)")
            params.extend([f"%{p}%", f"%{p}%"])
    if search:
        s = f"%{search.strip()}%"
        where.append(
            "(src_ip LIKE ? OR dst_ip LIKE ? OR CAST(src_port AS TEXT) LIKE ? OR CAST(dst_port AS TEXT) LIKE ?)"
        )
        params.extend([s, s, s, s])
    if time_from:
        where.append("timestamp >= ?")
        params.append(time_from)
    if time_to:
        where.append("timestamp <= ?")
        params.append(time_to)
    if size_min is not None:
        where.append("size >= ?")
        params.append(size_min)
    if size_max is not None:
        where.append("size <= ?")
        params.append(size_max)

    wh = (" WHERE " + " AND ".join(where)) if where else ""

    with _db_lock:
        with get_connection() as conn:
            total_row = conn.execute(
                f"SELECT COUNT(*) FROM packets{wh}", params
            ).fetchone()
            total = int(total_row[0]) if total_row else 0
            offset = (page - 1) * per_page
            rows = conn.execute(
                f"""
                SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size, ttl, payload, raw_summary
                FROM packets{wh}
                ORDER BY id DESC
                LIMIT ? OFFSET ?
                """,
                params + [per_page, offset],
            ).fetchall()

    out = []
    for r in rows:
        out.append(
            {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "src_ip": r["src_ip"],
                "dst_ip": r["dst_ip"],
                "src_port": r["src_port"],
                "dst_port": r["dst_port"],
                "protocol": r["protocol"],
                "size": r["size"],
                "ttl": r["ttl"],
                "payload": r["payload"],
                "raw_summary": r["raw_summary"],
            }
        )
    return out, total


def get_packet_by_id(packet_id: int) -> Optional[Dict[str, Any]]:
    with _db_lock:
        with get_connection() as conn:
            r = conn.execute(
                "SELECT * FROM packets WHERE id = ?", (packet_id,)
            ).fetchone()
            if not r:
                return None
            return dict(r)


def protocol_distribution() -> Dict[str, int]:
    global _proto_cache, _proto_cache_ts
    now = time.time()
    with _db_lock:
        if _proto_cache is not None and (now - _proto_cache_ts) < _QUERY_CACHE_TTL_S:
            return dict(_proto_cache)
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT protocol, COUNT(*) as c FROM packets GROUP BY protocol"
            ).fetchall()
        out = {r["protocol"]: r["c"] for r in rows}
        _proto_cache = out
        _proto_cache_ts = time.time()
        return dict(out)


def top_ips(kind: str = "src", limit: int = 10) -> List[Dict[str, Any]]:
    col = "src_ip" if kind == "src" else "dst_ip"
    with _db_lock:
        with get_connection() as conn:
            rows = conn.execute(
                f"""
                SELECT {col} as ip, COUNT(*) as cnt FROM packets
                GROUP BY {col} ORDER BY cnt DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return [{"ip": r["ip"], "count": r["cnt"]} for r in rows]


def top_ports(limit: int = 15) -> List[Dict[str, Any]]:
    with _db_lock:
        with get_connection() as conn:
            rows = conn.execute(
                """
                SELECT dst_port as port, COUNT(*) as cnt FROM packets
                WHERE dst_port IS NOT NULL
                GROUP BY dst_port ORDER BY cnt DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return [{"port": r["port"], "count": r["cnt"]} for r in rows]


def packets_over_time(bucket: str) -> List[Dict[str, Any]]:
    # bucket: hour | day | week — group counts by time bucket.
    with _db_lock:
        with get_connection() as conn:
            if bucket == "week":
                rows = conn.execute(
                    """
                    SELECT strftime('%Y-%W', timestamp) as t, COUNT(*) as c
                    FROM packets GROUP BY t ORDER BY t DESC LIMIT 50
                    """
                ).fetchall()
            elif bucket == "day":
                rows = conn.execute(
                    """
                    SELECT date(timestamp) as t, COUNT(*) as c
                    FROM packets GROUP BY t ORDER BY t DESC LIMIT 90
                    """
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as t, COUNT(*) as c
                    FROM packets GROUP BY t ORDER BY t DESC LIMIT 72
                    """
                ).fetchall()
    return [{"label": r["t"], "count": r["c"]} for r in reversed(rows)]


def save_filter(name: str, filter_json: str) -> int:
    with _db_lock:
        with get_connection() as conn:
            cur = conn.execute(
                "INSERT INTO saved_filters (name, filter_json) VALUES (?, ?)",
                (name, filter_json),
            )
            return int(cur.lastrowid)


def list_saved_filters() -> List[Dict[str, Any]]:
    with _db_lock:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT id, name, filter_json, created_at FROM saved_filters ORDER BY id DESC"
            ).fetchall()
    return [dict(r) for r in rows]


def aggregate_stats() -> Dict[str, Any]:
    global _agg_cache, _agg_cache_ts
    now = time.time()
    with _db_lock:
        if _agg_cache is not None and (now - _agg_cache_ts) < _QUERY_CACHE_TTL_S:
            return dict(_agg_cache)
        with get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            top_p = conn.execute(
                """
                SELECT protocol, COUNT(*) as c FROM packets
                GROUP BY protocol ORDER BY c DESC LIMIT 1
                """
            ).fetchone()
            top_s = conn.execute(
                """
                SELECT src_ip, COUNT(*) as c FROM packets
                GROUP BY src_ip ORDER BY c DESC LIMIT 1
                """
            ).fetchone()
        out: Dict[str, Any] = {
            "total_packets": int(total),
            "top_protocol": top_p["protocol"] if top_p else None,
            "top_protocol_count": int(top_p["c"]) if top_p else 0,
            "top_src_ip": top_s["src_ip"] if top_s else None,
            "top_src_count": int(top_s["c"]) if top_s else 0,
        }
        _agg_cache = out
        _agg_cache_ts = time.time()
        return dict(out)


def recent_packet_ids(limit: int = 10) -> List[int]:
    with _db_lock:
        with get_connection() as conn:
            rows = conn.execute(
                "SELECT id FROM packets ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    return [r["id"] for r in rows]


def get_recent_packets_detail(limit: int = 10) -> List[Dict[str, Any]]:
    with _db_lock:
        with get_connection() as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size
                FROM packets ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return [dict(r) for r in rows]


def anomaly_metrics() -> Dict[str, Any]:
    # Heuristic spike detection + watched suspicious ports.
    suspicious = [4444, 31337, 12345, 6667, 5900, 3389, 22, 23, 135, 445]
    with _db_lock:
        with get_connection() as conn:
            last5 = conn.execute(
                """
                SELECT COUNT(*) FROM packets
                WHERE datetime(timestamp) >= datetime('now', '-5 minutes')
                """
            ).fetchone()[0]
            prev5 = conn.execute(
                """
                SELECT COUNT(*) FROM packets
                WHERE datetime(timestamp) < datetime('now', '-5 minutes')
                  AND datetime(timestamp) >= datetime('now', '-10 minutes')
                """
            ).fetchone()[0]
            sus_rows = conn.execute(
                """
                SELECT dst_port, COUNT(*) as c FROM packets
                WHERE dst_port IN ({})
                GROUP BY dst_port ORDER BY c DESC
                """.format(",".join("?" * len(suspicious))),
                suspicious,
            ).fetchall()
    spike = False
    if prev5 > 0 and last5 > prev5 * 3:
        spike = True
    elif prev5 == 0 and last5 > 100:
        spike = True
    return {
        "spike_detected": spike,
        "packets_last_5m": int(last5),
        "packets_prev_5m": int(prev5),
        "suspicious_ports": [{"port": r["dst_port"], "count": r["c"]} for r in sus_rows],
    }
