# -*- coding: utf-8 -*-
# Flask + Socket.IO: use threading (not eventlet) so Windows is responsive (Ctrl+C, DB, UI).
import csv
import io
import json
import os
import sys
import ctypes

def _silence_scapy_libpcap_warning() -> None:
    # Mutes Scapy's libpcap warning line; install Npcap to actually capture.
    try:
        import scapy.error as _se

        if getattr(_se, "_packet_analyzer_warn_patch", False):
            return
        _orig = _se.warning

        def _w(x, *a, **k):
            try:
                if isinstance(x, str) and "No libpcap provider" in x:
                    return
            except Exception:
                pass
            return _orig(x, *a, **k)

        _se.warning = _w
        _se._packet_analyzer_warn_patch = True
    except Exception:
        pass


_silence_scapy_libpcap_warning()

from flask import Flask, Response, jsonify, render_template, request, send_from_directory
from flask_socketio import SocketIO

import database as db
import sniffer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
APP_VERSION = "1.0.0"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(24).hex()
# threading: Werkzeug multi-thread; avoids eventlet freezing on SQLite locks + slow Ctrl+C on Windows
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    ping_timeout=60,
    ping_interval=25,
)


def is_windows_admin() -> bool:
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


@app.route("/assets/<path:filename>")
def serve_assets(filename: str):
    try:
        return send_from_directory(os.path.join(BASE_DIR, "assets"), filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@app.route("/")
def index():
    return render_template("index.html", version=APP_VERSION)


@app.route("/packets")
def packets_page():
    return render_template("packets.html", version=APP_VERSION)


@app.route("/analysis")
def analysis_page():
    return render_template("analysis.html", version=APP_VERSION)


@app.route("/filters")
def filters_page():
    return render_template("filters.html", version=APP_VERSION)


@app.route("/settings")
def settings_page():
    return render_template("settings.html", version=APP_VERSION)


@app.post("/api/start")
def api_start():
    try:
        if not is_windows_admin():
            return (
                jsonify(
                    {
                        "ok": False,
                        "message": "يلزم تشغيل التطبيق بصلاحيات المسؤول لالتقاط الحزم على ويندوز.",
                    }
                ),
                403,
            )
        body = request.get_json(silent=True) or {}
        iface = body.get("interface")
        ok, msg = sniffer.start_capture(interface=iface)
        if not ok:
            return jsonify({"ok": False, "message": msg}), 400
        return jsonify({"ok": True, "message": msg})
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500


@app.post("/api/stop")
def api_stop():
    try:
        ok, msg = sniffer.stop_capture()
        if not ok:
            return jsonify({"ok": False, "message": msg}), 400
        return jsonify({"ok": True, "message": msg})
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500


@app.get("/api/status")
def api_status():
    try:
        return jsonify(
            {
                "recording": sniffer.is_recording(),
                "admin": is_windows_admin(),
                "version": APP_VERSION,
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def _int_param(name: str, default: int) -> int:
    try:
        return int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default


def _optional_int(name: str):
    v = request.args.get(name)
    if v is None or v == "":
        return None
    try:
        return int(v)
    except ValueError:
        return None


def _packet_query_args():
    return {
        "page": max(1, _int_param("page", 1)),
        "per_page": max(1, min(200, _int_param("per_page", 50))),
        "protocol": request.args.get("protocol") or None,
        "search": request.args.get("search") or None,
        "src_ip": request.args.get("src_ip") or None,
        "dst_ip": request.args.get("dst_ip") or None,
        "port": request.args.get("port") or None,
        "time_from": request.args.get("time_from") or None,
        "time_to": request.args.get("time_to") or None,
        "size_min": _optional_int("size_min"),
        "size_max": _optional_int("size_max"),
    }


@app.get("/api/packets")
def api_packets():
    try:
        q = _packet_query_args()
        rows, total = db.get_packets_page(**q)
        per = q["per_page"] or 50
        pages = max(1, (total + per - 1) // per) if total else 1
        return jsonify(
            {
                "packets": rows,
                "total": total,
                "page": q["page"],
                "per_page": per,
                "pages": pages,
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/packets/<int:packet_id>")
def api_packet_one(packet_id: int):
    try:
        row = db.get_packet_by_id(packet_id)
        if not row:
            return jsonify({"error": "الحزمة غير موجودة."}), 404
        return jsonify(row)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/stats")
def api_stats():
    try:
        agg = db.aggregate_stats()
        agg["packets_per_second"] = sniffer.current_pps()
        agg["pps_history"] = sniffer.get_pps_history()
        return jsonify(agg)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/protocols")
def api_protocols():
    try:
        dist = db.protocol_distribution()
        return jsonify({"distribution": dist})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/top-ips")
def api_top_ips():
    try:
        limit = int(request.args.get("limit", 10))
        kind = request.args.get("kind", "both")
        if kind == "src":
            return jsonify({"src": db.top_ips("src", limit)})
        if kind == "dst":
            return jsonify({"dst": db.top_ips("dst", limit)})
        return jsonify(
            {
                "src": db.top_ips("src", limit),
                "dst": db.top_ips("dst", limit),
            }
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/settings")
def api_settings_get():
    try:
        s = db.load_settings()
        s["db_size_bytes"] = db.get_db_size_bytes()
        s["version"] = APP_VERSION
        return jsonify(s)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.post("/api/settings")
def api_settings_post():
    try:
        body = request.get_json(silent=True) or {}
        cur = db.load_settings()
        if "interface" in body:
            cur["interface"] = str(body.get("interface") or "")
        if "max_packets" in body:
            cur["max_packets"] = max(1000, int(body.get("max_packets", 100000)))
        db.save_settings(cur)
        return jsonify({"ok": True, "settings": cur})
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500


@app.get("/api/interfaces")
def api_interfaces():
    try:
        from scapy.all import get_if_list

        ifaces = get_if_list()
        return jsonify({"interfaces": [{"name": x, "id": i} for i, x in enumerate(ifaces)]})
    except Exception as e:
        return jsonify({"interfaces": [], "error": str(e)})


@app.post("/api/clear")
def api_clear():
    try:
        db.clear_all_packets()
        sniffer.reset_runtime_stats()
        return jsonify(
            {"ok": True, "message": "تم حذف بيانات الحزم والجلسات (لم تُمس الفلاتر المحفوظة)."}
        )
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500


@app.post("/api/filters/save")
def api_filters_save():
    try:
        body = request.get_json(silent=True) or {}
        name = (body.get("name") or "").strip()
        filt = body.get("filter") or body.get("filter_json")
        if not name:
            return jsonify({"ok": False, "message": "اسم الفلتر مطلوب."}), 400
        if isinstance(filt, dict):
            filt = json.dumps(filt, ensure_ascii=False)
        if not filt:
            return jsonify({"ok": False, "message": "محتوى الفلتر مطلوب."}), 400
        fid = db.save_filter(name, filt if isinstance(filt, str) else json.dumps(filt))
        return jsonify({"ok": True, "id": fid})
    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500


@app.get("/api/filters")
def api_filters_list():
    try:
        return jsonify({"filters": db.list_saved_filters()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/export/csv")
def api_export_csv():
    try:
        q = _packet_query_args()
        q["page"] = 1
        q["per_page"] = 100000
        rows, _ = db.get_packets_page(**q)
        output = io.StringIO()
        w = csv.writer(output)
        w.writerow(
            [
                "id",
                "timestamp",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "size",
                "ttl",
                "raw_summary",
            ]
        )
        for r in rows:
            w.writerow(
                [
                    r["id"],
                    r["timestamp"],
                    r["src_ip"],
                    r["dst_ip"],
                    r["src_port"],
                    r["dst_port"],
                    r["protocol"],
                    r["size"],
                    r["ttl"],
                    r.get("raw_summary") or "",
                ]
            )
        return Response(
            "\ufeff" + output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": "attachment; filename=packets_export.csv"
            },
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/analysis/ports")
def api_analysis_ports():
    try:
        return jsonify({"ports": db.top_ports(20)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/analysis/time")
def api_analysis_time():
    try:
        bucket = request.args.get("bucket", "hour")
        if bucket not in ("hour", "day", "week"):
            bucket = "hour"
        return jsonify({"series": db.packets_over_time(bucket), "bucket": bucket})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/analysis/anomalies")
def api_analysis_anomalies():
    try:
        return jsonify(db.anomaly_metrics())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/protocol-percentages")
def api_protocol_percentages():
    try:
        dist = db.protocol_distribution()
        total = sum(dist.values()) or 1
        pct = {k: round(100.0 * v / total, 2) for k, v in dist.items()}
        return jsonify({"percentages": pct, "total": total})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@socketio.on("connect")
def on_connect():
    try:
        socketio.emit(
            "status",
            {"recording": sniffer.is_recording()},
            namespace="/",
        )
    except Exception:
        pass


def main() -> None:
    db.init_db()
    sniffer.init_sniffer(socketio, app)
    print("", flush=True)
    print("  Packet Analyzer -- server is running.", flush=True)
    print("  Open in browser: http://127.0.0.1:5000", flush=True)
    print("  Press Ctrl+C to stop.", flush=True)
    print("", flush=True)
    try:
        socketio.run(
            app,
            host="127.0.0.1",
            port=5000,
            debug=False,
            use_reloader=False,
            allow_unsafe_werkzeug=True,
        )
    except KeyboardInterrupt:
        print("\n  Stopping (Ctrl+C).", flush=True)
    finally:
        try:
            sniffer.prepare_for_exit()
        except Exception:
            pass
        try:
            db.shutdown_wal()
        except Exception:
            pass


if __name__ == "__main__":
    main()
