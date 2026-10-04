# -*- coding: utf-8 -*-
# Scapy AsyncSniffer in a thread; Socket.IO emits for live UI.
import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional

import database as db

_socketio = None
_app = None
_async_sniffer: Any = None
_sniffer_thread: Optional[threading.Thread] = None
_recording = False
_lock = threading.RLock()
_stats_started = False
_stats_stop = threading.Event()

_packet_times = deque(maxlen=100000)
_pps_history: List[int] = []


def init_sniffer(socketio, app) -> None:
    global _socketio, _app, _stats_started
    _socketio = socketio
    _app = app
    if not _stats_started:
        _stats_started = True
        threading.Thread(target=_stats_loop_forever, daemon=True).start()


def _emit(event: str, data: Any) -> None:
    if _socketio is None or _app is None:
        return
    try:
        with _app.app_context():
            _socketio.emit(event, data, namespace="/")
    except Exception:
        pass


def _emit_status() -> None:
    _emit("status", {"recording": _recording})


def _stop_async_sniffer_in_background(sniffer: Any) -> None:
    # AsyncSniffer.stop() joins the capture thread; on Windows/pcap that can
    # block until the next packet. Run it outside the request path so /api/stop
    # returns immediately and the UI can update at once.
    try:
        if sniffer is not None:
            sniffer.stop()
    except Exception:
        pass


def _trim_second_window() -> None:
    now = time.time()
    while _packet_times and now - _packet_times[0] > 1.0:
        _packet_times.popleft()


def current_pps() -> int:
    with _lock:
        _trim_second_window()
        return len(_packet_times)


def get_pps_history() -> List[int]:
    with _lock:
        return list(_pps_history)


def _stats_loop_forever() -> None:
    global _pps_history
    while not _stats_stop.is_set():
        if _stats_stop.wait(1.0):
            break
        try:
            pps = current_pps() if _recording else 0
            with _lock:
                _pps_history.append(pps)
                if len(_pps_history) > 60:
                    _pps_history = _pps_history[-60:]
            stats = db.aggregate_stats()
            stats["packets_per_second"] = pps
            stats["pps_history"] = list(_pps_history)
            _emit("stats_update", stats)
        except Exception:
            pass


def _packet_callback(pkt: Any) -> None:
    if not _recording:
        return
    try:
        from analyzer import classify_and_extract

        data = classify_and_extract(pkt)
        pid = db.insert_packet(
            data["src_ip"],
            data["dst_ip"],
            data["src_port"],
            data["dst_port"],
            data["protocol"],
            data["size"],
            data["ttl"],
            data["payload"],
            data["raw_summary"],
        )
        now = time.time()
        with _lock:
            _packet_times.append(now)
        if pid:
            row = db.get_packet_by_id(pid)
            if row:
                _emit("new_packet", {"packet": dict(row)})
    except Exception:
        pass


def is_recording() -> bool:
    return _recording


def _windows_layer2_capture_available() -> tuple:
    # Windows: require Npcap/WinPcap (L2) before starting capture.
    import sys

    if sys.platform != "win32":
        return True, ""
    try:
        from scapy.arch.windows import _NotAvailableSocket
        from scapy.config import conf

        if conf.L2listen is _NotAvailableSocket:
            return (
                False,
                "لم يُعثر على Npcap/WinPcap. ثبّت Npcap من https://npcap.com "
                "مع تفعيل خيار «Install Npcap in WinPcap API-compatible mode» ثم أعد تشغيل الجهاز. "
                "شغّل التطبيق كمسؤول بعد التثبيت.",
            )
    except Exception as e:
        return False, f"تعذر التحقق من واجهة التقاط الحزم: {e}"
    return True, ""


def start_capture(interface: Optional[str] = None) -> tuple:
    # Returns (success: bool, message: str).
    global _async_sniffer, _sniffer_thread, _recording

    ok_cap, cap_msg = _windows_layer2_capture_available()
    if not ok_cap:
        return False, cap_msg

    with _lock:
        if _recording:
            return False, "التسجيل يعمل بالفعل."
        iface = interface if interface is not None else db.load_settings().get("interface")
        if not iface:
            iface = None
        if iface == "":
            iface = None

        try:
            db.create_session()
        except Exception as e:
            return False, f"تعذر إنشاء الجلسة: {e}"

        _recording = True
        _emit_status()

        def run_sniffer() -> None:
            global _async_sniffer, _recording
            try:
                from scapy.all import AsyncSniffer

                kwargs: Dict[str, Any] = {"prn": _packet_callback, "store": False}
                if iface:
                    kwargs["iface"] = iface
                _async_sniffer = AsyncSniffer(**kwargs)
                _async_sniffer.start()
            except Exception:
                _recording = False
                try:
                    db.close_active_session()
                except Exception:
                    pass
                _emit_status()

        _sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
        _sniffer_thread.start()
        time.sleep(0.5)

        if not _recording:
            try:
                db.close_active_session()
            except Exception:
                pass
            return False, "تعذر بدء المقتطف. تحقق من تثبيت Npcap واختيار الواجهة الصحيحة وصلاحيات المسؤول."

        return True, "تم بدء التسجيل."


def stop_capture() -> tuple:
    global _async_sniffer, _recording
    sniffer_to_join = None
    with _lock:
        if not _recording:
            return False, "التسجيل متوقف بالفعل."
        _recording = False
        sniffer_to_join = _async_sniffer
        _async_sniffer = None
        try:
            db.close_active_session()
        except Exception:
            pass
    _emit_status()
    if sniffer_to_join is not None:
        threading.Thread(
            target=_stop_async_sniffer_in_background,
            args=(sniffer_to_join,),
            daemon=True,
        ).start()
    return True, "تم إيقاف التسجيل."


def reset_runtime_stats() -> None:
    with _lock:
        _packet_times.clear()
        _pps_history.clear()


def prepare_for_exit() -> None:
    _stats_stop.set()
    try:
        if is_recording():
            stop_capture()
    except Exception:
        pass
