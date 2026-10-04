# -*- coding: utf-8 -*-
# Classify Scapy packets and extract fields for DB/UI.
import binascii
import os
import sys
from typing import Any, Dict, Optional

# على ويندوز 10+ يساعد Python في إيجاد wpcap.dll داخل مجلد Npcap
if sys.platform == "win32":
    _npcap_dir = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "Npcap")
    if os.path.isdir(_npcap_dir) and hasattr(os, "add_dll_directory"):
        try:
            os.add_dll_directory(_npcap_dir)
        except OSError:
            pass


def _silence_scapy_libpcap_warning() -> None:
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

from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw  # noqa: F401
from scapy.packet import Packet


def _safe_str(data: Optional[bytes]) -> str:
    if not data:
        return ""
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return binascii.hexlify(data).decode("ascii")


def _payload_hex(pkt: Packet) -> str:
    if Raw in pkt:
        raw = pkt[Raw].load
        if len(raw) > 4096:
            raw = raw[:4096]
        return binascii.hexlify(raw).decode("ascii")
    return ""


def _ip_pair(pkt: Packet) -> tuple:
    src_ip, dst_ip = "0.0.0.0", "0.0.0.0"
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif IPv6 in pkt:
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst
    return src_ip, dst_ip


def _ports(pkt: Packet) -> tuple:
    sp: Optional[int] = None
    dp: Optional[int] = None
    if TCP in pkt:
        sp = int(pkt[TCP].sport)
        dp = int(pkt[TCP].dport)
    elif UDP in pkt:
        sp = int(pkt[UDP].sport)
        dp = int(pkt[UDP].dport)
    return sp, dp


def _ttl(pkt: Packet) -> Optional[int]:
    if IP in pkt:
        return int(pkt[IP].ttl)
    return None


def classify_and_extract(pkt: Packet) -> Dict[str, Any]:
    # Map packet layers to protocol + payload/summary for storage.
    src_ip, dst_ip = _ip_pair(pkt)
    src_port, dst_port = _ports(pkt)
    ttl = _ttl(pkt)
    size = len(pkt)
    raw_summary = pkt.summary()

    protocol = "Other"
    payload_text = ""

    if ARP in pkt:
        protocol = "ARP"
        payload_text = raw_summary
    elif ICMP in pkt:
        protocol = "ICMP"
        payload_text = _payload_hex(pkt) or raw_summary
    elif DNS in pkt:
        protocol = "DNS"
        payload_text = _payload_hex(pkt) or raw_summary
    elif TCP in pkt:
        dp = dst_port or 0
        sp = src_port or 0
        if dp in (80, 443, 8080) or sp in (80, 443, 8080):
            protocol = "HTTP"
            if Raw in pkt:
                payload_text = _safe_str(pkt[Raw].load)
            else:
                payload_text = raw_summary
        else:
            protocol = "TCP"
            payload_text = _payload_hex(pkt) or raw_summary
    elif UDP in pkt:
        dp = dst_port or 0
        sp = src_port or 0
        if dp == 53 or sp == 53:
            protocol = "DNS"
        else:
            protocol = "UDP"
        payload_text = _payload_hex(pkt) or raw_summary
    elif IP in pkt or IPv6 in pkt:
        protocol = "Other"

    if not payload_text:
        payload_text = _payload_hex(pkt) or raw_summary

    return {
        "src_ip": str(src_ip),
        "dst_ip": str(dst_ip),
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "size": size,
        "ttl": ttl,
        "payload": payload_text[:8000] if payload_text else "",
        "raw_summary": raw_summary,
    }


def format_packet_layers(pkt: Packet) -> str:
    # Human-readable layer summaries for the detail modal.
    lines = []
    try:
        lay = pkt
        while lay:
            lines.append(str(lay.summary()))
            lay = lay.payload if lay.payload else None
            if lay is not None and not hasattr(lay, "summary"):
                break
    except Exception as e:
        lines.append(str(e))
    return "\n".join(lines)
