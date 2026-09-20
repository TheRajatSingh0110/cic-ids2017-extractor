"""Extraction of per-packet numeric features from captured packets.

The object model mirrors the fields of CICFlowMeter's ``BasicPacketInfo``:

+------------------------+-----------------------------------------------+
| field                  | meaning (reference source)                    |
+========================+===============================================+
| ``payload_bytes``      | TCP/UDP payload length                        |
| ``header_bytes``       | TCP header length (data offset*4) / 8 (UDP)   |
| ``tcp_window``         | TCP ``window`` field (0 for UDP)              |
| ``protocol``           | 6 = TCP, 17 = UDP                             |
| ``timestamp_us``       | capture timestamp in microseconds             |
+------------------------+-----------------------------------------------+

``packet_info_from_scapy`` converts a scapy ``Packet`` into a ``PacketInfo``.
Everything else can build a ``PacketInfo`` directly (used by the tests).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

__all__ = ["PacketInfo", "packet_info_from_scapy", "TCP", "UDP"]

TCP = 6
UDP = 17

#: TCP flag bit positions used by scapy's ``TCP.flags`` (LSB first).
_FLAG_FIN = 0x01
_FLAG_SYN = 0x02
_FLAG_RST = 0x04
_FLAG_PSH = 0x08
_FLAG_ACK = 0x10
_FLAG_URG = 0x20
_FLAG_ECE = 0x40
_FLAG_CWR = 0x80


@dataclass
class PacketInfo:
    """Single-packet summary consumed by the flow machinery (CICFlowMeter units)."""

    #: source IP address (string).
    src_ip: str
    #: destination IP address (string).
    dst_ip: str
    #: source transport port.
    src_port: int
    #: destination transport port.
    dst_port: int
    #: IP protocol number (6 = TCP, 17 = UDP).
    protocol: int
    #: capture timestamp in microseconds.
    timestamp_us: int
    #: transport payload size in bytes.
    payload_bytes: int
    #: transport header size in bytes (TCP data offset*4, or 8 for UDP).
    header_bytes: int
    #: TCP window value (0 for non-TCP).
    tcp_window: int = 0
    #: TCP flag bits (see final constants).
    flag_fin: bool = False
    flag_syn: bool = False
    flag_rst: bool = False
    flag_psh: bool = False
    flag_ack: bool = False
    flag_urg: bool = False
    flag_cwr: bool = False
    flag_ece: bool = False
    #: original scapy packet (retained for debugging/tools only).
    raw: Optional[object] = field(default=None, repr=False)

    @property
    def is_tcp(self) -> bool:
        return self.protocol == TCP

    @property
    def is_udp(self) -> bool:
        return self.protocol == UDP


def _ip_src_dst(packet) -> Optional[tuple]:
    """Return ``(src_ip, dst_ip, ip_hdr_len, ip_total_len)`` or None for non-IP."""
    if packet is None:
        return None
    if packet.haslayer("IP"):
        ip = packet["IP"]
        ihl = ip.ihl if ip.ihl is not None else 5
        ip_len = int(ip.len) if ip.len is not None else 0
        return str(ip.src), str(ip.dst), ihl * 4, ip_len
    if packet.haslayer("IPv6"):
        ip6 = packet["IPv6"]
        total = len(bytes(ip6))
        return str(ip6.src), str(ip6.dst), 40, total
    return None


def _tcp_header_bytes(tcp) -> int:
    """TCP header length in bytes (``data offset * 4``, 20 with no options).

    ``dataofs`` is ``None`` on freshly-built scapy packets until the layer is
    serialised, so fall back to the serialised data-offset nibble.
    """
    do = tcp.dataofs
    if do:
        return do * 4
    try:
        raw = bytes(tcp)
        if len(raw) >= 4:
            return ((raw[12] >> 4) & 0x0F) * 4
    except Exception:  # pragma: no cover - defensive
        pass
    return 20


def _tcp_payload(ip_total: int, ip_hdr: int, tcp) -> int:
    tcp_hdr = _tcp_header_bytes(tcp)
    if ip_total > 0:
        return max(0, ip_total - ip_hdr - tcp_hdr)
    return max(0, len(bytes(tcp)) - tcp_hdr)


def _udp_payload(udp) -> int:
    udp_len = int(udp.len) if udp.len is not None else 0
    if udp_len >= 8:
        return max(0, udp_len - 8)
    return max(0, len(bytes(udp)) - 8)


def packet_info_from_scapy(packet) -> Optional[PacketInfo]:
    """Convert a scapy ``Packet`` to a ``PacketInfo`` (None for non-IP/TCP/UDP).

    * only IPv4/IPv6 with a TCP or UDP transport are converted,
    * IP fragments other than the first are ignored,
    * timestamps are converted from scapy's float seconds to microseconds.

    Payload/header sizes follow the reference's jnetpcap parsing (see module doc).
    """
    addresses = _ip_src_dst(packet)
    if addresses is None:
        return None
    src_ip, dst_ip, ip_hdr, ip_total = addresses
    if packet.haslayer("IP"):
        ip = packet["IP"]
        if int(ip.frag) not in (0,):  # fragmented: transport headers are unsafe
            return None
    ts_us = int(round(packet.time * 1_000_000)) if packet.time else 0

    if packet.haslayer("TCP"):
        tcp = packet["TCP"]
        tcp_hdr = _tcp_header_bytes(tcp)
        flags_val = tcp.flags
        if hasattr(flags_val, "value"):
            flags = int(flags_val.value)
        else:
            flags = int(flags_val)
        return PacketInfo(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(tcp.sport),
            dst_port=int(tcp.dport),
            protocol=TCP,
            timestamp_us=ts_us,
            payload_bytes=_tcp_payload(ip_total, ip_hdr, tcp),
            header_bytes=tcp_hdr,
            tcp_window=int(tcp.window),
            flag_fin=bool(flags & _FLAG_FIN),
            flag_syn=bool(flags & _FLAG_SYN),
            flag_rst=bool(flags & _FLAG_RST),
            flag_psh=bool(flags & _FLAG_PSH),
            flag_ack=bool(flags & _FLAG_ACK),
            flag_urg=bool(flags & _FLAG_URG),
            flag_cwr=bool(flags & _FLAG_CWR),
            flag_ece=bool(flags & _FLAG_ECE),
            raw=packet,
        )

    if packet.haslayer("UDP"):
        udp = packet["UDP"]
        return PacketInfo(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=int(udp.sport),
            dst_port=int(udp.dport),
            protocol=UDP,
            timestamp_us=ts_us,
            payload_bytes=_udp_payload(udp),
            header_bytes=8,
            tcp_window=0,
            raw=packet,
        )

    return None