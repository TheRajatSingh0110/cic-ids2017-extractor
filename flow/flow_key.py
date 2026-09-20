"""5-tuple flow key helpers - the flow-id strings used by CICFlowMeter.

A CICFlowMeter ``flowId`` is the string ``"srcIP-dstIP-srcPort-dstPort-protocol"``
with the source always listed first (``fwdFlowId``) or always the receiver first
(``bwdFlowId``).  ``FlowGenerator`` stores live flows keyed on ``fwdFlowId`` and
re-uses a flow when an incoming packet matches either the forward or the backward
spelling (this is what makes the flows bidirectional).
"""

from __future__ import annotations

import socket
from typing import Optional


def fwd_flow_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> str:
    """Flow-id string in the forward direction (source first), reference format."""
    return f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{protocol}"


def bwd_flow_id(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: int) -> str:
    """Flow-id string in the backward direction (destination first)."""
    return f"{dst_ip}-{src_ip}-{dst_port}-{src_port}-{protocol}"


def is_ipv4(text: str) -> bool:
    """True if ``text`` parses as an IPv4 dotted-quad address."""
    try:
        socket.inet_pton(socket.AF_INET, text)
    except (OSError, ValueError):
        return False
    return True


def is_ipv6(text: str) -> bool:
    """True if ``text`` parses as an IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET6, text)
    except (OSError, ValueError):
        return False
    return True


def normalize_ip(ip: Optional[str]) -> Optional[str]:
    """Return a canonical str form of an IP address (or ``None``).

    Convenience for capture backends that may hand us ``bytes``/``None``.
    """
    if ip is None:
        return None
    if isinstance(ip, bytes):
        try:
            return socket.inet_ntop(socket.AF_INET6 if len(ip) == 16 else socket.AF_INET, ip)
        except (OSError, ValueError):
            return str(ip)
    return str(ip)