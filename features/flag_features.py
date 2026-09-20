"""TCP flag counting and CIC-IDS2017 naming.

CICFlowMeter counts eight flags with ``checkFlags`` in the order
``FIN, SYN, RST, PSH, ACK, URG, CWR, ECE``.  The CIC-IDS2017 CSV labels the
CWR counter "CWE Flag Count" (a well-known typo in the published header), so the
feature emitted at position 48 is the CWR count under the name "CWE Flag Count".
"""

from __future__ import annotations

from typing import Dict, List

__all__ = ["FLAG_KEYS", "flag_counts_to_cic_order", "flag_list_of_packet"]

#: canonical internal flag keys (CICFlowMeter ``initFlags`` / ``checkFlags``).
FLAG_KEYS = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWR", "ECE")

#: output order with the dataset's CWE naming for the CWR counter.
CIC_FLAG_ORDER = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWE", "ECE")


def flag_counts_to_cic_order(counts: Dict[str, int]) -> List[int]:
    """Project a ``{FIN: n, ..., CWR: n, ECE: n}`` dict onto the 8 CSV columns."""
    return [
        int(counts.get("FIN", 0)),
        int(counts.get("SYN", 0)),
        int(counts.get("RST", 0)),
        int(counts.get("PSH", 0)),
        int(counts.get("ACK", 0)),
        int(counts.get("URG", 0)),
        int(counts.get("CWR", 0)),  # labelled "CWE Flag Count" in CIC-IDS2017
        int(counts.get("ECE", 0)),
    ]


def flag_list_of_packet(packet_info) -> List[int]:
    """True/False list of the 8 flags for a packet (``checkFlags`` order)."""
    return [
        int(bool(packet_info.flag_fin)),
        int(bool(packet_info.flag_syn)),
        int(bool(packet_info.flag_rst)),
        int(bool(packet_info.flag_psh)),
        int(bool(packet_info.flag_ack)),
        int(bool(packet_info.flag_urg)),
        int(bool(packet_info.flag_cwr)),
        int(bool(packet_info.flag_ece)),
    ]