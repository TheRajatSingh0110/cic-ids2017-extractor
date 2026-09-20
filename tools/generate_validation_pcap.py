"""Generate synthetic pcap files with fully-known flows for validation.

The generated traffic is deterministic, so feature vectors computed from it can
be hand-checked and cross-validated against an independent CICFlowMeter run.

Output: ``sample_pcaps/synthetic.pcap`` (and ``.pcapng`` variant).
"""

from __future__ import annotations

import os
import sys

from scapy.all import Ether, IP, Raw, TCP, UDP, wrpcap

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "..", "sample_pcaps")

CLIENT = "192.168.1.10"
SERVER = "93.184.216.34"
CLIENT_PORT = 52345
SERVER_PORT = 443
UDP_CLIENT_PORT = 5353


def build_tcp_session() -> list:
    """A clean TCP session: SYN, SYN-ACK, ACK, one data packet, FIN closure.

    Timestamps are absolute microseconds; the flow lasts 5000 µs total.
    """
    pkts = []
    t = 10_000_000

    def add(src, sport, dst, dport, flags, ts_us, window, payload=None):
        pkt = Ether() / IP(src=src, dst=dst) / TCP(
            sport=sport, dport=dport, flags=flags, window=window
        )
        if payload:
            pkt = pkt / Raw(load=payload)
        pkt.time = ts_us / 1_000_000.0
        pkts.append(pkt)

    add(CLIENT, CLIENT_PORT, SERVER, SERVER_PORT, "S", t, 64240)      # SYN
    add(SERVER, SERVER_PORT, CLIENT, CLIENT_PORT, "SA", t + 1_000, 32120)  # SYN-ACK
    add(CLIENT, CLIENT_PORT, SERVER, SERVER_PORT, "A", t + 2_000, 64240)   # ACK
    add(CLIENT, CLIENT_PORT, SERVER, SERVER_PORT, "PA", t + 2_500, 64240, b"GET / HTTP/1.1\r\n\r\n")  # req
    add(SERVER, SERVER_PORT, CLIENT, CLIENT_PORT, "A", t + 3_000, 32120, b"HTTP/1.1 200 OK\r\n")  # resp
    add(CLIENT, CLIENT_PORT, SERVER, SERVER_PORT, "FA", t + 4_000, 64240)   # FIN
    add(SERVER, SERVER_PORT, CLIENT, CLIENT_PORT, "FA", t + 5_000, 32120)   # FIN-ACK
    return pkts


def build_udp_exchange_pkts() -> list:
    pkts = []
    t = 20_000_000
    p1 = Ether() / IP(src=CLIENT, dst=SERVER) / UDP(sport=UDP_CLIENT_PORT, dport=53) / Raw(b"query")
    p1.time = t / 1_000_000.0
    p2 = Ether() / IP(src=SERVER, dst=CLIENT) / UDP(sport=53, dport=UDP_CLIENT_PORT) / Raw(b"answer!!")
    p2.time = (t + 1_500) / 1_000_000.0
    return [p1, p2]


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)
    packets = build_tcp_session() + build_udp_exchange_pkts()
    out_pcap = os.path.join(OUT_DIR, "synthetic.pcap")
    out_pcapng = os.path.join(OUT_DIR, "synthetic.pcapng")
    wrpcap(out_pcap, packets)
    wrpcap(out_pcapng, packets)
    print(f"[+] wrote {len(packets)} packets -> {out_pcap}, {out_pcapng}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())