"""Packet -> PacketInfo extraction (mirrors reference jnetpcap parsing)."""

from scapy.all import Ether, IP, Raw, TCP, UDP

from features import packet_info_from_scapy


def _tcp(payload: bytes = b"", flags: str = "PA", window: int = 5840,
         src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport,
                                               flags=flags, window=window)
    if payload:
        pkt = pkt / Raw(load=payload)
    pkt.time = 1234.567890
    return pkt


def test_tcp_payload_and_header_match_reference():
    info = packet_info_from_scapy(_tcp(payload=b"x" * 100, flags="PA", window=30000))
    assert info is not None
    assert info.protocol == 6
    assert info.src_ip == "10.0.0.1"
    assert info.dst_ip == "10.0.0.2"
    assert info.src_port == 1234
    assert info.dst_port == 80
    assert info.payload_bytes == 100
    assert info.header_bytes == 20              # data offset 5 -> 20 bytes
    assert info.tcp_window == 30000
    assert info.flag_psh is True
    assert info.flag_ack is True
    assert info.flag_syn is False


def test_tcp_syn_has_zero_payload():
    info = packet_info_from_scapy(_tcp(flags="S", window=64240))
    assert info is not None
    assert info.payload_bytes == 0
    assert info.flag_syn is True


def test_tcp_header_length_uses_data_offset():
    from scapy.all import TCPOptions
    pkt = Ether() / IP() / TCP(flags="S", options=[("MSS", 1460)])
    pkt = pkt / Raw(b"abc")
    pkt.time = 1.0
    info = packet_info_from_scapy(pkt)
    assert info is not None
    assert info.header_bytes == 24              # 20 + 4 bytes MSS option
    assert info.payload_bytes == 3


def test_udp_payload_and_fixed_header():
    pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=5353) / Raw(b"hi")
    pkt.time = 1.0
    info = packet_info_from_scapy(pkt)
    assert info is not None
    assert info.protocol == 17
    assert info.payload_bytes == 2
    assert info.header_bytes == 8               # fixed UDP header length
    assert info.tcp_window == 0


def test_non_ip_packet_is_ignored():
    from scapy.all import ARP
    pkt = Ether() / ARP()
    pkt.time = 1.0
    assert packet_info_from_scapy(pkt) is None


def test_timestamp_is_microseconds():
    info = packet_info_from_scapy(_tcp())
    assert info.timestamp_us == 1_234_567_890