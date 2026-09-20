"""FlowState unit tests - verifies reference feature accumulation and edge cases."""

import math

import pytest

from features.cic_features import feature_values
from features.packet_features import PacketInfo
from flow.flow_state import FlowState


def make_pkt(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80, proto=6,
             ts=0, payload=0, hdr=20, win=0, syn=False, ack=False, fin=False,
             rst=False, psh=False, urg=False, cwr=False, ece=False):
    return PacketInfo(
        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol=proto,
        timestamp_us=ts, payload_bytes=payload, header_bytes=hdr, tcp_window=win,
        flag_syn=syn, flag_ack=ack, flag_fin=fin, flag_rst=rst, flag_psh=psh,
        flag_urg=urg, flag_cwr=cwr, flag_ece=ece,
    )


def assert_finite(values):
    for v in values:
        if isinstance(v, float):
            assert not math.isnan(v) and not math.isinf(v), f"non-finite {v=}"


def test_single_packet_flow_is_zero_safe():
    flow = FlowState(make_pkt(proto=17, payload=40, hdr=8, ts=1000))
    values = feature_values(flow)
    assert_finite(values)
    assert values[0] == 80              # destination port
    assert values[1] == 0               # flow duration
    assert values[2] == 1 and values[3] == 0   # fwd/bwd packet counts
    assert values[32] == 8              # fwd header length (UDP = 8)
    assert values[33] == 0              # bwd header length
    assert values[57] == 0              # init win bytes fwd (UDP)
    assert values[6] == 40.0            # fwd packet length max
    assert values[7] == 40.0            # fwd packet length min
    assert values[8] == 40.0            # fwd packet length mean
    assert values[9] == 0.0             # fwd packet length std
    for i in (5, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
              23, 24, 25, 26, 27, 28, 29):
        assert values[i] == 0


def test_two_packet_tcp_handshake_math():
    flow = FlowState(make_pkt(syn=True, win=64240, ts=1_000_000))
    flow.add_packet(make_pkt(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234,
                             syn=True, ack=True, win=32120, ts=1_001_000))
    values = feature_values(flow)

    assert values[1] == 1000                      # duration (us)
    assert values[2] == 1 and values[3] == 1      # fwd/bwd packets
    assert values[4] == 0 and values[5] == 0      # total lengths
    assert values[16] == 1000.0                   # flow IAT mean
    assert values[17] == 0.0                      # flow IAT std
    assert values[18] == 1000.0                   # flow IAT max
    assert values[19] == 1000.0                   # flow IAT min
    assert values[20] == 0                        # fwd IAT total (1 fwd pkt only)
    assert values[25] == 0                        # bwd IAT total
    assert values[32] == 20 and values[33] == 20  # fwd/bwd header lengths
    assert values[15] == pytest.approx(2000.0)    # flow packets/s (2 / 0.001s)
    assert values[34] == pytest.approx(1000.0)    # fwd packets/s
    assert values[35] == pytest.approx(1000.0)    # bwd packets/s
    assert values[41] == 0                        # FIN
    assert values[42] == 2                        # SYN (both)
    assert values[45] == 1                        # ACK (SYN-ACK)
    assert values[49] == 1.0                      # down/up ratio
    assert values[57] == 64240                    # init win fwd
    assert values[58] == 32120                    # init win bwd
    assert values[59] == 0                        # act_data_pkt_fwd
    assert values[60] == 20                       # min_seg_size_forward
    for i in range(61, 69):
        assert values[i] == 0                     # active/idle empty


def test_fwd_psh_and_urg_first_packet():
    flow = FlowState(make_pkt(psh=True, urg=True, ts=0))
    values = feature_values(flow)
    assert values[30] == 1                        # Fwd PSH Flags
    assert values[31] == 1                        # Fwd URG Flags


def test_fwd_psh_only_first_packet_matters_reference_quirk():
    flow = FlowState(make_pkt(ts=0))
    flow.add_packet(make_pkt(psh=True, ack=True, ts=1_000))
    flow.add_packet(make_pkt(ack=True, ts=2_000))
    values = feature_values(flow)
    assert values[30] == 0                        # reference only counts 1st pkt


def test_act_data_pkt_fwd_counts_payload_after_first_packet():
    flow = FlowState(make_pkt(payload=10, ts=0))
    flow.add_packet(make_pkt(payload=20, ack=True, ts=1_000))
    flow.add_packet(make_pkt(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234,
                             payload=30, ack=True, ts=2_000))
    flow.add_packet(make_pkt(payload=0, ack=True, ts=3_000))
    assert flow.act_data_pkt_fwd == 1


def test_min_seg_size_forward_takes_min_of_forward_header_bytes():
    flow = FlowState(make_pkt(hdr=24, ts=0))
    flow.add_packet(make_pkt(hdr=28, ack=True, ts=1_000))
    flow.add_packet(make_pkt(hdr=20, ack=True, ts=2_000))   # fwd
    flow.add_packet(make_pkt(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234,
                             hdr=30, ack=True, ts=3_000))  # bwd ignored
    assert flow.min_seg_size_fwd == 20


def test_average_packet_size_replicates_reference_double_add():
    flow = FlowState(make_pkt(proto=17, payload=40, hdr=8, ts=0))
    values = feature_values(flow)
    assert values[50] == 80.0    # flowLengthStats sum (40*2) / packetCount (1)
    assert values[36] == 40.0    # min packet length
    assert values[37] == 40.0    # max packet length
    assert values[38] == 40.0    # mean
    assert values[39] == 0.0     # std
    assert values[40] == 0.0     # variance


def test_subflow_split_on_one_second_gap():
    flow = FlowState(make_pkt(payload=10, ts=0))
    flow.add_packet(make_pkt(payload=20, ack=True, ts=1_000))
    flow.add_packet(make_pkt(payload=30, ack=True, ts=1_600_000))  # >1s gap
    assert flow.subflow_count == 1
    values = feature_values(flow)
    assert values[53] == 3       # subflow fwd packets = 3//1
    assert values[54] == 60      # subflow fwd bytes = 60//1


def test_idle_recorded_when_gap_exceeds_activity_timeout():
    flow = FlowState(make_pkt(ts=0), activity_timeout_us=2_000_000)
    flow.update_active_idle(1_000_000)
    flow.add_packet(make_pkt(ack=True, ts=1_000_000))     # extends active to 1s
    flow.add_packet(make_pkt(ack=True, ts=4_000_000))     # gap 3s > 2s threshold
    values = feature_values(flow)
    assert values[65] == pytest.approx(3_000_000.0)       # idle mean
    assert values[68] == pytest.approx(3_000_000.0)       # idle min


def test_active_recorded_for_segments_on_other_side_of_idle():
    flow = FlowState(make_pkt(ts=0), activity_timeout_us=2_000_000)
    flow.update_active_idle(1_000_000)
    flow.add_packet(make_pkt(ack=True, ts=1_000_000))     # active segment 0->1s
    flow.add_packet(make_pkt(ack=True, ts=4_000_000))     # idle 1s->4s recorded
    flow.add_packet(make_pkt(ack=True, ts=4_500_000))     # new active 4s->4.5s
    values = feature_values(flow)
    assert values[61] == pytest.approx(1_000_000.0)       # active mean
    assert values[64] == pytest.approx(1_000_000.0)       # active max
    assert values[65] == pytest.approx(3_000_000.0)       # idle mean