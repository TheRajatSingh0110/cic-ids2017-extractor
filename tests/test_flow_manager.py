"""FlowManager behaviour - mirrors CICFlowMeter FlowGenerator termination rules."""

from features.packet_features import PacketInfo
from flow.flow_manager import FlowManager


def make_pkt(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80, proto=6,
             ts=0, payload=0, syn=False, ack=False, fin=False, rst=False):
    return PacketInfo(
        src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol=proto,
        timestamp_us=ts, payload_bytes=payload, header_bytes=20, tcp_window=1024,
        flag_syn=syn, flag_ack=ack, flag_fin=fin, flag_rst=rst,
        flag_psh=False, flag_urg=False, flag_cwr=False, flag_ece=False,
    )


def test_bidirectional_flow_merges_both_directions():
    completed = []
    mgr = FlowManager(on_flow_complete=completed.append)
    mgr.add_packet(make_pkt(syn=True, ts=0))
    mgr.add_packet(make_pkt(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234,
                            syn=True, ack=True, ts=1_000))
    mgr.add_packet(make_pkt(ack=True, ts=2_000))
    assert mgr.current_flow_count() == 1
    mgr.flush()
    assert len(completed) == 1
    flow = completed[0]
    assert flow.fwd_packets == 2
    assert flow.bwd_packets == 1
    assert flow.flow_duration_us == 2_000


def test_fin_closes_flow_only_after_both_directions():
    completed = []
    mgr = FlowManager(on_flow_complete=completed.append)
    mgr.add_packet(make_pkt(syn=True, ts=0))
    mgr.add_packet(make_pkt(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234,
                            syn=True, ack=True, ts=1_000))
    mgr.add_packet(make_pkt(ack=True, ts=2_000))
    mgr.add_packet(make_pkt(fin=True, ack=True, ts=3_000))   # fwd FIN -> kept
    assert mgr.current_flow_count() == 1
    mgr.add_packet(make_pkt(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234,
                            fin=True, ack=True, ts=4_000))   # bwd FIN -> close
    assert len(completed) == 1
    assert mgr.current_flow_count() == 0
    flow = completed[0]
    assert flow.packet_count() == 5
    assert flow.fwd_fin_count() == 1 and flow.bwd_fin_count() == 1


def test_rst_closes_flow_immediately():
    completed = []
    mgr = FlowManager(on_flow_complete=completed.append)
    mgr.add_packet(make_pkt(syn=True, ts=0))
    mgr.add_packet(make_pkt(rst=True, ack=True, ts=1_000))
    assert len(completed) == 1
    assert mgr.current_flow_count() == 0
    assert completed[0].packet_count() == 2


def test_flow_timeout_emits_and_restarts_same_key():
    completed = []
    mgr = FlowManager(flow_timeout_us=1_000, on_flow_complete=completed.append)
    mgr.add_packet(make_pkt(syn=True, ts=0))
    mgr.add_packet(make_pkt(ack=True, ts=2_000))   # gap 2000 > timeout 1000
    mgr.add_packet(make_pkt(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234,
                            syn=True, ack=True, ts=2_500))
    assert mgr.current_flow_count() == 1          # restarted under same key
    mgr.flush()
    assert len(completed) == 1                     # old 1-packet flow not emitted
    flow = completed[0]
    assert flow.flow_start_time_us == 2_000
    assert flow.flow_duration_us == 500
    assert flow.fwd_packets == 1 and flow.bwd_packets == 1


def test_single_packet_flows_dropped_by_default_and_emitted_opt_in():
    dropped = []
    mgr = FlowManager(on_flow_complete=dropped.append)
    mgr.add_packet(make_pkt(proto=17, ts=0))
    mgr.flush()
    assert dropped == []

    emitted = []
    mgr = FlowManager(emit_single_packet=True, on_flow_complete=emitted.append)
    mgr.add_packet(make_pkt(proto=17, ts=0))
    mgr.flush()
    assert len(emitted) == 1


def test_timeout_terminates_unclosed_flow_on_flush():
    completed = []
    mgr = FlowManager(on_flow_complete=completed.append)
    mgr.add_packet(make_pkt(syn=True, ts=0))
    mgr.add_packet(make_pkt(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234,
                            syn=True, ack=True, ts=1_000))
    mgr.flush()
    assert len(completed) == 1
    assert completed[0].packet_count() == 2


def test_direction_is_preserved_when_flow_restarts_on_timeout():
    mgr = FlowManager(flow_timeout_us=1_000)
    mgr.add_packet(make_pkt(syn=True, ts=0))
    mgr.add_packet(make_pkt(ack=True, ts=5_000))   # timeout restart
    fm = [f for f in mgr._flows.values()][0]
    assert fm.src == "10.0.0.1"
    assert fm.dst == "10.0.0.2"