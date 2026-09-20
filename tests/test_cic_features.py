"""69-feature serialisation guarantees: order, width, finiteness, JSON keys."""

import json
import math

import pytest

from features.cic_features import (
    FEATURE_NAMES,
    count_columns,
    feature_row_csv,
    feature_values,
    to_feature_dict,
)
from features.packet_features import PacketInfo
from flow.flow_manager import FlowManager


def udp_flow(payload=40):
    mgr = FlowManager()
    mgr.add_packet(PacketInfo(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1234, dst_port=53,
        protocol=17, timestamp_us=0, payload_bytes=payload, header_bytes=8,
        tcp_window=0,
    ))
    mgr.add_packet(PacketInfo(
        src_ip="10.0.0.2", dst_ip="10.0.0.1", src_port=53, dst_port=1234,
        protocol=17, timestamp_us=1_000, payload_bytes=payload, header_bytes=8,
        tcp_window=0,
    ))
    return list(mgr._flows.values())[0]


def test_feature_values_width_and_finiteness():
    values = feature_values(udp_flow())
    assert len(values) == 69
    for v in values:
        if isinstance(v, float):
            assert not math.isnan(v)
            assert not math.isinf(v)


def test_feature_dict_key_order_matches_names_and_total_69():
    d = to_feature_dict(udp_flow())
    assert list(d.keys()) == FEATURE_NAMES
    assert len(d) == 69
    assert d["Destination Port"] == 53


def test_csv_row_has_exactly_69_columns():
    row = feature_row_csv(udp_flow())
    assert count_columns(row) == 69


def test_down_up_ratio_uses_integer_division_like_reference():
    mgr = FlowManager()
    p = lambda **kw: PacketInfo(
        src_ip=kw.get("src", "10.0.0.1"), dst_ip=kw.get("dst", "10.0.0.2"),
        src_port=80 if kw.get("src") == "10.0.0.2" else 1234,
        dst_port=1234 if kw.get("src") == "10.0.0.2" else 80,
        protocol=6,
        timestamp_us=kw["ts"], payload_bytes=0, header_bytes=20,
        tcp_window=100, flag_syn=kw.get("syn", False), flag_ack=kw.get("ack", False),
    )
    mgr.add_packet(p(src="10.0.0.1", dst="10.0.0.2", ts=0, syn=True))
    mgr.add_packet(p(src="10.0.0.2", dst="10.0.0.1", ts=1_000, syn=True, ack=True))
    mgr.add_packet(p(src="10.0.0.2", dst="10.0.0.1", ts=2_000, ack=True))
    flow = list(mgr._flows.values())[0]           # fwd=1, bwd=2
    assert feature_values(flow)[49] == 2.0        # int division 2//1


def test_zero_rates_when_duration_is_zero():
    mgr = FlowManager(emit_single_packet=True)
    mgr.add_packet(PacketInfo(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1, dst_port=1,
        protocol=6, timestamp_us=5, payload_bytes=0, header_bytes=20,
        tcp_window=0,
    ))
    flow = list(mgr._flows.values())[0]
    values = feature_values(flow)
    assert values[14] == 0.0        # Flow Bytes/s
    assert values[15] == 0.0        # Flow Packets/s
    assert values[50] == 0.0        # Average Packet Size (0/1 packe... len 0)
    assert all(isinstance(x, (int, float)) for x in values)


def test_json_roundtrip_preserves_all_69_keys():
    d = to_feature_dict(udp_flow())
    text = json.dumps(d)
    loaded = json.loads(text)
    assert list(loaded.keys()) == FEATURE_NAMES
    assert loaded["Flow Duration"] == 1_000
    assert loaded["Total Fwd Packets"] == 1
    assert loaded["Total Backward Packets"] == 1


def test_format_value_types():
    from features.cic_features import format_value
    assert format_value(80) == "80"
    assert format_value(1.5) == "1.5"
    assert format_value(0.0) == "0.0"
    assert format_value(64240) == "64240"