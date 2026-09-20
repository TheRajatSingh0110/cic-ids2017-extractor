"""End-to-end: synthetic pcap -> OfflineCapture -> FlowManager -> CSV/JSON."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from capture import OfflineCapture
from features import packet_info_from_scapy
from features.cic_features import FEATURE_NAMES, count_columns
from flow.flow_manager import FlowManager
from output import CsvWriter, JsonWriter
from tools.generate_validation_pcap import main as generate_pcap


@pytest.fixture(scope="module")
def pcap_path():
    generate_pcap()
    root = os.path.join(os.path.dirname(__file__), "..")
    return os.path.join(root, "sample_pcaps", "synthetic.pcap")


def run_pipeline(pcap_path, writer):
    mgr = FlowManager(on_flow_complete=writer.write_flow)
    cap = OfflineCapture(pcap_path)
    try:
        for pkt in cap.packets():
            info = packet_info_from_scapy(pkt)
            if info is not None:
                mgr.add_packet(info)
    finally:
        mgr.flush()
        writer.close()
    return writer


def read_csv(path):
    with open(path, "r") as fh:
        return [line.strip() for line in fh if line.strip()]


def test_pcap_validation_generates_csv_rows(tmp_path, pcap_path):
    out = str(tmp_path / "flows.csv")
    run_pipeline(pcap_path, CsvWriter(out))
    rows = read_csv(out)
    assert len(rows) == 2
    for row in rows:
        assert count_columns(row) == 69
    tcp = rows[0].split(",")
    assert tcp[0] == "443"                       # destination port
    assert tcp[1] == "5000"                      # flow duration (us)
    assert tcp[2] == "4" and tcp[3] == "3"       # fwd/bwd packets
    assert tcp[4] == "18.0" and tcp[5] == "17.0" # fwd/bwd payload bytes (Java-style doubles)
    assert float(tcp[14]) == pytest.approx(7000.0)   # Flow Bytes/s (35/0.005)
    assert float(tcp[15]) == pytest.approx(1400.0)   # Flow Packets/s (7/0.005)
    assert tcp[41] == "2"                        # FIN
    assert tcp[42] == "2"                        # SYN
    assert tcp[44] == "1"                        # PSH
    assert tcp[45] == "6"                        # ACK
    assert tcp[57] == "64240"                    # init win fwd
    assert tcp[58] == "32120"                    # init win bwd
    assert tcp[59] == "1"                        # act_data_pkt_fwd
    udp = rows[1].split(",")
    assert udp[0] == "53"                        # encrypted? no - UDP dns port
    assert udp[2] == "1" and udp[3] == "1"
    assert udp[1] == "1500"


def test_pcap_validation_json_output(tmp_path, pcap_path):
    out = str(tmp_path / "flows.json")
    run_pipeline(pcap_path, JsonWriter(out))
    with open(out) as fh:
        objs = [json.loads(line) for line in fh if line.strip()]
    assert len(objs) == 2
    for obj in objs:
        assert list(obj.keys()) == FEATURE_NAMES
    tcp = objs[0]
    assert tcp["Destination Port"] == 443
    assert tcp["Flow Duration"] == 5000
    assert tcp["Total Fwd Packets"] == 4
    assert tcp["Total Backward Packets"] == 3
    assert tcp["Flow Bytes/s"] == pytest.approx(7000.0)