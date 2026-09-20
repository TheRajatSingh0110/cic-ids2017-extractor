"""CIC-IDS2017 live/offline flow feature extractor - orchestration entry point.

Usage
-----
Live capture on Windows (requires Npcap + admin shell)::

    python main.py --interface "Ethernet" --out C:\\flows\\live --format csv

Offline validation against a known pcap::

    python main.py --pcap sample.pcapng --out C:\\flows\\offline --format csv

List capture interfaces::

    python main.py --list-interfaces

Output is raw CIC-IDS2017 features - 69 columns, no header (*no* ML
preprocessing: no standardisation, no PCA, no SMOTE).
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import Optional

from capture import LiveCapture, OfflineCapture, list_network_interfaces
from features import packet_info_from_scapy
from flow import FlowManager
from output import CsvWriter, JsonWriter

#: CICFlowMeter defaults (microseconds).
FLOW_TIMEOUT_US = 120_000_000   # 120 seconds
ACTIVITY_TIMEOUT_US = 5_000_000  # 5 seconds


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cic-ids2017-extractor",
        description="Windows live network-flow feature extractor (CIC-IDS2017, 69 features).",
    )
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--interface", help="Npcap capture interface name (live mode).")
    src.add_argument("--pcap", help="pcap/pcapng file to read (offline validation mode).")
    src.add_argument("--list-interfaces", action="store_true", help="List Npcap interfaces and exit.")

    p.add_argument("--out", default="flows",
                   help="Output file base (without extension). Default: %(default)s")
    p.add_argument("--format", choices=("csv", "json"), default="csv",
                   help="Output serialisation. Default: %(default)s")
    p.add_argument("--filter", default="ip or ip6",
                   help="BPF capture filter for live mode. Default: %(default)s")
    p.add_argument("--flow-timeout-us", type=int, default=FLOW_TIMEOUT_US,
                   help="Flow timeout in microseconds (TCP/UDP). Default: %(default)s")
    p.add_argument("--activity-timeout-us", type=int, default=ACTIVITY_TIMEOUT_US,
                   help="Active/Idle activity timeout in microseconds. Default: %(default)s")
    p.add_argument("--include-single-packet", action="store_true",
                   help="Emit single-packet flows (CICFlowMeter drops them).")
    p.add_argument("--duration", type=float, default=None,
                   help="Live capture duration in seconds (default: run until Ctrl+C).")
    p.add_argument("--write-csv-header", action="store_true",
                   help="Prepend a header row to CSV output (off by default).")
    return p


def _make_writer(args: argparse.Namespace):
    ext = args.format
    path = f"{args.out}.{ext}"
    if ext == "csv":
        return CsvWriter(path, write_header=args.write_csv_header)
    return JsonWriter(path)


def _process_packet(manager: FlowManager, raw_packet) -> None:
    info = packet_info_from_scapy(raw_packet)
    if info is not None:
        manager.add_packet(info)


def run_live(args: argparse.Namespace) -> int:
    if args.duration:
        stop_at = time.monotonic() + args.duration
    writer = _make_writer(args)
    manager = FlowManager(
        flow_timeout_us=args.flow_timeout_us,
        activity_timeout_us=args.activity_timeout_us,
        on_flow_complete=writer.write_flow,
        emit_single_packet=args.include_single_packet,
    )
    print(f"[+] capturing on '{args.interface}' -> {args.out}.{args.format}",
          file=sys.stderr)
    try:
        with LiveCapture(args.interface, bpf_filter=args.filter) as cap:
            for raw in cap.packets():
                _process_packet(manager, raw)
                if args.duration and time.monotonic() >= stop_at:
                    break
    except KeyboardInterrupt:
        print("[!] interrupted", file=sys.stderr)
    finally:
        manager.flush()
        writer.close()
    print(f"[+] flows emitted: {writer.row_count}", file=sys.stderr)
    return 0


def run_offline(args: argparse.Namespace) -> int:
    writer = _make_writer(args)
    manager = FlowManager(
        flow_timeout_us=args.flow_timeout_us,
        activity_timeout_us=args.activity_timeout_us,
        on_flow_complete=writer.write_flow,
        emit_single_packet=args.include_single_packet,
    )
    print(f"[+] reading {args.pcap} -> {args.out}.{args.format}", file=sys.stderr)
    started = time.monotonic()
    try:
        cap = OfflineCapture(args.pcap)
        for raw in cap.packets():
            _process_packet(manager, raw)
    finally:
        manager.flush()
        writer.close()
    elapsed = time.monotonic() - started
    print(
        f"[+] flows emitted: {writer.row_count} in {elapsed:.2f}s",
        file=sys.stderr,
    )
    return 0


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_interfaces:
        for name in list_network_interfaces():
            print(name)
        return 0

    if args.interface:
        return run_live(args)
    return run_offline(args)


if __name__ == "__main__":
    raise SystemExit(main())