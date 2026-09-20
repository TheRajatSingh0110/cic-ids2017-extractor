# CIC-IDS2017 Flow Feature Extractor (Windows)

Live/offline network flow feature extractor producing exactly the **69
CIC-IDS2017 features** in the canonical order, faithful to CICFlowMeter
(ahlashkari/CICFlowMeter, `jnetpcap` edition) semantics.

## Features

- Bidirectional flows keyed on the reference 5-tuple flow-id (`fwdFlowId` /
  `bwdFlowId`), direction decided by source IP like the original
- Reference-exact accumulation: payload = TCP/UDP payload length, header =
  TCP data-offset*4 (or 8 for UDP), first-packet double-count quirk, sample
  std/var (n-1), integer-division Down/Up ratio and subflow features,
  Active/Idle split on activity-timeout gaps, FIN/RST/timeout termination
- Deterministic 69-feature order (see `features/cic_features.py`)
- Zero-safe output: no NaN/Inf ever (degenerate rates/statistics are 0)
- Flat CSV (69 columns, no header) or JSONL, raw features only (no
  preprocessing)

## Install

```
pip install -r requirements.txt        # scapy, pytest
```

Live capture additionally needs [Npcap](https://npcap.com) (WinPcap
API-compatible mode).

## Usage

```text
# validate against a known pcap
python main.py --pcap sample_pcaps/synthetic.pcap --out out/flows --format csv

# live capture
python main.py --interface <name> --out out/live --format csv

# list capture interfaces
python main.py --list-interfaces
```

Options: `--filter <bpf>` (default `ip or ip6`), `--flow-timeout-us`
(default 120000000), `--activity-timeout-us` (default 5000000),
`--include-single-packet`, `--duration <sec>`, `--write-csv-header`.

## Validation

```
python tools/generate_validation_pcap.py   # builds sample_pcaps/synthetic.pcap
python -m pytest tests                     # 40 unit + end-to-end tests
```

## Layout

```text
capture/    live (Npcap/Scapy) + offline (pcap) capture
features/   per-feature statistics and the 69-value extractor
flow/       flow state and the flow manager (FlowGenerator port)
output/     CSV / JSON writers
tools/      synthetic pcap generator for validation
tests/      pytest suite
```