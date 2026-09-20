"""CIC-IDS2017 feature extraction - the 69 features in document order.

This module converts a finished ``FlowState`` into the 69 numeric features used
to train/augment CIC-IDS2017 models.  The ORDER (index 1..69) is fixed and is
reproduced verbatim from the project specification:

1. Destination Port                2. Flow Duration                3. Total Fwd Packets
4. Total Backward Packets          5. Total Length of Fwd Packets  6. Total Length of Bwd Packets
7. Fwd Packet Length Max           8. Fwd Packet Length Min        9. Fwd Packet Length Mean
10. Fwd Packet Length Std          11. Bwd Packet Length Max       12. Bwd Packet Length Min
13. Bwd Packet Length Mean         14. Bwd Packet Length Std      15. Flow Bytes/s
16. Flow Packets/s                 17. Flow IAT Mean               18. Flow IAT Std
19. Flow IAT Max                   20. Flow IAT Min               21. Fwd IAT Total
22. Fwd IAT Mean                   23. Fwd IAT Std                24. Fwd IAT Max
25. Fwd IAT Min                    26. Bwd IAT Total              27. Bwd IAT Mean
28. Bwd IAT Std                    29. Bwd IAT Max                30. Bwd IAT Min
31. Fwd PSH Flags                  32. Fwd URG Flags              33. Fwd Header Length
34. Bwd Header Length              35. Fwd Packets/s              36. Bwd Packets/s
37. Min Packet Length              38. Max Packet Length          39. Packet Length Mean
40. Packet Length Std              41. Packet Length Variance     42. FIN Flag Count
43. SYN Flag Count                 44. RST Flag Count             45. PSH Flag Count
46. ACK Flag Count                 47. URG Flag Count             48. CWE Flag Count
49. ECE Flag Count                 50. Down/Up Ratio              51. Average Packet Size
52. Avg Fwd Segment Size           53. Avg Bwd Segment Size       54. Subflow Fwd Packets
55. Subflow Fwd Bytes              56. Subflow Bwd Packets        57. Subflow Bwd Bytes
58. Init_Win_bytes_forward         59. Init_Win_bytes_backward    60. act_data_pkt_fwd
61. min_seg_size_forward           62. Active Mean                63. Active Std
64. Active Max                     65. Active Min                 66. Idle Mean
67. Idle Std                       68. Idle Max                   69. Idle Min

All formulas mirror ``BasicFlow.dumpFlowBasedFeaturesEx`` so the output is
directly consumable by models trained on CIC-IDS2017 (no normalisation, no PCA,
no SMOTE).  No value can be NaN or Inf: every rate/statistic is guarded.
"""

from __future__ import annotations

from typing import List, Sequence

from features.flag_features import flag_counts_to_cic_order
from flow.flow_state import FlowState

__all__ = ["FEATURE_NAMES", "feature_names", "feature_values", "to_feature_dict", "format_value"]

# --------------------------------------------------------------------------- #
# 1..69 - fixed order (do not reorder, do not rename)
# --------------------------------------------------------------------------- #
FEATURE_NAMES: List[str] = [
    "Destination Port",              # 1
    "Flow Duration",                 # 2
    "Total Fwd Packets",             # 3
    "Total Backward Packets",        # 4
    "Total Length of Fwd Packets",   # 5
    "Total Length of Bwd Packets",   # 6
    "Fwd Packet Length Max",         # 7
    "Fwd Packet Length Min",         # 8
    "Fwd Packet Length Mean",        # 9
    "Fwd Packet Length Std",         # 10
    "Bwd Packet Length Max",         # 11
    "Bwd Packet Length Min",         # 12
    "Bwd Packet Length Mean",        # 13
    "Bwd Packet Length Std",         # 14
    "Flow Bytes/s",                  # 15
    "Flow Packets/s",                # 16
    "Flow IAT Mean",                 # 17
    "Flow IAT Std",                  # 18
    "Flow IAT Max",                  # 19
    "Flow IAT Min",                  # 20
    "Fwd IAT Total",                 # 21
    "Fwd IAT Mean",                  # 22
    "Fwd IAT Std",                   # 23
    "Fwd IAT Max",                   # 24
    "Fwd IAT Min",                   # 25
    "Bwd IAT Total",                 # 26
    "Bwd IAT Mean",                  # 27
    "Bwd IAT Std",                   # 28
    "Bwd IAT Max",                   # 29
    "Bwd IAT Min",                   # 30
    "Fwd PSH Flags",                 # 31
    "Fwd URG Flags",                 # 32
    "Fwd Header Length",             # 33
    "Bwd Header Length",             # 34
    "Fwd Packets/s",                 # 35
    "Bwd Packets/s",                 # 36
    "Min Packet Length",             # 37
    "Max Packet Length",             # 38
    "Packet Length Mean",            # 39
    "Packet Length Std",             # 40
    "Packet Length Variance",        # 41
    "FIN Flag Count",                # 42
    "SYN Flag Count",                # 43
    "RST Flag Count",                # 44
    "PSH Flag Count",                # 45
    "ACK Flag Count",                # 46
    "URG Flag Count",                # 47
    "CWE Flag Count",                # 48
    "ECE Flag Count",                # 49
    "Down/Up Ratio",                 # 50
    "Average Packet Size",           # 51
    "Avg Fwd Segment Size",          # 52
    "Avg Bwd Segment Size",          # 53
    "Subflow Fwd Packets",           # 54
    "Subflow Fwd Bytes",             # 55
    "Subflow Bwd Packets",           # 56
    "Subflow Bwd Bytes",             # 57
    "Init_Win_bytes_forward",        # 58
    "Init_Win_bytes_backward",       # 59
    "act_data_pkt_fwd",              # 60
    "min_seg_size_forward",          # 61
    "Active Mean",                   # 62
    "Active Std",                    # 63
    "Active Max",                    # 64
    "Active Min",                    # 65
    "Idle Mean",                     # 66
    "Idle Std",                      # 67
    "Idle Max",                      # 68
    "Idle Min",                      # 69
]


def feature_names() -> List[str]:
    """Return the 69 feature names (defensive copy)."""
    return list(FEATURE_NAMES)


def _micros_to_seconds(duration_us: int) -> float:
    """Flow duration in seconds for the per-second rates (microsecond input)."""
    return duration_us / 1_000_000.0


def feature_values(flow: FlowState) -> List[object]:
    """Compute the ordered 69 feature values for a finished flow.

    Every rate uses the flow duration in seconds; when the duration is zero the
    rate is 0 (division guard).  Statistical accessors never return NaN/Inf.
    """
    duration_us = flow.flow_duration_us
    duration_s = _micros_to_seconds(duration_us)

    fwd_n = flow.fwd_packets
    bwd_n = flow.bwd_packets
    total_n = flow.packet_count()
    fwd_stats = flow.fwd_pkt_stats
    bwd_stats = flow.bwd_pkt_stats
    len_stats = flow.flow_length_stats

    def per_second(amount: float) -> float:
        return amount / duration_s if duration_s > 0 else 0.0

    v: List[object] = [0.0] * 69

    v[0] = flow.dst_port                                   # 1
    v[1] = duration_us                                     # 2
    v[2] = fwd_n                                           # 3
    v[3] = bwd_n                                           # 4
    v[4] = fwd_stats.get_sum()                             # 5
    v[5] = bwd_stats.get_sum()                             # 6

    # 7..14  forward/backward packet-length statistics (guarded -> 0)
    v[6] = fwd_stats.max() if fwd_n > 0 else 0.0
    v[7] = fwd_stats.min() if fwd_n > 0 else 0.0
    v[8] = fwd_stats.mean() if fwd_n > 0 else 0.0
    v[9] = fwd_stats.std() if fwd_n > 0 else 0.0
    v[10] = bwd_stats.max() if bwd_n > 0 else 0.0
    v[11] = bwd_stats.min() if bwd_n > 0 else 0.0
    v[12] = bwd_stats.mean() if bwd_n > 0 else 0.0
    v[13] = bwd_stats.std() if bwd_n > 0 else 0.0

    v[14] = per_second(flow.fwd_bytes + flow.bwd_bytes)   # 15 Flow Bytes/s
    v[15] = per_second(total_n)                            # 16 Flow Packets/s
    v[16] = flow.flow_iat.mean()                           # 17
    v[17] = flow.flow_iat.std()                            # 18
    v[18] = flow.flow_iat.max()                            # 19
    v[19] = flow.flow_iat.min()                            # 20

    fwd_iat_ok = fwd_n > 1
    bwd_iat_ok = bwd_n > 1
    v[20] = flow.fwd_iat.get_sum() if fwd_iat_ok else 0.0    # 21
    v[21] = flow.fwd_iat.mean() if fwd_iat_ok else 0.0       # 22
    v[22] = flow.fwd_iat.std() if fwd_iat_ok else 0.0        # 23
    v[23] = flow.fwd_iat.max() if fwd_iat_ok else 0.0        # 24
    v[24] = flow.fwd_iat.min() if fwd_iat_ok else 0.0        # 25
    v[25] = flow.bwd_iat.get_sum() if bwd_iat_ok else 0.0    # 26
    v[26] = flow.bwd_iat.mean() if bwd_iat_ok else 0.0       # 27
    v[27] = flow.bwd_iat.std() if bwd_iat_ok else 0.0        # 28
    v[28] = flow.bwd_iat.max() if bwd_iat_ok else 0.0        # 29
    v[29] = flow.bwd_iat.min() if bwd_iat_ok else 0.0        # 30

    v[30] = flow.f_psh_cnt                                    # 31 Fwd PSH Flags
    v[31] = flow.f_urg_cnt                                    # 32 Fwd URG Flags
    v[32] = flow.f_header_bytes                               # 33 Fwd Header Length
    v[33] = flow.b_header_bytes                               # 34 Bwd Header Length
    v[34] = per_second(fwd_n)                                 # 35 Fwd Packets/s
    v[35] = per_second(bwd_n)                                 # 36 Bwd Packets/s

    # 37..41  min/max/mean/std/variance packet length (all packets)
    v[36] = len_stats.min() if total_n > 0 else 0.0
    v[37] = len_stats.max() if total_n > 0 else 0.0
    v[38] = len_stats.mean() if total_n > 0 else 0.0
    v[39] = len_stats.std() if total_n > 0 else 0.0
    v[40] = len_stats.variance() if total_n > 0 else 0.0

    # 42..49  flag counts (FIN, SYN, RST, PSH, ACK, URG, CWE, ECE)
    flag_values = flag_counts_to_cic_order(flow.flag_counts)
    v[41:49] = flag_values

    # 50  Down/Up Ratio - integer division exactly like the reference
    v[49] = float(bwd_n // fwd_n) if fwd_n > 0 else 0.0
    # 51  Average Packet Size
    v[50] = len_stats.get_sum() / total_n if total_n > 0 else 0.0
    # 52/53  Average forward/backward segment size
    v[51] = fwd_stats.get_sum() / fwd_n if fwd_n > 0 else 0.0
    v[52] = bwd_stats.get_sum() / bwd_n if bwd_n > 0 else 0.0

    # 54..57  Subflow features (integer division, 0 when no subflow split)
    sf = flow.subflow_count
    v[53] = fwd_n // sf if sf > 0 else 0
    v[54] = flow.fwd_bytes // sf if sf > 0 else 0
    v[55] = bwd_n // sf if sf > 0 else 0
    v[56] = flow.bwd_bytes // sf if sf > 0 else 0

    v[57] = flow.init_win_fwd                                  # 58
    v[58] = flow.init_win_bwd                                  # 59
    v[59] = flow.act_data_pkt_fwd                              # 60
    v[60] = flow.min_seg_size_fwd                              # 61

    v[61] = flow.flow_active.mean()                            # 62
    v[62] = flow.flow_active.std()                             # 63
    v[63] = flow.flow_active.max()                             # 64
    v[64] = flow.flow_active.min()                             # 65
    v[65] = flow.flow_idle.mean()                              # 66
    v[66] = flow.flow_idle.std()                               # 67
    v[67] = flow.flow_idle.max()                               # 68
    v[68] = flow.flow_idle.min()                               # 69

    return v


def to_feature_dict(flow: FlowState) -> dict:
    """Return an insertion-ordered dict mapping the 69 names to their values."""
    return dict(zip(FEATURE_NAMES, feature_values(flow)))


def _java_double_string(x: float) -> str:
    """Render a float the way Java's ``Double.toString`` does.

    CICFlowMeter appends doubles directly (``StringBuilder.append``), so whole
    values print with ``.0`` (``18.0``) and values outside ``[1e-3, 1e7)`` use
    uppercase scientific notation (``1.0E7``); Python's ``repr`` differs there.
    """
    import math

    if math.isnan(x) or math.isinf(x):
        return "0"
    if x == 0.0:
        return "-0.0" if math.copysign(1.0, x) < 0 else "0.0"

    sign = "-" if x < 0 else ""
    body = repr(abs(x))

    if "e" in body or "E" in body:
        mant, exp_part = body.split("e", 1)
        if "." not in mant:
            mant += ".0"
        exp = int(exp_part)
        return sign + mant + ("-" if exp < 0 else "") + str(abs(exp))

    exponent = math.floor(math.log10(abs(x)))
    if -3 <= exponent < 7:
        return sign + body  # same decimal notation as Java

    digits = body.replace(".", "")
    first_nonzero = 0
    while first_nonzero < len(digits) and digits[first_nonzero] == "0":
        first_nonzero += 1
    frac = digits[first_nonzero + 1:].rstrip("0")
    mantissa = digits[first_nonzero] + ("." + frac if frac else ".0")
    return sign + mantissa + ("-" if exponent < 0 else "") + str(abs(exponent))


def format_value(value: object) -> str:
    """Render one feature value the way the reference prints it in its CSV.

    Ints stay ints (``80``), floats are printed like Java ``Double.toString``
    (``18.0``, ``1.5``, ``1.0E7``), and NaN/Inf never occur (guarded to ``0``).
    """
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _java_double_string(value)
    return str(value)


def feature_row_csv(flow: FlowState) -> str:
    """Serialise exactly 69 comma-separated values with no header."""
    return ",".join(format_value(x) for x in feature_values(flow))


def count_columns(row: str) -> int:
    """Number of columns in a CSV data row (used by tests/validation)."""
    return len(row.split(","))