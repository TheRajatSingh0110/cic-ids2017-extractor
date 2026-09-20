"""Bidirectional flow state — a faithful port of CICFlowMeter's ``BasicFlow``.

Every formula in this module mirrors ``BasicFlow.java`` from
https://github.com/ahlashkari/CICFlowMeter (v4.0, ``jnetpcap/BasicFlow.java``):

* timestamps are in **microseconds**,
* ``payload_bytes`` = TCP/UDP payload length,
* ``header_bytes``  = TCP header length (``data offset * 4``) or ``8`` for UDP,
* the first packet always establishes the *forward* direction,
* **note the reference quirk**: ``BasicFlow.firstPacket`` adds the first packet's
  payload to ``flowLengthStats`` *twice*, which affects the *Min/Max/Mean/Std/
  Variance Packet Length* and *Average Packet Size* features; we reproduce it.
* subflows split on **> 1 s** gaps, Active/Idle split on gaps **> activity timeout**.

All statistical helpers are division-by-zero safe and never return NaN/Inf.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from features.active_idle import update_active_idle
from features.iat_features import OnlineStats
from features.packet_features import PacketInfo


class FlowState:
    """Accumulates per-flow statistics for one bidirectional 5-tuple flow."""

    __slots__ = (
        "src", "dst", "src_port", "dst_port", "protocol", "is_bidirectional",
        "_activity_timeout_us",
        "_flow_start_time", "_flow_last_seen",
        "_fwd_last_seen", "_bwd_last_seen",
        "_fwd_pkt_stats", "_bwd_pkt_stats", "_flow_length_stats",
        "_flow_iat", "_fwd_iat", "_bwd_iat",
        "_flow_active", "_flow_idle",
        "_fwd_bytes", "_bwd_bytes",
        "_f_header_bytes", "_b_header_bytes",
        "_fwd_packets", "_bwd_packets",
        "_fPSH_cnt", "_fURG_cnt",
        "_fwd_fin_cnt", "_bwd_fin_cnt",
        "_flag_counts",
        "_act_data_pkt_fwd", "_min_seg_size_fwd",
        "_init_win_fwd", "_init_win_bwd",
        "_subflow_count", "_sf_last_ts", "_sf_ac_helper",
        "_start_active_time", "_end_active_time",
    )

    def __init__(
        self,
        packet: PacketInfo,
        activity_timeout_us: int = 5_000_000,
        is_bidirectional: bool = True,
    ) -> None:
        self.is_bidirectional = is_bidirectional
        #: IP protocol number (6 = TCP, 17 = UDP).
        self.protocol: int = packet.protocol
        #: Flow source IP string (direction established by the first packet).
        self.src: Optional[str] = packet.src_ip
        #: Flow destination IP string.
        self.dst: Optional[str] = packet.dst_ip
        #: Source port of the flow.
        self.src_port: int = packet.src_port
        #: Destination port of the flow.
        self.dst_port: int = packet.dst_port
        #: Active/Idle threshold in microseconds (CICFlowMeter default 5 s).
        self._activity_timeout_us: int = int(activity_timeout_us)

        self._flow_start_time: int = 0
        self._flow_last_seen: int = 0
        self._fwd_last_seen: int = 0
        self._bwd_last_seen: int = 0

        self._fwd_pkt_stats = OnlineStats()
        self._bwd_pkt_stats = OnlineStats()
        self._flow_length_stats = OnlineStats()
        self._flow_iat = OnlineStats()
        self._fwd_iat = OnlineStats()
        self._bwd_iat = OnlineStats()
        self._flow_active = OnlineStats()
        self._flow_idle = OnlineStats()

        self._fwd_bytes: int = 0
        self._bwd_bytes: int = 0
        self._f_header_bytes: int = 0
        self._b_header_bytes: int = 0
        self._fwd_packets: int = 0
        self._bwd_packets: int = 0

        self._fPSH_cnt: int = 0
        self._fURG_cnt: int = 0
        self._fwd_fin_cnt: int = 0
        self._bwd_fin_cnt: int = 0

        self._flag_counts: Dict[str, int] = {
            "FIN": 0, "SYN": 0, "RST": 0, "PSH": 0,
            "ACK": 0, "URG": 0, "CWR": 0, "ECE": 0,
        }

        self._act_data_pkt_fwd: int = 0
        self._min_seg_size_fwd: int = 0
        self._init_win_fwd: int = 0
        self._init_win_bwd: int = 0

        self._subflow_count: int = 0
        self._sf_last_ts: int = -1
        self._sf_ac_helper: int = -1

        self._start_active_time: int = 0
        self._end_active_time: int = 0

        self._first_packet(packet)

    # ------------------------------------------------------------------ #
    #  Packet ingestion (mirrors BasicFlow.firstPacket / addPacket)      #
    # ------------------------------------------------------------------ #
    def _first_packet(self, packet: PacketInfo) -> None:
        """Register the first packet (always counted as forward).

        Mirrors ``BasicFlow.firstPacket``: the first packet's payload is added to
        ``flowLengthStats`` twice (matching CICFlowMeter exactly, see module doc).
        """
        self._detect_update_subflows(packet)
        self._check_flags(packet)

        self._flow_start_time = packet.timestamp_us
        self._flow_last_seen = packet.timestamp_us
        self._start_active_time = packet.timestamp_us
        self._end_active_time = packet.timestamp_us

        self._flow_length_stats.add(packet.payload_bytes)

        # src/dst are already set from the first packet, so the following branch
        # is always the forward one (matches reference behaviour).
        self._min_seg_size_fwd = packet.header_bytes
        self._init_win_fwd = packet.tcp_window
        self._flow_length_stats.add(packet.payload_bytes)  # reference double-add
        self._fwd_pkt_stats.add(packet.payload_bytes)
        self._f_header_bytes = packet.header_bytes
        self._fwd_last_seen = packet.timestamp_us
        self._fwd_bytes += packet.payload_bytes
        self._fwd_packets += 1

        if packet.flag_psh:
            self._fPSH_cnt += 1
        if packet.flag_urg:
            self._fURG_cnt += 1

    def add_packet(self, packet: PacketInfo) -> None:
        """Register a subsequent packet (forward or backward, by source IP).

        Mirrors ``BasicFlow.addPacket`` in bidirectional mode.
        """
        self._detect_update_subflows(packet)
        self._check_flags(packet)
        current = packet.timestamp_us

        if self.is_bidirectional:
            self._flow_length_stats.add(packet.payload_bytes)

            if self.src is not None and packet.src_ip == self.src:
                if packet.payload_bytes >= 1:
                    self._act_data_pkt_fwd += 1
                self._fwd_pkt_stats.add(packet.payload_bytes)
                self._f_header_bytes += packet.header_bytes
                self._fwd_bytes += packet.payload_bytes
                self._fwd_packets += 1
                if self._fwd_packets > 1:
                    self._fwd_iat.add(current - self._fwd_last_seen)
                self._fwd_last_seen = current
                self._min_seg_size_fwd = min(packet.header_bytes, self._min_seg_size_fwd)
            else:
                self._bwd_pkt_stats.add(packet.payload_bytes)
                self._init_win_bwd = packet.tcp_window
                self._b_header_bytes += packet.header_bytes
                self._bwd_bytes += packet.payload_bytes
                self._bwd_packets += 1
                if self._bwd_packets > 1:
                    self._bwd_iat.add(current - self._bwd_last_seen)
                self._bwd_last_seen = current
        else:
            if packet.payload_bytes >= 1:
                self._act_data_pkt_fwd += 1
            self._fwd_pkt_stats.add(packet.payload_bytes)
            self._flow_length_stats.add(packet.payload_bytes)
            self._f_header_bytes += packet.header_bytes
            self._fwd_bytes += packet.payload_bytes
            self._fwd_packets += 1
            if self._fwd_packets > 1:
                self._fwd_iat.add(current - self._fwd_last_seen)
            self._fwd_last_seen = current
            self._min_seg_size_fwd = min(packet.header_bytes, self._min_seg_size_fwd)

        self._flow_iat.add(current - self._flow_last_seen)
        self._flow_last_seen = current

    # ------------------------- helpers used by the manager ------------- #
    def update_active_idle(self, current_time_us: int) -> None:
        """Feed the Active/Idle statistics (CICFlowMeter ``updateActiveIdleTime``)."""
        start, end = update_active_idle(
            self._flow_active,
            self._flow_idle,
            self._start_active_time,
            self._end_active_time,
            current_time_us,
            self._activity_timeout_us,
        )
        self._start_active_time = start
        self._end_active_time = end

    def _detect_update_subflows(self, packet: PacketInfo) -> None:
        """CICFlowMeter ``detectUpdateSubflows`` — split subflows at >1 s gaps."""
        ts = packet.timestamp_us
        if self._sf_last_ts == -1:
            self._sf_last_ts = ts
            self._sf_ac_helper = ts
            return
        if (ts - self._sf_last_ts) / 1_000_000.0 > 1.0:
            self._subflow_count += 1
            self.update_active_idle(ts)
            self._sf_ac_helper = ts
        self._sf_last_ts = ts

    def _check_flags(self, packet: PacketInfo) -> None:
        """Accumulate global TCP flag counts (CICFlowMeter ``checkFlags``)."""
        fc = self._flag_counts
        if packet.flag_fin:
            fc["FIN"] += 1
        if packet.flag_syn:
            fc["SYN"] += 1
        if packet.flag_rst:
            fc["RST"] += 1
        if packet.flag_psh:
            fc["PSH"] += 1
        if packet.flag_ack:
            fc["ACK"] += 1
        if packet.flag_urg:
            fc["URG"] += 1
        if packet.flag_cwr:
            fc["CWR"] += 1
        if packet.flag_ece:
            fc["ECE"] += 1

    # ------------------------------------------------------------------ #
    #  Read-only accessors used by the feature extractor                 #
    # ------------------------------------------------------------------ #
    def packet_count(self) -> int:
        """Total number of packets (forward + backward)."""
        if self.is_bidirectional:
            return self._fwd_packets + self._bwd_packets
        return self._fwd_packets

    @property
    def fwd_packets(self) -> int:
        return self._fwd_packets

    @property
    def bwd_packets(self) -> int:
        return self._bwd_packets

    @property
    def fwd_bytes(self) -> int:
        return self._fwd_bytes

    @property
    def bwd_bytes(self) -> int:
        return self._bwd_bytes

    @property
    def fwd_pkt_stats(self) -> OnlineStats:
        return self._fwd_pkt_stats

    @property
    def bwd_pkt_stats(self) -> OnlineStats:
        return self._bwd_pkt_stats

    @property
    def flow_length_stats(self) -> OnlineStats:
        return self._flow_length_stats

    @property
    def flow_iat(self) -> OnlineStats:
        return self._flow_iat

    @property
    def fwd_iat(self) -> OnlineStats:
        return self._fwd_iat

    @property
    def bwd_iat(self) -> OnlineStats:
        return self._bwd_iat

    @property
    def flow_active(self) -> OnlineStats:
        return self._flow_active

    @property
    def flow_idle(self) -> OnlineStats:
        return self._flow_idle

    @property
    def f_psh_cnt(self) -> int:
        return self._fPSH_cnt

    @property
    def f_urg_cnt(self) -> int:
        return self._fURG_cnt

    @property
    def f_header_bytes(self) -> int:
        return self._f_header_bytes

    @property
    def b_header_bytes(self) -> int:
        return self._b_header_bytes

    @property
    def flag_counts(self) -> Dict[str, int]:
        return dict(self._flag_counts)

    @property
    def act_data_pkt_fwd(self) -> int:
        return self._act_data_pkt_fwd

    @property
    def min_seg_size_fwd(self) -> int:
        return self._min_seg_size_fwd

    @property
    def init_win_fwd(self) -> int:
        return self._init_win_fwd

    @property
    def init_win_bwd(self) -> int:
        return self._init_win_bwd

    @property
    def subflow_count(self) -> int:
        return self._subflow_count

    @property
    def flow_duration_us(self) -> int:
        return self._flow_last_seen - self._flow_start_time

    @property
    def flow_start_time_us(self) -> int:
        return self._flow_start_time

    def fwd_fin_count(self) -> int:
        return self._fwd_fin_cnt

    def bwd_fin_count(self) -> int:
        return self._bwd_fin_cnt

    def increment_fwd_fin(self) -> int:
        self._fwd_fin_cnt += 1
        return self._fwd_fin_cnt

    def increment_bwd_fin(self) -> int:
        self._bwd_fin_cnt += 1
        return self._bwd_fin_cnt

    def set_direction(
        self,
        src: str,
        dst: str,
        src_port: int,
        dst_port: int,
    ) -> None:
        """Overwrite the stored direction (used when a flow restarts on timeout)."""
        self.src = src
        self.dst = dst
        self.src_port = src_port
        self.dst_port = dst_port