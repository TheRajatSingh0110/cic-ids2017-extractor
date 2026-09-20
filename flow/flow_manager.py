"""Bidirectional flow construction — faithful port of CICFlowMeter's ``FlowGenerator``.

Behaviour preserved from the reference:

* a flow is keyed on ``fwdFlowId``; an incoming packet joins the flow if its
  forward *or* backward flow-id is already tracked (bidirectional),
* direction (forward/backward) is decided by comparing the **source IP only**
  against the flow's stored source,
* TCP termination: a FIN closes the flow only after **both** directions have
  seen a FIN (the reference checks ``2*bwdFIN == 2``); an extra FIN in the same
  direction is dropped.  A RST closes the flow immediately,
* a flow older than ``flow_timeout_us`` is emitted and restarted under the same
  key, preserving the original src/dst direction,
* UDP and everything else: timeout only,
* emission rules match the reference: FIN/RST closures are emitted
  unconditionally, while timeout / end-of-file dumps only emit flows with
  ``packet_count() > 1`` (``emit_single_packet`` opts into the latter),
* Active/Idle statistics are fed before every normal packet (not for a closing
  FIN/RST), matching ``FlowGenerator.addPacket``.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Callable, Dict, Optional

from features.packet_features import PacketInfo
from flow.flow_key import bwd_flow_id, fwd_flow_id
from flow.flow_state import FlowState

#: Callable invoked with a completed flow.  FlowState is passed by reference.
FlowCallback = Callable[[FlowState], None]


class FlowManager:
    """Tracks live bidirectional flows and terminates them like CICFlowMeter."""

    def __init__(
        self,
        flow_timeout_us: int = 120_000_000,
        activity_timeout_us: int = 5_000_000,
        on_flow_complete: Optional[FlowCallback] = None,
        emit_single_packet: bool = False,
    ) -> None:
        #: Maximum flow duration before forced termination (microseconds).
        self._flow_timeout_us = int(flow_timeout_us)
        #: Active/Idle gap threshold (microseconds).
        self._activity_timeout_us = int(activity_timeout_us)
        self._callback = on_flow_complete
        #: Emit single-packet flows too (default False matches CICFlowMeter).
        self._emit_single_packet = bool(emit_single_packet)
        self._flows: "OrderedDict[str, FlowState]" = OrderedDict()

    # ------------------------------------------------------------------ #
    #  Core dispatcher (mirrors FlowGenerator.addPacket)                 #
    # ------------------------------------------------------------------ #
    def add_packet(self, packet: PacketInfo) -> None:
        """Route ``packet`` to an existing bidirectional flow or create one."""
        fid = fwd_flow_id(packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol)
        bid = bwd_flow_id(packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, packet.protocol)

        if fid in self._flows:
            flow, key = self._flows[fid], fid
        elif bid in self._flows:
            flow, key = self._flows[bid], bid
        else:
            flow = FlowState(packet, self._activity_timeout_us, is_bidirectional=True)
            self._flows[fid] = flow
            return

        current = packet.timestamp_us

        if (current - flow.flow_start_time_us) > self._flow_timeout_us:
            self._emit(flow)
            del self._flows[key]
            restarted = FlowState(packet, self._activity_timeout_us, is_bidirectional=True)
            restarted.set_direction(flow.src, flow.dst, flow.src_port, flow.dst_port)
            self._flows[key] = restarted
            return

        if packet.flag_fin:
            self._handle_fin(flow, packet, key)
            return

        if packet.flag_rst:
            flow.add_packet(packet)
            self._emit(flow, force=True)
            del self._flows[key]
            return

        #     normal packet ------------------------------------------ #
        if flow.src == packet.src_ip and flow.fwd_fin_count() == 0:
            flow.update_active_idle(current)
            flow.add_packet(packet)
        elif flow.bwd_fin_count() == 0:
            flow.update_active_idle(current)
            flow.add_packet(packet)
        # else: flow already closed in this direction -> packet dropped

    def _handle_fin(self, flow: FlowState, packet: PacketInfo, key: str) -> None:
        """CICFlowMeter FIN handling (closes when both directions have sent FIN)."""
        if flow.src == packet.src_ip:
            is_first = flow.increment_fwd_fin() == 1
        else:
            is_first = flow.increment_bwd_fin() == 1

        if not is_first:
            return  # reference drops a duplicated FIN in the same direction

        if (flow.bwd_fin_count() + flow.bwd_fin_count()) == 2:
            flow.add_packet(packet)
            self._emit(flow, force=True)
            del self._flows[key]
        else:
            flow.update_active_idle(packet.timestamp_us)
            flow.add_packet(packet)

    # ------------------------------------------------------------------ #
    #  Utility                                                           #
    # ------------------------------------------------------------------ #
    def _emit(self, flow: FlowState, force: bool = False) -> None:
        """Notify the callback that ``flow`` is complete.

        Matches the reference's per-path emission rules in this module:
        FIN/RST closures are emitted unconditionally (``force``), while
        timeouts and end-of-file dumps only emit flows with ``packet_count``
        greater than 1 (unless ``emit_single_packet`` is enabled).
        """
        if self._callback is None:
            return
        if not force and not self._emit_single_packet and flow.packet_count() <= 1:
            return
        self._callback(flow)

    def flush(self) -> None:
        """Emit every remaining in-progress flow (offline end-of-file)."""
        for key in list(self._flows.keys()):
            self._emit(self._flows[key])
        self._flows.clear()

    def current_flow_count(self) -> int:
        return len(self._flows)