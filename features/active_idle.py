"""Active / Idle period computation - port of CICFlowMeter updateActiveIdleTime.

A flow alternates between *active* and *idle* periods delimited by packet gaps
that exceed ``threshold`` (the activity timeout).  The reference keeps
``startActiveTime`` / ``endActiveTime`` on the flow and, whenever a packet has
an inter-arrival gap bigger than the threshold, records the finished active
segment plus the idle segment, then starts a fresh active period.

Values are microseconds.  Empty-result guards are applied so the statistics
always come back as real numbers (no NaN/Inf).
"""

from __future__ import annotations

from typing import Tuple

from features.iat_features import OnlineStats


def update_active_idle(
    active_stats: OnlineStats,
    idle_stats: OnlineStats,
    start_active: int,
    end_active: int,
    current_time_us: int,
    threshold_us: int,
) -> Tuple[int, int]:
    """Feed Active/Idle stats; return the updated ``(start_active, end_active)``.

    Mirrors ``BasicFlow.updateActiveIdleTime(long, long)`` exactly: when the gap
    ``current - end_active > threshold`` the previous active segment (if longer
    than zero) is recorded, the idle gap is recorded unconditionally, and a new
    active period starts at ``current``.  Otherwise the active period simply
    extends to ``current``.
    """
    if (current_time_us - end_active) > threshold_us:
        if (end_active - start_active) > 0:
            active_stats.add(end_active - start_active)
        idle_stats.add(current_time_us - end_active)
        return current_time_us, current_time_us
    return start_active, current_time_us


def close_active_idle(
    active_stats: OnlineStats,
    idle_stats: OnlineStats,
    start_active: int,
    end_active: int,
    current_time_us: int,
    threshold_us: int,
    flow_timeout_us: int,
    is_flag_end: bool,
) -> None:
    """Final Active/Idle bookkeeping when a flow ends (reference endActiveIdleTime).

    The current implementation of CICFlowMeter's ``FlowGenerator`` does not call
    this method, so it is provided for completeness and it is intentionally not
    invoked by ``FlowManager``; callers that want a final active segment can use
    it before serialising a finished flow.
    """
    if (end_active - start_active) > 0:
        active_stats.add(end_active - start_active)
    if not is_flag_end and (flow_timeout_us - (end_active - start_active)) > 0:
        idle_stats.add(flow_timeout_us - (end_active - start_active))
    _ = current_time_us, threshold_us