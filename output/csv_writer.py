"""Flat CSV output - one row per flow, 69 columns, no header by default.

``CsvWriter`` writes raw feature values.  Headers and labels are omitted to match
the project requirements; every row contains exactly 69 comma-separated values.
"""

from __future__ import annotations

import os
from typing import List, Optional, Sequence, TextIO

from features.cic_features import feature_names, format_value, feature_values
from flow.flow_state import FlowState

__all__ = ["CsvWriter"]


class CsvWriter:
    """Streaming CSV sink with optional header row and periodic flushing."""

    def __init__(
        self,
        path: str,
        write_header: bool = False,
        flush_every: int = 1,
    ) -> None:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._path = path
        self._write_header = bool(write_header)
        self._flush_every = max(1, int(flush_every))
        self._nrows = 0
        self._fh: TextIO = open(path, "w", newline="", encoding="utf-8")

    # ------------------------------------------------------------------ #
    def write_flow(self, flow: FlowState) -> None:
        """Serialise one flow as a 69-column row."""
        self.write_values(feature_values(flow))

    def write_values(self, values: Sequence[object]) -> None:
        row = format_row(values)
        if self._nrows == 0 and self._write_header:
            self._fh.write(format_row_names() + "\n")
        self._fh.write(row + "\n")
        self._nrows += 1
        if self._nrows % self._flush_every == 0:
            self.flush()

    # ------------------------------------------------------------------ #
    def flush(self) -> None:
        self._fh.flush()

    def close(self) -> None:
        if not self._fh.closed:
            self.flush()
            self._fh.close()

    @property
    def row_count(self) -> int:
        return self._nrows

    def __enter__(self) -> "CsvWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def format_row(values: Sequence[object]) -> str:
    """Render values (69 columns) as a single, comma-separated data row."""
    return ",".join(format_value(v) for v in values)


def format_row_names(names: Optional[List[str]] = None) -> str:
    """Header line with the 69 feature names (not written by default)."""
    return ",".join(names if names is not None else feature_names())