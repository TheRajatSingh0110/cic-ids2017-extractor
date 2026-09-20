"""JSON output - newline-delimited JSON objects, one per flow.

Each line is a single JSON object mapping the 69 feature names to their numeric
values (keys in feature order).  No ML preprocessing, no extra metadata.
"""

from __future__ import annotations

import json
import os
from typing import IO, Optional

from features.cic_features import to_feature_dict
from flow.flow_state import FlowState

__all__ = ["JsonWriter"]


class JsonWriter:
    """Streaming JSONL sink (one flow per line)."""

    def __init__(self, path: str, pretty: bool = False) -> None:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._path = path
        self._pretty = bool(pretty)
        self._nrows = 0
        self._fh: IO = open(path, "w", encoding="utf-8")

    # ------------------------------------------------------------------ #
    def write_flow(self, flow: FlowState) -> None:
        """Serialise one flow as one JSON object (feature names in order)."""
        data = to_feature_dict(flow)
        if self._pretty:
            self._fh.write(json.dumps(data, indent=2, sort_keys=False) + "\n")
        else:
            self._fh.write(json.dumps(data, sort_keys=False) + "\n")
        self._nrows += 1
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

    def __enter__(self) -> "JsonWriter":
        return self

    def __exit__(self, *exc) -> None:
        self.close()