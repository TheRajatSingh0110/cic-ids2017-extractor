"""Npcap packet capture for Windows (backed by Scapy).

Once Npcap is installed (https://npcap.com, "WinPcap API-compatible mode"),
Scapy can sniff with ``sniff(iface=...)`` on Windows.  Two sources are exposed:

* ``LiveCapture``  - streaming live capture into a thread-safe queue,
* ``OfflineCapture`` - streaming read of a pcap/pcapng file (validation mode).

Both yield raw scapy packets; convert them with
``packet_features.packet_info_from_scapy`` before feeding the flow manager.
"""

from __future__ import annotations

import threading
from queue import Empty, Queue
from typing import Generator, List, Optional

__all__ = ["LiveCapture", "OfflineCapture", "list_network_interfaces", "is_capture_available"]

_EOF = object()


def is_capture_available() -> bool:
    """Best-effort check whether Scapy + Npcap are importable."""
    try:
        import scapy.all  # noqa: F401

        return True
    except Exception:
        return False


def list_network_interfaces() -> List[str]:
    """Names of the capture interfaces visible to Scapy/Npcap on this host."""
    try:
        from scapy.all import get_if_list

        return list(get_if_list())
    except Exception as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(f"cannot enumerate interfaces: {exc}") from exc


class LiveCapture:
    """Streaming live packet capture using Scapy on top of Npcap."""

    def __init__(
        self,
        interface: Optional[str] = None,
        bpf_filter: str = "ip or ip6",
        promisc: bool = True,
    ) -> None:
        try:
            from scapy.all import conf
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("scapy is not installed (pip install scapy)") from exc

        if not is_capture_available():  # pragma: no cover
            raise RuntimeError("scapy or Npcap is missing; install Npcap from npcap.com")

        conf.use_pcap = True  # WinPcap/Npcap API support on Windows
        self._interface = interface
        self._bpf_filter = bpf_filter
        self._promisc = promisc
        self._queue: "Queue[object]" = Queue(maxsize=8192)
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    # ------------------------------------------------------------------ #
    def start(self) -> None:
        """Begin capturing on a background thread."""
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._thread.start()

    def _capture_loop(self) -> None:  # pragma: no cover - runs in worker thread
        from scapy.all import sniff

        def _stop_check(_pkt) -> bool:
            return self._stop_event.is_set()

        try:
            sniff(
                iface=self._interface,
                filter=self._bpf_filter,
                prn=lambda pkt: self._queue_put(pkt),
                store=False,
                stop_filter=_stop_check,
            )
        finally:
            self._queue.put(_EOF)

    def _queue_put(self, pkt) -> None:
        self._queue.put(pkt)

    def packets(self, timeout: float = 0.5) -> Generator:
        """Yield captured packets until ``stop()`` is called.

        ``timeout`` is the queue-poll interval (seconds); it keeps the loop
        reactive to Ctrl+C while the sniffer thread runs.
        """
        while not self._stop_event.is_set() or not self._queue.empty():
            try:
                item = self._queue.get(timeout=timeout)
            except Empty:
                if self._stop_event.is_set():
                    break
                continue
            if item is _EOF:
                break
            yield item

    # ------------------------------------------------------------------ #
    def stop(self) -> None:
        """Stop capturing and wait for the worker thread to finish."""
        self._stop_event.set()
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=5)

    def __enter__(self) -> "LiveCapture":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


class OfflineCapture:
    """Streaming pcap/pcapng reader used for validation against known files."""

    def __init__(self, pcap_path: str) -> None:
        import os

        if not os.path.isfile(pcap_path):
            raise FileNotFoundError(pcap_path)
        self._path = pcap_path

    def packets(self) -> Generator:
        """Yield the packets of the pcap file one by one."""
        from scapy.all import PcapReader

        with PcapReader(self._path) as reader:
            for pkt in reader:
                yield pkt