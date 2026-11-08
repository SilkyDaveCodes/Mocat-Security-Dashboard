"""Flow-classifier feature extractor shared by training and the live detector (CLAUDE.md §6.3, §7).

``models/train_flow.py`` and the live ``agent/detectors/flow_model.py`` both call
:func:`vector` (or :func:`features`), so the model is always scored on exactly the features it was
trained on. This module is pure Python: no NFStream, no network, no files, no OS-specific code.

Input
    A mapping of raw NFStream statistics: the same dict that ``agent/capture.py`` puts in
    ``FlowEvent.features`` (its ``FEATURE_FIELDS``, which :data:`RAW_FIELDS` mirrors; a test keeps
    them equal). Training builds the same dict from each pcap flow. A missing, ``None``,
    non-numeric, NaN or infinite value counts as ``0.0``; extra keys are ignored.

Features, all ``float``, in :data:`FEATURE_NAMES` order
    * every :data:`RAW_FIELDS` entry as-is: per-direction (``bidirectional``, ``src2dst``,
      ``dst2src``) duration, packet and byte counts, packet-size stats (``*_ps``), packet
      inter-arrival-time stats (``*_piat_ms``) and TCP flag counts;
    * derived ratios (:data:`DERIVED_NAMES`), each ``0.0`` when its denominator is ``0``:

      ``bytes_per_packet``      bidirectional_bytes / bidirectional_packets
      ``src2dst_byte_share``    src2dst_bytes / bidirectional_bytes
      ``src2dst_packet_share``  src2dst_packets / bidirectional_packets
      ``syn_share``             bidirectional_syn_packets / bidirectional_packets
      ``rst_share``             bidirectional_rst_packets / bidirectional_packets
      ``packets_per_s``         bidirectional_packets / (bidirectional_duration_ms / 1000);
                                a 0 ms flow uses 1 ms

Only behaviour: never IP addresses, ports, MACs, VLANs, timestamps, flow ids or the protocol
number (§7). No feature name contains ``ip`` or ``port`` (tested).
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from typing import Any

_DIRECTIONS = ("bidirectional", "src2dst", "dst2src")
_STATS = ("min", "mean", "stddev", "max")
_TCP_FLAGS = ("syn", "cwr", "ece", "urg", "ack", "psh", "rst", "fin")

RAW_FIELDS: tuple[str, ...] = (
    *(f"{d}_{m}" for d in _DIRECTIONS for m in ("duration_ms", "packets", "bytes")),
    *(f"{d}_{s}_ps" for d in _DIRECTIONS for s in _STATS),
    *(f"{d}_{s}_piat_ms" for d in _DIRECTIONS for s in _STATS),
    *(f"{d}_{f}_packets" for d in _DIRECTIONS for f in _TCP_FLAGS),
)
"""NFStream fields used as-is. Mirrors ``agent.capture.FEATURE_FIELDS``."""

DERIVED_NAMES: tuple[str, ...] = (
    "bytes_per_packet",
    "src2dst_byte_share",
    "src2dst_packet_share",
    "syn_share",
    "rst_share",
    "packets_per_s",
)

FEATURE_NAMES: tuple[str, ...] = (*RAW_FIELDS, *DERIVED_NAMES)
"""Column order of every feature vector."""


def _num(value: Any) -> float:
    try:
        x = float(value)
    except (TypeError, ValueError):
        return 0.0
    return x if math.isfinite(x) else 0.0


def _ratio(num: float, den: float) -> float:
    return num / den if den > 0 else 0.0


def features(raw: Mapping[str, Any] | None) -> dict[str, float]:
    """Feature dict (keys in :data:`FEATURE_NAMES` order) from raw NFStream statistics."""
    raw = raw or {}
    out = {name: _num(raw.get(name)) for name in RAW_FIELDS}
    packets = out["bidirectional_packets"]
    total_bytes = out["bidirectional_bytes"]
    duration_s = max(out["bidirectional_duration_ms"], 1.0) / 1000.0
    out["bytes_per_packet"] = _ratio(total_bytes, packets)
    out["src2dst_byte_share"] = _ratio(out["src2dst_bytes"], total_bytes)
    out["src2dst_packet_share"] = _ratio(out["src2dst_packets"], packets)
    out["syn_share"] = _ratio(out["bidirectional_syn_packets"], packets)
    out["rst_share"] = _ratio(out["bidirectional_rst_packets"], packets)
    out["packets_per_s"] = packets / duration_s
    return out


def vector(raw: Mapping[str, Any] | None) -> list[float]:
    """:func:`features` as a list in :data:`FEATURE_NAMES` order (one model input row)."""
    feats = features(raw)
    return [feats[name] for name in FEATURE_NAMES]
