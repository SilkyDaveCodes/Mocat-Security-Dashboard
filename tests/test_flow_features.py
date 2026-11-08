"""Tests for agent/detectors/flow_features.py (ticket #47). Pure Python, no NFStream."""

from __future__ import annotations

import math

import pytest

from agent import capture
from agent.detectors import flow_features
from agent.detectors.flow_features import DERIVED_NAMES, FEATURE_NAMES, RAW_FIELDS, features, vector


def test_no_feature_name_contains_ip_or_port():
    for name in FEATURE_NAMES:
        lowered = name.lower()
        assert "ip" not in lowered, name
        assert "port" not in lowered, name


@pytest.mark.parametrize(
    "banned", ["src_ip", "dst_ip", "src_port", "dst_port", "src_mac", "vlan_id", "protocol",
               "id", "expiration_id", "bidirectional_first_seen_ms", "bidirectional_last_seen_ms"],
)
def test_identity_and_time_fields_are_not_features(banned):
    assert banned not in FEATURE_NAMES
    # and passing them in does not change the vector
    base = {"bidirectional_packets": 3, "bidirectional_bytes": 180}
    assert vector({**base, banned: 12345}) == vector(base)


def test_raw_fields_match_what_capture_puts_in_flow_event_features():
    assert RAW_FIELDS == capture.FEATURE_FIELDS


def test_feature_names_are_unique_and_ordered():
    assert len(set(FEATURE_NAMES)) == len(FEATURE_NAMES)
    assert FEATURE_NAMES == (*RAW_FIELDS, *DERIVED_NAMES)
    assert list(features({}).keys()) == list(FEATURE_NAMES)


def test_missing_bad_and_nonfinite_values_become_zero():
    raw = {
        "bidirectional_packets": None,
        "bidirectional_bytes": "oops",
        "src2dst_mean_ps": float("nan"),
        "dst2src_max_ps": float("inf"),
    }
    feats = features(raw)
    assert all(isinstance(v, float) and math.isfinite(v) for v in feats.values())
    assert feats["bidirectional_packets"] == 0.0
    assert feats["src2dst_mean_ps"] == 0.0
    assert feats["dst2src_max_ps"] == 0.0
    assert features(None) == features({})


def test_derived_ratios():
    raw = {
        "bidirectional_packets": 10, "bidirectional_bytes": 1000,
        "src2dst_packets": 4, "src2dst_bytes": 250,
        "bidirectional_syn_packets": 2, "bidirectional_rst_packets": 1,
        "bidirectional_duration_ms": 2000,
    }
    f = features(raw)
    assert f["bytes_per_packet"] == 100.0
    assert f["src2dst_byte_share"] == 0.25
    assert f["src2dst_packet_share"] == 0.4
    assert f["syn_share"] == 0.2
    assert f["rst_share"] == 0.1
    assert f["packets_per_s"] == 5.0


def test_zero_denominators_and_zero_duration():
    f = features({"bidirectional_packets": 2, "bidirectional_duration_ms": 0})
    assert f["bytes_per_packet"] == 0.0
    assert f["src2dst_byte_share"] == 0.0
    assert f["packets_per_s"] == 2000.0  # 0 ms counts as 1 ms
    assert features({})["packets_per_s"] == 0.0


def test_vector_follows_feature_order():
    raw = {name: i + 1 for i, name in enumerate(RAW_FIELDS)}
    vec = vector(raw)
    assert len(vec) == len(FEATURE_NAMES)
    assert vec[: len(RAW_FIELDS)] == [float(i + 1) for i in range(len(RAW_FIELDS))]
    assert vec == [flow_features.features(raw)[k] for k in FEATURE_NAMES]
