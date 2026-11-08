"""Tests for models/train_flow.py (ticket #47). Synthetic flows, no NFStream, no pcaps."""

from __future__ import annotations

import csv
import io
import random
from pathlib import Path

import joblib
import pytest

from agent.detectors.flow_features import FEATURE_NAMES, vector
from models import train_flow

LABELS = ("benign", "portscan", "bruteforce", "dos")


def synth_flow(label: str, rng: random.Random) -> dict:
    """One raw NFStream-statistics dict with a label-typical shape."""
    j = rng.uniform(0.8, 1.2)
    if label == "benign":  # longish two-way exchange, big payloads
        pk, out_pk, b, dur, syn, rst = 40, 18, 30_000, 4000, 1, 0
    elif label == "portscan":  # one SYN, one RST back, tiny packets
        pk, out_pk, b, dur, syn, rst = 2, 1, 114, 1, 1, 1
    elif label == "bruteforce":  # short login attempt, small packets both ways
        pk, out_pk, b, dur, syn, rst = 10, 5, 1_400, 60, 1, 0
    else:  # dos: many small packets from the client, very fast
        pk, out_pk, b, dur, syn, rst = 300, 295, 18_000, 200, 50, 5
    pk = max(1, int(pk * j))
    out_pk = min(pk, max(1, int(out_pk * j)))
    b = int(b * j)
    return {
        "bidirectional_packets": pk,
        "src2dst_packets": out_pk,
        "dst2src_packets": pk - out_pk,
        "bidirectional_bytes": b,
        "src2dst_bytes": b * out_pk // pk,
        "dst2src_bytes": b - b * out_pk // pk,
        "bidirectional_duration_ms": int(dur * j),
        "bidirectional_mean_ps": b / pk,
        "bidirectional_syn_packets": syn,
        "bidirectional_rst_packets": rst,
        "bidirectional_mean_piat_ms": dur * j / max(pk - 1, 1),
        # identity fields that must never reach the model
        "src_ip": f"192.168.56.{rng.randint(2, 250)}",
        "dst_port": rng.randint(1, 65535),
    }


def synth_flows(counts: dict[str, int] | None = None, seed: int = 7) -> dict[str, list[dict]]:
    rng = random.Random(seed)
    counts = counts or {label: 60 for label in LABELS}
    return {label: [synth_flow(label, rng) for _ in range(n)] for label, n in counts.items()}


def run_small(tmp_path, flows=None, cap=50, name="flow", out=None):
    return train_flow.run(
        flows if flows is not None else synth_flows(),
        out_path=tmp_path / f"{name}.joblib",
        confusion_path=tmp_path / f"{name}_confusion.csv",
        cap=cap,
        n_estimators=15,
        out=out if out is not None else io.StringIO(),
    )


def write_labels(tmp_path: Path) -> Path:
    pcaps = tmp_path / "pcaps"
    pcaps.mkdir()
    lines = ["version: 1", "pcaps:"]
    for label in LABELS:
        (pcaps / f"{label}.pcapng").write_bytes(b"")  # loader is injected; content unused
        lines += [f"  - file: {label}.pcapng", f"    label: {label}"]
    path = pcaps / "labels.yaml"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def fake_loader(flows: dict[str, list[dict]]):
    seen: list[Path] = []

    def load(path: Path):
        seen.append(path)
        return flows[path.stem]

    load.seen = seen  # type: ignore[attr-defined]
    return load


# --- AC1: small fixture -> loadable model that predicts the four labels ------------------------


def test_main_writes_loadable_model_that_predicts_four_labels(tmp_path):
    labels_path = write_labels(tmp_path)
    loader = fake_loader(synth_flows())
    model_path = tmp_path / "out" / "flow.joblib"

    rc = train_flow.main(
        ["--labels", str(labels_path), "--out", str(model_path),
         "--confusion", str(tmp_path / "out" / "c.csv"), "--cap", "50", "--n-estimators", "15"],
        flow_loader=loader,
    )

    assert rc == 0
    assert sorted(p.name for p in loader.seen) == sorted(f"{lb}.pcapng" for lb in LABELS)
    bundle = joblib.load(model_path)
    model = bundle["model"]
    assert set(model.classes_) == set(LABELS)
    assert bundle["classes"] == list(LABELS)
    assert bundle["feature_names"] == list(FEATURE_NAMES)

    rng = random.Random(1234)
    probes = {label: vector(synth_flow(label, rng)) for label in LABELS}
    preds = model.predict(list(probes.values()))
    assert set(preds) <= set(LABELS)
    assert list(preds) == list(probes)  # each clean probe gets its own label back
    probs = model.predict_proba(list(probes.values()))
    for row, label in enumerate(probes):
        assert probs[row][bundle["class_index"][label]] > 0.5


def test_confusion_matrix_saved_as_csv(tmp_path):
    run_small(tmp_path)
    with open(tmp_path / "flow_confusion.csv", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == ["true\\predicted", *LABELS]
    assert [r[0] for r in rows[1:]] == list(LABELS)
    assert sum(int(v) for r in rows[1:] for v in r[1:]) == 40  # 20% of 4 * 50 rows


def test_missing_pcap_is_a_clear_error(tmp_path):
    labels_path = write_labels(tmp_path)
    (labels_path.parent / "dos.pcapng").unlink()
    with pytest.raises(FileNotFoundError, match="dos.pcapng"):
        train_flow.load_labeled_flows(labels_path, flow_loader=fake_loader(synth_flows()))


def test_read_labels_rejects_unknown_label(tmp_path):
    path = tmp_path / "labels.yaml"
    path.write_text("version: 1\npcaps:\n  - file: x.pcapng\n    label: ddos\n", encoding="utf-8")
    with pytest.raises(ValueError, match="ddos"):
        train_flow.read_labels(path)


def test_repo_labels_file_parses():
    pairs = train_flow.read_labels(train_flow.DEFAULT_LABELS)
    assert sorted({label for _, label in pairs}) == sorted(LABELS)
    assert all(p.parent == train_flow.DEFAULT_LABELS.parent for p, _ in pairs)


# --- AC2: prints class counts, classification report, confusion matrix, top features -----------


def test_prints_required_sections(tmp_path, capsys):
    labels_path = write_labels(tmp_path)
    train_flow.main(
        ["--labels", str(labels_path), "--out", str(tmp_path / "m.joblib"),
         "--confusion", str(tmp_path / "c.csv"), "--cap", "50", "--n-estimators", "15"],
        flow_loader=fake_loader(synth_flows()),
    )
    text = capsys.readouterr().out

    assert "Loaded flows: benign=60 portscan=60 bruteforce=60 dos=60" in text
    assert "Class counts after cap=50: benign=50 portscan=50 bruteforce=50 dos=50" in text

    report = text.split("Classification report")[1].split("Confusion matrix")[0]
    assert "precision" in report and "recall" in report and "f1-score" in report
    for label in LABELS:
        assert label in report

    matrix = text.split("Confusion matrix")[1].split("Top features")[0]
    parts = [ln.split() for ln in matrix.splitlines()]
    matrix_rows = [r for r in parts if len(r) == 1 + len(LABELS) and r[0] in LABELS]
    assert [r[0] for r in matrix_rows] == list(LABELS)
    assert sum(int(v) for r in matrix_rows for v in r[1:]) == 40

    top = text.split("Top features")[1].split("Saved model")[0]
    ranked = [ln.split() for ln in top.splitlines() if ln.strip()[:1].isdigit()]
    assert len(ranked) == 15
    assert ranked[0][0] == "1."
    assert all(r[1] in FEATURE_NAMES for r in ranked)
    importances = [float(r[2]) for r in ranked]
    assert importances == sorted(importances, reverse=True) and importances[0] > 0


# --- AC3: no feature name contains ip or port ---------------------------------------------------


def test_saved_feature_names_have_no_ip_or_port(tmp_path):
    bundle = run_small(tmp_path)
    assert bundle["feature_names"]
    for name in bundle["feature_names"]:
        assert "ip" not in name.lower(), name
        assert "port" not in name.lower(), name
    assert bundle["model"].n_features_in_ == len(FEATURE_NAMES)


def test_featurize_ignores_ip_and_port_fields():
    flow = synth_flows({"benign": 1})["benign"][0]
    stripped = {k: v for k, v in flow.items() if k not in ("src_ip", "dst_port")}
    assert train_flow.featurize([flow]) == train_flow.featurize([stripped])


# --- AC4: capped at 20k and balanced on a lopsided fixture --------------------------------------


def test_default_cap_is_20k():
    assert train_flow.DEFAULT_CAP == 20_000
    assert train_flow.parse_args([]).cap == 20_000


def test_cap_and_balance_lopsided_uses_smallest_class():
    flows = synth_flows({"benign": 300, "portscan": 25, "bruteforce": 80, "dos": 150})
    balanced = train_flow.cap_and_balance(flows, cap=1000)
    assert {label: len(v) for label, v in balanced.items()} == {label: 25 for label in LABELS}
    for label in LABELS:
        assert all(row in flows[label] for row in balanced[label])


def test_cap_and_balance_applies_cap_when_all_classes_are_bigger():
    flows = synth_flows({"benign": 300, "portscan": 90, "bruteforce": 120, "dos": 200})
    balanced = train_flow.cap_and_balance(flows, cap=40)
    assert all(len(balanced[label]) == 40 for label in LABELS)
    for label in LABELS:  # sampled without replacement
        assert len({id(row) for row in balanced[label]}) == 40


def test_cap_and_balance_is_seeded():
    flows = synth_flows({"benign": 200, "portscan": 100, "bruteforce": 100, "dos": 100})
    assert train_flow.cap_and_balance(flows, cap=30) == train_flow.cap_and_balance(flows, cap=30)


def test_cap_and_balance_rejects_empty_class_and_bad_cap():
    flows = synth_flows({"benign": 10, "portscan": 10, "bruteforce": 10, "dos": 0})
    with pytest.raises(ValueError, match="dos"):
        train_flow.cap_and_balance(flows, cap=10)
    with pytest.raises(ValueError):
        train_flow.cap_and_balance(synth_flows(), cap=0)


def test_run_on_lopsided_data_trains_balanced(tmp_path):
    buf = io.StringIO()
    flows = synth_flows({"benign": 400, "portscan": 70, "bruteforce": 45, "dos": 120})
    bundle = run_small(tmp_path, flows=flows, cap=60, out=buf)
    assert bundle["trained_rows_per_class"] == 45
    assert "benign=45 portscan=45 bruteforce=45 dos=45" in buf.getvalue()


# --- determinism ---------------------------------------------------------------------------------


def test_two_runs_identical_predictions_and_random_state_42(tmp_path):
    a = run_small(tmp_path, name="a")
    b = run_small(tmp_path, name="b")
    probe = train_flow.featurize(
        [row for rows in synth_flows(seed=99).values() for row in rows]
    )
    assert (a["model"].predict_proba(probe) == b["model"].predict_proba(probe)).all()
    assert a["random_state"] == 42 and a["model"].random_state == 42
