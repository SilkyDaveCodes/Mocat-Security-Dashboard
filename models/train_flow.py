"""Train the inbound flow classifier (CLAUDE.md §6.3, §7) -> ``models/flow.joblib``.

Data
    ``lab/pcaps/labels.yaml`` (``--labels``; format in that file and ``lab/pcaps/README.md``):
    ``version: 1`` and ``pcaps: [{file, label}]``, ``file`` relative to the labels file's folder,
    ``label`` one of :data:`CLASSES`. A label may list several pcaps; their flows are pooled.
    Every pcap is read with NFStream (``statistical_analysis=True``, the same statistics live
    capture copies into ``FlowEvent.features``), one row per flow. The pcaps are made on the lab
    VM and are not in git. NFStream is imported only inside :func:`pcap_flows`, and the loader is
    injectable (``flow_loader=``), so tests run anywhere without NFStream or pcaps.

Pipeline
    load -> cap/balance (every class cut to ``min(cap, smallest class)`` rows by a seeded random
    sample, so all four classes end up the same size and never above the cap) -> featurize with
    :func:`agent.detectors.flow_features.vector` -> stratified 80/20 split ->
    ``RandomForestClassifier`` -> report. ``random_state=42`` everywhere and ``n_jobs=1``.
    Features are exactly :data:`agent.detectors.flow_features.FEATURE_NAMES`; no IPs or ports (§7).

Saved model format (``joblib.dump`` of a dict)::

    {
        "format_version": 1,
        "model": RandomForestClassifier,      # fitted on string labels; predict -> label strings
        "feature_names": [...],               # == list(FEATURE_NAMES), column order of X
        "classes": ["benign", "portscan", "bruteforce", "dos"],
        "class_index": {"benign": i, ...},    # column of predict_proba for each label
        "random_state": 42,
        "trained_rows_per_class": int,
    }

    The live detector builds ``vector(event.features)`` and reads
    ``bundle["model"].predict_proba([vec])[0]``, using ``class_index`` to find each label.

Confusion matrix
    Printed, and saved as CSV (``--confusion``, default ``models/flow_confusion.csv``). Rows are
    the true class, columns the predicted class.

Usage::

    .venv\\Scripts\\python models\\train_flow.py
    .venv\\Scripts\\python models\\train_flow.py --labels lab\\pcaps\\labels.yaml --cap 20000
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path
from typing import Any, TextIO

# Allow running as a plain script (python models/train_flow.py) as well as importing in tests.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agent.detectors.flow_features import FEATURE_NAMES, RAW_FIELDS, vector  # noqa: E402

RANDOM_STATE = 42
DEFAULT_CAP = 20_000
DEFAULT_N_ESTIMATORS = 200
DEFAULT_TEST_SIZE = 0.2
DEFAULT_LABELS = _REPO_ROOT / "lab" / "pcaps" / "labels.yaml"
DEFAULT_OUT = _REPO_ROOT / "models" / "flow.joblib"
DEFAULT_CONFUSION = _REPO_ROOT / "models" / "flow_confusion.csv"
CLASSES: tuple[str, ...] = ("benign", "portscan", "bruteforce", "dos")
LABELS_VERSION = 1
FORMAT_VERSION = 1

RawFlow = Mapping[str, Any]
"""One flow's raw NFStream statistics (the ``FlowEvent.features`` dict)."""

FlowLoader = Callable[[Path], Iterable[RawFlow]]
"""Reads one pcap and yields one :data:`RawFlow` per flow."""


# --------------------------------------------------------------------------- load


def pcap_flows(path: Path) -> list[dict[str, Any]]:  # pragma: no cover - needs NFStream + pcap
    """Read ``path`` with NFStream and return each flow's :data:`RAW_FIELDS` statistics."""
    from nfstream import NFStreamer

    rows: list[dict[str, Any]] = []
    for flow in NFStreamer(source=str(path), statistical_analysis=True):
        rows.append({name: getattr(flow, name, None) for name in RAW_FIELDS})
    return rows


def read_labels(path: str | Path) -> list[tuple[Path, str]]:
    """Parse ``labels.yaml`` into ``(absolute pcap path, label)`` pairs; ValueError if malformed."""
    import yaml

    path = Path(path)
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict) or data.get("version") != LABELS_VERSION:
        raise ValueError(f"{path}: expected a mapping with version: {LABELS_VERSION}")
    entries = data.get("pcaps")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"{path}: 'pcaps' must be a non-empty list")
    out: list[tuple[Path, str]] = []
    for entry in entries:
        if not isinstance(entry, dict) or "file" not in entry or "label" not in entry:
            raise ValueError(f"{path}: every pcaps entry needs 'file' and 'label': {entry!r}")
        label = str(entry["label"])
        if label not in CLASSES:
            raise ValueError(f"{path}: unknown label {label!r} (expected one of {CLASSES})")
        out.append((path.parent / str(entry["file"]), label))
    return out


def load_labeled_flows(
    labels_path: str | Path = DEFAULT_LABELS, flow_loader: FlowLoader = pcap_flows
) -> dict[str, list[RawFlow]]:
    """Flows per label (every label in :data:`CLASSES` present, possibly empty)."""
    flows: dict[str, list[RawFlow]] = {label: [] for label in CLASSES}
    for pcap, label in read_labels(labels_path):
        if not pcap.is_file():
            raise FileNotFoundError(
                f"{pcap} is missing; capture it on the lab VM (see lab/pcaps/README.md)"
            )
        flows[label].extend(flow_loader(pcap))
    return flows


# --------------------------------------------------------------------------- cap / balance


def cap_and_balance(
    flows: Mapping[str, Sequence[RawFlow]],
    cap: int = DEFAULT_CAP,
    random_state: int = RANDOM_STATE,
) -> dict[str, list[RawFlow]]:
    """Cut every class in :data:`CLASSES` to ``min(cap, smallest class)`` rows (seeded sample)."""
    if cap <= 0:
        raise ValueError("cap must be positive")
    empty = [label for label in CLASSES if not flows.get(label)]
    if empty:
        raise ValueError(f"every class needs at least one flow; empty: {empty}")
    n = min(cap, *(len(flows[label]) for label in CLASSES))
    rng = random.Random(random_state)
    return {label: rng.sample(list(flows[label]), n) for label in CLASSES}


# --------------------------------------------------------------------------- featurize


def featurize(raw_flows: Iterable[RawFlow]) -> list[list[float]]:
    """One row per flow, columns in :data:`FEATURE_NAMES` order."""
    return [vector(raw) for raw in raw_flows]


def build_dataset(flows: Mapping[str, Sequence[RawFlow]]) -> tuple[list[list[float]], list[str]]:
    """Features and string labels, classes in :data:`CLASSES` order."""
    X: list[list[float]] = []
    y: list[str] = []
    for label in CLASSES:
        X.extend(featurize(flows[label]))
        y.extend([label] * len(flows[label]))
    return X, y


# --------------------------------------------------------------------------- train


def train(X, y, n_estimators: int = DEFAULT_N_ESTIMATORS, random_state: int = RANDOM_STATE):
    """Fit a deterministic random forest."""
    from sklearn.ensemble import RandomForestClassifier

    model = RandomForestClassifier(
        n_estimators=n_estimators, random_state=random_state, n_jobs=1
    )
    model.fit(X, y)
    return model


def make_bundle(model, rows_per_class: int) -> dict:
    """The dict that is saved to ``flow.joblib`` (format in the module docstring)."""
    model_classes = [str(c) for c in model.classes_]
    return {
        "format_version": FORMAT_VERSION,
        "model": model,
        "feature_names": list(FEATURE_NAMES),
        "classes": list(CLASSES),
        "class_index": {label: model_classes.index(label) for label in CLASSES},
        "random_state": RANDOM_STATE,
        "trained_rows_per_class": rows_per_class,
    }


# --------------------------------------------------------------------------- report


def top_features(model) -> list[tuple[str, float]]:
    """Feature importances, highest first."""
    pairs = zip(FEATURE_NAMES, model.feature_importances_, strict=True)
    return sorted(((n, float(v)) for n, v in pairs), key=lambda p: p[1], reverse=True)


def report(model, X_test, y_test, out: TextIO | None = None, top_n: int = 15) -> list[list[int]]:
    """Print a classification report, confusion matrix and top features; return the matrix."""
    from sklearn.metrics import classification_report, confusion_matrix

    out = out if out is not None else sys.stdout
    labels = list(CLASSES)

    y_pred = model.predict(X_test)
    print("\nClassification report (test split):", file=out)
    print(
        classification_report(y_test, y_pred, labels=labels, zero_division=0),
        file=out,
    )
    matrix = confusion_matrix(y_test, y_pred, labels=labels).tolist()
    print("Confusion matrix (rows = true, columns = predicted):", file=out)
    width = max(len(c) for c in CLASSES) + 2
    print(" " * width + "".join(f"{c:>{width}}" for c in CLASSES), file=out)
    for name, row in zip(CLASSES, matrix, strict=True):
        print(f"{name:<{width}}" + "".join(f"{v:>{width}}" for v in row), file=out)
    print(f"\nTop features (importance, top {top_n}):", file=out)
    for rank, (name, value) in enumerate(top_features(model)[:top_n], start=1):
        print(f"  {rank}. {name:<32} {value:.4f}", file=out)
    return matrix


def save_confusion(matrix: Sequence[Sequence[int]], path: str | Path) -> None:
    """Write the confusion matrix as CSV: header ``true\\predicted,benign,portscan,...``."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["true\\predicted", *CLASSES])
        for name, row in zip(CLASSES, matrix, strict=True):
            writer.writerow([name, *row])


# --------------------------------------------------------------------------- main


def _counts(flows: Mapping[str, Sequence[RawFlow]]) -> str:
    return " ".join(f"{label}={len(flows.get(label, ()))}" for label in CLASSES)


def run(
    flows: Mapping[str, Sequence[RawFlow]],
    out_path: str | Path = DEFAULT_OUT,
    confusion_path: str | Path = DEFAULT_CONFUSION,
    cap: int = DEFAULT_CAP,
    n_estimators: int = DEFAULT_N_ESTIMATORS,
    test_size: float = DEFAULT_TEST_SIZE,
    out: TextIO | None = None,
) -> dict:
    """Train on in-memory flows per label, save model + confusion matrix; return the bundle."""
    import joblib
    from sklearn.model_selection import train_test_split

    out = out if out is not None else sys.stdout

    print(f"Loaded flows: {_counts(flows)}", file=out)
    balanced = cap_and_balance(flows, cap=cap)
    print(f"Class counts after cap={cap}: {_counts(balanced)}", file=out)

    X, y = build_dataset(balanced)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=RANDOM_STATE
    )
    print(f"Train rows={len(X_train)} test rows={len(X_test)}", file=out)

    model = train(X_train, y_train, n_estimators=n_estimators)
    matrix = report(model, X_test, y_test, out=out)

    rows_per_class = len(balanced[CLASSES[0]])
    bundle = make_bundle(model, rows_per_class=rows_per_class)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out_path)
    save_confusion(matrix, confusion_path)
    print(f"\nSaved model -> {out_path}", file=out)
    print(f"Saved confusion matrix -> {confusion_path}", file=out)
    return bundle


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train the HomeSOC inbound flow classifier.")
    p.add_argument("--labels", default=str(DEFAULT_LABELS), help="labels.yaml listing the pcaps")
    p.add_argument("--out", default=str(DEFAULT_OUT), help="model output path")
    p.add_argument("--confusion", default=str(DEFAULT_CONFUSION), help="confusion matrix CSV path")
    p.add_argument("--cap", type=int, default=DEFAULT_CAP, help="max rows per class")
    p.add_argument("--n-estimators", type=int, default=DEFAULT_N_ESTIMATORS)
    p.add_argument("--test-size", type=float, default=DEFAULT_TEST_SIZE)
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None, flow_loader: FlowLoader = pcap_flows) -> int:
    args = parse_args(argv)
    flows = load_labeled_flows(args.labels, flow_loader=flow_loader)
    run(
        flows,
        out_path=args.out,
        confusion_path=args.confusion,
        cap=args.cap,
        n_estimators=args.n_estimators,
        test_size=args.test_size,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
