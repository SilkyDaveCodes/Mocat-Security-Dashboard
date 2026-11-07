"""Train the DGA classifier (CLAUDE.md §6.3, §7) -> ``models/dga.joblib``.

Data
    * Benign: Tranco top 100k. Pass ``--benign FILE`` (one domain per line), or leave it out and
      the list is fetched with the ``tranco`` package (the only network use of this script).
    * DGA: ``--dga FILE``, one domain per line, which you generate locally from a few families in
      ``github.com/baderj/domain_generation_algorithms``. That code is GPL-2.0 and is used for
      training only: it is never vendored into this repo or shipped.

    Input files: blank lines and lines starting with ``#`` are skipped. Each line is stripped and
    lowercased; if a line has extra columns (``1,google.com`` or ``google.com  family``) the field
    that looks like a domain is used. Duplicates are dropped (first occurrence kept).

Pipeline
    load -> cap/balance (both classes cut to ``min(len(benign), len(dga), cap)`` by a seeded random
    sample) -> featurize with :func:`agent.detectors.dga_features.features` -> stratified 80/20
    split -> ``RandomForestClassifier`` -> report. ``random_state=42`` everywhere (sampling, split,
    model) and ``n_jobs=1``, so two runs on the same data give identical predictions.
    Features are exactly :data:`agent.detectors.dga_features.FEATURE_NAMES`; no IPs or ports (§7).

Saved model format (``joblib.dump`` of a dict)::

    {
        "format_version": 1,
        "model": RandomForestClassifier,        # fitted; has predict_proba
        "feature_names": ["length", ...],       # == list(FEATURE_NAMES), column order of X
        "classes": ["benign", "dga"],           # label 0, label 1
        "dga_class_index": 1,                   # column of predict_proba that is P(dga)
        "random_state": 42,
        "trained_rows_per_class": int,
    }

    The live detector builds a vector as ``[features(host)[k] for k in bundle["feature_names"]]``
    and reads ``bundle["model"].predict_proba([vec])[0][bundle["dga_class_index"]]``.

Confusion matrix
    Printed, and saved as CSV (``--confusion``, default ``models/dga_confusion.csv``) for the
    metrics slide. Rows are the true class, columns the predicted class. No matplotlib needed.

Usage::

    .venv\\Scripts\\python models\\train_dga.py --dga data\\dga_domains.txt
    .venv\\Scripts\\python models\\train_dga.py --benign tranco.txt --dga dga.txt --cap 100000
"""

from __future__ import annotations

import argparse
import csv
import random
import sys
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import TextIO

# Allow running as a plain script (python models/train_dga.py) as well as importing in tests.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from agent.detectors.dga_features import FEATURE_NAMES, features  # noqa: E402

RANDOM_STATE = 42
DEFAULT_CAP = 100_000
DEFAULT_N_ESTIMATORS = 200
DEFAULT_TEST_SIZE = 0.2
DEFAULT_OUT = _REPO_ROOT / "models" / "dga.joblib"
DEFAULT_CONFUSION = _REPO_ROOT / "models" / "dga_confusion.csv"
CLASSES: tuple[str, str] = ("benign", "dga")
BENIGN, DGA = 0, 1
FORMAT_VERSION = 1


# --------------------------------------------------------------------------- load


def _pick_domain(line: str) -> str:
    """Return the domain-looking field of a line (handles ``rank,domain`` and extra columns)."""
    fields = [f for f in line.replace(",", " ").replace("\t", " ").split(" ") if f]
    for field in fields:
        if "." in field and not field.replace(".", "").isdigit():
            return field
    return fields[0] if fields else ""


def parse_domains(lines: Iterable[str]) -> list[str]:
    """Clean raw lines into a de-duplicated list of lowercase domains (rules in the docstring)."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domain = _pick_domain(line).strip().lower().rstrip(".")
        if domain and domain not in seen:
            seen.add(domain)
            out.append(domain)
    return out


def load_domains(path: str | Path) -> list[str]:
    """Read a one-domain-per-line file."""
    with open(path, encoding="utf-8") as fh:
        return parse_domains(fh)


def fetch_tranco(top: int) -> list[str]:  # pragma: no cover - network
    """Fetch the Tranco top ``top`` domains with the ``tranco`` package (cached locally)."""
    from tranco import Tranco

    cache_dir = _REPO_ROOT / "data" / "cache" / "tranco"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return parse_domains(Tranco(cache=True, cache_dir=str(cache_dir)).list().top(top))


# --------------------------------------------------------------------------- cap / balance


def cap_and_balance(
    benign: Sequence[str],
    dga: Sequence[str],
    cap: int = DEFAULT_CAP,
    random_state: int = RANDOM_STATE,
) -> tuple[list[str], list[str]]:
    """Cut both classes to ``min(len(benign), len(dga), cap)`` rows each by seeded sampling."""
    if cap <= 0:
        raise ValueError("cap must be positive")
    n = min(len(benign), len(dga), cap)
    if n == 0:
        raise ValueError("both classes need at least one domain")
    rng = random.Random(random_state)
    return rng.sample(list(benign), n), rng.sample(list(dga), n)


# --------------------------------------------------------------------------- featurize


def featurize(domains: Iterable[str]) -> list[list[float]]:
    """One row per domain, columns in :data:`FEATURE_NAMES` order."""
    rows = []
    for domain in domains:
        feats = features(domain)
        rows.append([feats[name] for name in FEATURE_NAMES])
    return rows


def build_dataset(benign: Sequence[str], dga: Sequence[str]) -> tuple[list[list[float]], list[int]]:
    """Features and labels (``0`` benign, ``1`` dga)."""
    X = featurize(benign) + featurize(dga)
    y = [BENIGN] * len(benign) + [DGA] * len(dga)
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
    """The dict that is saved to ``dga.joblib`` (format in the module docstring)."""
    return {
        "format_version": FORMAT_VERSION,
        "model": model,
        "feature_names": list(FEATURE_NAMES),
        "classes": list(CLASSES),
        "dga_class_index": list(model.classes_).index(DGA),
        "random_state": RANDOM_STATE,
        "trained_rows_per_class": rows_per_class,
    }


# --------------------------------------------------------------------------- report


def top_features(model) -> list[tuple[str, float]]:
    """Feature importances, highest first."""
    pairs = zip(FEATURE_NAMES, model.feature_importances_, strict=True)
    return sorted(((n, float(v)) for n, v in pairs), key=lambda p: p[1], reverse=True)


def report(model, X_test, y_test, out: TextIO | None = None) -> list[list[int]]:
    """Print a classification report, confusion matrix and top features; return the matrix."""
    from sklearn.metrics import classification_report, confusion_matrix

    out = out if out is not None else sys.stdout

    y_pred = model.predict(X_test)
    print("\nClassification report (test split):", file=out)
    print(
        classification_report(
            y_test, y_pred, labels=[BENIGN, DGA], target_names=list(CLASSES), zero_division=0
        ),
        file=out,
    )
    matrix = confusion_matrix(y_test, y_pred, labels=[BENIGN, DGA]).tolist()
    print("Confusion matrix (rows = true, columns = predicted):", file=out)
    width = max(len(c) for c in CLASSES) + 2
    print(" " * width + "".join(f"{c:>{width}}" for c in CLASSES), file=out)
    for name, row in zip(CLASSES, matrix, strict=True):
        print(f"{name:<{width}}" + "".join(f"{v:>{width}}" for v in row), file=out)
    print("\nTop features (importance):", file=out)
    for rank, (name, value) in enumerate(top_features(model), start=1):
        print(f"  {rank}. {name:<24} {value:.4f}", file=out)
    return matrix


def save_confusion(matrix: Sequence[Sequence[int]], path: str | Path) -> None:
    """Write the confusion matrix as CSV: header ``true\\predicted,benign,dga``."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["true\\predicted", *CLASSES])
        for name, row in zip(CLASSES, matrix, strict=True):
            writer.writerow([name, *row])


# --------------------------------------------------------------------------- main


def run(
    benign: Sequence[str],
    dga: Sequence[str],
    out_path: str | Path = DEFAULT_OUT,
    confusion_path: str | Path = DEFAULT_CONFUSION,
    cap: int = DEFAULT_CAP,
    n_estimators: int = DEFAULT_N_ESTIMATORS,
    test_size: float = DEFAULT_TEST_SIZE,
    out: TextIO | None = None,
) -> dict:
    """Train on in-memory domain lists, save the model and confusion matrix, return the bundle."""
    import joblib
    from sklearn.model_selection import train_test_split

    out = out if out is not None else sys.stdout

    print(f"Loaded: benign={len(benign)} dga={len(dga)}", file=out)
    benign_s, dga_s = cap_and_balance(benign, dga, cap=cap)
    print(f"Class counts after cap={cap}: benign={len(benign_s)} dga={len(dga_s)}", file=out)

    X, y = build_dataset(benign_s, dga_s)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=RANDOM_STATE
    )
    print(f"Train rows={len(X_train)} test rows={len(X_test)}", file=out)

    model = train(X_train, y_train, n_estimators=n_estimators)
    matrix = report(model, X_test, y_test, out=out)

    bundle = make_bundle(model, rows_per_class=len(benign_s))
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, out_path)
    save_confusion(matrix, confusion_path)
    print(f"\nSaved model -> {out_path}", file=out)
    print(f"Saved confusion matrix -> {confusion_path}", file=out)
    return bundle


def parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Train the HomeSOC DGA classifier.")
    p.add_argument("--benign", help="benign domains file (default: fetch Tranco top --cap)")
    p.add_argument("--dga", required=True, help="DGA domains file (generated locally from baderj)")
    p.add_argument("--out", default=str(DEFAULT_OUT), help="model output path")
    p.add_argument("--confusion", default=str(DEFAULT_CONFUSION), help="confusion matrix CSV path")
    p.add_argument("--cap", type=int, default=DEFAULT_CAP, help="max rows per class")
    p.add_argument("--n-estimators", type=int, default=DEFAULT_N_ESTIMATORS)
    p.add_argument("--test-size", type=float, default=DEFAULT_TEST_SIZE)
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    benign = load_domains(args.benign) if args.benign else fetch_tranco(args.cap)
    dga = load_domains(args.dga)
    run(
        benign,
        dga,
        out_path=args.out,
        confusion_path=args.confusion,
        cap=args.cap,
        n_estimators=args.n_estimators,
        test_size=args.test_size,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
