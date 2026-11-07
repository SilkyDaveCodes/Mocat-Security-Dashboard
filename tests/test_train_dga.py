"""Tests for models/train_dga.py (ticket #11). Small synthetic fixtures, no network."""

from __future__ import annotations

import csv
import io
import random
import string

import joblib
import pytest

from agent.detectors.dga_features import FEATURE_NAMES, features
from models import train_dga

WORDS = [
    "google", "wiki", "news", "shop", "mail", "cloud", "music", "photo", "video", "games",
    "bank", "travel", "health", "sport", "weather", "market", "store", "home", "book", "food",
]


def benign_fixture(n: int = 120) -> list[str]:
    domains = [f"{a}{b}.com" for a in WORDS for b in WORDS if a != b]
    return domains[:n]


def dga_fixture(n: int = 120, seed: int = 7) -> list[str]:
    rng = random.Random(seed)
    alphabet = string.ascii_lowercase + string.digits
    return [
        "".join(rng.choice(alphabet) for _ in range(rng.randint(14, 24))) + ".net"
        for _ in range(n)
    ]


def run_small(tmp_path, benign=None, dga=None, cap=100, name="dga", out=None):
    return train_dga.run(
        benign if benign is not None else benign_fixture(),
        dga if dga is not None else dga_fixture(),
        out_path=tmp_path / f"{name}.joblib",
        confusion_path=tmp_path / f"{name}_confusion.csv",
        cap=cap,
        n_estimators=15,
        out=out if out is not None else io.StringIO(),
    )


# --- AC1: writes a loadable model with predict_proba -------------------------------------------


def test_main_writes_loadable_model_with_predict_proba(tmp_path):
    benign_file = tmp_path / "benign.txt"
    dga_file = tmp_path / "dga.txt"
    benign_file.write_text("# tranco\n" + "\n".join(benign_fixture()) + "\n\n", encoding="utf-8")
    dga_file.write_text("\n".join(dga_fixture()), encoding="utf-8")
    model_path = tmp_path / "out" / "dga.joblib"
    confusion_path = tmp_path / "out" / "dga_confusion.csv"

    rc = train_dga.main([
        "--benign", str(benign_file), "--dga", str(dga_file), "--out", str(model_path),
        "--confusion", str(confusion_path), "--cap", "100", "--n-estimators", "15",
    ])

    assert rc == 0
    bundle = joblib.load(model_path)
    model = bundle["model"]
    idx = bundle["dga_class_index"]
    vec = lambda host: [features(host)[k] for k in bundle["feature_names"]]  # noqa: E731
    probs = model.predict_proba([vec("xk2q9vbz7mw3plr.net"), vec("musicbank.com")])
    assert probs.shape == (2, 2)
    assert probs[0][idx] > 0.5
    assert probs[1][idx] < 0.5
    assert bundle["classes"] == ["benign", "dga"]


def test_confusion_matrix_saved_as_csv(tmp_path):
    run_small(tmp_path)
    with open(tmp_path / "dga_confusion.csv", encoding="utf-8") as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == ["true\\predicted", "benign", "dga"]
    assert [r[0] for r in rows[1:]] == ["benign", "dga"]
    total = sum(int(v) for r in rows[1:] for v in r[1:])
    assert total == 40  # 20% of 2 * 100 rows


def test_parse_domains_skips_comments_blanks_and_duplicates():
    lines = ["# header", "", "  Google.com. ", "1,wikipedia.org", "google.com", "abc.net dga_x"]
    assert train_dga.parse_domains(lines) == ["google.com", "wikipedia.org", "abc.net"]


# --- AC2: prints class counts, classification report, confusion matrix, top features -----------


def test_prints_required_sections(tmp_path):
    buf = io.StringIO()
    run_small(tmp_path, out=buf)
    text = buf.getvalue()

    assert "Class counts after cap=100: benign=100 dga=100" in text
    assert "Classification report" in text
    assert "precision" in text and "recall" in text and "f1-score" in text
    assert "Confusion matrix" in text
    assert "Top features" in text
    top_section = text.split("Top features")[1]
    for name in FEATURE_NAMES:
        assert name in top_section


def test_main_prints_to_stdout(tmp_path, capsys):
    (tmp_path / "b.txt").write_text("\n".join(benign_fixture()), encoding="utf-8")
    (tmp_path / "d.txt").write_text("\n".join(dga_fixture()), encoding="utf-8")
    train_dga.main([
        "--benign", str(tmp_path / "b.txt"), "--dga", str(tmp_path / "d.txt"),
        "--out", str(tmp_path / "m.joblib"), "--confusion", str(tmp_path / "c.csv"),
        "--cap", "50", "--n-estimators", "5",
    ])
    out = capsys.readouterr().out
    for section in ("Class counts", "Classification report", "Confusion matrix", "Top features"):
        assert section in out


# --- AC3: capped and balanced on a lopsided fixture --------------------------------------------


def test_cap_and_balance_lopsided_uses_smaller_class():
    benign, dga = train_dga.cap_and_balance(benign_fixture(300), dga_fixture(40), cap=1000)
    assert len(benign) == len(dga) == 40
    assert set(benign) <= set(benign_fixture(300))


def test_cap_and_balance_applies_cap():
    benign, dga = train_dga.cap_and_balance(benign_fixture(300), dga_fixture(200), cap=25)
    assert len(benign) == len(dga) == 25
    assert len(set(benign)) == 25 and len(set(dga)) == 25


def test_cap_and_balance_rejects_empty_class():
    with pytest.raises(ValueError):
        train_dga.cap_and_balance(benign_fixture(10), [], cap=10)


def test_run_on_lopsided_data_trains_balanced(tmp_path):
    buf = io.StringIO()
    bundle = run_small(tmp_path, benign=benign_fixture(300), dga=dga_fixture(60), cap=1000, out=buf)
    assert bundle["trained_rows_per_class"] == 60
    assert "benign=60 dga=60" in buf.getvalue()
    # stratified split keeps the training set balanced too
    assert int(bundle["model"].n_features_in_) == len(FEATURE_NAMES)


def test_default_cap_is_100k():
    assert train_dga.DEFAULT_CAP == 100_000
    assert train_dga.parse_args(["--dga", "x.txt"]).cap == 100_000


# --- AC4: features are exactly the dga_features keys, no IPs/ports ------------------------------


def test_feature_names_match_dga_features_keys(tmp_path):
    bundle = run_small(tmp_path)
    assert bundle["feature_names"] == list(FEATURE_NAMES)
    assert bundle["feature_names"] == list(features("example.com").keys())
    assert bundle["model"].n_features_in_ == len(FEATURE_NAMES)
    lowered = [n.lower() for n in bundle["feature_names"]]
    assert not any("ip" in n.split("_") or "port" in n for n in lowered)


def test_featurize_rows_follow_feature_order():
    rows = train_dga.featurize(["google.com", "xk2q9vbz7mw3plr.net"])
    for host, row in zip(["google.com", "xk2q9vbz7mw3plr.net"], rows, strict=True):
        assert row == [features(host)[k] for k in FEATURE_NAMES]


# --- AC5: two runs on the same data give identical predictions ----------------------------------


def test_two_runs_identical_predictions(tmp_path):
    a = run_small(tmp_path, name="a")
    b = run_small(tmp_path, name="b")
    probe = train_dga.featurize(benign_fixture(200)[100:] + dga_fixture(50, seed=99))
    assert (a["model"].predict_proba(probe) == b["model"].predict_proba(probe)).all()
    assert (a["model"].predict(probe) == b["model"].predict(probe)).all()
    assert (tmp_path / "a_confusion.csv").read_text() == (tmp_path / "b_confusion.csv").read_text()


def test_random_state_is_42(tmp_path):
    bundle = run_small(tmp_path)
    assert bundle["random_state"] == 42
    assert bundle["model"].random_state == 42
