"""Tests for the lab pcap labels file and its README (CLAUDE.md §6.3, §7).

Acceptance criterion 2: a labels file maps each pcap to one of the four flow-classifier
labels; this validates every entry's label and that all four labels are covered.

Acceptance criterion 3: the documented pcap filenames are consistent -- every pcap named in
``labels.yaml`` is also documented in ``README.md`` (and vice versa), so the capture
instructions and the trainer's input list cannot drift apart.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
PCAPS_DIR = REPO_ROOT / "lab" / "pcaps"
LABELS_FILE = PCAPS_DIR / "labels.yaml"
README_FILE = PCAPS_DIR / "README.md"

# The four flow-classifier labels (CLAUDE.md §6.3 flow_model: benign, portscan, bruteforce, dos).
VALID_LABELS = {"benign", "portscan", "bruteforce", "dos"}


def _load_labels() -> dict:
    return yaml.safe_load(LABELS_FILE.read_text(encoding="utf-8"))


def _pcap_entries() -> list[dict]:
    data = _load_labels()
    assert isinstance(data, dict), "labels.yaml must be a mapping"
    pcaps = data.get("pcaps")
    assert isinstance(pcaps, list) and pcaps, "labels.yaml must have a non-empty 'pcaps' list"
    return pcaps


# --- AC2: every label is valid and all four labels are covered -------------------------------


def test_labels_file_exists_and_parses() -> None:
    assert LABELS_FILE.is_file(), "lab/pcaps/labels.yaml must exist"
    assert isinstance(_load_labels(), dict)


def test_every_entry_has_a_valid_label_and_file() -> None:
    for entry in _pcap_entries():
        assert isinstance(entry, dict), f"each pcap entry must be a mapping, got {entry!r}"
        assert "file" in entry and isinstance(entry["file"], str) and entry["file"].strip()
        assert "label" in entry, f"entry {entry!r} is missing a label"
        assert entry["label"] in VALID_LABELS, (
            f"label {entry['label']!r} is not one of {sorted(VALID_LABELS)}"
        )


def test_all_four_labels_are_covered() -> None:
    labels = {entry["label"] for entry in _pcap_entries()}
    assert labels == VALID_LABELS, (
        f"labels.yaml must cover exactly {sorted(VALID_LABELS)}, got {sorted(labels)}"
    )


def test_pcap_filenames_are_unique() -> None:
    files = [entry["file"] for entry in _pcap_entries()]
    assert len(files) == len(set(files)), f"duplicate pcap filename(s) in labels.yaml: {files}"


# --- AC3: the README documents exactly the pcap filenames the labels file lists ---------------


def test_readme_mentions_every_labelled_pcap() -> None:
    readme = README_FILE.read_text(encoding="utf-8")
    for entry in _pcap_entries():
        assert entry["file"] in readme, (
            f"pcap {entry['file']!r} from labels.yaml is not documented in README.md"
        )


def test_readme_pcaps_are_all_in_labels_file() -> None:
    import re

    readme = README_FILE.read_text(encoding="utf-8")
    documented = set(re.findall(r"[\w./-]+\.pcapng", readme))
    labelled = {entry["file"] for entry in _pcap_entries()}
    # Every .pcapng filename the README references must be a known, labelled capture.
    assert documented, "README.md should reference the .pcapng capture filenames"
    extra = {Path(name).name for name in documented} - labelled
    assert not extra, f"README.md references pcap(s) absent from labels.yaml: {sorted(extra)}"
