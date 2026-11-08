"""Regenerate data/tranco_top100k.txt, the bundled Tranco fallback for the DGA detector (§6.3).

The DGA detector skips hostnames whose domain is in the Tranco top N. It prefers the downloaded
cache (``paths.tranco_cache``, data/cache/tranco, written by ``models/train_dga.py`` through the
``tranco`` package); a fresh install has no cache, so it falls back to this committed list
(``paths.tranco_bundled``). Build-time only: never bundled (the spec ships the .txt, not this).

Run from the repo root after ``train_dga.py`` has filled the cache, then commit the .txt:

    .venv\\Scripts\\python models\\make_tranco_list.py
    .venv\\Scripts\\python models\\make_tranco_list.py --src data\\cache\\tranco\\Q2VV4.csv

No network: it only reads the cached ``rank,domain`` CSV.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / "data" / "cache" / "tranco"
OUT = ROOT / "data" / "tranco_top100k.txt"
TOP_N = 100_000
SOURCE_URL = "https://tranco-list.eu/"


def newest_csv(cache_dir: Path = CACHE_DIR) -> Path:
    """The newest ``*.csv`` in the tranco package cache (same rule as agent/detectors/dga.py)."""
    csvs = sorted(cache_dir.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not csvs:
        raise FileNotFoundError(f"no Tranco *.csv in {cache_dir}; run models/train_dga.py first")
    return csvs[0]


def top_domains(lines: Iterable[str], top: int = TOP_N) -> list[str]:
    """The first ``top`` distinct domains of ``rank,domain`` (or bare domain) lines, in order."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domain = line.split(",")[-1].strip().lower().rstrip(".")
        if not domain or domain in seen:
            continue
        seen.add(domain)
        out.append(domain)
        if len(out) >= top:
            break
    return out


def list_id(csv_path: Path) -> str:
    """The Tranco list ID: the CSV's stem (the tranco package names files ``<ID>.csv``)."""
    return csv_path.stem


def make_list(src: Path, dst: Path = OUT, top: int = TOP_N) -> list[str]:
    """Write ``dst``: one ``#`` header line, then the top ``top`` domains, one per line."""
    with src.open(encoding="utf-8") as fh:
        domains = top_domains(fh, top)
    header = (f"# Tranco top {len(domains)} ({SOURCE_URL}, list ID {list_id(src)}); "
              f"regenerate with models/make_tranco_list.py")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(header + "\n" + "\n".join(domains) + "\n", encoding="utf-8", newline="\n")
    return domains


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--src", type=Path, help="Tranco CSV (default: newest in the cache)")
    parser.add_argument("--out", type=Path, default=OUT)
    parser.add_argument("--top", type=int, default=TOP_N)
    args = parser.parse_args(argv)
    src = args.src or newest_csv()
    meta = src.parent / "metadata.json"
    if meta.is_file():
        print(f"cache metadata: {json.loads(meta.read_text(encoding='utf-8'))}")
    domains = make_list(src, args.out, args.top)
    print(f"wrote {len(domains)} domains from {src.name} to {args.out} "
          f"({args.out.stat().st_size / 1e6:.2f} MB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
