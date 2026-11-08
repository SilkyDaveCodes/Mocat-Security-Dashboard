"""DGA lookup detector (CLAUDE.md §6.3 "dga.py").

Scores the hostname of every DNS flow (``dst_port == 53`` or ``app_proto`` containing "DNS") with
the classifier in ``models/dga.joblib``. Features come from
:func:`agent.detectors.dga_features.features`, the same function training uses, and are put in the
column order saved in the model bundle, so live and training features always match.

Skipped without calling the model:
    * hostnames that end in a ``skip_suffixes`` entry (``*.local``, ``*.arpa``) or are IP literals,
    * hostnames whose domain (or any parent domain down to the registered domain) is in the
      Tranco top-N list or in ``data/domain_allowlist.txt``. The Tranco list is the downloaded
      cache (``paths.tranco_cache``) when present, else the committed, bundled
      ``paths.tranco_bundled`` (``data/tranco_top100k.txt``), so a fresh install has one too.

``P(dga) >= probability_threshold`` gives a Signal with ``score = P(dga)``. If the same process
has made ``>= burst_count`` such lookups within ``burst_window_s`` (by flow timestamp), the score is
raised by ``burst_boost``, capped at 1.0.

No network: the Tranco list is only read from local files. Missing Tranco lists (both), allowlist
or model are logged; with no model the detector returns no signals.
"""

from __future__ import annotations

import logging
from collections import deque
from pathlib import Path
from typing import Any

from agent import config as config_module
from agent.detectors.dga_features import (
    FEATURE_NAMES,
    MULTI_PART_SUFFIXES,
    features,
    registered_label,
)
from agent.events import FlowEvent, Signal

logger = logging.getLogger(__name__)

DETECTOR_NAME = "dga"
MITRE_TECHNIQUE = "T1568.002"  # Dynamic Resolution: Domain Generation Algorithms
DNS_PORT = 53
DNS_APP_PROTO = "dns"
COMMENT_PREFIX = "#"
DEFAULT_DGA_CLASS_INDEX = 1  # bare models (no bundle dict): label 1 is "dga", as in train_dga.py
# Only for a config.yaml seeded before paths.tranco_bundled existed (the data root's copy is
# never overwritten on upgrade); config.yaml sets the same value.
DEFAULT_TRANCO_BUNDLED = "data/tranco_top100k.txt"


def normalize_host(hostname: str | None) -> str:
    """Strip, lowercase and drop trailing dots."""
    return (hostname or "").strip().lower().rstrip(".")


def registered_domain(host: str) -> str:
    """The registered domain of a normalized host, using the same suffix rules as dga_features.

    ``www.google.com`` -> ``google.com``, ``news.bbc.co.uk`` -> ``bbc.co.uk``.
    """
    labels = [label for label in host.split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def candidate_domains(host: str) -> list[str]:
    """``host`` and each parent domain down to (and including) its registered domain."""
    labels = [label for label in host.split(".") if label]
    stop = len(registered_domain(host).split("."))
    return [".".join(labels[i:]) for i in range(0, max(len(labels) - stop, 0) + 1)]


def parse_domain_lines(text: str, limit: int | None = None) -> frozenset[str]:
    """Domains from ``domain`` or ``rank,domain`` lines; ``#`` comments and blanks skipped."""
    domains: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(COMMENT_PREFIX):
            continue
        field = line.split(",")[-1] if "," in line else line.split()[0]
        domain = normalize_host(field)
        if domain:
            domains.append(domain)
        if limit is not None and len(domains) >= limit:
            break
    return frozenset(domains)


def _resolve_tranco_file(path: Path) -> Path | None:
    if path.is_dir():
        csvs = sorted(path.glob("*.csv"), key=lambda p: p.stat().st_mtime, reverse=True)
        return csvs[0] if csvs else None
    return path if path.exists() else None


def _read_domains(path: Path | None, label: str, limit: int | None = None) -> frozenset[str]:
    if path is None:
        logger.warning("No %s found; continuing without it", label)
        return frozenset()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.warning("No %s at %s; continuing without it", label, path)
        return frozenset()
    except (OSError, ValueError) as exc:
        logger.warning("Could not read %s at %s: %s", label, path, exc)
        return frozenset()
    domains = parse_domain_lines(text, limit)
    logger.info("Loaded %d domains from %s (%s)", len(domains), label, path)
    return domains


def load_tranco(cache_path: Path, bundled_path: Path | None, limit: int) -> frozenset[str]:
    """The Tranco top-``limit`` set: the downloaded cache if present, else the bundled list.

    The cache (a file or the tranco package's cache directory) wins when it holds any domain.
    A fresh install has no cache, so the committed ``data/tranco_top100k.txt`` is used (INFO).
    WARNING only when neither gives a domain; the detector then runs without a Tranco skip-list.
    """
    cache_file = _resolve_tranco_file(cache_path)
    if cache_file is not None:
        domains = _read_domains(cache_file, "Tranco cache", limit)
        if domains:
            return domains
    if bundled_path is not None and bundled_path.is_file():
        logger.info("No usable Tranco cache at %s; using the bundled Tranco list", cache_path)
        domains = _read_domains(bundled_path, "bundled Tranco list", limit)
        if domains:
            return domains
    logger.warning(
        "No Tranco list found (cache %s, bundled %s); continuing without it",
        cache_path,
        bundled_path,
    )
    return frozenset()


def _load_model(path: Path) -> Any | None:
    try:
        import joblib

        return joblib.load(path)
    except FileNotFoundError:
        logger.warning("DGA model not found at %s; DGA detection is off", path)
    except Exception:  # a broken model file must not stop the agent
        logger.exception("Could not load DGA model from %s; DGA detection is off", path)
    return None


class DgaDetector:
    """Flags DNS lookups of machine-generated-looking domains."""

    def __init__(
        self,
        cfg: dict[str, Any] | None = None,
        *,
        model: Any | None = None,
        model_path: str | Path | None = None,
        tranco_path: str | Path | None = None,
        tranco_bundled_path: str | Path | None = None,
        domain_allowlist_path: str | Path | None = None,
    ) -> None:
        """
        Args:
            cfg: The full config dict (``agent.config.load()``). Loaded from disk when omitted.
            model: A ``train_dga.py`` bundle dict, or a bare object with ``predict_proba``.
                Loaded from ``model_path`` when omitted. Tests pass a stub here.
            model_path: Defaults to ``paths.dga_model``.
            tranco_path: Tranco cache file or directory. Defaults to ``paths.tranco_cache``.
            tranco_bundled_path: Fallback list used when the cache is missing. Defaults to
                ``paths.tranco_bundled`` (``data/tranco_top100k.txt`` if an older config.yaml
                in the data root lacks the key).
            domain_allowlist_path: Defaults to ``paths.domain_allowlist``.
        """
        cfg = cfg if cfg is not None else config_module.load()
        dga_cfg = cfg["detectors"]["dga"]
        paths = cfg["paths"]

        self._threshold = float(dga_cfg["probability_threshold"])
        self._burst_count = int(dga_cfg["burst_count"])
        self._burst_window_ms = int(float(dga_cfg["burst_window_s"]) * 1000)
        self._burst_boost = float(dga_cfg["burst_boost"])
        self._skip_suffixes = tuple(normalize_host(s) for s in dga_cfg["skip_suffixes"])
        tranco_top_n = int(dga_cfg["tranco_top_n"])

        if model is None:
            model = _load_model(Path(model_path or _repo_path(paths["dga_model"])))
        self._model, self._feature_names, self._dga_index = _unpack_model(model)

        self._tranco = load_tranco(
            Path(tranco_path or _repo_path(paths["tranco_cache"])),
            Path(
                tranco_bundled_path
                or _repo_path(paths.get("tranco_bundled") or DEFAULT_TRANCO_BUNDLED)
            ),
            tranco_top_n,
        )
        self._allowed = _read_domains(
            Path(domain_allowlist_path or _repo_path(paths["domain_allowlist"])),
            "DGA domain allowlist",
        )
        self._recent: dict[str, deque[int]] = {}

    def process(self, event: FlowEvent) -> list[Signal]:
        """Return one DGA Signal for a DNS lookup that looks machine-generated, else ``[]``."""
        if self._model is None or not _is_dns(event):
            return []
        host = normalize_host(event.hostname)
        if not host or self._should_skip(host):
            return []

        probability = self._predict(host)
        if probability < self._threshold:
            return []

        count = self._record(event.process, event.ts_ms)
        score = probability
        reasons = [f"looked up {host}, which looks machine-generated (DGA model {probability:.2f})"]
        if count >= self._burst_count:
            score = min(1.0, probability + self._burst_boost)
            window_s = self._burst_window_ms / 1000
            reasons.append(f"made {count} random-looking lookups within {window_s:g} s")
        return [
            Signal(
                detector=DETECTOR_NAME,
                process=event.process,
                pid=event.pid,
                target=host,
                score=score,
                reasons=reasons,
                mitre=MITRE_TECHNIQUE,
                ts_ms=event.ts_ms,
            )
        ]

    # --- internals ---------------------------------------------------------------------------

    def _should_skip(self, host: str) -> bool:
        if not registered_label(host):  # IP literal or nothing usable
            return True
        if any(host == s.lstrip(".") or host.endswith(s) for s in self._skip_suffixes):
            return True
        return any(d in self._tranco or d in self._allowed for d in candidate_domains(host))

    def _predict(self, host: str) -> float:
        feats = features(host)
        vector = [feats[name] for name in self._feature_names]
        return float(self._model.predict_proba([vector])[0][self._dga_index])

    def _record(self, process: str, ts_ms: int) -> int:
        """Remember a DGA-looking lookup; return how many this process made within the window."""
        times = self._recent.setdefault(process, deque())
        times.append(ts_ms)
        while times and ts_ms - times[0] > self._burst_window_ms:
            times.popleft()
        return sum(1 for t in times if abs(ts_ms - t) <= self._burst_window_ms)


def _is_dns(event: FlowEvent) -> bool:
    return event.dst_port == DNS_PORT or DNS_APP_PROTO in (event.app_proto or "").lower()


def _unpack_model(model: Any | None) -> tuple[Any | None, list[str], int]:
    if model is None:
        return None, list(FEATURE_NAMES), DEFAULT_DGA_CLASS_INDEX
    if isinstance(model, dict):
        return (
            model["model"],
            list(model.get("feature_names", FEATURE_NAMES)),
            int(model.get("dga_class_index", DEFAULT_DGA_CLASS_INDEX)),
        )
    return model, list(FEATURE_NAMES), DEFAULT_DGA_CLASS_INDEX


def _repo_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else config_module.REPO_ROOT / path


_default_detector: DgaDetector | None = None


def process(event: FlowEvent) -> list[Signal]:
    """Module-level detector entry point (§6.3), backed by one lazily created DgaDetector."""
    global _default_detector
    if _default_detector is None:
        _default_detector = DgaDetector()
    return _default_detector.process(event)
