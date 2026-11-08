"""Known-bad IP detector (CLAUDE.md §6.3 "intel.py").

Flags flows whose remote IP is on the abuse.ch Feodo Tracker *recommended* blocklist or on the
lab-only ``data/test_intel.txt`` list.

Safety (§9.2): this module never connects to a listed IP. Its only network call is downloading
the blocklist itself, in :func:`download_feed`.

Refresh timing: construction loads the cached feed and the test list from disk (fast, no network)
and then *schedules* a download. :meth:`IntelDetector.process` schedules another one once
``refresh_interval_s`` has passed since the last attempt. By default a download runs on a daemon
thread, so the capture loop never waits on the network. A failed download is logged and the
detector keeps using the cached list (or only the test list if there is no cache).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import ssl
import threading
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from agent import config as config_module
from agent.events import FlowEvent, Signal

logger = logging.getLogger(__name__)

DETECTOR_NAME = "intel"
MITRE_TECHNIQUE = "T1071"  # Application Layer Protocol (§6.3)
CACHE_FILE_NAME = "feodo_ipblocklist_recommended.txt"
COMMENT_PREFIX = "#"
REQUIRED_URL_SCHEME = "https://"
USER_AGENT = "HomeSOC-intel/0.1"

Clock = Callable[[], float]
Spawner = Callable[[Callable[[], None]], None]


def tls_context() -> ssl.SSLContext:
    """A certificate-verifying TLS context for the feed download.

    Uses certifi's CA bundle when certifi is importable (it ships with httpx, and PyInstaller's
    hook-certifi bundles its ``cacert.pem``): a fresh Windows install lacks some roots until
    Windows fetches them on demand, which Python's ssl cannot trigger, so the system store alone
    fails with CERTIFICATE_VERIFY_FAILED. Without certifi, the default (system) context is used.
    Verification is always on: ``CERT_REQUIRED`` and hostname checking, never an unverified context.
    """
    try:
        import certifi

        cafile: str | None = certifi.where()
    except ImportError:
        cafile = None
    if cafile is not None:
        try:
            return ssl.create_default_context(cafile=cafile)
        except (OSError, ssl.SSLError) as exc:  # bundle missing/unreadable in a broken build
            logger.warning(
                "Could not load certifi CA bundle %s (%s); using system roots", cafile, exc
            )
    return ssl.create_default_context()


def download_feed(url: str, timeout_s: float) -> str:
    """Download the blocklist text. The ONLY network call in this module (§9.2).

    Raises ``urllib.error.URLError`` / ``HTTPError`` / ``TimeoutError`` / ``OSError`` on failure
    (``ssl.SSLError`` and certificate errors are ``OSError`` subclasses).
    """
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout_s, context=tls_context()) as response:
        return response.read().decode("utf-8")


def parse_feed(text: str) -> frozenset[str]:
    """Return the normalized IPs in a blocklist: one IP per line, ``#`` comments and blanks skipped.

    Lines that are not a valid IP address are skipped (logged at debug level).
    """
    ips: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(COMMENT_PREFIX):
            continue
        normalized = _normalize_ip(line)
        if normalized is None:
            logger.debug("Skipping blocklist line that is not an IP: %r", line)
            continue
        ips.add(normalized)
    return frozenset(ips)


def _normalize_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def _spawn_daemon(task: Callable[[], None]) -> None:
    threading.Thread(target=task, name="intel-refresh", daemon=True).start()


def _read_list(path: Path, label: str) -> frozenset[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        logger.info("No %s at %s", label, path)
        return frozenset()
    except (OSError, ValueError) as exc:
        logger.warning("Could not read %s at %s: %s", label, path, exc)
        return frozenset()
    ips = parse_feed(text)
    logger.info("Loaded %d IPs from %s (%s)", len(ips), label, path)
    return ips


class IntelDetector:
    """Matches flows against the Feodo Tracker list plus the lab test list."""

    def __init__(
        self,
        cfg: dict[str, Any] | None = None,
        *,
        cache_dir: str | Path | None = None,
        test_intel_path: str | Path | None = None,
        clock: Clock = time.time,
        spawn: Spawner = _spawn_daemon,
    ) -> None:
        """
        Args:
            cfg: The full config dict (``agent.config.load()``). Loaded from disk when omitted.
            cache_dir: Where the downloaded feed is cached. Defaults to ``paths.cache_dir``.
            test_intel_path: Lab test list. Defaults to ``paths.test_intel``.
            clock: Returns the current time in seconds. Injected so tests can fake it.
            spawn: Runs a refresh task. Defaults to a daemon thread; tests pass a synchronous one.
        """
        cfg = cfg if cfg is not None else config_module.load()
        intel_cfg = cfg["detectors"]["intel"]
        paths = cfg["paths"]

        self._feed_url: str = intel_cfg["feed_url"]
        if not self._feed_url.startswith(REQUIRED_URL_SCHEME):
            raise ValueError(f"detectors.intel.feed_url must use https, got {self._feed_url!r}")
        self._timeout_s = float(intel_cfg["download_timeout_s"])
        self._refresh_interval_s = float(intel_cfg["refresh_interval_s"])
        self._score = float(intel_cfg["score"])

        self._cache_path = Path(cache_dir or _repo_path(paths["cache_dir"])) / CACHE_FILE_NAME
        self._test_intel_path = Path(test_intel_path or _repo_path(paths["test_intel"]))
        self._clock = clock
        self._spawn = spawn

        self._refresh_lock = threading.Lock()
        self._last_attempt: float | None = None
        self._test_ips = _read_list(self._test_intel_path, "test intel list")
        self._feed_ips: frozenset[str] = frozenset()
        self._ips: frozenset[str] = self._test_ips
        self._set_feed(_read_list(self._cache_path, "cached blocklist"))

        self._maybe_schedule_refresh()

    @property
    def ips(self) -> frozenset[str]:
        """Every IP currently treated as known-bad (feed + test list)."""
        return self._ips

    @property
    def feed_ips(self) -> frozenset[str]:
        """IPs from the downloaded (or cached) Feodo Tracker list only."""
        return self._feed_ips

    def process(self, event: FlowEvent) -> list[Signal]:
        """Return one intel Signal if the flow's remote IP is listed, else an empty list."""
        self._maybe_schedule_refresh()

        hit = self._listed_remote_ip(event)
        if hit is None:
            return []
        if event.direction == "inbound":
            reason = f"receives a connection from {hit}, which is on a known-bad IP list"
        else:
            reason = f"talks to {hit}, which is on a known-bad IP list"
        return [
            Signal(
                detector=DETECTOR_NAME,
                process=event.process,
                pid=event.pid,
                target=hit,
                score=self._score,
                reasons=[reason],
                mitre=MITRE_TECHNIQUE,
                ts_ms=event.ts_ms,
            )
        ]

    def refresh(self) -> None:
        """Download the feed, cache it and swap it in. Never raises; failures keep the old list."""
        if not self._refresh_lock.acquire(blocking=False):
            logger.debug("Blocklist refresh already running; skipping")
            return
        try:
            self._refresh_once()
        except Exception:  # refreshing must never break detection
            logger.exception("Unexpected error while refreshing the blocklist")
        finally:
            self._refresh_lock.release()

    # --- internals ---------------------------------------------------------------------------

    def _listed_remote_ip(self, event: FlowEvent) -> str | None:
        # Check the direction's remote IP first, then the other one, so a flow whose direction
        # was guessed wrong is still caught. A listed IP is never this PC's own address, so the
        # extra check cannot misfire; returning the first hit keeps it to one Signal per flow.
        if event.direction == "inbound":
            candidates = (event.src_ip, event.dst_ip)
        else:
            candidates = (event.dst_ip, event.src_ip)
        listed = self._ips
        for candidate in candidates:
            normalized = _normalize_ip(candidate) if candidate else None
            if normalized is not None and normalized in listed:
                return normalized
        return None

    def _set_feed(self, feed_ips: frozenset[str]) -> None:
        # Both sets are replaced whole (never mutated), so a reader on another thread always sees
        # a complete list, either the old one or the new one.
        self._feed_ips = feed_ips
        self._ips = feed_ips | self._test_ips

    def _maybe_schedule_refresh(self) -> None:
        now = self._clock()
        if self._last_attempt is not None and now - self._last_attempt < self._refresh_interval_s:
            return
        # Stamp the attempt before spawning, so later flows don't start another download.
        self._last_attempt = now
        self._spawn(self.refresh)

    def _refresh_once(self) -> None:
        try:
            text = download_feed(self._feed_url, self._timeout_s)
        except (OSError, ValueError) as exc:  # URLError, HTTPError, timeouts, bad encoding
            logger.warning(
                "Blocklist download from %s failed (%s); using %d cached IPs",
                self._feed_url,
                exc,
                len(self._feed_ips),
            )
            return

        ips = parse_feed(text)
        if not ips:
            logger.warning(
                "Blocklist download from %s held no IPs; keeping %d cached IPs",
                self._feed_url,
                len(self._feed_ips),
            )
            return

        self._set_feed(ips)
        logger.info("Refreshed blocklist: %d IPs from %s", len(ips), self._feed_url)
        self._write_cache(text)

    def _write_cache(self, text: str) -> None:
        tmp_path = self._cache_path.with_name(self._cache_path.name + ".tmp")
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.write_text(text, encoding="utf-8")
            os.replace(tmp_path, self._cache_path)
        except OSError as exc:
            logger.warning("Could not write blocklist cache %s: %s", self._cache_path, exc)


def _repo_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else config_module.REPO_ROOT / path


_default_detector: IntelDetector | None = None


def process(event: FlowEvent) -> list[Signal]:
    """Module-level detector entry point (§6.3), backed by one lazily created IntelDetector."""
    global _default_detector
    if _default_detector is None:
        _default_detector = IntelDetector()
    return _default_detector.process(event)
