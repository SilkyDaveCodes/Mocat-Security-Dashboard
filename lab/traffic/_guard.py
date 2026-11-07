"""Shared host-only-lab guardrail for the traffic generators (CLAUDE.md §9).

Every traffic generator in :mod:`lab.traffic` imports this module and calls
:func:`check_target` (or the pure :func:`validate_target`) **before any socket, DNS or
connect activity**, mirroring ``lab/fake_malware/freegamecheats.py``. The guardrail enforces
two things, the same safety model as the fake-malware simulator (CLAUDE.md §9.1):

1. the environment variable ``HOMESOC_LAB`` must be exactly ``"1"``, and
2. the target must resolve to address(es) **entirely inside** the host-only lab network
   ``192.168.56.0/24``.

For a hostname target the guard resolves the name and requires that **every** resolved
address is inside the lab range; a public hostname, a name that resolves outside the range,
and a name that does not resolve at all are all refused. The guard performs only that DNS
lookup (for a hostname) and no connect/send, so a refused run attempts zero connections.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
from collections.abc import Callable, Sequence

logger = logging.getLogger("homesoc.lab.traffic.guard")

# The only network these generators may ever talk to (CLAUDE.md §8/§9).
LAB_NETWORK = ipaddress.ip_network("192.168.56.0/24")
# Default lab target address (the lab C2 / service host); overridable only to another
# address or name that resolves inside LAB_NETWORK.
DEFAULT_LAB_TARGET = "192.168.56.20"
# Environment variable that arms the generators (required, exactly "1").
ENV_HOMESOC_LAB = "HOMESOC_LAB"
ENV_LAB_ENABLED_VALUE = "1"

# A resolver has the shape of ``socket.getaddrinfo``: name -> list of addrinfo tuples whose
# 5th element (index 4) is the sockaddr, whose first element (index 0) is the IP string.
Resolver = Callable[..., Sequence[tuple]]


class LabGuardError(RuntimeError):
    """Raised when the §9 guardrail is not satisfied. No connect/send has happened."""


def is_lab_enabled(env: dict[str, str] | None = None) -> bool:
    """True only if ``HOMESOC_LAB`` is exactly ``"1"`` in the environment."""
    environ = os.environ if env is None else env
    return environ.get(ENV_HOMESOC_LAB) == ENV_LAB_ENABLED_VALUE


def _ip_in_lab(ip: str) -> bool:
    """True only if ``ip`` parses as an IP address inside ``192.168.56.0/24``."""
    try:
        return ipaddress.ip_address(ip) in LAB_NETWORK
    except ValueError:
        return False


def _resolve(host: str, resolver: Resolver) -> list[str]:
    """Resolve ``host`` to a list of IP strings; raise :class:`LabGuardError` if it fails.

    Any resolver error (``OSError``/``socket.gaierror``) means the name is not usable in the
    sealed lab, so the target is refused rather than guessed.
    """
    try:
        infos = resolver(host, None)
    except OSError as exc:
        raise LabGuardError(
            f"refusing to run: cannot resolve {host!r} inside the lab ({exc})"
        ) from exc
    addrs: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr:
            addrs.append(str(sockaddr[0]))
    return addrs


def validate_target(
    target: str, *, lab_enabled: bool, resolver: Resolver | None = None
) -> list[str]:
    """Enforce the §9 guardrails; return the validated in-range IP address(es).

    Raises :class:`LabGuardError` (having done no connect/send) when:

    * ``lab_enabled`` is false (``HOMESOC_LAB`` is not ``"1"``),
    * ``target`` is an IP literal outside ``192.168.56.0/24``,
    * ``target`` is a hostname that does not resolve, or
    * ``target`` is a hostname that resolves to *any* address outside the lab network.

    An IP literal is checked directly with no DNS lookup. A hostname is resolved with
    ``resolver`` (default :func:`socket.getaddrinfo`) and every resulting address must be in
    range. This function performs no connect and sends no packet.
    """
    if resolver is None:
        resolver = socket.getaddrinfo

    if not lab_enabled:
        raise LabGuardError(
            f"refusing to run: {ENV_HOMESOC_LAB}={ENV_LAB_ENABLED_VALUE!r} is required "
            "(these are lab-only generators, CLAUDE.md §9)"
        )

    # IP literal: validate directly, no DNS needed.
    try:
        ip = ipaddress.ip_address(target)
    except ValueError:
        ip = None
    if ip is not None:
        if ip not in LAB_NETWORK:
            raise LabGuardError(
                f"refusing to run: target {target!r} is not inside the host-only lab "
                f"network {LAB_NETWORK} (CLAUDE.md §9)"
            )
        return [str(ip)]

    # Hostname: resolve and require EVERY resolved address to be inside the lab network.
    addrs = _resolve(target, resolver)
    if not addrs:
        raise LabGuardError(
            f"refusing to run: {target!r} did not resolve to any address in the lab"
        )
    outside = [a for a in addrs if not _ip_in_lab(a)]
    if outside:
        raise LabGuardError(
            f"refusing to run: {target!r} resolves outside the host-only lab network "
            f"{LAB_NETWORK} (e.g. {outside[0]}) (CLAUDE.md §9)"
        )
    return addrs


def check_target(
    target: str, *, env: dict[str, str] | None = None, resolver: Resolver | None = None
) -> list[str]:
    """Convenience wrapper: read ``HOMESOC_LAB`` from ``env`` then :func:`validate_target`.

    Returns the validated in-range IP address(es); raises :class:`LabGuardError` otherwise.
    """
    return validate_target(
        target, lab_enabled=is_lab_enabled(env), resolver=resolver
    )
