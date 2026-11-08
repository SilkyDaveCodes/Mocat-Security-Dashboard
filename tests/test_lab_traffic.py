"""Tests for the lab traffic generators and their host-only-lab guardrail (CLAUDE.md §9).

Acceptance criterion 1: each generator refuses targets outside ``192.168.56.0/24`` and makes
*zero* connection attempts when it refuses. These tests assert REAL behaviour:

* For each of the four generators (benign, portscan, bruteforce, dos), running ``main`` with
  ``8.8.8.8`` and with a public hostname (DNS mocked to a public IP) exits with an error and
  the connect/send layer (``socket.create_connection`` / ``http.client.HTTPConnection``) is
  never called -- proven with a tripwire that counts and refuses any call.
* A lab IP (``192.168.56.20``) is accepted by the guard, and a hostname that resolves into
  the lab range is accepted, while a non-resolvable name is refused.

No test makes a real network call: DNS is always mocked, and the connect layer is a tripwire.
"""

from __future__ import annotations

import http.client
import socket

import pytest

from lab.traffic import _guard, benign, bruteforce, dos, portscan
from lab.traffic._guard import LabGuardError

LAB_IP = "192.168.56.20"
PUBLIC_IP = "93.184.216.34"
PUBLIC_HOST = "example.com"

# Every generator module exposes main(argv) and takes --target.
GENERATORS = [benign, portscan, bruteforce, dos]
GENERATOR_IDS = [m.__name__.rsplit(".", 1)[-1] for m in GENERATORS]


class _ConnectTripwire:
    """Stands in for every connect/send entrypoint; records and refuses any attempt."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, *args: object, **kwargs: object):
        self.calls += 1
        raise AssertionError("connection attempted despite the lab guardrail")


@pytest.fixture
def no_connect(monkeypatch: pytest.MonkeyPatch) -> _ConnectTripwire:
    """Patch the connect/send layer the generators use; any call fails and is counted."""
    tripwire = _ConnectTripwire()
    monkeypatch.setattr(socket, "create_connection", tripwire)
    monkeypatch.setattr(http.client, "HTTPConnection", tripwire)
    return tripwire


def _fake_getaddrinfo_returning(ip: str):
    def _resolver(host: str, port, *args: object, **kwargs: object):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    return _resolver


def _fake_getaddrinfo_failing(host: str, port, *args: object, **kwargs: object):
    raise socket.gaierror("Name or service not known")


# --- AC1: each generator refuses an out-of-range IP, no connection attempted -----------------


@pytest.mark.parametrize("module", GENERATORS, ids=GENERATOR_IDS)
def test_generator_refuses_public_ip_and_makes_no_connection(
    module, monkeypatch: pytest.MonkeyPatch, no_connect: _ConnectTripwire
) -> None:
    monkeypatch.setenv(_guard.ENV_HOMESOC_LAB, "1")  # armed: only the target should fail

    with pytest.raises(SystemExit) as excinfo:
        module.main(["--target", "8.8.8.8"])

    assert excinfo.value.code == 2
    assert no_connect.calls == 0  # refused before any connect/send


@pytest.mark.parametrize("module", GENERATORS, ids=GENERATOR_IDS)
def test_generator_refuses_public_hostname_and_makes_no_connection(
    module, monkeypatch: pytest.MonkeyPatch, no_connect: _ConnectTripwire
) -> None:
    monkeypatch.setenv(_guard.ENV_HOMESOC_LAB, "1")
    # DNS is mocked: the public hostname resolves to a public IP (no real lookup happens).
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo_returning(PUBLIC_IP))

    with pytest.raises(SystemExit) as excinfo:
        module.main(["--target", PUBLIC_HOST])

    assert excinfo.value.code == 2
    assert no_connect.calls == 0


@pytest.mark.parametrize("module", GENERATORS, ids=GENERATOR_IDS)
def test_generator_refuses_when_lab_flag_unset(
    module, monkeypatch: pytest.MonkeyPatch, no_connect: _ConnectTripwire
) -> None:
    monkeypatch.delenv(_guard.ENV_HOMESOC_LAB, raising=False)

    with pytest.raises(SystemExit) as excinfo:
        module.main(["--target", LAB_IP])  # in-range, but the flag is missing

    assert excinfo.value.code == 2
    assert no_connect.calls == 0


# --- AC1: the guard accepts a lab IP / lab-resolving hostname, refuses otherwise --------------


def test_guard_accepts_lab_ip() -> None:
    assert _guard.validate_target(LAB_IP, lab_enabled=True) == [LAB_IP]


def test_guard_accepts_hostname_resolving_into_lab() -> None:
    resolver = _fake_getaddrinfo_returning(LAB_IP)
    assert _guard.validate_target("c2.lab", lab_enabled=True, resolver=resolver) == [LAB_IP]


def test_guard_refuses_public_ip() -> None:
    with pytest.raises(LabGuardError, match="192.168.56.0/24"):
        _guard.validate_target("8.8.8.8", lab_enabled=True)


def test_guard_refuses_public_hostname() -> None:
    resolver = _fake_getaddrinfo_returning(PUBLIC_IP)
    with pytest.raises(LabGuardError, match="outside"):
        _guard.validate_target(PUBLIC_HOST, lab_enabled=True, resolver=resolver)


def test_guard_refuses_unresolvable_hostname() -> None:
    with pytest.raises(LabGuardError, match="cannot resolve"):
        _guard.validate_target("nope.invalid", lab_enabled=True, resolver=_fake_getaddrinfo_failing)


def test_guard_refuses_when_lab_flag_unset() -> None:
    with pytest.raises(LabGuardError, match=_guard.ENV_HOMESOC_LAB):
        _guard.validate_target(LAB_IP, lab_enabled=False)


def test_guard_refuses_hostname_with_mixed_addresses() -> None:
    # If ANY resolved address is out of range, the whole target is refused.
    def resolver(host: str, port, *a: object, **k: object):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (LAB_IP, 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, 0)),
        ]

    with pytest.raises(LabGuardError, match="outside"):
        _guard.validate_target("mixed.lab", lab_enabled=True, resolver=resolver)


@pytest.mark.parametrize(
    "host,inside",
    [
        ("192.168.56.20", True),
        ("192.168.56.1", True),
        ("192.168.56.255", True),
        ("192.168.57.20", False),  # adjacent subnet
        ("8.8.8.8", False),
        ("127.0.0.1", False),  # loopback is NOT the lab network
        ("not-an-ip", False),
    ],
)
def test_ip_in_lab(host: str, inside: bool) -> None:
    assert _guard._ip_in_lab(host) is inside


def test_is_lab_enabled_requires_exactly_one() -> None:
    assert _guard.is_lab_enabled({"HOMESOC_LAB": "1"}) is True
    assert _guard.is_lab_enabled({"HOMESOC_LAB": "0"}) is False
    assert _guard.is_lab_enabled({"HOMESOC_LAB": "true"}) is False
    assert _guard.is_lab_enabled({}) is False
