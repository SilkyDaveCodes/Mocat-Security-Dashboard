"""The shared event contract (CLAUDE.md §5). SHARED by CE and CS: see §2 before changing it.

All modules talk through these types. The WebSocket sends them as JSON via ``to_json()``
(``asdict()`` + ``"type"``).
"""

# The dataclasses below are copied verbatim from §5, which spells optional fields as Optional[...].
# ruff: noqa: UP045

from dataclasses import asdict, dataclass, field, is_dataclass
from typing import Any, Literal, Optional


@dataclass
class FlowEvent:
    type: Literal["flow"] = "flow"
    ts_ms: int = 0                    # bidirectional_first_seen_ms
    end_ms: int = 0                   # bidirectional_last_seen_ms
    process: str = "unknown"          # e.g. "chrome.exe"
    pid: int = -1
    exe_path: Optional[str] = None
    src_ip: str = ""
    src_port: int = 0
    dst_ip: str = ""
    dst_port: int = 0
    protocol: int = 0
    hostname: Optional[str] = None    # NFStream requested_server_name (DNS query / TLS SNI)
    app_proto: Optional[str] = None   # NFStream application_name
    bytes_out: int = 0                # src2dst_bytes
    bytes_in: int = 0                 # dst2src_bytes
    packets: int = 0
    direction: Literal["outbound", "inbound"] = "outbound"
    features: dict = field(default_factory=dict)   # raw NFStream stats for flow_model


@dataclass
class Signal:
    type: Literal["signal"] = "signal"
    detector: Literal["intel", "dga", "beacon", "anomaly", "flow_model"] = "intel"
    process: str = "unknown"
    pid: int = -1
    target: str = ""                  # IP or domain the signal is about
    score: float = 0.0                # 0..1
    reasons: list[str] = field(default_factory=list)   # short, human-readable
    mitre: Optional[str] = None       # e.g. "T1071.001"
    ts_ms: int = 0


@dataclass
class Alert:
    type: Literal["alert"] = "alert"
    id: str = ""
    ts_ms: int = 0
    severity: Literal["low", "medium", "high", "critical"] = "low"
    process: str = "unknown"
    exe_path: Optional[str] = None
    risk: float = 0.0
    title: str = ""
    what_happened: str = ""
    what_we_did: str = ""
    what_you_should_do: str = ""
    signals: list[Signal] = field(default_factory=list)
    action_ids: list[str] = field(default_factory=list)


@dataclass
class Action:
    type: Literal["action"] = "action"
    id: str = ""
    ts_ms: int = 0
    kind: Literal["block_ip", "quarantine_app", "kill_process", "undo"] = "block_ip"
    target: str = ""                  # IP or exe path
    rule_names: list[str] = field(default_factory=list)
    undone: bool = False


def to_json(obj: Any) -> dict[str, Any]:
    """Turn an event dataclass instance into a JSON-ready dict for the WebSocket.

    Uses ``dataclasses.asdict()`` (so an Alert's nested Signals become dicts too) and makes sure
    the ``"type"`` key is present (``flow`` / ``signal`` / ``alert`` / ``action``).

    Raises ``TypeError`` if ``obj`` is not a dataclass instance (a dataclass class is rejected
    too), or if it is a dataclass without a ``type`` field, since the UI dispatches on ``"type"``.
    """
    if not is_dataclass(obj) or isinstance(obj, type):
        raise TypeError(f"to_json() expects a dataclass instance, got {type(obj).__name__}")
    data = asdict(obj)
    if "type" not in data:
        raise TypeError(
            f"to_json() needs a dataclass with a 'type' field, got {type(obj).__name__}"
        )
    return data
