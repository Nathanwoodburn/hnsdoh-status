from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

ProtocolName = Literal["dns_udp", "dns_tcp", "doh", "dot"]


@dataclass
class CheckResult:
    protocol: ProtocolName
    ok: bool
    latency_ms: float | None
    checked_at: datetime
    reason: str = ""


@dataclass
class NodeSnapshot:
    ip: str
    results: dict[ProtocolName, CheckResult] = field(default_factory=dict)


@dataclass
class Snapshot:
    domain: str
    checked_at: datetime
    node_count: int
    nodes: list[NodeSnapshot]
    discovery_error: str = ""


@dataclass
class StatusPayload:
    generated_at: datetime
    interval_seconds: int
    stale_after_seconds: int
    current: Snapshot | None
    history: dict[str, list[dict[ProtocolName, CheckResult]]]
