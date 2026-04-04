from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timezone

from hnsdoh_status.models import CheckResult, ProtocolName, Snapshot


class StatusStore:
    def __init__(self, history_size: int):
        self._history_size = history_size
        self._current: Snapshot | None = None
        self._history: dict[str, deque[dict[ProtocolName, CheckResult]]] = defaultdict(
            lambda: deque(maxlen=self._history_size)
        )

    def update(self, snapshot: Snapshot) -> None:
        self._current = snapshot
        for node in snapshot.nodes:
            # Each history entry stores one full protocol result set for the node.
            self._history[node.ip].append(dict(node.results))

    def current(self) -> Snapshot | None:
        return self._current

    def history(self) -> dict[str, list[dict[ProtocolName, CheckResult]]]:
        return {ip: list(entries) for ip, entries in self._history.items()}

    def generated_at(self) -> datetime:
        return datetime.now(timezone.utc)
