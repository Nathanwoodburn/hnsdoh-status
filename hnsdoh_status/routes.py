from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from flask import Blueprint, Flask, Response, jsonify, render_template

from hnsdoh_status.config import Settings
from hnsdoh_status.models import CheckResult, ProtocolName, Snapshot
from hnsdoh_status.store import StatusStore


def _result_to_dict(result: CheckResult) -> dict[str, Any]:
    return {
        "protocol": result.protocol,
        "ok": result.ok,
        "latency_ms": round(result.latency_ms, 2)
        if result.latency_ms is not None
        else None,
        "checked_at": result.checked_at.isoformat(),
        "reason": result.reason,
    }


def _snapshot_to_dict(snapshot: Snapshot | None) -> dict | None:
    if snapshot is None:
        return None

    return {
        "domain": snapshot.domain,
        "checked_at": snapshot.checked_at.isoformat(),
        "node_count": snapshot.node_count,
        "discovery_error": snapshot.discovery_error,
        "nodes": [
            {
                "ip": node.ip,
                "results": {
                    protocol: _result_to_dict(result)
                    for protocol, result in node.results.items()
                },
            }
            for node in snapshot.nodes
        ],
    }


def _history_to_dict(
    history: dict[str, list[dict[ProtocolName, CheckResult]]],
) -> dict[str, list[dict[str, dict]]]:
    rendered: dict[str, list[dict[str, dict]]] = {}
    for ip, entries in history.items():
        rendered[ip] = []
        for entry in entries:
            rendered[ip].append(
                {
                    protocol: _result_to_dict(result)
                    for protocol, result in entry.items()
                }
            )
    return rendered


def create_routes(app: Flask, settings: Settings, store: StatusStore) -> Blueprint:
    bp = Blueprint("status", __name__)

    @bp.get("/")
    def index() -> str:
        return render_template(
            "index.html",
            domain=settings.domain,
            ui_refresh_seconds=settings.ui_refresh_seconds,
        )

    @bp.get("/api/health")
    def health() -> tuple[dict, int]:
        now = datetime.now(timezone.utc)
        current = store.current()

        if current is None:
            return {"ok": False, "reason": "No checks completed yet."}, 503

        age_seconds = (now - current.checked_at).total_seconds()
        stale = age_seconds > settings.stale_after_seconds
        status_code = 200 if not stale else 503
        return {
            "ok": not stale,
            "stale": stale,
            "age_seconds": age_seconds,
            "checked_at": current.checked_at.isoformat(),
        }, status_code

    @bp.get("/api/status")
    def status() -> Response:
        return jsonify(
            {
                "generated_at": store.generated_at().isoformat(),
                "interval_seconds": settings.check_interval_seconds,
                "stale_after_seconds": settings.stale_after_seconds,
                "current": _snapshot_to_dict(store.current()),
                "history": _history_to_dict(store.history()),
            }
        )

    app.register_blueprint(bp)
    return bp
