from __future__ import annotations

from apscheduler.schedulers.background import BackgroundScheduler

from hnsdoh_status.checks import run_full_check
from hnsdoh_status.config import Settings
from hnsdoh_status.store import StatusStore


def create_scheduler(settings: Settings, store: StatusStore) -> BackgroundScheduler:
    scheduler = BackgroundScheduler(daemon=True)

    def run_checks() -> None:
        snapshot = run_full_check(
            domain=settings.domain,
            doh_path=settings.doh_path,
            dns_timeout=settings.dns_timeout_seconds,
            doh_timeout=settings.doh_timeout_seconds,
            dot_timeout=settings.dot_timeout_seconds,
        )
        store.update(snapshot)

    # Run once on startup so the UI/API is populated immediately.
    run_checks()

    scheduler.add_job(
        run_checks,
        "interval",
        seconds=settings.check_interval_seconds,
        id="node-health-check",
        max_instances=1,
        coalesce=True,
    )
    return scheduler
