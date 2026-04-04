from __future__ import annotations

from flask import Flask

from hnsdoh_status.config import Settings
from hnsdoh_status.routes import create_routes
from hnsdoh_status.scheduler import create_scheduler
from hnsdoh_status.store import StatusStore


scheduler = None


def create_app() -> Flask:
    app = Flask(__name__)
    settings = Settings()
    store = StatusStore(history_size=settings.history_size)

    app.config["SETTINGS"] = settings
    app.config["STORE"] = store

    create_routes(app, settings, store)

    global scheduler
    if scheduler is None:
        scheduler = create_scheduler(settings, store)
        scheduler.start()

    return app
