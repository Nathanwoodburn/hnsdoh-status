from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


@dataclass(frozen=True)
class Settings:
    domain: str = os.getenv("HNSDOH_DOMAIN", "hnsdoh.com")
    doh_path: str = os.getenv("HNSDOH_DOH_PATH", "/dns-query")
    check_interval_seconds: int = int(os.getenv("HNSDOH_CHECK_INTERVAL_SECONDS", "300"))
    ui_refresh_seconds: int = int(os.getenv("HNSDOH_UI_REFRESH_SECONDS", "30"))
    history_size: int = int(os.getenv("HNSDOH_HISTORY_SIZE", "12"))
    stale_after_seconds: int = int(os.getenv("HNSDOH_STALE_AFTER_SECONDS", "900"))

    dns_timeout_seconds: float = float(os.getenv("HNSDOH_DNS_TIMEOUT_SECONDS", "5"))
    doh_timeout_seconds: float = float(os.getenv("HNSDOH_DOH_TIMEOUT_SECONDS", "10"))
    dot_timeout_seconds: float = float(os.getenv("HNSDOH_DOT_TIMEOUT_SECONDS", "10"))

    webhook_url: str = os.getenv("TMP_DISCORD_HOOK", "")
