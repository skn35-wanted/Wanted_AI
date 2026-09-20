"""Privacy-safe structured logging for the docXray backend.

Logs are operational metadata only. Never add uploaded filenames, raw text,
detected values, session identifiers, download identifiers, or API keys here.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any


_request_id: ContextVar[str] = ContextVar("request_id", default="")

# Only these explicitly reviewed fields may leave the process. Keeping an
# allowlist prevents an innocent extra={...} change from leaking content.
_SAFE_FIELDS = (
    "event",
    "request_id",
    "method",
    "route",
    "status_code",
    "duration_ms",
    "file_count",
    "file_types",
    "input_bytes",
    "masked_file_count",
    "total_findings",
    "filtered_out",
    "finding_counts",
    "risk_levels",
    "error_code",
    "removed_count",
    "cache_hit",
    "training_mode",
    "db_mode",
    "training_level",
    "turn_no",
    "training_status",
    "db_connection_id",
    "idle_seconds",
)


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "event": getattr(record, "event", record.getMessage()),
        }
        context_request_id = _request_id.get()
        if context_request_id:
            payload["request_id"] = context_request_id
        for field in _SAFE_FIELDS:
            value = getattr(record, field, None)
            if value is not None and value != "":
                payload[field] = value
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def configure_logging() -> None:
    """Configure the application logger once.

    Uvicorn's access logger records raw URLs. It is disabled because the batch
    download credential is a query parameter; main.py emits a route-template
    access event without query strings instead.
    """
    logger = logging.getLogger("infoguard")
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
    level_name = os.getenv("INFOGUARD_LOG_LEVEL", "INFO").upper()
    logger.setLevel(getattr(logging, level_name, logging.INFO))
    logger.propagate = False
    logging.getLogger("uvicorn.access").disabled = True


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"infoguard.{name}")


def set_request_id(value: str):
    return _request_id.set(value)


def reset_request_id(token) -> None:
    _request_id.reset(token)


def log_event(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    """Emit one event; fields outside _SAFE_FIELDS are discarded."""
    safe = {key: value for key, value in fields.items() if key in _SAFE_FIELDS}
    safe["event"] = event
    logger.log(level, event, extra=safe)

