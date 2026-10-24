"""Structured JSON logging configuration using structlog."""

import logging
import sys
from typing import cast

import structlog
from structlog.types import EventDict, WrappedLogger


def add_request_context(_: WrappedLogger, __: str, event_dict: EventDict) -> EventDict:
    """Ensure standard request context fields are present if available."""
    if "request_id" not in event_dict:
        event_dict["request_id"] = None
    return event_dict


def configure_logging(log_level: str = "INFO") -> None:
    """Configures standard library logging and structlog to output JSON."""
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, log_level.upper(), logging.INFO),
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            add_request_context,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )



def get_logger(name: str = "cyberq") -> structlog.stdlib.BoundLogger:
    return cast(structlog.stdlib.BoundLogger, structlog.get_logger(name))
