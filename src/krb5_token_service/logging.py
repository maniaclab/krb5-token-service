from __future__ import annotations

import logging
import sys
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from structlog.types import EventDict, WrappedLogger


class SensitiveValueRedactProcessor:
    """Replaces secret-bearing values before log records are emitted.

    Neither the CERN password, the minted ccache, nor the inbound bearer
    token may ever appear in log output. The mint and auth code paths
    already avoid logging them; this processor is defense in depth against a
    future code path getting it wrong. It mutates the event dict in-place so
    every layer of structlog's chain sees the redacted form.
    """

    _REDACTED_KEYS: frozenset[str] = frozenset(
        {"token", "bearer", "authorization", "password", "ccache", "ccache_b64"}
    )
    _REDACTED_VALUE: str = "[REDACTED]"

    def __call__(
        self,
        logger: WrappedLogger,  # noqa: ARG002 (structlog processor signature)
        method: str,  # noqa: ARG002 (structlog processor signature)
        event_dict: EventDict,
    ) -> EventDict:
        for key in self._REDACTED_KEYS:
            if key in event_dict:
                event_dict[key] = self._REDACTED_VALUE
        return event_dict


def configure_logging(log_level: str = "INFO") -> None:
    """Wire structlog to emit JSON lines to stdout.

    Call once at application startup before any log statements.
    """
    shared_processors: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        SensitiveValueRedactProcessor(),
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            # stdlib compatibility: format_exc_info converts exc_info tuples
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        # Not cached: structlog.testing.capture_logs (used by the audit-line
        # tests) reconfigures processors globally, which cached loggers would
        # ignore once first used. The per-call cost is irrelevant at this
        # service's request rate.
        cache_logger_on_first_use=False,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.ExceptionRenderer(),
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers = [handler]
    root_logger.setLevel(log_level.upper())

    # Quieten noisy third-party loggers that we don't need at DEBUG
    for noisy in ("uvicorn.access", "httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
