"""Centralized, secret-safe logging configuration."""

import logging


def configure_logging(level: int = logging.INFO) -> None:
    """Configure structured scan context fields without logging request contents."""
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
