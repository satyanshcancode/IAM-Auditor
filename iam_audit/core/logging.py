"""IAM logging configuration."""

import logging
import sys


def setup_logging(level: int = logging.INFO, log_file: str | None = None) -> logging.Logger:
    """Configure logging for the IAM audit tool."""
    logger = logging.getLogger("iam_audit")
    logger.setLevel(level)
    logger.handlers = []

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "iam_audit") -> logging.Logger:
    """Get a logger instance."""
    return logging.getLogger(name)
