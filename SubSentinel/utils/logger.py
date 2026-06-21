"""
utils/logger.py - Logging configuration
"""

import logging
import sys
from pathlib import Path
from rich.logging import RichHandler


def setup_logger(name: str, verbose: bool = False, debug: bool = False) -> logging.Logger:
    """Configure and return a logger with Rich handler."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)

    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                rich_tracebacks=True,
                show_path=debug,
                markup=True,
            )
        ],
    )

    logger = logging.getLogger(name)
    logger.setLevel(level)

    # File handler for debug logs
    if debug:
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        fh = logging.FileHandler(log_dir / "subsentinel_debug.log")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        logger.addHandler(fh)

    return logger
