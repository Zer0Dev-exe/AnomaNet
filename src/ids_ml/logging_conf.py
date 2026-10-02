"""Configuración de logging con salida enriquecida (rich).

Un único punto de entrada, `get_logger`, para que todos los módulos emitan
logs con el mismo formato y nivel (configurable por IDS_ML_LOG_LEVEL).
"""
from __future__ import annotations

import logging

from rich.logging import RichHandler

from .config import settings

_CONFIGURED = False


def _configure() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    logging.basicConfig(
        level=settings.log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )
    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Devuelve un logger ya configurado para el módulo dado."""
    _configure()
    return logging.getLogger(name)
