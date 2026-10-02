"""Integración con Wazuh.

Escribe las alertas como JSON-lines en un fichero que el agente de Wazuh
ingiere mediante un bloque <localfile> (log_format json). Es la vía de
integración más sencilla y robusta: no toca la API de Wazuh, solo deja que el
agente "lea" el fichero.

Ver docs/wazuh-integration.md y examples/wazuh/ para decoder y reglas listos.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .config import settings
from .detector import ScoredFlow
from .logging_conf import get_logger

logger = get_logger(__name__)


def severity_of(score: float) -> str:
    """Traduce el score de anomalía a una severidad legible."""
    if score >= 0.85:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def build_event(flow: ScoredFlow, source: str) -> dict:
    """Construye el evento JSON que consumirá Wazuh."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "integration": "ids-ml",
        "source_capture": source,
        "anomaly_score": round(flow.score, 4),
        "severity": severity_of(flow.score),
        "src": flow.src,
        "dst": flow.dst,
        "protocol": flow.protocol,
        "top_features": [
            {"feature": name, "scaled_value": round(val, 3)}
            for name, val in flow.top_features
        ],
    }


def emit(
    flows: list[ScoredFlow],
    source: str,
    threshold: float | None = None,
) -> int:
    """Escribe en el fichero de Wazuh los flujos que superan el umbral.

    Args:
        flows: flujos ya puntuados.
        source: identificador de la captura (ruta o interfaz) para trazabilidad.
        threshold: umbral de score; por defecto, el de la configuración.

    Returns:
        Número de alertas emitidas.
    """
    threshold = settings.alert_threshold if threshold is None else threshold
    settings.ensure_dirs()

    alerts = [f for f in flows if f.score >= threshold]
    with open(settings.wazuh_alerts_path, "a", encoding="utf-8") as fh:
        for flow in alerts:
            fh.write(json.dumps(build_event(flow, source), ensure_ascii=False) + "\n")

    logger.info(
        "%d alerta(s) escritas en %s (umbral %.2f)",
        len(alerts),
        settings.wazuh_alerts_path,
        threshold,
    )
    return len(alerts)
