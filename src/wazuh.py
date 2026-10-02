"""Integración con Wazuh.

Escribe las alertas como JSON-lines en un fichero que el agente de Wazuh
puede ingerir. Es la vía de integración más sencilla y robusta: no toca la
API de Wazuh, solo deja que el agente "lea" el fichero.

Configura en el agente (ossec.conf) un bloque localfile apuntando a este
fichero (ver README para el snippet exacto):

    <localfile>
      <log_format>json</log_format>
      <location>C:\\...\\outputs\\ids_ml_alerts.json</location>
    </localfile>
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from . import config
from .detect import ScoredFlow


def _event(flow: ScoredFlow, source: str) -> dict:
    """Construye el evento JSON que consumirá Wazuh."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "integration": "ids-ml",
        "source_capture": source,
        "anomaly_score": round(flow.score, 4),
        "src": flow.src,
        "dst": flow.dst,
        "protocol": flow.protocol,
        "top_features": [
            {"feature": name, "scaled_value": round(val, 3)}
            for name, val in flow.top_features
        ],
        # Severidad orientativa derivada del score, para reglas de Wazuh.
        "severity": _severity(flow.score),
    }


def _severity(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def emit(flows: list[ScoredFlow], source: str,
         threshold: float = config.ALERT_THRESHOLD) -> int:
    """Escribe en el fichero de Wazuh los flujos que superan el umbral.

    Devuelve el número de alertas emitidas.
    """
    alerts = [f for f in flows if f.score >= threshold]
    with open(config.WAZUH_ALERTS_PATH, "a", encoding="utf-8") as fh:
        for flow in alerts:
            fh.write(json.dumps(_event(flow, source), ensure_ascii=False) + "\n")
    return len(alerts)
