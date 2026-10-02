"""Tests de la integración con Wazuh."""
from __future__ import annotations

import json

from ids_ml import wazuh
from ids_ml.detector import ScoredFlow


def _flow(score: float) -> ScoredFlow:
    return ScoredFlow(
        src="10.0.0.1:1234",
        dst="8.8.8.8:53",
        protocol=17,
        score=score,
        top_features=[("bidirectional_bytes", 4.2)],
    )


def test_severity_of():
    assert wazuh.severity_of(0.9) == "high"
    assert wazuh.severity_of(0.7) == "medium"
    assert wazuh.severity_of(0.1) == "low"


def test_build_event_tiene_campos_clave():
    ev = wazuh.build_event(_flow(0.9), source="captura.pcap")
    assert ev["integration"] == "ids-ml"
    assert ev["severity"] == "high"
    assert ev["anomaly_score"] == 0.9
    assert ev["top_features"][0]["feature"] == "bidirectional_bytes"


def test_emit_solo_escribe_por_encima_del_umbral():
    flows = [_flow(0.9), _flow(0.5), _flow(0.7)]
    n = wazuh.emit(flows, source="captura.pcap", threshold=0.6)
    assert n == 2

    lines = wazuh.settings.wazuh_alerts_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) >= 2
    # La última línea es JSON válido con el campo esperado.
    assert json.loads(lines[-1])["integration"] == "ids-ml"
