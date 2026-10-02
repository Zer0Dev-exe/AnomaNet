"""ids_ml — Analizador de capturas de red con detección de anomalías por ML.

Paquete con cuatro piezas principales:
    - features:  extracción de flujos desde PCAP/interfaz (nfstream).
    - detector:  entrenamiento y scoring de anomalías (Isolation Forest).
    - wazuh:     emisión de alertas en JSON para el agente de Wazuh.
    - cli:       interfaz de línea de comandos (comando `ids-ml`).
"""
from __future__ import annotations

__version__ = "0.2.0"
__all__ = ["__version__"]
