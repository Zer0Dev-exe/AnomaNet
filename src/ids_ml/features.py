"""Extracción de características de flujos de red desde PCAP o interfaz.

Usa nfstream (libpcap/Npcap por debajo) para convertir paquetes en flujos
bidireccionales con estadísticas tipo CICFlowMeter, sin depender de Java.

Decisión de diseño clave: ESTE módulo es la única fuente de características.
Se usa tanto para entrenar el detector (con tráfico normal) como para analizar
una captura nueva, de modo que nunca hay descuadre entre entrenamiento e
inferencia.
"""
from __future__ import annotations

import pandas as pd

from .logging_conf import get_logger

logger = get_logger(__name__)

# Columnas de identificación del flujo: se muestran en la alerta pero NO se
# usan como características del modelo (serían identificadores, no patrones).
META_COLUMNS: list[str] = [
    "id",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "protocol",
    "application_name",
]

# Columnas estadísticas numéricas que alimentan al modelo. nfstream expone
# muchas más; se elige un subconjunto estable y con significado defensivo.
FEATURE_COLUMNS: list[str] = [
    "bidirectional_duration_ms",
    "bidirectional_packets",
    "bidirectional_bytes",
    "src2dst_packets",
    "src2dst_bytes",
    "dst2src_packets",
    "dst2src_bytes",
    "bidirectional_min_ps",
    "bidirectional_mean_ps",
    "bidirectional_max_ps",
    "bidirectional_stddev_ps",
    "bidirectional_min_piat_ms",
    "bidirectional_mean_piat_ms",
    "bidirectional_max_piat_ms",
    "bidirectional_stddev_piat_ms",
    "bidirectional_syn_packets",
    "bidirectional_ack_packets",
    "bidirectional_psh_packets",
    "bidirectional_rst_packets",
    "bidirectional_fin_packets",
]


def _streamer(source: str, is_live: bool):
    """Crea un NFStreamer. Import diferido para que el paquete se pueda
    importar (y testear) aunque nfstream no esté instalado."""
    from nfstream import NFStreamer  # import local a propósito

    return NFStreamer(
        source=source,
        statistical_analysis=True,
        # En vivo conviene cerrar flujos inactivos pronto; en PCAP se ignora.
        idle_timeout=15 if is_live else 30,
        active_timeout=120,
    )


def extract(source: str, is_live: bool = False) -> pd.DataFrame:
    """Extrae flujos de un PCAP (ruta) o de una interfaz de red (si is_live).

    Args:
        source: ruta al .pcap/.pcapng o nombre de la interfaz (p. ej. "eth0").
        is_live: True para capturar en vivo de una interfaz.

    Returns:
        DataFrame con las columnas meta + las de características disponibles.
    """
    logger.debug("Extrayendo flujos de %s (live=%s)", source, is_live)
    df = _streamer(source, is_live).to_pandas()

    if df.empty:
        logger.warning("No se extrajo ningún flujo de %s", source)
        return df

    meta = [c for c in META_COLUMNS if c in df.columns]
    feats = [c for c in FEATURE_COLUMNS if c in df.columns]
    missing = set(FEATURE_COLUMNS) - set(feats)
    if missing:
        logger.debug("Características no presentes en esta versión de nfstream: %s", missing)

    logger.info("Flujos extraídos: %d", len(df))
    return df[meta + feats].copy()


def feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Devuelve solo las columnas numéricas de características, en orden fijo.

    Rellena ausentes con 0.0 para robustez frente a versiones de nfstream.
    """
    cols = [c for c in FEATURE_COLUMNS if c in df.columns]
    return df[cols].fillna(0.0)
