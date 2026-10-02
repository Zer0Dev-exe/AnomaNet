"""Extracción de características de flujos de red desde PCAP o interfaz.

Usa nfstream (libpcap/Npcap por debajo) para convertir paquetes en flujos
bidireccionales con estadísticas tipo CICFlowMeter, sin depender de Java.

Clave de diseño: ESTE módulo es la única fuente de características. Se usa
tanto para entrenar el detector (con tu tráfico normal) como para analizar
un PCAP nuevo, así nunca hay descuadre entre entrenamiento e inferencia.
"""
from __future__ import annotations

import pandas as pd
from nfstream import NFStreamer

# Columnas de identificación del flujo: útiles para mostrar la alerta,
# pero NO se usan como características del modelo (serían identificadores).
META_COLUMNS = [
    "id", "src_ip", "src_port", "dst_ip", "dst_port",
    "protocol", "bidirectional_first_seen_ms",
    "application_name",
]

# Columnas estadísticas numéricas que sí alimentan al modelo. nfstream
# expone muchas; seleccionamos un subconjunto estable y con sentido.
FEATURE_COLUMNS = [
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


def extract(source: str, is_live: bool = False) -> pd.DataFrame:
    """Extrae flujos de un PCAP (ruta) o de una interfaz de red (si is_live).

    Devuelve un DataFrame con las columnas meta + las de características.
    """
    streamer = NFStreamer(
        source=source,
        statistical_analysis=True,
        # En captura en vivo conviene limitar el tiempo de vida del flujo;
        # para PCAP se ignora.
        idle_timeout=15,
        active_timeout=120,
    )
    df = streamer.to_pandas()

    if df.empty:
        return df

    # Conserva solo las columnas que existan (nfstream varía entre versiones).
    meta = [c for c in META_COLUMNS if c in df.columns]
    feats = [c for c in FEATURE_COLUMNS if c in df.columns]
    return df[meta + feats].copy()


def feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    """Devuelve solo las columnas numéricas de características, en orden fijo."""
    feats = [c for c in FEATURE_COLUMNS if c in df.columns]
    return df[feats].fillna(0.0)


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Uso: python -m src.features <captura.pcap>")
        sys.exit(1)
    flows = extract(sys.argv[1])
    print(f"Flujos extraídos: {len(flows)}")
    print(flows.head())
