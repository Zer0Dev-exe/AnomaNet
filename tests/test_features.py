"""Tests del módulo de características (sin depender de nfstream)."""
from __future__ import annotations

import pandas as pd

from ids_ml import features


def test_feature_matrix_selecciona_columnas(normal_flows):
    X = features.feature_matrix(normal_flows)
    assert list(X.columns) == [c for c in features.FEATURE_COLUMNS if c in normal_flows]
    assert not X.isnull().any().any()


def test_feature_matrix_rellena_ausentes():
    df = pd.DataFrame({"bidirectional_packets": [1.0, None]})
    X = features.feature_matrix(df)
    # El NaN se rellena con 0.0
    assert X["bidirectional_packets"].tolist() == [1.0, 0.0]


def test_feature_matrix_ignora_columnas_desconocidas():
    df = pd.DataFrame({"columna_rara": [1, 2], "bidirectional_bytes": [10, 20]})
    X = features.feature_matrix(df)
    assert "columna_rara" not in X.columns
    assert "bidirectional_bytes" in X.columns
