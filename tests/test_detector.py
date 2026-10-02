"""Tests del detector de anomalías con datos sintéticos.

No requieren nfstream: inyectamos los DataFrames directamente, saltándonos la
extracción de PCAP.
"""
from __future__ import annotations

import pandas as pd
import pytest

from ids_ml import detector
from ids_ml.detector import Detector, ModelNotTrainedError


def _train_with(monkeypatch, df: pd.DataFrame):
    """Entrena el detector forzando que features.extract devuelva `df`."""
    monkeypatch.setattr(detector.features, "extract", lambda path: df)
    return detector.train(["fake.pcap"])


def test_detector_sin_entrenar_lanza_error(monkeypatch, tmp_path):
    # Apuntamos a un modelo inexistente.
    monkeypatch.setattr(detector.settings, "model_path", tmp_path / "noexiste.joblib")
    with pytest.raises(ModelNotTrainedError):
        Detector()


def test_entrenamiento_persiste_metadatos(monkeypatch, normal_flows):
    meta = _train_with(monkeypatch, normal_flows)
    assert meta["n_flows"] == len(normal_flows)
    assert meta["n_features"] > 0
    assert detector.settings.model_path.exists()


def test_flujo_anomalo_puntua_mas_alto(monkeypatch, normal_flows, anomalous_flow):
    _train_with(monkeypatch, normal_flows)
    det = Detector()

    normal_scores = [f.score for f in det.score(normal_flows)]
    anomalo = det.score(anomalous_flow)[0]

    media_normal = sum(normal_scores) / len(normal_scores)
    assert anomalo.score > media_normal
    assert anomalo.top_features  # debe explicar por qué


def test_score_dataframe_vacio_devuelve_lista_vacia(monkeypatch, normal_flows):
    _train_with(monkeypatch, normal_flows)
    assert Detector().score(pd.DataFrame()) == []
