"""Detector de anomalías de tráfico de red (Isolation Forest).

Se entrena con TU tráfico normal (uno o varios PCAP de actividad legítima) y
luego puntúa flujos nuevos: cuanto más se desvían del patrón aprendido, mayor
su score de anomalía (0 = normal, 1 = muy anómalo).

No necesita datos etiquetados de ataques: aprende lo "normal" de tu red.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from . import features
from .config import RANDOM_STATE, settings
from .logging_conf import get_logger

logger = get_logger(__name__)


@dataclass
class ScoredFlow:
    """Un flujo puntuado, con su identificación y factores destacados."""

    src: str
    dst: str
    protocol: int
    score: float  # 0-1, mayor = más anómalo
    top_features: list[tuple[str, float]] = field(default_factory=list)


class ModelNotTrainedError(RuntimeError):
    """Se intenta puntuar sin haber entrenado el detector."""


def _anomaly_score(raw: np.ndarray) -> np.ndarray:
    """Convierte `decision_function` (mayor = más normal) en un score 0-1
    (mayor = más anómalo) mediante una sigmoide estable."""
    return 1.0 / (1.0 + np.exp(raw * 4.0))


def train(normal_pcaps: list[str]) -> dict:
    """Entrena el detector con PCAP(s) de tráfico normal y lo persiste.

    Returns:
        Metadatos del entrenamiento (nº de flujos, características, fecha).
    """
    settings.ensure_dirs()

    frames = [features.extract(p) for p in normal_pcaps]
    frames = [f for f in frames if not f.empty]
    if not frames:
        raise ValueError("No se extrajeron flujos de los PCAP indicados.")

    df = pd.concat(frames, ignore_index=True)
    X = features.feature_matrix(df)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=settings.contamination,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    joblib.dump(model, settings.model_path)
    joblib.dump(scaler, settings.scaler_path)

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_flows": int(len(X)),
        "n_features": int(X.shape[1]),
        "feature_names": list(X.columns),
        "contamination": settings.contamination,
        "sources": list(normal_pcaps),
    }
    settings.metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    logger.info("Detector entrenado con %d flujos normales.", len(X))
    logger.info("Modelo guardado en %s", settings.model_path)
    return metadata


class Detector:
    """Carga el modelo entrenado y puntúa flujos nuevos."""

    def __init__(self) -> None:
        if not settings.model_path.exists():
            raise ModelNotTrainedError(
                "No hay detector entrenado. Ejecuta primero: ids-ml train <normal.pcap>"
            )
        self.model: IsolationForest = joblib.load(settings.model_path)
        self.scaler: StandardScaler = joblib.load(settings.scaler_path)
        self.feature_names: list[str] = json.loads(
            settings.metadata_path.read_text(encoding="utf-8")
        )["feature_names"]

    def score(self, df: pd.DataFrame) -> list[ScoredFlow]:
        """Puntúa cada flujo del DataFrame y lo ordena de más a menos anómalo."""
        if df.empty:
            return []

        X = df.reindex(columns=self.feature_names, fill_value=0.0).fillna(0.0)
        X_scaled = self.scaler.transform(X)
        scores = _anomaly_score(self.model.decision_function(X_scaled))

        results = [
            ScoredFlow(
                src=f"{row.get('src_ip', '?')}:{row.get('src_port', '?')}",
                dst=f"{row.get('dst_ip', '?')}:{row.get('dst_port', '?')}",
                protocol=int(row.get("protocol", 0) or 0),
                score=float(scores[i]),
                top_features=self._top_features(X_scaled[i]),
            )
            for i, (_, row) in enumerate(df.iterrows())
        ]
        results.sort(key=lambda r: r.score, reverse=True)
        return results

    def _top_features(self, x_scaled: np.ndarray, k: int = 4) -> list[tuple[str, float]]:
        """Características que más se alejan de lo normal.

        Como los datos están estandarizados, un |valor escalado| alto equivale
        a un z-score alto: es la característica que más se desvía de la media
        aprendida. Es una explicación rápida, interpretable y sin dependencias.
        """
        order = np.argsort(-np.abs(x_scaled))[:k]
        return [(self.feature_names[j], float(x_scaled[j])) for j in order]
