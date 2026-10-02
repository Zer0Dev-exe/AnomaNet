"""Detector de anomalías de tráfico de red.

Entrena un Isolation Forest con TU tráfico normal (uno o varios PCAP de
actividad legítima) y luego puntúa flujos nuevos: cuanto más se desvían del
patrón aprendido, mayor su score de anomalía (0 = normal, 1 = muy anómalo).

No necesita datos etiquetados de ataques: aprende lo "normal" de tu red.
"""
from __future__ import annotations

from dataclasses import dataclass

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from . import config, features


@dataclass
class ScoredFlow:
    """Un flujo puntuado, con su identificación y contribuciones top."""
    src: str
    dst: str
    protocol: int
    score: float  # 0-1, mayor = más anómalo
    top_features: list[tuple[str, float]]


def train(normal_pcaps: list[str]) -> None:
    """Entrena el detector con PCAP(s) de tráfico normal y lo persiste."""
    frames = [features.extract(p) for p in normal_pcaps]
    df = pd.concat(frames, ignore_index=True)
    X = features.feature_matrix(df)
    if X.empty:
        raise ValueError("No se extrajeron flujos de los PCAP indicados.")

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=config.CONTAMINATION,
        random_state=config.RANDOM_STATE,
        n_jobs=-1,
    )
    model.fit(X_scaled)

    joblib.dump(model, config.MODEL_PATH)
    joblib.dump(scaler, config.SCALER_PATH)
    joblib.dump(list(X.columns), config.FEATURES_PATH)
    print(f"Detector entrenado con {len(X)} flujos normales.")
    print(f"Modelo guardado en {config.MODEL_PATH}")


def _to_score(raw: np.ndarray) -> np.ndarray:
    """Convierte decision_function (mayor = más normal) a score 0-1
    (mayor = más anómalo), normalizando de forma estable."""
    # Invertimos el signo y escalamos con una sigmoide centrada en 0.
    return 1.0 / (1.0 + np.exp(raw * 4.0))


class Detector:
    """Carga el modelo entrenado y puntúa flujos nuevos."""

    def __init__(self):
        self.model: IsolationForest = joblib.load(config.MODEL_PATH)
        self.scaler: StandardScaler = joblib.load(config.SCALER_PATH)
        self.feature_names: list[str] = joblib.load(config.FEATURES_PATH)

    def score(self, df: pd.DataFrame) -> list[ScoredFlow]:
        """Puntúa cada flujo del DataFrame y lo ordena de más a menos anómalo."""
        X = df.reindex(columns=self.feature_names, fill_value=0.0).fillna(0.0)
        X_scaled = self.scaler.transform(X)
        scores = _to_score(self.model.decision_function(X_scaled))

        results: list[ScoredFlow] = []
        for i, (_, row) in enumerate(df.iterrows()):
            results.append(
                ScoredFlow(
                    src=f"{row.get('src_ip', '?')}:{row.get('src_port', '?')}",
                    dst=f"{row.get('dst_ip', '?')}:{row.get('dst_port', '?')}",
                    protocol=int(row.get("protocol", 0)),
                    score=float(scores[i]),
                    top_features=self._top_features(X_scaled[i]),
                )
            )
        results.sort(key=lambda r: r.score, reverse=True)
        return results

    def _top_features(self, x_scaled: np.ndarray, k: int = 4) -> list[tuple[str, float]]:
        """Características que más se alejan de lo normal (mayor |z-score|).

        Aproximación rápida e interpretable: como los datos están escalados,
        un valor con |valor escalado| alto es el que más se desvía.
        """
        order = np.argsort(-np.abs(x_scaled))[:k]
        return [(self.feature_names[j], float(x_scaled[j])) for j in order]
