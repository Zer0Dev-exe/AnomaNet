"""Explicabilidad mediante valores SHAP (OE4).

Proporciona explicaciones globales (qué características importan en general)
y locales (por qué un flujo concreto se clasificó como ataque), que es lo
que necesita un analista del SOC para actuar sobre una alerta.

Usa TreeExplainer, exacto y eficiente para modelos de árboles (XGBoost / RF).
"""
from __future__ import annotations

import joblib
import numpy as np
import pandas as pd
import shap

from . import config


class Explainer:
    """Envuelve un SHAP TreeExplainer sobre el modelo persistido."""

    def __init__(self, model_path=config.MODEL_PATH,
                 features_path=config.FEATURES_PATH):
        self.model = joblib.load(model_path)
        self.feature_names: list[str] = joblib.load(features_path)
        self._explainer = shap.TreeExplainer(self.model)

    def explain_local(self, x: pd.DataFrame, top_k: int = 5) -> list[dict]:
        """Devuelve las top_k características que más empujan la predicción.

        Cada entrada: {feature, value, shap_value}. Un shap_value positivo
        empuja hacia "ataque"; negativo, hacia "benigno".
        """
        shap_values = self._explainer.shap_values(x)
        # Para clasificación binaria con XGBoost, shap_values es 2D (n, feats).
        if isinstance(shap_values, list):
            shap_values = shap_values[1]
        row = np.asarray(shap_values)[0]

        contributions = [
            {
                "feature": self.feature_names[i],
                "value": float(x.iloc[0, i]),
                "shap_value": float(row[i]),
            }
            for i in range(len(self.feature_names))
        ]
        contributions.sort(key=lambda d: abs(d["shap_value"]), reverse=True)
        return contributions[:top_k]

    def global_importance(self, X: pd.DataFrame, top_k: int = 15) -> list[dict]:
        """Importancia global: media del |SHAP| por característica."""
        shap_values = self._explainer.shap_values(X)
        if isinstance(shap_values, list):
            shap_values = shap_values[1]
        mean_abs = np.abs(np.asarray(shap_values)).mean(axis=0)
        importance = [
            {"feature": self.feature_names[i], "importance": float(mean_abs[i])}
            for i in range(len(self.feature_names))
        ]
        importance.sort(key=lambda d: d["importance"], reverse=True)
        return importance[:top_k]
