"""Entrenamiento y evaluación de modelos (OE2, OE3).

Entrena un baseline (regresión logística), Random Forest y XGBoost sobre
el conjunto balanceado con SMOTE, y los evalúa con un protocolo común:
matriz de confusión, precisión, recall, F1, ROC-AUC, PR-AUC y FPR.

El énfasis en la tasa de falsos positivos (FPR) responde al problema de
fatiga de alertas descrito en la memoria (sección 2.1).
"""
from __future__ import annotations

from dataclasses import dataclass, field

import joblib
import numpy as np
from imblearn.over_sampling import SMOTE
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from xgboost import XGBClassifier

from . import config
from .preprocessing import Dataset, build


@dataclass
class EvalResult:
    name: str
    precision: float
    recall: float
    f1: float
    roc_auc: float
    pr_auc: float
    fpr: float  # tasa de falsos positivos: FP / (FP + TN)
    confusion: np.ndarray = field(repr=False)

    def summary(self) -> str:
        return (
            f"{self.name:<20} "
            f"P={self.precision:.3f} R={self.recall:.3f} F1={self.f1:.3f} "
            f"ROC-AUC={self.roc_auc:.3f} PR-AUC={self.pr_auc:.3f} "
            f"FPR={self.fpr:.4f}"
        )


def evaluate(name: str, model, X_test, y_test) -> EvalResult:
    """Calcula el conjunto de métricas sobre test."""
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    return EvalResult(
        name=name,
        precision=precision_score(y_test, y_pred, zero_division=0),
        recall=recall_score(y_test, y_pred, zero_division=0),
        f1=f1_score(y_test, y_pred, zero_division=0),
        roc_auc=roc_auc_score(y_test, y_proba),
        pr_auc=average_precision_score(y_test, y_proba),
        fpr=fpr,
        confusion=confusion_matrix(y_test, y_pred),
    )


def _models() -> dict:
    """Define los modelos a comparar."""
    return {
        "LogReg (baseline)": LogisticRegression(
            max_iter=1000, n_jobs=-1, random_state=config.RANDOM_STATE
        ),
        "RandomForest": RandomForestClassifier(
            n_estimators=200, n_jobs=-1, random_state=config.RANDOM_STATE,
            class_weight="balanced",
        ),
        "XGBoost": XGBClassifier(
            n_estimators=300, max_depth=8, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8,
            eval_metric="logloss", n_jobs=-1,
            random_state=config.RANDOM_STATE,
        ),
    }


def run(ds: Dataset | None = None, save_best: bool = True) -> list[EvalResult]:
    """Entrena todos los modelos y devuelve sus métricas ordenadas por F1."""
    if ds is None:
        ds = build()

    # SMOTE solo sobre train (nunca sobre test).
    smote = SMOTE(random_state=config.RANDOM_STATE)
    X_res, y_res = smote.fit_resample(ds.X_train, ds.y_train)
    print(f"Tras SMOTE: {X_res.shape[0]} muestras "
          f"(ataques: {y_res.mean():.3f})")

    results: list[EvalResult] = []
    trained: dict = {}
    for name, model in _models().items():
        model.fit(X_res, y_res)
        res = evaluate(name, model, ds.X_test, ds.y_test)
        results.append(res)
        trained[name] = model
        print(res.summary())

    results.sort(key=lambda r: r.f1, reverse=True)

    if save_best:
        best_name = results[0].name
        # Persistimos XGBoost para la API si está entre los mejores,
        # por su soporte nativo en SHAP TreeExplainer.
        to_save = "XGBoost" if "XGBoost" in trained else best_name
        joblib.dump(trained[to_save], config.MODEL_PATH)
        joblib.dump(ds.scaler, config.SCALER_PATH)
        joblib.dump(ds.feature_names, config.FEATURES_PATH)
        print(f"\nModelo persistido: {to_save} -> {config.MODEL_PATH}")

    return results


if __name__ == "__main__":
    run()
