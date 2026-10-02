"""API de inferencia con FastAPI (OE5).

Expone el modelo entrenado: recibe las características de un flujo de red,
devuelve la puntuación de riesgo, la clase, la explicación SHAP y la técnica
MITRE ATT&CK asociada. Es la pieza que un SIEM o un dashboard consumen.

Arranque:  uvicorn src.api:app --reload
"""
from __future__ import annotations

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import config
from .explain import Explainer

app = FastAPI(
    title="IDS-ML API",
    description="Detección de intrusiones en red asistida por ML con "
                "explicabilidad (TFM Ciberseguridad).",
    version="0.1.0",
)

# Mapeo orientativo de la clase de ataque a MITRE ATT&CK (ver memoria 3.1).
# En el modelo binario inicial solo distinguimos ataque/benigno; este mapa
# se enriquecerá al pasar al clasificador multiclase.
ATTACK_TACTIC = "Impact / Reconnaissance (según tipo)"

_model = None
_explainer: Explainer | None = None
_feature_names: list[str] = []


@app.on_event("startup")
def _load():
    global _model, _explainer, _feature_names
    try:
        _model = joblib.load(config.MODEL_PATH)
        _feature_names = joblib.load(config.FEATURES_PATH)
        _explainer = Explainer()
    except FileNotFoundError:
        # El modelo aún no se ha entrenado; la API arranca pero /predict
        # devolverá 503 hasta que exista el artefacto.
        _model = None


class FlowFeatures(BaseModel):
    """Características de un flujo. Se aceptan como diccionario nombre->valor
    para no fijar en el esquema las 70+ columnas de CIC-IDS2017."""
    features: dict[str, float] = Field(
        ..., description="Mapa característica->valor del flujo de red."
    )
    threshold: float = Field(
        config.DEFAULT_THRESHOLD, ge=0.0, le=1.0,
        description="Umbral de decisión para la clase 'ataque'.",
    )


class Prediction(BaseModel):
    risk_score: float
    is_attack: bool
    threshold: float
    attack_tactic: str
    explanation: list[dict]


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _model is not None}


@app.post("/predict", response_model=Prediction)
def predict(payload: FlowFeatures):
    if _model is None or _explainer is None:
        raise HTTPException(
            status_code=503,
            detail="Modelo no disponible. Ejecuta primero 'python -m src.train'.",
        )

    # Construye el vector en el orden exacto de las características de entrenamiento;
    # las ausentes se rellenan con 0 (el escalador ya se aplicó en entrenamiento).
    row = pd.DataFrame(
        [[payload.features.get(name, 0.0) for name in _feature_names]],
        columns=_feature_names,
    )

    proba = float(_model.predict_proba(row)[0, 1])
    is_attack = proba >= payload.threshold

    return Prediction(
        risk_score=round(proba, 4),
        is_attack=is_attack,
        threshold=payload.threshold,
        attack_tactic=ATTACK_TACTIC if is_attack else "N/A",
        explanation=_explainer.explain_local(row, top_k=5),
    )
