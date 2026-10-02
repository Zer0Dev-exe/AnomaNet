"""Dashboard interactivo con Streamlit (OE5).

Permite a un analista introducir las características de un flujo (o cargar un
CSV) y obtener la puntuación de riesgo junto con la explicación SHAP de los
factores que han pesado en la decisión.

Arranque:  streamlit run dashboard/app.py
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import streamlit as st

# Permite importar el paquete src cuando se lanza desde la raíz del repo.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import config  # noqa: E402

st.set_page_config(page_title="IDS-ML · TFM", page_icon="🛡️", layout="wide")

st.title("🛡️ Detección de intrusiones asistida por ML")
st.caption("TFM · Detección explicable de tráfico de red malicioso")


@st.cache_resource
def load_artifacts():
    import joblib
    from src.explain import Explainer
    model = joblib.load(config.MODEL_PATH)
    features = joblib.load(config.FEATURES_PATH)
    explainer = Explainer()
    return model, features, explainer


try:
    model, feature_names, explainer = load_artifacts()
    model_ready = True
except FileNotFoundError:
    model_ready = False

if not model_ready:
    st.warning(
        "⚠️ No hay modelo entrenado todavía. Ejecuta `python -m src.train` "
        "para generar los artefactos y recarga la página."
    )
    st.stop()

threshold = st.sidebar.slider(
    "Umbral de decisión (ataque)", 0.0, 1.0, config.DEFAULT_THRESHOLD, 0.01,
    help="Más bajo → detecta más ataques pero sube la tasa de falsos positivos.",
)

st.subheader("Analizar un flujo")
uploaded = st.file_uploader("Sube un CSV con flujos (columnas = características)", type="csv")

if uploaded is not None:
    df = pd.read_csv(uploaded)
    row = pd.DataFrame(
        [[df.iloc[0].get(name, 0.0) for name in feature_names]],
        columns=feature_names,
    )
    proba = float(model.predict_proba(row)[0, 1])
    is_attack = proba >= threshold

    col1, col2 = st.columns(2)
    col1.metric("Puntuación de riesgo", f"{proba:.1%}")
    col2.metric("Veredicto", "🔴 ATAQUE" if is_attack else "🟢 Benigno")

    st.subheader("¿Por qué? (explicación SHAP)")
    contributions = explainer.explain_local(row, top_k=8)
    exp_df = pd.DataFrame(contributions)
    exp_df["dirección"] = exp_df["shap_value"].apply(
        lambda v: "→ ataque" if v > 0 else "→ benigno"
    )
    st.dataframe(exp_df, use_container_width=True)
else:
    st.info("Sube un CSV para obtener una predicción explicada.")
