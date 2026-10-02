"""Configuración central de la herramienta.

Rutas y parámetros compartidos. Centralizar aquí evita rutas dispersas por
el código y facilita cambiar el comportamiento sin tocar la lógica.
"""
from __future__ import annotations

from pathlib import Path

# --- Rutas base -----------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
OUTPUTS_DIR = ROOT / "outputs"

for _d in (MODELS_DIR, OUTPUTS_DIR):
    _d.mkdir(exist_ok=True)

# --- Reproducibilidad -----------------------------------------------------
RANDOM_STATE = 42

# --- Detector de anomalías ------------------------------------------------
# Proporción esperada de flujos anómalos al entrenar el Isolation Forest.
# Es una estimación "a priori"; se puede ajustar según tu red.
CONTAMINATION = 0.02

# Artefactos persistidos tras entrenar con tu tráfico normal.
MODEL_PATH = MODELS_DIR / "anomaly_model.joblib"
SCALER_PATH = MODELS_DIR / "scaler.joblib"
FEATURES_PATH = MODELS_DIR / "feature_names.joblib"

# --- Salida / Wazuh -------------------------------------------------------
# Fichero de alertas en formato JSON-lines que el agente de Wazuh puede
# leer con un bloque <localfile> (log_format json). Ver src/wazuh.py.
WAZUH_ALERTS_PATH = OUTPUTS_DIR / "ids_ml_alerts.json"

# Umbral de score de anomalía (0-1) a partir del cual se emite alerta.
# Score alto = más anómalo. Ajústalo tras ver resultados en tu tráfico.
ALERT_THRESHOLD = 0.6
