"""Configuración central de la herramienta.

Todos los parámetros se pueden sobreescribir con variables de entorno
(ver .env.example). Si no se definen, se usan valores por defecto razonables.

Centralizar la configuración aquí mantiene el resto del código libre de rutas
y constantes "mágicas", y facilita cambiar el comportamiento sin tocar la
lógica.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

# Raíz del repositorio (…/src/ids_ml/config.py -> sube 3 niveles).
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


@dataclass(frozen=True)
class Settings:
    """Ajustes efectivos de la ejecución actual."""

    home: Path
    contamination: float
    alert_threshold: float
    log_level: str

    # --- Rutas derivadas ---
    @property
    def models_dir(self) -> Path:
        return self.home / "models"

    @property
    def outputs_dir(self) -> Path:
        return self.home / "outputs"

    @property
    def model_path(self) -> Path:
        return self.models_dir / "anomaly_model.joblib"

    @property
    def scaler_path(self) -> Path:
        return self.models_dir / "scaler.joblib"

    @property
    def metadata_path(self) -> Path:
        return self.models_dir / "model_metadata.json"

    @property
    def wazuh_alerts_path(self) -> Path:
        return self.outputs_dir / "ids_ml_alerts.json"

    def ensure_dirs(self) -> None:
        """Crea las carpetas de trabajo si no existen."""
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.outputs_dir.mkdir(parents=True, exist_ok=True)


def load_settings() -> Settings:
    """Construye los ajustes a partir del entorno (o valores por defecto)."""
    home = Path(os.environ.get("IDS_ML_HOME", PROJECT_ROOT)).expanduser().resolve()
    return Settings(
        home=home,
        contamination=_env_float("IDS_ML_CONTAMINATION", 0.02),
        alert_threshold=_env_float("IDS_ML_ALERT_THRESHOLD", 0.6),
        log_level=os.environ.get("IDS_ML_LOG_LEVEL", "INFO").upper(),
    )


# Semilla para reproducibilidad de los modelos.
RANDOM_STATE = 42

# Instancia única usada por el resto del paquete.
settings = load_settings()
