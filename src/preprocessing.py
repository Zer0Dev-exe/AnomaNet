"""Carga y preprocesado del dataset CIC-IDS2017 (OE1).

Responsabilidades:
    - Cargar y concatenar los CSV del dataset.
    - Normalizar nombres de columnas (CIC-IDS trae espacios iniciales).
    - Limpiar valores nulos e infinitos (frecuentes en las columnas de ratios).
    - Construir la etiqueta binaria (BENIGN vs. ataque) y la multiclase.
    - Partir en train/test de forma estratificada SIN fuga de datos.

Decisiones clave (ver memoria 4.2):
    - El escalado se ajusta solo con train.
    - SMOTE se aplica solo a train, en train.py, nunca aquí sobre todo el set.
"""
from __future__ import annotations

import glob
import re
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from . import config


@dataclass
class Dataset:
    """Contenedor del resultado del preprocesado."""
    X_train: pd.DataFrame
    X_test: pd.DataFrame
    y_train: pd.Series  # etiqueta binaria (0 = benigno, 1 = ataque)
    y_test: pd.Series
    y_train_multi: pd.Series  # etiqueta por tipo de ataque
    y_test_multi: pd.Series
    feature_names: list[str]
    scaler: StandardScaler


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Pasa los nombres a minúsculas, sin espacios ni caracteres raros."""
    def clean(name: str) -> str:
        name = name.strip().lower()
        name = re.sub(r"[^0-9a-z]+", "_", name)
        return name.strip("_")

    df = df.rename(columns={c: clean(c) for c in df.columns})
    return df


def load_raw(data_dir=config.DATA_DIR) -> pd.DataFrame:
    """Carga y concatena todos los CSV del dataset."""
    csv_files = sorted(glob.glob(str(data_dir / "*.csv")))
    if not csv_files:
        raise FileNotFoundError(
            f"No se encontraron CSV en {data_dir}. "
            "Descarga CIC-IDS2017 y colócalo ahí."
        )
    frames = [pd.read_csv(f, low_memory=False) for f in csv_files]
    df = pd.concat(frames, ignore_index=True)
    return _normalize_columns(df)


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Limpia nulos e infinitos y elimina columnas no informativas."""
    # Reemplaza infinitos (aparecen en ratios con denominador 0) por NaN.
    df = df.replace([np.inf, -np.inf], np.nan)

    # Elimina columnas constantes (varianza 0) salvo la etiqueta.
    label = config.LABEL_COLUMN
    feature_cols = [c for c in df.columns if c != label]
    nunique = df[feature_cols].nunique()
    constant_cols = nunique[nunique <= 1].index.tolist()
    df = df.drop(columns=constant_cols)

    # Descarta filas con NaN (son una fracción pequeña del dataset).
    df = df.dropna()

    # Elimina duplicados exactos.
    df = df.drop_duplicates().reset_index(drop=True)
    return df


def build(data_dir=config.DATA_DIR) -> Dataset:
    """Pipeline completo: carga → limpieza → split → escalado."""
    df = clean(load_raw(data_dir))
    label = config.LABEL_COLUMN

    if label not in df.columns:
        raise KeyError(
            f"No se encuentra la columna de etiqueta '{label}'. "
            f"Columnas disponibles: {list(df.columns)[:10]}..."
        )

    y_multi = df[label].astype(str).str.upper().str.strip()
    y_bin = (y_multi != config.BENIGN_LABEL).astype(int)
    X = df.drop(columns=[label]).select_dtypes(include=[np.number])
    feature_names = X.columns.tolist()

    # Split estratificado por la etiqueta multiclase para conservar
    # la proporción de cada tipo de ataque.
    X_train, X_test, y_train, y_test, ym_train, ym_test = train_test_split(
        X, y_bin, y_multi,
        test_size=config.TEST_SIZE,
        random_state=config.RANDOM_STATE,
        stratify=y_multi,
    )

    # Escalado: fit SOLO en train (evita data leakage).
    scaler = StandardScaler()
    X_train_s = pd.DataFrame(
        scaler.fit_transform(X_train), columns=feature_names, index=X_train.index
    )
    X_test_s = pd.DataFrame(
        scaler.transform(X_test), columns=feature_names, index=X_test.index
    )

    return Dataset(
        X_train=X_train_s, X_test=X_test_s,
        y_train=y_train, y_test=y_test,
        y_train_multi=ym_train, y_test_multi=ym_test,
        feature_names=feature_names, scaler=scaler,
    )


if __name__ == "__main__":
    ds = build()
    print(f"Train: {ds.X_train.shape}  Test: {ds.X_test.shape}")
    print(f"Características: {len(ds.feature_names)}")
    print(f"Proporción de ataques (train): {ds.y_train.mean():.3f}")
