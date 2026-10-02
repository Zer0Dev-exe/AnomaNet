"""Fixtures compartidas.

Importante: fijamos IDS_ML_HOME a un directorio temporal ANTES de importar el
paquete, para que los tests no escriban modelos/alertas en el repo real.
"""
from __future__ import annotations

import os

import numpy as np
import pandas as pd
import pytest


@pytest.fixture(scope="session", autouse=True)
def _tmp_home(tmp_path_factory):
    home = tmp_path_factory.mktemp("ids_ml_home")
    os.environ["IDS_ML_HOME"] = str(home)
    yield home


@pytest.fixture
def normal_flows() -> pd.DataFrame:
    """Flujos 'normales' sintéticos con las columnas de características."""
    from ids_ml import features

    rng = np.random.default_rng(0)
    n = 300
    data = {col: rng.normal(100, 5, n) for col in features.FEATURE_COLUMNS}
    data["src_ip"] = ["10.0.0.1"] * n
    data["src_port"] = [12345] * n
    data["dst_ip"] = ["10.0.0.2"] * n
    data["dst_port"] = [443] * n
    data["protocol"] = [6] * n
    return pd.DataFrame(data)


@pytest.fixture
def anomalous_flow() -> pd.DataFrame:
    """Un flujo claramente fuera de la distribución normal."""
    from ids_ml import features

    data = {col: [100.0] for col in features.FEATURE_COLUMNS}
    data["bidirectional_bytes"] = [100000.0]  # muy desviado
    data["bidirectional_packets"] = [50000.0]
    data["src_ip"] = ["10.0.0.99"]
    data["src_port"] = [6666]
    data["dst_ip"] = ["8.8.8.8"]
    data["dst_port"] = [53]
    data["protocol"] = [17]
    return pd.DataFrame(data)
