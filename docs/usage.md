# Guía de uso

## Instalación

```bash
python -m venv .venv
.venv\Scripts\activate            # Windows (Linux/mac: source .venv/bin/activate)
pip install -e .                  # o: pip install -e ".[dev,explain]"
```

Requisito en Windows: **Npcap** (npcap.com), instalado en modo "WinPcap API
compatible". Sin él, nfstream no puede leer capturas ni capturar en vivo.

## Comandos

### `train` — aprender tu tráfico normal

```bash
ids-ml train normal_lunes.pcap normal_martes.pcap
```

Cuanto más representativo sea el tráfico normal (distintos días, servicios,
horas), mejor distinguirá luego lo anómalo. Solo necesitas hacerlo una vez (o
reentrenar cuando tu red cambie).

### `scan` — analizar una captura

```bash
ids-ml scan sospechoso.pcap                 # tabla en consola
ids-ml scan sospechoso.pcap --top 30        # mostrar 30 flujos
ids-ml scan sospechoso.pcap --wazuh         # + alertas a Wazuh
ids-ml scan sospechoso.pcap --threshold 0.75
```

### `live` — capturar en vivo

```bash
ids-ml live "Wi-Fi" --seconds 60 --wazuh
```

### `info` — estado del modelo

```bash
ids-ml info
```

## Interpretar los resultados

- **Score** (0–1): mayor = más anómalo. Severidad: `high ≥ 0.85`,
  `medium ≥ 0.6`, resto `low`.
- **Factores destacados**: características cuyo valor más se desvía de lo
  normal. Un `+` indica por encima de la media aprendida; `-`, por debajo.
  Ejemplos de lectura:
  - `bidirectional_bytes=+7.4` → transferencia muy superior a lo habitual
    (posible exfiltración o descarga anómala).
  - `bidirectional_syn_packets=+6.1` → muchísimos SYN (posible escaneo/DoS).

## Ajuste del umbral

Empieza con el valor por defecto (`0.6`) en modo observación. Si ves demasiados
falsos positivos, súbelo (`--threshold 0.75`); si se te escapan cosas, bájalo.
Puedes fijar el valor por defecto con la variable `IDS_ML_ALERT_THRESHOLD`.
