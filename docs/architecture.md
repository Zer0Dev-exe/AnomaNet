# Arquitectura

## Visión general

`ids-ml` convierte una captura de red en una lista priorizada de flujos
sospechosos, aprendiendo previamente cómo es el tráfico **normal** de tu red.

```mermaid
flowchart LR
    PCAP[PCAP / interfaz] --> EXT[features.py<br/>nfstream]
    EXT --> MAT[Matriz de características<br/>por flujo]
    MAT --> DET[detector.py<br/>Isolation Forest]
    DET --> SCORE[Score de anomalía 0-1<br/>+ factores destacados]
    SCORE --> CLI[cli.py<br/>tabla en consola]
    SCORE --> WZ[wazuh.py<br/>alertas JSON]
    WZ --> AGENT[Agente Wazuh<br/>localfile]
    AGENT --> MGR[Wazuh manager<br/>reglas]
```

## Componentes

| Módulo | Responsabilidad | Entrada | Salida |
|---|---|---|---|
| `features.py` | Extraer flujos y características | PCAP / interfaz | DataFrame de flujos |
| `detector.py` | Aprender lo normal y puntuar | DataFrame | `ScoredFlow[]` |
| `wazuh.py` | Emitir alertas | `ScoredFlow[]` | JSON-lines |
| `cli.py` | Orquestar y mostrar | argumentos | tabla / alertas |
| `config.py` | Parámetros y rutas | entorno | `Settings` |

## ¿Por qué detección de anomalías no supervisada?

- **No necesitas etiquetas.** No vas a tener un dataset etiquetado de ataques
  de *tu* red. El Isolation Forest solo necesita tráfico normal.
- **Detecta lo desconocido.** Al modelar "lo normal", cualquier desviación
  (incluidos patrones nunca vistos) sube de score, cubriendo el caso de día cero.
- **Interpretable.** Como las características van estandarizadas, el |z-score|
  más alto señala directamente qué métrica del flujo se dispara (p. ej. muchos
  bytes, muchos paquetes SYN, duración anómala).

## Decisiones de diseño

1. **Un único extractor** para entrenamiento e inferencia → sin descuadre de
   características.
2. **Escalado ajustado solo con el tráfico de entrenamiento**; en scoring se
   aplica `transform`, nunca `fit` → sin fuga de datos.
3. **Import diferido de nfstream** dentro de `features.py` → el paquete se
   puede importar y testear sin tener nfstream/Npcap instalados.
4. **Configuración por entorno** (`Settings`) → nada de rutas fijas en el
   código; portable entre equipos.

## Flujo de inferencia

```mermaid
sequenceDiagram
    participant U as Analista
    participant CLI as ids-ml scan
    participant F as features
    participant D as Detector
    participant W as wazuh

    U->>CLI: ids-ml scan sospechoso.pcap --wazuh
    CLI->>F: extract(pcap)
    F-->>CLI: DataFrame de flujos
    CLI->>D: score(df)
    D-->>CLI: flujos ordenados por score
    CLI->>U: tabla con top anómalos
    CLI->>W: emit(flujos > umbral)
    W-->>U: alertas en outputs/ids_ml_alerts.json
```
