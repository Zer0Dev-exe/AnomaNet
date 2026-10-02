#!/usr/bin/env python
"""Herramienta de línea de comandos para analizar capturas de red.

Flujo de trabajo típico del día a día:

    1) Entrenar el detector una vez con tráfico normal de tu red:
         python analyze_pcap.py train normal1.pcap normal2.pcap

    2) Analizar cualquier captura sospechosa:
         python analyze_pcap.py scan sospechoso.pcap
         python analyze_pcap.py scan sospechoso.pcap --wazuh
         python analyze_pcap.py scan sospechoso.pcap --top 30

Muestra los flujos ordenados por score de anomalía, con las características
que más se desvían de lo normal, y opcionalmente manda las alertas a Wazuh.
"""
from __future__ import annotations

import argparse
import sys

from rich.console import Console
from rich.table import Table

from src import config, features, wazuh
from src.detect import Detector, train

console = Console()


def _cmd_train(args: argparse.Namespace) -> int:
    console.print(f"[bold]Entrenando detector[/] con {len(args.pcaps)} captura(s)...")
    train(args.pcaps)
    console.print("[green]Listo.[/] Ya puedes usar 'scan'.")
    return 0


def _cmd_scan(args: argparse.Namespace) -> int:
    if not config.MODEL_PATH.exists():
        console.print("[red]No hay detector entrenado.[/] "
                      "Ejecuta primero: python analyze_pcap.py train <normal.pcap>")
        return 1

    console.print(f"[bold]Extrayendo flujos de[/] {args.pcap} ...")
    df = features.extract(args.pcap)
    if df.empty:
        console.print("[yellow]No se extrajo ningún flujo de la captura.[/]")
        return 0

    detector = Detector()
    flows = detector.score(df)
    console.print(f"Flujos analizados: [bold]{len(flows)}[/]\n")

    table = Table(title=f"Flujos más anómalos (top {args.top})")
    table.add_column("Score", justify="right", style="bold")
    table.add_column("Origen")
    table.add_column("Destino")
    table.add_column("Proto", justify="right")
    table.add_column("Factores destacados")

    for flow in flows[: args.top]:
        color = "red" if flow.score >= 0.85 else "yellow" if flow.score >= 0.6 else "green"
        factors = ", ".join(f"{n}={v:+.1f}" for n, v in flow.top_features)
        table.add_row(
            f"[{color}]{flow.score:.2f}[/]",
            flow.src, flow.dst, str(flow.protocol), factors,
        )
    console.print(table)

    if args.wazuh:
        n = wazuh.emit(flows, source=args.pcap, threshold=args.threshold)
        console.print(f"\n[cyan]{n} alerta(s)[/] escritas en {config.WAZUH_ALERTS_PATH}")

    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_train = sub.add_parser("train", help="Entrenar el detector con tráfico normal")
    p_train.add_argument("pcaps", nargs="+", help="Uno o más PCAP de tráfico legítimo")
    p_train.set_defaults(func=_cmd_train)

    p_scan = sub.add_parser("scan", help="Analizar una captura")
    p_scan.add_argument("pcap", help="Captura a analizar (.pcap / .pcapng)")
    p_scan.add_argument("--top", type=int, default=20, help="Nº de flujos a mostrar")
    p_scan.add_argument("--wazuh", action="store_true", help="Emitir alertas a Wazuh")
    p_scan.add_argument("--threshold", type=float, default=config.ALERT_THRESHOLD,
                        help="Umbral de score para alertar (0-1)")
    p_scan.set_defaults(func=_cmd_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
