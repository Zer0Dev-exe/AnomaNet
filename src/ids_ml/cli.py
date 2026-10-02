"""Interfaz de línea de comandos: comando `ids-ml`.

Subcomandos:
    train   Entrena el detector con uno o más PCAP de tráfico normal.
    scan    Analiza una captura y lista los flujos más anómalos.
    live    Captura en vivo de una interfaz durante N segundos y la analiza.
    info    Muestra el estado del modelo entrenado.

Ejemplos:
    ids-ml train normal_lunes.pcap normal_martes.pcap
    ids-ml scan sospechoso.pcap --top 30 --wazuh
    ids-ml live eth0 --seconds 60 --wazuh
    ids-ml info
"""
from __future__ import annotations

import argparse
import json
import sys

from rich.console import Console
from rich.table import Table

from . import __version__, features, wazuh
from .config import settings
from .detector import Detector, ModelNotTrainedError, ScoredFlow, train
from .logging_conf import get_logger

console = Console()
logger = get_logger(__name__)


def _render_table(flows: list[ScoredFlow], top: int) -> None:
    table = Table(title=f"Flujos más anómalos (top {top})")
    table.add_column("Score", justify="right", style="bold")
    table.add_column("Severidad")
    table.add_column("Origen")
    table.add_column("Destino")
    table.add_column("Proto", justify="right")
    table.add_column("Factores destacados")

    for flow in flows[:top]:
        sev = wazuh.severity_of(flow.score)
        color = {"high": "red", "medium": "yellow", "low": "green"}[sev]
        factors = ", ".join(f"{n}={v:+.1f}" for n, v in flow.top_features)
        table.add_row(
            f"[{color}]{flow.score:.2f}[/]",
            f"[{color}]{sev}[/]",
            flow.src,
            flow.dst,
            str(flow.protocol),
            factors,
        )
    console.print(table)


def _analyze(df, source: str, top: int, use_wazuh: bool, threshold: float) -> int:
    if df.empty:
        console.print("[yellow]No se extrajo ningún flujo de la captura.[/]")
        return 0
    try:
        detector = Detector()
    except ModelNotTrainedError as exc:
        console.print(f"[red]{exc}[/]")
        return 1

    flows = detector.score(df)
    console.print(f"Flujos analizados: [bold]{len(flows)}[/]\n")
    _render_table(flows, top)

    if use_wazuh:
        n = wazuh.emit(flows, source=source, threshold=threshold)
        console.print(f"\n[cyan]{n} alerta(s)[/] escritas en {settings.wazuh_alerts_path}")
    return 0


def cmd_train(args: argparse.Namespace) -> int:
    console.print(f"[bold]Entrenando detector[/] con {len(args.pcaps)} captura(s)…")
    meta = train(args.pcaps)
    console.print(
        f"[green]Listo.[/] {meta['n_flows']} flujos, "
        f"{meta['n_features']} características. Ya puedes usar 'scan'."
    )
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    console.print(f"[bold]Extrayendo flujos de[/] {args.pcap} …")
    df = features.extract(args.pcap)
    return _analyze(df, args.pcap, args.top, args.wazuh, args.threshold)


def cmd_live(args: argparse.Namespace) -> int:
    console.print(
        f"[bold]Capturando en vivo[/] de {args.interface} durante {args.seconds}s… "
        "(Ctrl+C para parar)"
    )
    # nfstream captura hasta que se agota el PCAP/stream; para una interfaz,
    # limitamos con una señal temporal simple basada en el nº de paquetes/idle.
    df = features.extract(args.interface, is_live=True)
    return _analyze(df, args.interface, args.top, args.wazuh, args.threshold)


def cmd_info(_: argparse.Namespace) -> int:
    if not settings.metadata_path.exists():
        console.print("[yellow]No hay modelo entrenado todavía.[/]")
        return 0
    meta = json.loads(settings.metadata_path.read_text(encoding="utf-8"))
    table = Table(title="Estado del detector")
    table.add_column("Campo")
    table.add_column("Valor")
    for key in ("trained_at", "n_flows", "n_features", "contamination"):
        table.add_row(key, str(meta.get(key)))
    table.add_row("sources", ", ".join(meta.get("sources", [])))
    console.print(table)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ids-ml",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"ids-ml {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_train = sub.add_parser("train", help="Entrenar el detector con tráfico normal")
    p_train.add_argument("pcaps", nargs="+", help="Uno o más PCAP de tráfico legítimo")
    p_train.set_defaults(func=cmd_train)

    def _add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--top", type=int, default=20, help="Nº de flujos a mostrar")
        p.add_argument("--wazuh", action="store_true", help="Emitir alertas a Wazuh")
        p.add_argument(
            "--threshold",
            type=float,
            default=settings.alert_threshold,
            help="Umbral de score para alertar (0-1)",
        )

    p_scan = sub.add_parser("scan", help="Analizar una captura PCAP")
    p_scan.add_argument("pcap", help="Captura a analizar (.pcap / .pcapng)")
    _add_common(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    p_live = sub.add_parser("live", help="Capturar en vivo de una interfaz y analizar")
    p_live.add_argument("interface", help="Interfaz de red (p. ej. eth0, Wi-Fi)")
    p_live.add_argument("--seconds", type=int, default=60, help="Duración de la captura")
    _add_common(p_live)
    p_live.set_defaults(func=cmd_live)

    p_info = sub.add_parser("info", help="Mostrar el estado del modelo")
    p_info.set_defaults(func=cmd_info)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrumpido por el usuario.[/]")
        return 130
    except Exception as exc:  # noqa: BLE001 - frontera de la CLI
        logger.exception("Error inesperado")
        console.print(f"[red]Error:[/] {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
