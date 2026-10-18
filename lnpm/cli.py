"""Command-line interface for Live Network & Process Monitor."""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime

from . import __version__
from .core import (
    SORT_KEYS,
    BaselineError,
    export,
    flags_for,
    listeners,
    load_baseline,
    new_listeners,
    prime_cpu,
    save_baseline,
    snapshot,
    top,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="lnpm",
        description="Real-time view of processes, resource use and network activity.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("-s", "--sort", choices=sorted(SORT_KEYS), default="cpu",
                   help="sort column (default: cpu)")
    p.add_argument("-n", "--top", type=int, default=15, help="rows to show, 0 = all (default: 15)")
    p.add_argument("-i", "--interval", type=float, default=2.0, help="refresh seconds (default: 2)")
    p.add_argument("-f", "--filter", help="only show processes whose name contains this text")
    p.add_argument("--once", action="store_true", help="print one snapshot and exit")
    p.add_argument("--cpu-warn", type=float, default=50.0, help="highlight CPU %% at or above (default: 50)")
    p.add_argument("--mem-warn", type=float, default=1024.0,
                   help="highlight memory MB at or above (default: 1024)")
    p.add_argument("--save-baseline", metavar="FILE",
                   help="record the current listening ports as known-good, then exit")
    p.add_argument("--baseline", metavar="FILE",
                   help="flag processes listening on ports that are not in this baseline")
    p.add_argument("--export", metavar="FILE",
                   help="write the snapshot to FILE (.csv or .json) and exit")
    return p


def render(rows, args, unexpected, new_items, total):
    try:
        from rich.console import Console
        from rich.table import Table
    except ImportError:
        for p in rows:
            flags = ",".join(flags_for(p, args.cpu_warn, args.mem_warn, unexpected))
            print(f"{p.pid:>7} {p.name[:22]:22} {p.cpu:>6} {p.memory_mb:>9} {p.connections:>5}"
                  f" {p.listening} {flags}")
        for item in new_items:
            print(f"NEW LISTENER: {item.process} {item.protocol}/{item.address}:{item.port}")
        return

    console = Console()
    table = Table(title=f"Live Network & Process Monitor - {datetime.now():%H:%M:%S}",
                  caption=f"{total} processes | sorted by {args.sort} | Ctrl+C to quit")
    table.add_column("PID", justify="right", style="cyan")
    table.add_column("Process", style="green")
    table.add_column("User")
    table.add_column("CPU %", justify="right")
    table.add_column("Mem MB", justify="right")
    table.add_column("Conns", justify="right")
    table.add_column("Listening")
    table.add_column("Flags", style="bold")
    for p in rows:
        flags = flags_for(p, args.cpu_warn, args.mem_warn, unexpected)
        style = "red" if "new-listener" in flags else ("yellow" if flags else "")
        table.add_row(str(p.pid), p.name[:24], p.user[:14], f"{p.cpu:.1f}", f"{p.memory_mb:.1f}",
                      str(p.connections), p.listening[:30], " ".join(flags), style=style)
    if not args.once:
        console.clear()
    console.print(table)
    for item in new_items:
        console.print(f"[bold red]NEW LISTENER[/] {item.process} {item.protocol}/{item.address}:{item.port}"
                      " (not in baseline)")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    prime_cpu()
    time.sleep(0.5)  # give cpu_percent a measurement window

    if args.save_baseline:
        try:
            n = save_baseline(args.save_baseline, listeners(snapshot()))
        except OSError as exc:
            print(f"Error: cannot write {args.save_baseline}: {exc}", file=sys.stderr)
            return 2
        print(f"Saved {n} listening ports to {args.save_baseline}")
        return 0

    try:
        baseline = load_baseline(args.baseline) if args.baseline else None
    except BaselineError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    try:
        while True:
            procs = snapshot()
            new_items = new_listeners(listeners(procs), baseline) if baseline is not None else []
            unexpected = {item.process.lower() for item in new_items}
            rows = top(procs, args.sort, args.top, args.filter)
            if args.export:
                try:
                    export(args.export, rows)
                except OSError as exc:
                    print(f"Error: cannot write {args.export}: {exc}", file=sys.stderr)
                    return 2
                print(f"Exported {len(rows)} processes to {args.export}")
                return 0
            render(rows, args, unexpected, new_items, len(procs))
            if args.once:
                return 0
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped by user.", file=sys.stderr)
        return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
