"""Process snapshots, listening-port baselines and exports."""

from __future__ import annotations

import csv
import json
import os
import socket
from collections import Counter
from dataclasses import asdict, dataclass
from typing import Iterable, Optional

SORT_KEYS = {
    "cpu": lambda p: p.cpu,
    "mem": lambda p: p.memory_mb,
    "conns": lambda p: p.connections,
    "pid": lambda p: -p.pid,  # ascending pid when reverse=True
}


@dataclass
class ProcInfo:
    pid: int
    name: str
    user: str
    status: str
    cpu: float
    memory_mb: float
    connections: int
    listen: tuple = ()  # ((proto, address, port), ...)

    @property
    def listening(self) -> str:
        """Human-readable, e.g. 'tcp/445, tcp/127.0.0.1:8080' (wildcard addresses omitted)."""
        return ", ".join(f"{p}/{n}" if a in WILDCARDS else f"{p}/{a}:{n}" for p, a, n in self.listen)

    def as_row(self) -> dict:
        row = asdict(self)
        row["listen"] = self.listening
        return row


WILDCARDS = {"0.0.0.0", "::", ""}


class BaselineError(Exception):
    pass


@dataclass(frozen=True)
class Listener:
    process: str
    protocol: str
    address: str
    port: int

    def key(self) -> str:
        # Address is part of the key: the same port moving from 127.0.0.1 to 0.0.0.0
        # (local-only -> reachable from the network) is a meaningful change.
        return f"{self.process.lower()}|{self.protocol}|{self.address}|{self.port}"


def _proto(sock_type) -> str:
    return "tcp" if sock_type == socket.SOCK_STREAM else "udp"


def read_sockets(psutil_mod) -> tuple[Counter, dict]:
    """One system-wide socket scan: active-connection counts and listeners per pid."""
    counts: Counter = Counter()
    listening: dict[int, set] = {}
    try:
        conns = psutil_mod.net_connections(kind="inet")
    except psutil_mod.AccessDenied:
        return counts, listening
    for c in conns:
        if c.pid is None:
            continue
        is_listen = (c.status == psutil_mod.CONN_LISTEN) or (
            _proto(c.type) == "udp" and not c.raddr)
        if is_listen and c.laddr:
            listening.setdefault(c.pid, set()).add((_proto(c.type), c.laddr.ip, c.laddr.port))
        elif c.raddr:
            counts[c.pid] += 1
    return counts, listening


def snapshot(psutil_mod=None) -> list[ProcInfo]:
    """Collect one snapshot. Call ``prime_cpu`` once beforehand for real CPU values."""
    if psutil_mod is None:
        import psutil as psutil_mod

    counts, listening = read_sockets(psutil_mod)
    out = []
    attrs = ["pid", "name", "username", "status", "cpu_percent", "memory_info"]
    for proc in psutil_mod.process_iter(attrs):
        info = proc.info
        mem = info.get("memory_info")
        pid = info["pid"]
        ports = tuple(sorted(listening.get(pid, ()), key=lambda x: (x[0], x[2], x[1])))
        out.append(ProcInfo(
            pid=pid,
            name=(info.get("name") or "?"),
            user=(info.get("username") or "-").split("\\")[-1],
            status=info.get("status") or "?",
            cpu=round(info.get("cpu_percent") or 0.0, 1),
            memory_mb=round(mem.rss / (1024 * 1024), 1) if mem else 0.0,
            connections=counts.get(pid, 0),
            listen=ports,
        ))
    return out


def prime_cpu(psutil_mod=None) -> None:
    """First cpu_percent() call always returns 0; call this once at startup."""
    if psutil_mod is None:
        import psutil as psutil_mod
    for proc in psutil_mod.process_iter():
        try:
            proc.cpu_percent(None)
        except (psutil_mod.NoSuchProcess, psutil_mod.AccessDenied):
            pass


def top(procs: Iterable[ProcInfo], sort: str = "cpu", n: int = 10,
        name_filter: Optional[str] = None) -> list[ProcInfo]:
    items = list(procs)
    if name_filter:
        needle = name_filter.lower()
        items = [p for p in items if needle in p.name.lower()]
    items.sort(key=SORT_KEYS[sort], reverse=True)
    return items[:n] if n > 0 else items


def listeners(procs: Iterable[ProcInfo]) -> set[Listener]:
    found = set()
    for p in procs:
        for proto, address, port in p.listen:
            found.add(Listener(p.name, proto, address, port))
    return found


def save_baseline(path: str, current: set[Listener]) -> int:
    data = [asdict(item) for item in sorted(current, key=lambda x: (x.port, x.protocol, x.process))]
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"version": 2, "listeners": data}, fh, indent=2)
    os.replace(tmp, path)  # atomic: never leaves a half-written baseline
    return len(data)


def load_baseline(path: str) -> set[str]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return {Listener(d["process"], d["protocol"], d["address"], int(d["port"])).key()
                for d in data["listeners"]}
    except FileNotFoundError as exc:
        raise BaselineError(f"baseline file not found: {path} (create it with --save-baseline)") from exc
    except (ValueError, KeyError, TypeError) as exc:
        raise BaselineError(f"baseline file {path} is invalid or from an older version; "
                            "re-create it with --save-baseline") from exc


def new_listeners(current: set[Listener], baseline: set[str]) -> list[Listener]:
    """Listeners present now but not in the saved baseline."""
    return sorted((item for item in current if item.key() not in baseline),
                  key=lambda x: (x.port, x.process, x.address))


def flags_for(p: ProcInfo, cpu_warn: float, mem_warn: float,
              unexpected: set[str]) -> list[str]:
    flags = []
    if p.cpu >= cpu_warn:
        flags.append("high-cpu")
    if p.memory_mb >= mem_warn:
        flags.append("high-mem")
    if p.name.lower() in unexpected:
        flags.append("new-listener")
    return flags


def export(path: str, procs: list[ProcInfo]) -> None:
    rows = [p.as_row() for p in procs]
    if path.lower().endswith(".json"):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(rows, fh, indent=2)
        return
    fields = list(ProcInfo.__dataclass_fields__)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
