# Live Network & Process Monitor

![CI](https://github.com/partha-cybersec/Live-Network-Process-Monitor/actions/workflows/ci.yml/badge.svg)

A lightweight terminal monitor for **Windows and Linux** that shows which processes are using CPU,
memory and the network right now - and warns you when something starts **listening on a port it
never listened on before**. Think of it as a tiny, read-only HIDS for learning endpoint visibility.

> Companion project to [Suspicious-Connection-Detector](https://github.com/partha-cybersec/Suspicious-Connection-Detector):
> that tool looks at *where* connections go, this one looks at *which process* is doing what.

## What's new in v2

| v1 | v2 |
|----|----|
| Fixed top-10 by CPU | `--sort cpu/mem/conns/pid`, `--top N`, `--filter name` |
| Called `proc.connections()` for every process (slow, deprecated in psutil 6) | One system-wide socket scan per refresh |
| No warnings | Highlights high CPU / memory with configurable thresholds |
| No listening-port view | Shows listening TCP/UDP ports per process |
| - | **Baseline mode:** save known-good listeners, then flag new ones |
| - | CSV / JSON export for reports and evidence |
| No tests | 14 unit tests with a fake psutil + GitHub Actions on Windows and Linux |

## Install

```bash
git clone https://github.com/partha-cybersec/Live-Network-Process-Monitor.git
cd Live-Network-Process-Monitor
pip install -r requirements.txt
```

Run as **Administrator** (Windows) or with `sudo` (Linux) to see sockets and users of every process.

## Usage

```bash
python -m lnpm                          # live view, top 15 by CPU
python -m lnpm --sort mem --top 25      # biggest memory users
python -m lnpm --sort conns             # most network connections
python -m lnpm --filter powershell      # only matching processes
python -m lnpm --cpu-warn 30 --mem-warn 500
python -m lnpm --export snapshot.csv --top 0    # save every process and exit
```

The old command `python Live_Network_Process_Monitor.py` still works.

### Baseline mode (new-listener detection)

A process that suddenly opens a listening port can be a backdoor, a bind shell or an unwanted
service. Record what is normal on a clean machine, then compare:

```bash
python -m lnpm --save-baseline baseline.json    # run once on a known-good system
python -m lnpm --baseline baseline.json         # rows for new listeners turn red
```

A match is on *process name + protocol + listen address + port*, so a service that moves from
`127.0.0.1` (local only) to `0.0.0.0` (reachable from the network) is flagged too. Ephemeral ports
used by some apps will show up as new; review them, then re-run `--save-baseline` to accept them.
A missing or corrupt baseline file stops the tool with a clear error instead of silently
treating everything as normal. Exports contain only the columns shown - no command lines.

## Columns

| Column | Meaning |
|--------|---------|
| PID / Process / User | Who is running |
| CPU % | Usage since the last refresh (can exceed 100 on multi-core systems) |
| Mem MB | Resident memory (RSS) |
| Conns | Active TCP/UDP connections with a remote address |
| Listening | Local ports the process listens on: `tcp/445` = all interfaces, `tcp/127.0.0.1:8080` = local only |
| Flags | `high-cpu`, `high-mem`, `new-listener` |

## Limitations

- Read-only: it never kills or blocks anything.
- Without admin rights some processes show no sockets or user.
- Process names can be faked by malware; check the executable path in Task Manager / `ps` for anything flagged.
- High CPU or a new port is a reason to investigate, not proof of compromise.

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -q
```

Layout: `lnpm/core.py` (snapshot, baseline, export), `lnpm/cli.py` (options and table), `tests/`.

## Author

**Alluri Partha Saradhi Reddy** - [github.com/partha-cybersec](https://github.com/partha-cybersec)
