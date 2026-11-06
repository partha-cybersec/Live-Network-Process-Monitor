# Live Network & Process Monitor

![CI](https://github.com/partha-cybersec/Live-Network-Process-Monitor/actions/workflows/ci.yml/badge.svg)

A terminal monitor that shows which processes are using CPU, memory and the network, and can warn
you when a process **listens on a port that was not in a saved baseline**. It is a HIDS-style
learning tool for endpoint visibility, not a full host intrusion detection system: it only checks
while it is running, keeps no history and sends no alerts.

> Companion project to [Suspicious-Connection-Detector](https://github.com/partha-cybersec/Suspicious-Connection-Detector):
> that tool looks at *where* connections go, this one looks at *which process* is doing what.

## Tested results

Run by hand on Windows 11 with Python 3.12 and psutil 7.2.2, as a **standard user**, with about 255
processes running. Linux is covered by the CI checks only.

| Check | Result |
|-------|--------|
| Unit tests | 23 pass, using a fake psutil |
| CPU reading | 98-100% for a process using one full core (psutil reference: 100%) |
| TCP listeners | 13 of 13 matched `netstat -ano` |
| New listener detection | Found a real test listener on `127.0.0.1:45871` and flagged only that process |
| False new listeners | 2 UDP entries from a browser component appeared within seconds of saving a baseline |
| Scan time | About 1.1 seconds per scan |
| Live view cost | About 22% of one CPU core and 27 MB of memory |
| Refresh rate | 3 refreshes in about 12 seconds at the default setting |
| Standard user access | About half of processes showed no user, and 5 showed no memory |

Running as Administrator or with `sudo` was not tested by hand.

## What's new in v2

| v1 | v2 |
|----|----|
| Fixed top-10 by CPU | `--sort cpu/mem/conns/pid`, `--top N`, `--filter name` |
| Called `proc.connections()` for every process (slow, deprecated in psutil 6) | One system-wide socket scan per refresh |
| No warnings | Highlights high CPU / memory with configurable thresholds |
| No listening-port view | Shows listening TCP/UDP ports per process |
| - | **Baseline mode:** save known listeners, then flag new ones |
| - | CSV / JSON export |
| No tests | Unit tests with a fake psutil + GitHub Actions on Windows and Linux |

### Fixed in v2.0.1

Found by running the tool on a real Windows PC:

- A new listener marked every process with the same name. It now marks only the process that owns the port.
- `System Idle Process` appeared at the top with a false `high-cpu` flag (846% in testing). It is now left out.
- The tool flagged itself as `high-cpu` because of its own scan. It no longer does.
- Ports on both IPv4 and IPv6 appeared twice, such as `tcp/445, tcp/445`. They now appear once.
- Long port lists were cut off without notice. The table now shows `+N more`.
- A negative `--interval` crashed the live view, and a negative `--top` was treated as "show all". Both are now rejected.
- Exports had no flags, so baseline findings were lost. They now include a `flags` column.

## Install

```bash
git clone https://github.com/partha-cybersec/Live-Network-Process-Monitor.git
cd Live-Network-Process-Monitor
pip install -r requirements.txt
```

## Usage

```bash
python -m lnpm                          # live view, top 15 by CPU
python -m lnpm --once                   # one snapshot, then exit
python -m lnpm --sort mem --top 25      # biggest memory users
python -m lnpm --sort conns             # most network connections
python -m lnpm --filter powershell      # only matching processes
python -m lnpm --cpu-warn 30 --mem-warn 500
python -m lnpm --export snapshot.csv --top 0    # save every process and exit
```

The old command `python Live_Network_Process_Monitor.py` still works.

`--interval` is the wait between refreshes. Each refresh also includes the scan, so the real gap is longer.

`--export` writes JSON if the file name ends in `.json`, and CSV for any other name. It uses the same
`--top` limit as the table, so add `--top 0` to save every process. An existing file is overwritten.

### Baseline mode (new-listener detection)

A process that opens a new listening port can be a backdoor, a bind shell or an unwanted service, but
most new ports are harmless. Record what is normal, then compare:

```bash
python -m lnpm --save-baseline baseline.json    # run once on a system you trust
python -m lnpm --baseline baseline.json         # rows for new listeners turn red
```

A match is on *process name + protocol + listen address + port*, so a service that moves from
`127.0.0.1` (local only) to `0.0.0.0` (reachable from the network) is flagged too. A missing or
corrupt baseline file stops the tool with a clear error instead of treating everything as normal.

Expect noise from UDP. About three quarters of the entries in test baselines were UDP, and apps such
as browsers open new UDP ports often. Review them, then re-run `--save-baseline` to accept them.

## Columns

| Column | Meaning |
|--------|---------|
| PID / Process / User | Who is running |
| CPU % | Usage since the last refresh, where 100 = one full core, so it can exceed 100 |
| Mem MB | Resident memory (RSS) |
| Conns | Connections with a remote address |
| Listening | `tcp/445` = all interfaces, `tcp/127.0.0.1:8080` = local only. UDP sockets with no remote address also appear here |
| Flags | `high-cpu`, `high-mem`, `new-listener` |

Exports contain these columns plus `status`, and the full port list. They do not contain command lines.

## Limitations

- Read-only: it never kills or blocks anything.
- It only sees what exists at each scan, so a port opened and closed between scans is missed.
- A new-listener check does not detect outbound activity, such as a reverse shell.
- Process names can be faked. Malware using an expected name, protocol, address and port is not detected.
- It does not check executable paths, signatures or hashes.
- On a standard account, some processes show no user or memory. On Linux, sockets owned by other users may have no process and are skipped.
- If the OS refuses the socket scan, the tool shows no network data rather than an error.
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
