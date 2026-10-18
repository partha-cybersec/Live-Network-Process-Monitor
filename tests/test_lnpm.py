"""Unit tests with a fake psutil, so results do not depend on the machine."""

import csv
import json
import os
import socket
import tempfile
import unittest
from types import SimpleNamespace

from lnpm.cli import build_parser
from lnpm.core import (
    BaselineError,
    Listener,
    ProcInfo,
    export,
    flags_for,
    listeners,
    load_baseline,
    new_listeners,
    save_baseline,
    snapshot,
    top,
)


class NoSuchProcess(Exception):
    pass


class AccessDenied(Exception):
    pass


def addr(ip, port):
    return SimpleNamespace(ip=ip, port=port)


def sock(pid, status, laddr, raddr=(), kind=socket.SOCK_STREAM):
    return SimpleNamespace(pid=pid, status=status, laddr=laddr, raddr=raddr, type=kind)


def proc(pid, name, cpu, rss_mb, user="DESKTOP\\partha"):
    info = {"pid": pid, "name": name, "username": user, "status": "running",
            "cpu_percent": cpu, "memory_info": SimpleNamespace(rss=rss_mb * 1024 * 1024)}
    return SimpleNamespace(info=info)


def fake_psutil(procs, socks):
    return SimpleNamespace(
        process_iter=lambda attrs=None: iter(procs),
        net_connections=lambda kind: socks,
        CONN_LISTEN="LISTEN", AccessDenied=AccessDenied, NoSuchProcess=NoSuchProcess,
    )


SOCKS = [
    sock(1, "LISTEN", addr("0.0.0.0", 445)),
    sock(1, "ESTABLISHED", addr("10.0.0.2", 5000), addr("8.8.8.8", 443)),
    sock(1, "ESTABLISHED", addr("10.0.0.2", 5001), addr("1.1.1.1", 443)),
    sock(2, "NONE", addr("0.0.0.0", 5353), kind=socket.SOCK_DGRAM),
    sock(None, "TIME_WAIT", addr("10.0.0.2", 5002), addr("1.1.1.1", 443)),
]
PROCS = [proc(1, "svchost.exe", 2.0, 40), proc(2, "chrome.exe", 75.0, 1500),
         proc(3, "idle", 0.0, 1)]


class TestSnapshot(unittest.TestCase):
    def setUp(self):
        self.snap = {p.pid: p for p in snapshot(fake_psutil(PROCS, SOCKS))}

    def test_counts_connections_and_listeners(self):
        self.assertEqual(self.snap[1].connections, 2)
        self.assertEqual(self.snap[1].listening, "tcp/445")
        self.assertEqual(self.snap[1].listen, (("tcp", "0.0.0.0", 445),))
        self.assertEqual(self.snap[2].listening, "udp/5353")
        self.assertEqual(self.snap[3].connections, 0)

    def test_localhost_listener_shows_address(self):
        socks = [sock(5, "LISTEN", addr("127.0.0.1", 8080)), sock(5, "LISTEN", addr("::", 22))]
        snap = snapshot(fake_psutil([proc(5, "srv", 0, 1)], socks))
        self.assertEqual(snap[0].listening, "tcp/22, tcp/127.0.0.1:8080")

    def test_strips_domain_from_user_and_converts_memory(self):
        self.assertEqual(self.snap[1].user, "partha")
        self.assertEqual(self.snap[2].memory_mb, 1500.0)

    def test_access_denied_on_sockets_still_lists_processes(self):
        def denied(kind):
            raise AccessDenied()
        ps = fake_psutil(PROCS, [])
        ps.net_connections = denied
        self.assertEqual(len(snapshot(ps)), 3)


class TestTopAndFlags(unittest.TestCase):
    procs = [ProcInfo(i, n, "u", "running", c, m, k)
             for i, n, c, m, k in [(1, "a", 5, 100, 9), (2, "b", 90, 50, 1), (3, "chrome", 1, 900, 0)]]

    def test_sort_keys(self):
        self.assertEqual([p.pid for p in top(self.procs, "cpu")], [2, 1, 3])
        self.assertEqual([p.pid for p in top(self.procs, "mem")], [3, 1, 2])
        self.assertEqual([p.pid for p in top(self.procs, "conns")], [1, 2, 3])
        self.assertEqual([p.pid for p in top(self.procs, "pid")], [1, 2, 3])

    def test_top_n_and_filter(self):
        self.assertEqual(len(top(self.procs, "cpu", 2)), 2)
        self.assertEqual(len(top(self.procs, "cpu", 0)), 3)
        self.assertEqual([p.name for p in top(self.procs, "cpu", 10, "CHR")], ["chrome"])

    def test_threshold_flags(self):
        self.assertEqual(flags_for(self.procs[1], 50, 1024, set()), ["high-cpu"])
        self.assertEqual(flags_for(self.procs[2], 50, 800, {"chrome"}), ["high-mem", "new-listener"])


class TestBaseline(unittest.TestCase):
    def test_round_trip_and_new_listener_detection(self):
        snap = snapshot(fake_psutil(PROCS, SOCKS))
        current = listeners(snap)
        self.assertEqual(current, {Listener("svchost.exe", "tcp", "0.0.0.0", 445),
                                   Listener("chrome.exe", "udp", "0.0.0.0", 5353)})
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "baseline.json")
            self.assertEqual(save_baseline(path, current), 2)
            base = load_baseline(path)
        self.assertEqual(new_listeners(current, base), [])
        later = current | {Listener("nc.exe", "tcp", "0.0.0.0", 4444)}
        self.assertEqual(new_listeners(later, base), [Listener("nc.exe", "tcp", "0.0.0.0", 4444)])

    def test_baseline_match_is_case_insensitive_on_process(self):
        base = {Listener("SvcHost.exe", "tcp", "0.0.0.0", 445).key()}
        self.assertEqual(new_listeners({Listener("svchost.exe", "tcp", "0.0.0.0", 445)}, base), [])

    def test_rebinding_from_localhost_to_all_interfaces_is_flagged(self):
        base = {Listener("app.exe", "tcp", "127.0.0.1", 8080).key()}
        moved = Listener("app.exe", "tcp", "0.0.0.0", 8080)
        self.assertEqual(new_listeners({moved}, base), [moved])

    def test_missing_and_malformed_baseline_give_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(BaselineError):
                load_baseline(os.path.join(tmp, "nope.json"))
            bad = os.path.join(tmp, "bad.json")
            for content in ["{not json", '{"listeners": [{"process": "x"}]}', "[]"]:
                with open(bad, "w", encoding="utf-8") as fh:
                    fh.write(content)
                with self.assertRaises(BaselineError):
                    load_baseline(bad)


class TestExport(unittest.TestCase):
    def test_csv_and_json(self):
        rows = snapshot(fake_psutil(PROCS, SOCKS))
        with tempfile.TemporaryDirectory() as tmp:
            c, j = os.path.join(tmp, "s.csv"), os.path.join(tmp, "s.json")
            export(c, rows)
            export(j, rows)
            with open(c, newline="", encoding="utf-8") as fh:
                rows_csv = list(csv.DictReader(fh))
            self.assertEqual(len(rows_csv), 3)
            self.assertEqual(rows_csv[0]["listen"], "tcp/445")
            with open(j, encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)[0]["name"], "svchost.exe")


class TestCli(unittest.TestCase):
    def test_defaults(self):
        a = build_parser().parse_args([])
        self.assertEqual((a.sort, a.top, a.interval), ("cpu", 15, 2.0))

    def test_rejects_bad_sort(self):
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["--sort", "disk"])


if __name__ == "__main__":
    unittest.main()
