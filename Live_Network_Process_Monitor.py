import psutil
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table

console = Console()

def get_detailed_process_info():
    data = []

    for proc in psutil.process_iter(['pid', 'name', 'status', 'cpu_percent', 'memory_info']):
        try:
            conns = proc.connections(kind='inet')
            mem = round(proc.info['memory_info'].rss / (1024 * 1024), 1)
            cpu = proc.info['cpu_percent']
            num_conns = len(conns)

            data.append({
                'pid': proc.info['pid'],
                'name': proc.info['name'][:18],
                'status': proc.info['status'],
                'cpu': cpu,
                'memory': mem,
                'connections': num_conns
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Sort by CPU usage
    return sorted(data, key=lambda x: x['cpu'], reverse=True)[:10]

try:
    # Warm up CPU percent (first call always returns 0)
    for proc in psutil.process_iter():
        proc.cpu_percent()

    while True:
        time.sleep(1)
        info = get_detailed_process_info()

        table = Table(title=f"🔍 Detailed Live Process Monitor — {datetime.now().strftime('%H:%M:%S')}")
        table.add_column("PID", style="cyan")
        table.add_column("Process", style="green")
        table.add_column("Status", style="blue")
        table.add_column("CPU %", justify="right")
        table.add_column("Memory (MB)", justify="right")
        table.add_column("Connections", justify="center")

        for proc in info:
            table.add_row(
                str(proc['pid']),
                proc['name'],
                proc['status'],
                str(proc['cpu']),
                str(proc['memory']),
                str(proc['connections'])
            )

        console.clear()
        console.print(table)

except KeyboardInterrupt:
    print("\n[!] Monitoring stopped by user.")
