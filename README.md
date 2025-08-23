# 🔍 Live Network & Process Monitor (Windows Compatible)

A **real-time terminal-based monitoring tool** that displays detailed information about active processes and their network activity on a Windows system — built using Python and `psutil`.

---

## 📌 Features

- 🧠 Tracks live **CPU**, **Memory**, and **Process Status**
- 🌐 Lists number of active **network connections** per process
- ⚡ Sorted by CPU usage (top consumers shown first)
- 🖥️ Terminal UI with `rich` for clear and colorful output
- 💡 Designed for **cybersecurity awareness** and **network forensics**

---

## 🚀 Why This Matters in Cybersecurity

Knowing which processes are active, how much CPU they're using, and whether they maintain suspicious connections is crucial for:

- 🔐 Detecting malware or hidden services
- 🛡️ Investigating performance-based DoS or resource hogging
- 🧪 Reverse engineering & forensic investigations
- 🕵️‍♂️ Understanding endpoint behavior in real time

This tool provides a clean and practical way to monitor your system, much like a lightweight HIDS (Host-Based Intrusion Detection System).

---

## 🛠️ Requirements

- Python 3.8+
- `psutil`
- `rich`

### 📦 Install Requirements

```bash
pip install psutil rich
