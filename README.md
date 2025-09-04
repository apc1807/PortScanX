# PortScanX

**PortScanX** is a Python-based asynchronous port scanning tool with **Role-Based Access Control (RBAC)** and **Nmap integration** for vulnerability detection.  
It supports TCP/UDP scans, outputs results in JSON, and allows role-based access for safe testing.

---

## Features

- **Async TCP scanning** using Python `asyncio` and `ncat` for fast port enumeration.
- **UDP scanning** for common ports (53, 123, 161).
- **Vulnerability scanning** with Nmap scripts (`vulners`, `vulscan`).
- **RBAC (Role-Based Access Control)**:
  - **Admin** → full TCP/UDP scan + vuln detection
  - **Analyst** → TCP scan only, no vuln scripts
  - **Viewer** → view previously saved JSON results only
- **JSON output** with timestamps.
- **Verbose mode** for real-time scanning output.

---

## Role-Based Access Control (RBAC)

| Role    | TCP Scan | UDP Scan | Vulnerability Scan | View JSON |
|---------|----------|----------|------------------|-----------|
| Admin   | ✅        | ✅        | ✅                | ✅         |
| Analyst | ✅        | ❌        | ❌                | ✅         |
| Viewer  | ❌        | ❌        | ❌                | ✅         |

---

## Installation

1. **Install Python 3.8+**  
   [Python Download](https://www.python.org/downloads/)

2. **Install Nmap & Ncat**  
   - [Nmap Download](https://nmap.org/download.html)  
   - Ensure `ncat` and `nmap` are added to your system PATH.

3. **Install Python dependencies**
```bash
pip install python-nmap
```
4. Optional Linux tools
```bash
sudo apt install jq    # for pretty-printing JSON
```
Usage 
```bash
python scanner.py <targets> [--start START_PORT] [--end END_PORT] [--timeout TIMEOUT] [--json OUTPUT_FILE] [--verbose]
```
Example
```bash
python portscanx.py 127.0.0.1 --start 20 --end 1024 --timeout 5 --json results --verbose
Enter role (admin/analyst/viewer): admin
```
Targets: comma-separated IP addresses
Start/End ports: port range to scan
Timeout: seconds per port
JSON: base filename for results
Verbose: prints detailed output to terminal

Safe Testing

Only scan your own machine (127.0.0.1) or local network devices.
Viewer role can safely inspect saved JSON without performing scans.
UDP scans are limited to a few common ports for speed.

JSON Output Example
<details> <summary>
  ```json
  {

  "127.0.0.1": {
    "ports": {
      "22": { "service": "SSH" },
      "80": { "service": "HTTP" }
    },
    "vulnerabilities": {
      "tcp": { 
        "22": { "state": "open", "service": "ssh", "version": "OpenSSH 8.9p1" } 
      },
      "udp": { 
        "53": { "state": "open", "service": "dns" } 
      }
    }
  }
}
```
</summary>
