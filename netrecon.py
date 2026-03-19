#!/usr/bin/env python3

"""
NetRecon - Network Reconnaissance Tool
Author: Arash | GitHub: github.com/arash-123456
License: MIT

A professional network recon tool for SOC analysts and penetration testers.
Performs port scanning, service detection, and banner grabbing.
"""

import socket
import argparse
import json
import sys
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

# ─────────────────────────────────────────────
# Common services dictionary
# ─────────────────────────────────────────────

COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 1433: "MSSQL",
    5900: "VNC", 11211: "Memcached"
}

# Risk levels for common ports
HIGH_RISK_PORTS = {23, 21, 445, 3389, 5900, 11211}
MEDIUM_RISK_PORTS = {80, 8080, 3306, 27017, 6379}

class PortScanner:

    def __init__(self, target: str, timeout: float = 1.0, threads: int = 100):
        self.target = target
        self.timeout = timeout
        self.threads = threads
        self.results = []

    def resolve_target(self) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            ip = socket.gethostbyname(self.target)
            return ip
        except socket.gaierror:
            return None

    def grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Attempt to grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))
            if port in (80, 8080, 8443, 443):
                sock.send(b"HEAD / HTTP/1.0\r\nHost: " + self.target.encode() + b"\r\n\r\n")
            else:
                sock.send(b"\r\n")
            banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
            sock.close()
            return banner[:200] if banner else None
        except Exception:
            return None

    def scan_port(self, ip: str, port: int) -> dict:
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                service = COMMON_SERVICES.get(port, "Unknown")
                banner = self.grab_banner(ip, port)
                risk = "HIGH" if port in HIGH_RISK_PORTS else \
                       "MEDIUM" if port in MEDIUM_RISK_PORTS else "LOW"
                return {
                    "port": port,
                    "state": "OPEN",
                    "service": service,
                    "banner": banner,
                    "risk": risk
                }
        except Exception:
            pass
        return {"port": port, "state": "CLOSED"}

    def scan_range(self, start_port: int, end_port: int) -> list:
        """Scan a range of ports using threading."""
        ip = self.resolve_target()
        if not ip:
            print(f"[ERROR] Cannot resolve host: {self.target}")
            sys.exit(1)

        print(f"\n{'='*60}")
        print(f"  NetRecon v1.0 - Network Reconnaissance Tool")
        print(f"{'='*60}")
        print(f"  Target   : {self.target} ({ip})")
        print(f"  Ports    : {start_port}-{end_port}")
        print(f"  Threads  : {self.threads}")
        print(f"  Started  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*60}\n")

        open_ports = []
        ports = range(start_port, end_port + 1)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port, ip, port): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result["state"] == "OPEN":
                    open_ports.append(result)
                    risk_color = "⚠️ " if result["risk"] == "HIGH" else \
                                 "🟡" if result["risk"] == "MEDIUM" else "🟢"
                    print(f"  {risk_color} PORT {result['port']:5d}/tcp  OPEN  {result['service']:<15} {result.get('banner', '') or ''}")

        open_ports.sort(key=lambda x: x["port"])
        self.results = {
            "target": self.target,
            "ip": ip,
            "scan_time": datetime.now().isoformat(),
            "ports_scanned": end_port - start_port + 1,
            "open_ports": open_ports,
            "summary": {
                "total_open": len(open_ports),
                "high_risk": sum(1 for p in open_ports if p["risk"] == "HIGH"),
                "medium_risk": sum(1 for p in open_ports if p["risk"] == "MEDIUM"),
            }
        }
        return self.results

    def print_summary(self):
        """Print scan summary."""
        s = self.results.get("summary", {})
        print(f"\n{'='*60}")
        print(f"  SCAN SUMMARY")
        print(f"{'='*60}")
        print(f"  Open Ports   : {self.results.get('open_ports', []).__len__()}")
        print(f"  High Risk    : {s.get('high_risk', 0)} ⚠️")
        print(f"  Medium Risk  : {s.get('medium_risk', 0)} 🟡")
        print(f"{'='*60}\n")

    def export_json(self, filename: str):
        """Export results to JSON."""
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        print(f"  [+] Results saved to: {filename}")


def validate_ip_or_host(target: str) -> bool:
    """Validate IP address or hostname."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return len(target) > 0 and "." in target


def main():
    parser = argparse.ArgumentParser(
        description="NetRecon - Network Reconnaissance Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python netrecon.py -t 192.168.1.1
  python netrecon.py -t scanme.nmap.org -p 1-1024
  python netrecon.py -t 10.0.0.1 -p 1-65535 --threads 200 -o report.json
        """
    )
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range (default: 1-1024, format: start-end)")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout in seconds (default: 1.0)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    args = parser.parse_args()

    if not validate_ip_or_host(args.target):
        print("[ERROR] Invalid target IP or hostname.")
        sys.exit(1)

    try:
        start_port, end_port = map(int, args.ports.split("-"))
    except ValueError:
        print("[ERROR] Invalid port range. Use format: start-end (e.g., 1-1024)")
        sys.exit(1)

    scanner = PortScanner(args.target, timeout=args.timeout, threads=args.threads)
    scanner.scan_range(start_port, end_port)
    scanner.print_summary()

    if args.output:
        scanner.export_json(args.output)


if __name__ == "__main__":
    main()
