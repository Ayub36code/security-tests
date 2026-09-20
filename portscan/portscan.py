#!/usr/bin/env python3
"""
portscan/portscan.py

Multithreaded TCP connect() port scanner with light banner grabbing.

Notes
-----
* Uses full TCP connect() (no raw sockets), so it needs no root.
* It is NOISY — every probe shows up in the target's logs / IDS.
* Only run this against hosts you own or have written permission to test.

Usage
-----
    python -m portscan.portscan --host your-app.com
    python -m portscan.portscan --host your-app.com --ports 1-1024
    python -m portscan.portscan --host your-app.com --ports 22,80,443,8080 --json out.json
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import socket
import sys
from datetime import datetime, timezone

# Well-known / commonly-misconfigured ports worth checking on a web app.
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "microsoft-ds", 465: "smtps", 514: "syslog",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    2049: "nfs", 2181: "zookeeper", 2375: "docker", 2376: "docker-tls",
    3000: "dev-http", 3306: "mysql", 3389: "rdp", 4443: "https-alt",
    5000: "http-alt", 5432: "postgresql", 5601: "kibana", 5672: "amqp",
    5900: "vnc", 5984: "couchdb", 6379: "redis", 7001: "weblogic",
    8000: "http-alt", 8008: "http-alt", 8080: "http-proxy",
    8081: "http-alt", 8443: "https-alt", 8888: "http-alt",
    9000: "http-alt", 9090: "http-alt", 9200: "elasticsearch",
    9300: "elasticsearch", 11211: "memcached", 27017: "mongodb",
    27018: "mongodb", 50000: "sap",
}

# Ports where a plain "HEAD /" gets a useful banner back.
_HTTP_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 9200, 5601}
_TLS_PORTS = {443, 4443, 8443, 993, 995, 465, 636}


def parse_ports(spec: str) -> list[int]:
    """Parse '22,80,443' or '1-1024' or a mix into a sorted list of ints."""
    ports: set[int] = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_s, end_s = chunk.split("-", 1)
            start, end = int(start_s), int(end_s)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))
    return sorted(p for p in ports if 1 <= p <= 65535)


def _grab_banner(sock: socket.socket, port: int) -> str:
    """Best-effort banner grab. Never raises."""
    try:
        sock.settimeout(1.5)
        if port in _TLS_PORTS:
            return "(TLS — banner requires a handshake)"
        if port in _HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        else:
            sock.sendall(b"\r\n")
        data = sock.recv(1024)
        text = data.decode("utf-8", "replace").strip()
        return " | ".join(line for line in text.splitlines() if line.strip())[:200]
    except Exception:
        return ""


def scan_port(
    host: str, port: int, timeout: float = 3.0, banner: bool = True
) -> dict | None:
    """Return a dict describing the port if open, else None."""
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) != 0:
                return None
            result = {
                "port": port,
                "service_guess": COMMON_PORTS.get(port, "unknown"),
                "banner": _grab_banner(sock, port) if banner else "",
            }
            return result
    except (socket.timeout, OSError):
        return None


def scan_ports(
    host: str,
    ports: list[int],
    workers: int = 100,
    timeout: float = 3.0,
    banner: bool = True,
    verbose: bool = True,
) -> dict:
    """Scan a list of ports concurrently. Returns a report dict."""
    open_ports: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(scan_port, host, p, timeout, banner): p for p in ports
        }
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)
                if verbose:
                    label = f"{res['port']:>5}/{res['service_guess']}"
                    extra = f"  -> {res['banner']}" if res["banner"] else ""
                    print(f"[+] OPEN  {label}{extra}", file=sys.stderr)

    open_ports.sort(key=lambda r: r["port"])
    return {
        "scanner": "portscan",
        "host": host,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "ports_scanned": len(ports),
        "open_ports": open_ports,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="TCP connect port scanner")
    ap.add_argument("--host", required=True, help="Hostname or IP to scan")
    ap.add_argument(
        "--ports",
        default=",".join(str(p) for p in sorted(COMMON_PORTS)),
        help="Ports, e.g. '22,80,443' or '1-1024'",
    )
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--workers", type=int, default=100)
    ap.add_argument("--no-banner", action="store_true")
    ap.add_argument("--json", metavar="FILE", help="Write JSON report to FILE")
    args = ap.parse_args()

    ports = parse_ports(args.ports)
    print(f"[*] Scanning {args.host} — {len(ports)} ports, {args.workers} threads\n")

    report = scan_ports(
        args.host, ports, args.workers, args.timeout, not args.no_banner
    )

    print(f"\n[*] {len(report['open_ports'])} open port(s) found.")
    for entry in report["open_ports"]:
        print(f"    {entry['port']:<6} {entry['service_guess']:<16} {entry['banner']}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"\n[*] JSON report written to {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())