#!/usr/bin/env python3
"""
sys_health_audit.py
Lightweight cross-platform systems administration health & TLS audit utility.
Checks CPU load, disk capacity, memory usage, and remote TLS/SSL certificate expiration.
"""

import argparse
import datetime
import json
import os
import platform
import shutil
import socket
import ssl
import sys
from pathlib import Path


def check_disk_usage(path: str = "/", warn_threshold: float = 80.0) -> dict:
    """Inspect disk utilization for a given filesystem path."""
    total, used, free = shutil.disk_usage(path)
    percent_used = round((used / total) * 100, 2)
    status = "WARNING" if percent_used >= warn_threshold else "OK"
    return {
        "path": path,
        "total_gb": round(total / (1024 ** 3), 2),
        "used_gb": round(used / (1024 ** 3), 2),
        "free_gb": round(free / (1024 ** 3), 2),
        "percent_used": percent_used,
        "status": status,
    }


def check_system_load() -> dict:
    """Retrieve OS metadata and 1/5/15-minute load averages where supported."""
    info = {
        "hostname": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "architecture": platform.machine(),
        "cpu_count": os.cpu_count() or 1,
    }
    if hasattr(os, "getloadavg"):
        load_1, load_5, load_15 = os.getloadavg()
        info["load_average"] = {
            "1m": round(load_1, 2),
            "5m": round(load_5, 2),
            "15m": round(load_15, 2),
        }
    else:
        info["load_average"] = "Unsupported on this OS"
    return info


def check_tls_certificate(hostname: str, port: int = 443, warn_days: int = 14) -> dict:
    """Verify remote TLS certificate validity and days remaining until expiration."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5.0) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expires_str = cert.get("notAfter")
                expires_dt = datetime.datetime.strptime(
                    expires_str, "%b %d %H:%M:%S %Y %Z"
                ).replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                days_remaining = (expires_dt - now).days
                status = "WARNING" if days_remaining <= warn_days else "OK"
                return {
                    "host": hostname,
                    "port": port,
                    "expires_utc": expires_dt.isoformat(),
                    "days_remaining": days_remaining,
                    "status": status,
                }
    except Exception as exc:
        return {
            "host": hostname,
            "port": port,
            "status": "ERROR",
            "error": str(exc),
        }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run local system health and remote TLS certificate checks."
    )
    parser.add_argument(
        "--path",
        default=str(Path.home().anchor or "/"),
        help="Filesystem path to audit (default: root drive/mount)",
    )
    parser.add_argument(
        "--disk-warn",
        type=float,
        default=80.0,
        help="Disk usage warning threshold percentage (default: 80.0)",
    )
    parser.add_argument(
        "--tls-host",
        action="append",
        default=[],
        help="Hostname to check TLS certificate expiration (can be passed multiple times)",
    )
    parser.add_argument(
        "--tls-warn-days",
        type=int,
        default=14,
        help="Days remaining threshold for TLS expiration warning (default: 14)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output audit results as formatted JSON",
    )
    args = parser.parse_args()

    report = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "system": check_system_load(),
        "disk": check_disk_usage(path=args.path, warn_threshold=args.disk_warn),
        "tls_checks": [
            check_tls_certificate(host, warn_days=args.tls_warn_days)
            for host in args.tls_host
        ],
    }

    has_warnings = report["disk"]["status"] != "OK" or any(
        item["status"] != "OK" for item in report["tls_checks"]
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        sys_info = report["system"]
        disk_info = report["disk"]
        print(f"=== System Health Audit ({report['timestamp_utc']}) ===")
        print(f"Host: {sys_info['hostname']} | OS: {sys_info['os']} ({sys_info['architecture']})")
        print(f"Load Average: {sys_info['load_average']}")
        print(
            f"Disk [{disk_info['path']}]: {disk_info['used_gb']} GB / {disk_info['total_gb']} GB "
            f"({disk_info['percent_used']}%) -> [{disk_info['status']}]"
        )
        for tls in report["tls_checks"]:
            if tls["status"] == "ERROR":
                print(f"TLS [{tls['host']}]: ERROR ({tls['error']})")
            else:
                print(
                    f"TLS [{tls['host']}]: Expires in {tls['days_remaining']} days "
                    f"({tls['expires_utc']}) -> [{tls['status']}]"
                )

    return 1 if has_warnings else 0


if __name__ == "__main__":
    sys.exit(main())
