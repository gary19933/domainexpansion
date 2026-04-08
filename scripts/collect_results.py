#!/usr/bin/env python3
"""Collect checker node JSON results and convert to CSV format.

Reads JSON output from VPS checker nodes (out/{country}_node_results.json)
and writes CSV files (out/{country}_rows.csv) compatible with merge_summary.py.
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

ROW_FIELDS = ["date", "country", "domain", "http_code", "status", "reason"]

# Map checker_node verdict+signal combinations to CSV status/reason
VERDICT_MAP = {
    "OK": ("OK", "REACHABLE"),
    "ERROR": ("ERROR", "NODE_ERROR"),
}


def map_result_to_row(result: dict, day: str) -> dict[str, str]:
    """Convert a single DomainResult dict to a CSV row dict."""
    domain = result.get("domain", "")
    country = result.get("country", "")
    verdict = result.get("verdict", "SUSPECT")

    dns = result.get("dns", {})
    tls = result.get("tls", {})
    http = result.get("http", {})

    http_code = str(http.get("status_code", 0) or "000")
    if http_code == "0":
        http_code = "000"

    # Map verdict to status
    if verdict == "OK":
        status = "OK"
        reason = "REACHABLE"
    elif verdict == "BAN":
        status = "BAN"
        # Determine the primary reason from layer signals
        dns_signal = dns.get("signal", "")
        tls_signal = tls.get("signal", "")
        http_signal = http.get("signal", "")

        if dns_signal in ("DNS_POISONED", "DNS_NXDOMAIN"):
            reason = dns_signal
        elif tls_signal in ("SNI_BLOCKED", "TLS_MITM"):
            reason = tls_signal
        elif http_signal == "HTTP_BLOCKED":
            reason = "HTTP_BLOCK"
        elif http_signal == "HTTP_REDIRECT_BLOCK":
            reason = "REDIRECT_BLOCK"
        else:
            reason = "LIKELY_BANNED"
    elif verdict == "ERROR":
        status = "ERROR"
        # Try to pick a descriptive reason
        http_signal = http.get("signal", "")
        if http_signal == "HTTP_TIMEOUT":
            reason = "TIMEOUT"
        elif http_signal == "HTTP_ERROR":
            reason = http.get("detail", "NODE_ERROR")[:50]
        else:
            reason = "NODE_ERROR"
    elif verdict == "READY":
        status = "READY"
        reason = "READY_LANDER"
    else:
        status = "SUSPECT"
        http_signal = http.get("signal", "")
        if http_signal == "HTTP_CHALLENGE":
            reason = "CHALLENGE_PAGE"
        elif http_signal == "HTTP_TIMEOUT":
            reason = "TARGET_UNREACHABLE"
        else:
            reason = "UNKNOWN"

    return {
        "date": day,
        "country": country,
        "domain": domain,
        "http_code": http_code,
        "status": status,
        "reason": reason,
    }


def process_node_results(json_path: Path, day: str) -> list[dict[str, str]]:
    """Read a node's JSON results and return CSV rows."""
    if not json_path.exists():
        print(f"Warning: {json_path} not found, skipping", file=sys.stderr)
        return []

    with json_path.open(encoding="utf-8") as f:
        report = json.load(f)

    if not report.get("healthy", True):
        # Node was unhealthy — mark all expected domains as ERROR
        country = report.get("country", "")
        print(
            f"Warning: node {report.get('node_id', '?')} unhealthy: "
            f"{report.get('health_detail', 'unknown')}",
            file=sys.stderr,
        )
        return [{
            "date": day,
            "country": country,
            "domain": "(node_unhealthy)",
            "http_code": "000",
            "status": "ERROR",
            "reason": "NODE_UNHEALTHY",
        }]

    rows: list[dict[str, str]] = []
    for result in report.get("results", []):
        rows.append(map_result_to_row(result, day))

    return rows


def write_csv(rows: list[dict[str, str]], output_path: Path) -> None:
    """Write rows as CSV in the format merge_summary.py expects."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ROW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect VPS node results into CSV")
    parser.add_argument(
        "--date",
        default=datetime.now(timezone.utc).date().isoformat(),
        help="Date stamp for CSV rows (YYYY-MM-DD)",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("out"),
        help="Directory containing node JSON results and for CSV output",
    )
    parser.add_argument(
        "--countries",
        default="my,sg,th",
        help="Comma-separated list of VPS-based countries (default: my,sg,th)",
    )
    args = parser.parse_args()

    out_dir = args.out_dir
    countries = [c.strip() for c in args.countries.split(",") if c.strip()]

    for country in countries:
        json_path = out_dir / f"{country}_node_results.json"
        rows = process_node_results(json_path, args.date)
        if rows:
            csv_path = out_dir / f"{country}_rows.csv"
            write_csv(rows, csv_path)
            ban_count = sum(1 for r in rows if r["status"] == "BAN")
            print(f"{country}: {len(rows)} results, {ban_count} bans → {csv_path}")
        else:
            print(f"{country}: no results from {json_path}")


if __name__ == "__main__":
    main()
