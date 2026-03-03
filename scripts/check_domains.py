#!/usr/bin/env python3
import argparse
import csv
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ALLOWED_COUNTRIES = {"my", "sg", "th", "np"}
LOG_FIELDS = ["date", "country", "domain", "http_code", "status"]
LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def is_valid_domain(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if IPV4_RE.fullmatch(host):
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    for label in labels:
        if not LABEL_RE.fullmatch(label):
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    if labels[-1].isdigit():
        return False
    return True


def normalize_domain(raw: str) -> str:
    text = raw.strip().lower()
    if not text or text.startswith("#"):
        return ""
    token = text.split()[0]
    probe = token if "://" in token else f"https://{token}"
    parsed = urlparse(probe)
    host = (parsed.hostname or "").strip(".")
    if host.startswith("www."):
        host = host[4:]
    if not is_valid_domain(host):
        return ""
    return host


def load_domains(list_file: Path) -> list[str]:
    if not list_file.exists():
        return []
    seen = set()
    domains: list[str] = []
    for line in list_file.read_text(encoding="utf-8").splitlines():
        domain = normalize_domain(line)
        if domain and domain not in seen:
            seen.add(domain)
            domains.append(domain)
    return domains


def run_nslookup(domain: str) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            ["nslookup", domain],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
        return proc.returncode, proc.stdout + proc.stderr
    except FileNotFoundError:
        return 127, "nslookup command not found"
    except subprocess.TimeoutExpired:
        return 124, "nslookup timeout"


def run_curl_http_code(domain: str) -> str:
    cmd = [
        "curl",
        "-L",
        "--max-time",
        "20",
        "--connect-timeout",
        "8",
        "-o",
        os.devnull,
        "-sS",
        "-w",
        "%{http_code}",
        f"http://{domain}",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        output = (proc.stdout or "").strip()
        if re.fullmatch(r"\d{3}", output):
            return output
        match = re.search(r"(\d{3})", output)
        if match:
            return match.group(1)
        return "000"
    except FileNotFoundError:
        return "000"
    except subprocess.TimeoutExpired:
        return "000"


def is_ban(http_code: str) -> bool:
    if http_code in {"000", "403", "451"}:
        return True
    if re.fullmatch(r"52\d", http_code):
        return True
    if re.fullmatch(r"53\d", http_code):
        return True
    return False


def write_rows_csv(rows_output: Path, rows: list[dict[str, str]]) -> None:
    rows_output.parent.mkdir(parents=True, exist_ok=True)
    with rows_output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=LOG_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def append_log(log_file: Path, rows: list[dict[str, str]]) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    need_header = (not log_file.exists()) or log_file.stat().st_size == 0
    with log_file.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=LOG_FIELDS)
        if need_header:
            writer.writeheader()
        if rows:
            writer.writerows(rows)


def check_country(country: str, list_file: Path, day: str) -> list[dict[str, str]]:
    domains = load_domains(list_file)
    rows: list[dict[str, str]] = []
    for domain in domains:
        run_nslookup(domain)
        http_code = run_curl_http_code(domain)
        status = "BAN" if is_ban(http_code) else "OK"
        rows.append(
            {
                "date": day,
                "country": country,
                "domain": domain,
                "http_code": http_code,
                "status": status,
            }
        )
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check domain availability and append records/ban_log.csv."
    )
    parser.add_argument("--country", required=True, choices=sorted(ALLOWED_COUNTRIES))
    parser.add_argument("--list-file", type=Path)
    parser.add_argument("--log-file", type=Path, default=Path("records/ban_log.csv"))
    parser.add_argument("--rows-output", type=Path)
    parser.add_argument(
        "--date", default=datetime.now(timezone.utc).date().isoformat()
    )
    parser.add_argument(
        "--no-append-log",
        action="store_true",
        help="Do not append results to log file (useful for matrix jobs).",
    )
    args = parser.parse_args()

    list_file = args.list_file or Path("lists") / f"{args.country}.txt"
    rows_output = args.rows_output or Path("out") / f"{args.country}_rows.csv"

    rows = check_country(args.country, list_file, args.date)
    write_rows_csv(rows_output, rows)
    if not args.no_append_log:
        append_log(args.log_file, rows)

    print(
        f"country={args.country} domains={len(rows)} ban={sum(1 for r in rows if r['status'] == 'BAN')}"
    )


if __name__ == "__main__":
    main()
