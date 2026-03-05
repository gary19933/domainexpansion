#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ALLOWED_COUNTRIES = {"my", "sg", "th", "np"}
LOG_FIELDS = ["date", "country", "domain", "http_code", "status"]
ROW_FIELDS = ["date", "country", "domain", "http_code", "status", "reason"]
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


def run_nslookup(domain: str, proxy_url: str = "") -> tuple[int, str]:
    # nslookup itself does not support HTTP/SOCKS proxy.
    # When proxy is configured, use DoH via curl so DNS resolution also goes through proxy.
    if proxy_url:
        cmd = [
            "curl",
            "--proxy",
            proxy_url,
            "--max-time",
            "12",
            "-sS",
            "-H",
            "accept: application/dns-json",
            f"https://cloudflare-dns.com/dns-query?name={domain}&type=A",
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            output = (proc.stdout or "").strip()
            if not output:
                return 1, proc.stderr.strip() or "empty doh response"
            try:
                payload = json.loads(output)
            except json.JSONDecodeError:
                return 1, output
            status = int(payload.get("Status", 1))
            answers = payload.get("Answer", []) or []
            if status == 0 and answers:
                return 0, output
            return 1, output
        except FileNotFoundError:
            return 127, "curl command not found"
        except subprocess.TimeoutExpired:
            return 124, "doh lookup timeout"

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


def run_curl_probe(url: str, proxy_url: str = "") -> tuple[str, str, str]:
    cmd = ["curl"]
    if proxy_url:
        cmd.extend(["--proxy", proxy_url])
    cmd.extend(
        [
            "-L",
            "--max-time",
            "20",
            "--connect-timeout",
            "8",
            "-o",
            os.devnull,
            "-sS",
            "-w",
            "%{http_code}\t%{url_effective}",
            url,
        ]
    )
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        output = (proc.stdout or "").strip()
        err = (proc.stderr or "").strip().lower()
        if proc.returncode != 0 and not err:
            err = f"curl_exit_{proc.returncode}"

        code = "000"
        effective_url = ""
        if "\t" in output:
            left, right = output.split("\t", 1)
            left = left.strip()
            if re.fullmatch(r"\d{3}", left):
                code = left
            effective_url = right.strip()
        else:
            match = re.search(r"(\d{3})", output)
            if match:
                code = match.group(1)
        return code, effective_url, err
    except FileNotFoundError:
        return "000", "", "curl_not_found"
    except subprocess.TimeoutExpired:
        return "000", "", "timeout"


def is_block_code(http_code: str) -> bool:
    if http_code in {"403", "407", "451"}:
        return True
    if re.fullmatch(r"52\d", http_code):
        return True
    if re.fullmatch(r"53\d", http_code):
        return True
    return False


def is_success_code(http_code: str) -> bool:
    if not re.fullmatch(r"\d{3}", http_code):
        return False
    code = int(http_code)
    return 200 <= code <= 399


def matches_target_domain(target_domain: str, effective_url: str) -> bool:
    if not effective_url:
        return False
    host = (urlparse(effective_url).hostname or "").strip(".").lower()
    target = target_domain.strip(".").lower()
    if not host or not target:
        return False
    return host == target or host.endswith("." + target)


def infer_reason(http_code: str, status: str) -> str:
    if status == "OK":
        return "OK"
    if is_block_code(http_code):
        return "PROXY_BLOCK"
    if http_code == "000":
        return "NETWORK_ERROR"
    return "NETWORK_ERROR"


def write_rows_csv(rows_output: Path, rows: list[dict[str, str]]) -> None:
    rows_output.parent.mkdir(parents=True, exist_ok=True)
    with rows_output.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ROW_FIELDS)
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
            for row in rows:
                writer.writerow({k: row[k] for k in LOG_FIELDS})


def check_country(
    country: str,
    list_file: Path,
    day: str,
    proxy_url: str = "",
    workers: int = 2,
    retries: int = 2,
    dns_retries: int = 2,
) -> list[dict[str, str]]:
    domains = load_domains(list_file)
    if not domains:
        return []

    workers = max(1, workers)
    retries = max(1, retries)
    dns_retries = max(1, dns_retries)

    def dns_ok(domain: str) -> bool:
        for attempt in range(dns_retries):
            rc, _ = run_nslookup(domain, proxy_url)
            if rc == 0:
                return True
            if attempt < dns_retries - 1:
                time.sleep(0.2)
        return False

    def probe_with_retries(domain: str, url: str) -> tuple[bool, bool, bool, str]:
        has_success = False
        has_block = False
        has_mismatch = False
        best_code = "000"
        for attempt in range(retries):
            code, effective_url, _ = run_curl_probe(url, proxy_url)
            if best_code == "000" and code != "000":
                best_code = code
            if is_success_code(code):
                if matches_target_domain(domain, effective_url):
                    has_success = True
                    if best_code == "000":
                        best_code = code
                    break
                has_mismatch = True
            if is_block_code(code):
                has_block = True
            if attempt < retries - 1:
                time.sleep(0.2)
        return has_success, has_block, has_mismatch, best_code

    def check_one_domain(domain: str) -> dict[str, str]:
        resolved = dns_ok(domain)
        https_ok, https_block, https_mismatch, https_code = probe_with_retries(
            domain, f"https://{domain}"
        )
        http_ok, http_block, http_mismatch, http_code = probe_with_retries(
            domain, f"http://{domain}"
        )

        final_http_code = next(
            (code for code in (https_code, http_code) if code != "000"),
            "000",
        )

        if https_ok or http_ok:
            status = "OK"
            reason = "OK"
        else:
            status = "BAN"
            if https_block or http_block:
                reason = "PROXY_BLOCK"
            elif https_mismatch or http_mismatch:
                reason = "NETWORK_ERROR"
            elif not resolved:
                reason = "DNS_FAIL"
            else:
                reason = "NETWORK_ERROR"

        return {
            "date": day,
            "country": country,
            "domain": domain,
            "http_code": final_http_code,
            "status": status,
            "reason": reason,
        }

    max_workers = min(workers, len(domains))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        rows = list(executor.map(check_one_domain, domains))
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
    parser.add_argument(
        "--proxy-url",
        default=(os.getenv("RES_PROXY_URL", "").strip()),
        help="Optional proxy URL. Also reads RES_PROXY_URL env var.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=int(os.getenv("CHECK_WORKERS", "2")),
        help="Concurrent workers per country (default: 2 or CHECK_WORKERS env).",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=int(os.getenv("CHECK_RETRIES", "2")),
        help="HTTP retries per protocol (default: 2 or CHECK_RETRIES env).",
    )
    parser.add_argument(
        "--dns-retries",
        type=int,
        default=int(os.getenv("DNS_RETRIES", "2")),
        help="DNS retries per domain (default: 2 or DNS_RETRIES env).",
    )
    args = parser.parse_args()

    list_file = args.list_file or Path("lists") / f"{args.country}.txt"
    rows_output = args.rows_output or Path("out") / f"{args.country}_rows.csv"
    proxy_url = (args.proxy_url or "").strip()

    rows = check_country(
        args.country,
        list_file,
        args.date,
        proxy_url,
        args.workers,
        args.retries,
        args.dns_retries,
    )
    write_rows_csv(rows_output, rows)
    if not args.no_append_log:
        append_log(args.log_file, rows)

    print(
        f"country={args.country} domains={len(rows)} ban={sum(1 for r in rows if r['status'] == 'BAN')}"
    )


if __name__ == "__main__":
    main()
