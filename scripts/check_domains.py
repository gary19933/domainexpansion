#!/usr/bin/env python3
import argparse
import csv
import os
import re
import subprocess
import tempfile
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

ALLOWED_COUNTRIES = {"my", "sg", "th", "np"}
LOG_FIELDS = ["date", "country", "domain", "http_code", "status"]
ROW_FIELDS = ["date", "country", "domain", "http_code", "status", "reason"]

LABEL_RE = re.compile(r"^[a-z0-9-]{1,63}$")
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

BODY_PREVIEW_LIMIT = 5000
BLOCK_KEYWORDS = [
    "access denied",
    "forbidden",
    "blocked",
    "restricted",
    "not available in your region",
    "this site can’t be reached",
    "this site can't be reached",
]
CHALLENGE_STRONG_KEYWORDS = [
    "attention required",
    "captcha",
    "verify you are human",
    "checking your browser",
    "ddos protection",
]
CHALLENGE_WEAK_KEYWORDS = [
    "cloudflare",
]


@dataclass
class ProbeResult:
    http_code: str
    effective_url: str
    final_hostname: str
    response_received: bool
    stderr: str
    headers: str
    body_preview: str
    title: str
    error_hint: str


@dataclass
class AttemptOutcome:
    kind: str
    reason: str
    code: str


def normalize_hostname(host: str) -> str:
    return (host or "").strip().strip(".").lower()


def is_same_domain_or_www(original_host: str, final_host: str) -> bool:
    # Treat domain and www.<domain> as equivalent forms.
    orig = normalize_hostname(original_host)
    final = normalize_hostname(final_host)
    if not orig or not final:
        return False
    orig_base = orig[4:] if orig.startswith("www.") else orig
    final_base = final[4:] if final.startswith("www.") else final
    return orig_base == final_base


def is_error_redirect_target(effective_url: str, original_domain: str) -> bool:
    if not effective_url:
        return False
    parsed = urlparse(effective_url)
    effective_low = effective_url.lower()
    final_path = (parsed.path or "").lower()

    # Same host can still be unusable when final redirected path is known-bad.
    # Example: /lander or /cgi-sys/defaultwebpage.cgi.
    if "/lander" in final_path or "/lander" in effective_low:
        return True
    if "/cgi-sys/defaultwebpage.cgi" in final_path or "/cgi-sys/defaultwebpage.cgi" in effective_low:
        return True

    # Different final hostname is ERROR. Equivalent host and www.<host> are same.
    final_host = normalize_hostname(parsed.hostname or "")
    return not is_same_domain_or_www(original_domain, final_host)


def has_no_http_response(probe: ProbeResult) -> bool:
    # HTTP 000 must only represent connect-level/network failures where no
    # response headers were received from the server.
    if probe.response_received:
        return False
    if probe.http_code == "000":
        return True
    headers = probe.headers or ""
    return "HTTP/" not in headers


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


def _extract_title(html_preview: str) -> str:
    match = TITLE_RE.search(html_preview)
    if not match:
        return ""
    return " ".join(match.group(1).split())[:300]


def _infer_error_hint(stderr_text: str, http_code: str) -> str:
    text = (stderr_text or "").lower()
    if http_code == "407" or "proxy authentication" in text:
        return "PROXY_AUTH_FAIL"
    if "timed out" in text or "timeout" in text:
        return "TIMEOUT"
    if "ssl" in text or "tls" in text or "certificate" in text:
        return "TLS_FAIL"
    if "could not resolve host" in text:
        return "DNS_FAIL"
    if "connect tunnel failed" in text or "proxy connect aborted" in text:
        return "PROXY_DEAD"
    if "connection refused" in text or "failed to connect" in text:
        return "NETWORK_FAIL"
    return "UNKNOWN"


def run_curl_probe(url: str, proxy_url: str = "") -> ProbeResult:
    with tempfile.NamedTemporaryFile(delete=False) as headers_file, tempfile.NamedTemporaryFile(
        delete=False
    ) as body_file:
        headers_path = headers_file.name
        body_path = body_file.name

    cmd = ["curl"]
    if proxy_url:
        cmd.extend(["--proxy", proxy_url])
    cmd.extend(
        [
            "-L",
            # curl follows redirects with -L, so unusable domains can still end
            # on a 200/301/302 at a bad final destination.
            "--max-time",
            "20",
            "--connect-timeout",
            "8",
            "--max-redirs",
            "5",
            "--compressed",
            "-sS",
            "-A",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "-H",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "-H",
            "Accept-Language: en-US,en;q=0.9",
            "-H",
            "Upgrade-Insecure-Requests: 1",
            "-D",
            headers_path,
            "-o",
            body_path,
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
            timeout=35,
            check=False,
        )
        writeout = (proc.stdout or "").strip()
        stderr_text = (proc.stderr or "").strip()
        http_code = "000"
        effective_url = ""
        final_hostname = ""
        response_received = False
        if "\t" in writeout:
            left, right = writeout.split("\t", 1)
            if re.fullmatch(r"\d{3}", left.strip()):
                http_code = left.strip()
            effective_url = right.strip()
        else:
            match = re.search(r"(\d{3})", writeout)
            if match:
                http_code = match.group(1)

        headers_raw = Path(headers_path).read_text(encoding="utf-8", errors="replace")
        body_preview = Path(body_path).read_text(encoding="utf-8", errors="replace")[
            :BODY_PREVIEW_LIMIT
        ]
        final_hostname = normalize_hostname(urlparse(effective_url).hostname or "")
        response_received = bool(re.fullmatch(r"\d{3}", http_code) and http_code != "000")
        if not response_received and "HTTP/" in headers_raw:
            response_received = True
        title = _extract_title(body_preview)
        error_hint = _infer_error_hint(stderr_text, http_code)
        return ProbeResult(
            http_code=http_code,
            effective_url=effective_url,
            final_hostname=final_hostname,
            response_received=response_received,
            stderr=stderr_text,
            headers=headers_raw,
            body_preview=body_preview,
            title=title,
            error_hint=error_hint,
        )
    except FileNotFoundError:
        return ProbeResult(
            "000", "", "", False, "curl command not found", "", "", "", "CURL_NOT_FOUND"
        )
    except subprocess.TimeoutExpired:
        return ProbeResult("000", "", "", False, "curl timeout", "", "", "", "TIMEOUT")
    except Exception as exc:
        return ProbeResult("000", "", "", False, str(exc), "", "", "", "RUNTIME_ERROR")
    finally:
        for p in (headers_path, body_path):
            try:
                os.remove(p)
            except OSError:
                pass


def is_block_code(http_code: str) -> bool:
    if http_code in {"403", "451"}:
        return True
    if re.fullmatch(r"52\d", http_code) or re.fullmatch(r"53\d", http_code):
        return True
    return False


def _contains_any(text: str, keywords: list[str]) -> bool:
    low = (text or "").lower()
    return any(k in low for k in keywords)


def _domain_match_signal(target_domain: str, effective_url: str) -> bool:
    if not effective_url:
        return False
    host = (urlparse(effective_url).hostname or "").strip(".").lower()
    target = target_domain.strip(".").lower()
    if not host or not target:
        return False
    return host == target or host.endswith("." + target)


def _looks_like_real_page(probe: ProbeResult) -> bool:
    body_title = f"{probe.title}\n{probe.body_preview}".lower()
    if _contains_any(body_title, BLOCK_KEYWORDS) or _contains_any(
        body_title, CHALLENGE_STRONG_KEYWORDS
    ):
        return False
    if len(probe.body_preview.strip()) >= 120:
        return True
    if probe.title.strip():
        return True
    return False


def classify_probe(target_domain: str, probe: ProbeResult) -> AttemptOutcome:
    body_title = f"{probe.title}\n{probe.body_preview}".lower()
    headers_text = (probe.headers or "").lower()
    code = probe.http_code

    if has_no_http_response(probe):
        return AttemptOutcome("error", "NO_HTTP_RESPONSE", "000")

    # curl -L may finish on 200/301 after redirects; unusable redirect targets
    # must still be marked ERROR while preserving the real HTTP code.
    # Rules:
    # - different final hostname => ERROR
    # - same hostname + /lander or /cgi-sys/defaultwebpage.cgi => ERROR
    # - same hostname + normal path redirect (e.g. /th-th) => not ERROR here
    if is_error_redirect_target(probe.effective_url, target_domain):
        return AttemptOutcome("error", "ERROR_REDIRECT", code)

    if _contains_any(body_title, BLOCK_KEYWORDS):
        return AttemptOutcome("block", "BODY_BLOCK", code)

    has_strong_challenge = _contains_any(body_title, CHALLENGE_STRONG_KEYWORDS)
    has_weak_cf = _contains_any(body_title, CHALLENGE_WEAK_KEYWORDS)
    if has_strong_challenge or (
        has_weak_cf
        and ("cf-ray" in headers_text or "server: cloudflare" in headers_text)
        and ("verify you are human" in body_title or "checking your browser" in body_title)
    ):
        return AttemptOutcome("challenge", "CHALLENGE_PAGE", code)

    if is_block_code(code):
        return AttemptOutcome("block", "HTTP_BLOCK", code)

    code_ok = re.fullmatch(r"\d{3}", code) and 200 <= int(code) <= 399
    host_match = _domain_match_signal(target_domain, probe.effective_url)
    page_ok = _looks_like_real_page(probe)

    if code_ok and (host_match or page_ok):
        return AttemptOutcome("success", "REACHABLE", code)

    if code_ok and not host_match:
        return AttemptOutcome("redirect", "REDIRECT_OTHER_DOMAIN", code)

    return AttemptOutcome("suspect", "UNKNOWN", code)


def representative_http_code(codes: list[str]) -> str:
    # Use the most frequent non-000 code across attempts as representative code.
    # This reduces noise from occasional transient failures.
    non_zero = [c for c in codes if c != "000"]
    if not non_zero:
        return "000"
    freq = Counter(non_zero)
    return sorted(freq.items(), key=lambda x: (-x[1], x[0]))[0][0]


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
        for row in rows:
            writer.writerow({k: row[k] for k in LOG_FIELDS})


def check_country(
    country: str,
    list_file: Path,
    day: str,
    proxy_url: str = "",
    workers: int = 2,
    attempts: int = 5,
    control_domain: str = "google.com",
    retries: int = 2,
    control_domains: list[str] | None = None,
) -> list[dict[str, str]]:
    domains = load_domains(list_file)
    if not domains:
        return []

    workers = max(1, workers)
    attempts = max(1, attempts)
    retries = max(1, retries)
    controls = [d for d in (control_domains or []) if d]
    if not controls:
        controls = [control_domain]
    controls = [normalize_domain(x) for x in controls if normalize_domain(x)]
    if not controls:
        controls = ["example.com", "cloudflare.com", "microsoft.com"]
    required_success = attempts // 2 + 1

    def probe_with_retries(target_domain: str, url: str) -> AttemptOutcome:
        last = AttemptOutcome("network", "UNKNOWN", "000")
        for retry_i in range(retries):
            probe = run_curl_probe(url, proxy_url)
            outcome = classify_probe(target_domain, probe)
            last = outcome
            if outcome.kind in {"success", "block", "challenge"}:
                return outcome
            if retry_i < retries - 1:
                time.sleep(0.1)
        return last

    def check_one_domain(domain: str) -> dict[str, str]:
        outcomes: list[AttemptOutcome] = []
        control_ok_count = 0
        control_fail_count = 0

        success_count = 0
        block_count = 0
        challenge_count = 0
        network_count = 0
        redirect_count = 0
        suspect_count = 0
        no_http_response_count = 0
        error_redirect_count = 0

        for attempt_i in range(attempts):
            out = probe_with_retries(domain, f"https://{domain}")
            outcomes.append(out)

            if out.kind == "success":
                success_count += 1
                if out.reason == "REDIRECT_OTHER_DOMAIN":
                    redirect_count += 1
            elif out.kind == "redirect":
                redirect_count += 1
                suspect_count += 1
            elif out.kind == "block":
                block_count += 1
            elif out.kind == "challenge":
                challenge_count += 1
            elif out.kind == "network":
                network_count += 1
            elif out.kind == "error":
                if out.reason == "NO_HTTP_RESPONSE":
                    no_http_response_count += 1
                    network_count += 1
                elif out.reason == "ERROR_REDIRECT":
                    error_redirect_count += 1
                else:
                    suspect_count += 1
            else:
                suspect_count += 1

            if out.kind in {"network", "suspect", "error"}:
                c_domain = controls[attempt_i % len(controls)]
                c_out = probe_with_retries(c_domain, f"https://{c_domain}")

                # Control health is tolerant:
                # any non-000 response is considered path-healthy, unless explicit runtime/proxy-auth failures.
                if c_out.code != "000" and c_out.reason not in {
                    "PROXY_AUTH_FAIL",
                    "CURL_NOT_FOUND",
                    "RUNTIME_ERROR",
                }:
                    control_ok_count += 1
                elif c_out.code == "000" or c_out.reason in {
                    "PROXY_AUTH_FAIL",
                    "CURL_NOT_FOUND",
                    "RUNTIME_ERROR",
                    "PROXY_DEAD",
                    "TIMEOUT",
                    "NETWORK_FAIL",
                    "TLS_FAIL",
                    "UNKNOWN",
                }:
                    control_fail_count += 1
            else:
                control_ok_count += 1

            remaining = attempts - (attempt_i + 1)
            if success_count >= required_success:
                break
            if success_count + remaining < required_success and block_count >= required_success:
                break
            if attempt_i < attempts - 1:
                time.sleep(0.2)

        all_codes = [o.code for o in outcomes]
        final_http_code = representative_http_code(all_codes)

        # Conservative aggregation:
        # - BAN only with strong evidence.
        # - ERROR reserved for no-response, bad redirects, and control-path/proxy failures.
        # - Final classification is based on curl results only; DNS lookup is not
        #   used as a deciding signal because name resolution alone does not tell
        #   us whether the site is actually reachable through the target path.
        # - SUSPECT for ambiguous outcomes.
        if error_redirect_count >= required_success:
            status = "ERROR"
            reason = "ERROR_REDIRECT"
        elif no_http_response_count >= required_success:
            status = "ERROR"
            reason = "NO_HTTP_RESPONSE"
        elif success_count >= required_success:
            status = "OK"
            if redirect_count >= required_success:
                reason = "REDIRECT_OTHER_DOMAIN"
            else:
                reason = "REACHABLE"
        elif block_count >= required_success and control_ok_count >= required_success:
            status = "BAN"
            # Prefer body-level block if seen; otherwise HTTP-level block.
            reason = "BODY_BLOCK" if any(o.reason == "BODY_BLOCK" for o in outcomes) else "HTTP_BLOCK"
        elif control_fail_count >= required_success and network_count >= required_success:
            status = "ERROR"
            reason = "PROXY_DEAD"
        elif any(o.reason == "CURL_NOT_FOUND" for o in outcomes):
            status = "ERROR"
            reason = "CURL_NOT_FOUND"
        elif any(o.reason == "RUNTIME_ERROR" for o in outcomes):
            status = "ERROR"
            reason = "RUNTIME_ERROR"
        elif any(o.reason == "PROXY_AUTH_FAIL" for o in outcomes):
            status = "ERROR"
            reason = "PROXY_AUTH_FAIL"
        elif any(o.reason == "TIMEOUT" for o in outcomes) and control_fail_count >= required_success:
            status = "ERROR"
            reason = "TIMEOUT"
        elif any(o.reason == "TLS_FAIL" for o in outcomes) and control_ok_count >= required_success:
            status = "SUSPECT"
            reason = "TLS_FAIL"
        elif challenge_count >= required_success:
            status = "SUSPECT"
            reason = "CHALLENGE_PAGE"
        elif network_count >= required_success and control_ok_count >= required_success:
            status = "SUSPECT"
            reason = "TARGET_UNREACHABLE"
        else:
            status = "SUSPECT"
            reason = "NETWORK_FAIL" if network_count > 0 else "UNKNOWN"

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
        return list(executor.map(check_one_domain, domains))


def parse_control_domains(cli_value: str) -> list[str]:
    domains = []
    for token in (cli_value or "").split(","):
        d = normalize_domain(token)
        if d:
            domains.append(d)
    return domains


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check domain availability and append records/ban_log.csv."
    )
    parser.add_argument("--country", required=True, choices=sorted(ALLOWED_COUNTRIES))
    parser.add_argument("--list-file", type=Path)
    parser.add_argument("--log-file", type=Path, default=Path("records/ban_log.csv"))
    parser.add_argument("--rows-output", type=Path)
    parser.add_argument("--date", default=datetime.now(timezone.utc).date().isoformat())
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
        "--attempts",
        type=int,
        default=int(os.getenv("CHECK_ATTEMPTS", "5")),
        help="Attempts per domain before aggregation (default: 5).",
    )
    parser.add_argument(
        "--control-domain",
        default=(os.getenv("CONTROL_DOMAIN", "google.com").strip() or "google.com"),
        help="Backward-compatible single control domain (default: google.com).",
    )
    parser.add_argument(
        "--control-domains",
        default=(os.getenv("CONTROL_DOMAINS", "").strip()),
        help="Comma-separated control domains. Example: example.com,cloudflare.com,microsoft.com",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=int(os.getenv("CHECK_RETRIES", "2")),
        help="Retries per individual URL probe (default: 2).",
    )
    args = parser.parse_args()

    list_file = args.list_file or Path("lists") / f"{args.country}.txt"
    rows_output = args.rows_output or Path("out") / f"{args.country}_rows.csv"
    proxy_url = (args.proxy_url or "").strip()

    multi_controls = parse_control_domains(args.control_domains)
    if not multi_controls:
        multi_controls = parse_control_domains(args.control_domain)
    if not multi_controls:
        multi_controls = ["example.com", "cloudflare.com", "microsoft.com"]

    rows = check_country(
        args.country,
        list_file,
        args.date,
        proxy_url,
        args.workers,
        args.attempts,
        args.control_domain,
        args.retries,
        multi_controls,
    )
    write_rows_csv(rows_output, rows)
    if not args.no_append_log:
        append_log(args.log_file, rows)

    print(
        f"country={args.country} domains={len(rows)} "
        f"ban={sum(1 for r in rows if r['status'] == 'BAN')} "
        f"error={sum(1 for r in rows if r['status'] == 'ERROR')} "
        f"suspect={sum(1 for r in rows if r['status'] == 'SUSPECT')}"
    )


if __name__ == "__main__":
    main()
