#!/usr/bin/env python3
import argparse
import csv
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from classify import load_domains_with_expected

COUNTRIES = ["my", "sg", "th", "np"]
LOG_FIELDS = ["date", "country", "domain", "http_code", "status"]
ROW_FIELDS = ["date", "country", "domain", "http_code", "status", "reason"]

COUNTRY_TITLES = {
    "my": "\U0001f1f2\U0001f1fe Malaysia",
    "sg": "\U0001f1f8\U0001f1ec Singapore",
    "th": "\U0001f1f9\U0001f1ed Thailand",
    "np": "\U0001f1f3\U0001f1f5 Nepal",
}

LISTS_DIR = Path(__file__).resolve().parent.parent / "lists"
RECENTLY_BANNED_DAYS = 3


def infer_reason(http_code: str, status: str) -> str:
    code = (http_code or "").strip()
    if status == "OK":
        return "REACHABLE"
    if status == "READY":
        return "READY_LANDER"
    if status == "DOWN":
        return "DOMAIN_DOWN"
    if status == "ERROR":
        return "ERROR"
    if code == "000":
        return "NETWORK_ERROR"
    if code in {"403", "407", "451"}:
        return "PROXY_BLOCK"
    if re.fullmatch(r"52\d", code) or re.fullmatch(r"53\d", code):
        return "PROXY_BLOCK"
    return "LIKELY_BANNED"


def load_country_rows(out_dir: Path, day: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for country in COUNTRIES:
        path = out_dir / f"{country}_rows.csv"
        if not path.exists():
            continue
        with path.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            normalized: list[dict[str, str]] = []
            for row in reader:
                item = {
                    "date": (row.get("date") or day).strip() or day,
                    "country": (row.get("country") or country).strip() or country,
                    "domain": (row.get("domain") or "").strip(),
                    "http_code": (row.get("http_code") or "000").strip() or "000",
                    "status": (row.get("status") or "BAN").strip() or "BAN",
                    "reason": (
                        (row.get("reason") or "").strip()
                        or infer_reason(
                            (row.get("http_code") or "000").strip() or "000",
                            (row.get("status") or "BAN").strip() or "BAN",
                        )
                    ),
                }
                normalized.append(item)
                rows.append(item)
        write_country_rows(path, normalized)
    return rows


def write_country_rows(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=ROW_FIELDS)
        writer.writeheader()
        writer.writerows(rows)


def append_ban_log(log_file: Path, rows: list[dict[str, str]]) -> None:
    log_file.parent.mkdir(parents=True, exist_ok=True)
    need_header = (not log_file.exists()) or log_file.stat().st_size == 0
    with log_file.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=LOG_FIELDS)
        if need_header:
            writer.writeheader()
        for row in rows:
            writer.writerow({k: row[k] for k in LOG_FIELDS})


def get_recently_banned(
    log_file: Path,
    error: dict[str, list[str]],
    day: str,
) -> dict[str, list[str]]:
    today = datetime.strptime(day, "%Y-%m-%d").date()
    cutoff = today - timedelta(days=RECENTLY_BANNED_DAYS)

    # Find the earliest date each (country, domain) appeared as non-OK in the log
    first_banned: dict[tuple[str, str], object] = {}
    if log_file.exists():
        with log_file.open("r", newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if (row.get("status") or "").strip() == "OK":
                    continue
                key = (
                    (row.get("country") or "").strip(),
                    (row.get("domain") or "").strip(),
                )
                try:
                    d = datetime.strptime((row.get("date") or "").strip(), "%Y-%m-%d").date()
                except ValueError:
                    continue
                if key not in first_banned or d < first_banned[key]:
                    first_banned[key] = d

    recently: dict[str, list[str]] = {c: [] for c in COUNTRIES}
    for country in COUNTRIES:
        for domain in error[country]:
            key = (country, domain)
            fd = first_banned.get(key)
            if fd is not None and fd >= cutoff:
                recently[country].append(domain)
        recently[country].sort()

    return recently


def build_summary_text(rows: list[dict[str, str]], day: str, log_file: Path) -> str:
    # Deduplicate by (country, domain)
    unique_rows: dict[tuple[str, str], dict[str, str]] = {}
    for row in rows:
        unique_rows[(row["country"], row["domain"])] = row

    reachable: dict[str, list[str]] = {c: [] for c in COUNTRIES}
    error: dict[str, list[str]] = {c: [] for c in COUNTRIES}

    for (country, domain), row in unique_rows.items():
        if row["status"] == "OK":
            reachable[country].append(domain)
        else:
            error[country].append(domain)

    for c in COUNTRIES:
        reachable[c].sort()
        error[c].sort()

    total_reachable = sum(len(v) for v in reachable.values())
    total_error = sum(len(v) for v in error.values())
    total = total_reachable + total_error

    recently_banned = get_recently_banned(log_file, error, day)
    total_recently = sum(len(v) for v in recently_banned.values())

    lines = [
        "\U0001f4ca Daily Domain Check Report",
        f"Date: {day}",
        "",
        "—" * 6,
        f"\U0001f7e2 Active ({total_reachable})",
        "—" * 6,
        "",
    ]

    for country in COUNTRIES:
        domains = reachable[country]
        if not domains:
            continue
        lines.append(f"{COUNTRY_TITLES[country]} ({len(domains)})")
        for d in domains:
            lines.append(f"Domain: {d}")
        lines.append("")

    lines += [
        "—" * 6,
        f"\U0001f534 Banned ({total_error})",
        "—" * 6,
        "",
    ]

    for country in COUNTRIES:
        domains = error[country]
        if not domains:
            continue
        lines.append(f"{COUNTRY_TITLES[country]} ({len(domains)})")
        for d in domains:
            lines.append(f"Domain: {d}")
        lines.append("")

    if total_recently > 0:
        lines += [
            "—" * 6,
            f"\U0001f195 Recently Banned ({total_recently})",
            "—" * 6,
            "",
        ]
        for country in COUNTRIES:
            domains = recently_banned[country]
            if not domains:
                continue
            lines.append(f"{COUNTRY_TITLES[country]} ({len(domains)})")
            for d in domains:
                lines.append(f"Domain: {d}")
            lines.append("")

    lines += [
        "—" * 6,
        f"Total: {total}",
        f"\U0001f7e2 Active: {total_reachable}",
        f"\U0001f534 Banned: {total_error}",
    ]

    text = "\n".join(lines)
    return text if len(text) <= 3900 else text[:3860] + "\n...(truncated)"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Merge out/*_rows.csv, append records/ban_log.csv and build Telegram text."
    )
    parser.add_argument("--date", required=True, help="Run date in YYYY-MM-DD.")
    parser.add_argument("--out-dir", type=Path, default=Path("out"))
    parser.add_argument("--log-file", type=Path, default=Path("records/ban_log.csv"))
    parser.add_argument(
        "--summary-file", type=Path, default=Path("out/telegram_daily_summary.txt")
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    rows = load_country_rows(args.out_dir, args.date)
    append_ban_log(args.log_file, rows)
    summary = build_summary_text(rows, args.date, args.log_file)
    args.summary_file.parent.mkdir(parents=True, exist_ok=True)
    args.summary_file.write_text(summary, encoding="utf-8")
    print(f"rows={len(rows)} summary_file={args.summary_file}")


if __name__ == "__main__":
    main()
