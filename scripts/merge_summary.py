#!/usr/bin/env python3
import argparse
import csv
import re
from pathlib import Path

COUNTRIES = ["my", "sg", "th", "np"]
LOG_FIELDS = ["date", "country", "domain", "http_code", "status"]
ROW_FIELDS = ["date", "country", "domain", "http_code", "status", "reason"]

COUNTRY_TITLES = {
    "my": "🇲🇾 Malaysia",
    "sg": "🇸🇬 Singapore",
    "th": "🇹🇭 Thailand",
    "np": "🇳🇵 Nepal",
}

def infer_reason(http_code: str, status: str) -> str:
    code = (http_code or "").strip()
    if status == "OK":
        return "REACHABLE"
    if status == "READY":
        return "READY_LANDER"
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


def build_summary_text(rows: list[dict[str, str]], day: str, log_file: Path) -> str:
    ok_by_country: dict[str, list[dict[str, str]]] = {c: [] for c in COUNTRIES}
    ready_by_country: dict[str, list[dict[str, str]]] = {c: [] for c in COUNTRIES}
    error_by_country: dict[str, list[dict[str, str]]] = {c: [] for c in COUNTRIES}

    unique_rows: dict[tuple[str, str], dict[str, str]] = {}
    for row in rows:
        unique_rows[(row["country"], row["domain"])] = row

    for row in unique_rows.values():
        country = row["country"]
        status = row["status"]
        if status == "OK":
            ok_by_country[country].append(row)
        elif status == "READY" or row.get("reason") == "READY_LANDER":
            ready_by_country[country].append(row)
        else:
            error_by_country[country].append(row)

    for country in COUNTRIES:
        ok_by_country[country].sort(key=lambda x: x["domain"])
        ready_by_country[country].sort(key=lambda x: x["domain"])
        error_by_country[country].sort(key=lambda x: x["domain"])

    ok_count = sum(len(ok_by_country[c]) for c in COUNTRIES)
    ready_count = sum(len(ready_by_country[c]) for c in COUNTRIES)
    error_count = sum(len(error_by_country[c]) for c in COUNTRIES)
    total_count = ok_count + ready_count + error_count

    lines = [
        "📊 Daily Website Check Report",
        f"Date: {day}",
        "",
        "————————————",
        "🟢 Reachable",
        "————————————",
        "",
    ]

    has_ok = False
    for country in COUNTRIES:
        items = ok_by_country[country]
        if not items:
            continue
        has_ok = True
        lines.append(f"{COUNTRY_TITLES[country]} ({len(items)})")
        for item in items:
            suffix = ""
            if item.get("reason") == "WAF_BLOCK":
                suffix = f" [{item['http_code']}|WAF]"
            lines.append(f"Domain: {item['domain']}{suffix}")
        lines.append("")
    if not has_ok:
        lines.extend(["(none)", ""])

    lines.extend(
        [
            "————————————",
            f"🟠 Ready ({ready_count})",
            "————————————",
            "",
        ]
    )

    has_ready = False
    for country in COUNTRIES:
        items = ready_by_country[country]
        if not items:
            continue
        has_ready = True
        lines.append(f"{COUNTRY_TITLES[country]} ({len(items)})")
        for item in items:
            lines.append(f"Domain: {item['domain']}")
        lines.append("")
    if not has_ready:
        lines.extend(["(none)", ""])

    lines.extend(
        [
            "————————————",
            f"🔴 Error ({error_count})",
            "————————————",
            "",
        ]
    )

    has_error = False
    for country in COUNTRIES:
        items = error_by_country[country]
        if not items:
            continue
        has_error = True
        lines.append(f"{COUNTRY_TITLES[country]} ({len(items)})")
        for item in items:
            lines.append(
                f"Domain: {item['domain']} [{item['reason']}]"
            )
        lines.append("")
    if not has_error:
        lines.extend(["(none)", ""])

    lines.extend(
        [
            "————————————",
            f"Total: {total_count} | 🟢 {ok_count} | 🟠 {ready_count} | 🔴 {error_count}",
        ]
    )
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
