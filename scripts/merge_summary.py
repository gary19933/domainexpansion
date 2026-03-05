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
        return "OK"
    if code == "000":
        return "NETWORK_ERROR"
    if code in {"403", "407", "451"}:
        return "PROXY_BLOCK"
    if re.fullmatch(r"52\d", code) or re.fullmatch(r"53\d", code):
        return "PROXY_BLOCK"
    return "NETWORK_ERROR"


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
    ok_by_country: dict[str, list[str]] = {c: [] for c in COUNTRIES}
    errors_by_country: dict[str, list[dict[str, str]]] = {c: [] for c in COUNTRIES}

    unique_ok = set()
    unique_error: dict[tuple[str, str], dict[str, str]] = {}
    for row in rows:
        country = row["country"]
        domain = row["domain"]
        if row["status"] == "OK":
            key = (country, domain)
            if key not in unique_ok:
                unique_ok.add(key)
                ok_by_country[country].append(domain)
            continue
        unique_error[(country, domain)] = row

    for row in unique_error.values():
        errors_by_country[row["country"]].append(row)

    for country in COUNTRIES:
        ok_by_country[country].sort()
        errors_by_country[country].sort(key=lambda x: x["domain"])

    ok_count = sum(len(ok_by_country[c]) for c in COUNTRIES)
    err_count = sum(len(errors_by_country[c]) for c in COUNTRIES)
    total_count = ok_count + err_count

    lines = [
        "📊 Daily Website Check Report",
        f"Date: {day}",
        "",
        "————————————",
        f"🟢 Reachable ({ok_count})",
        "————————————",
        "",
    ]

    has_ok = False
    for country in COUNTRIES:
        items = ok_by_country[country]
        if not items:
            continue
        has_ok = True
        lines.append(COUNTRY_TITLES[country])
        for domain in items:
            lines.append(f"Domain: {domain}")
        lines.append("")
    if not has_ok:
        lines.extend(["(none)", ""])

    lines.extend(
        [
            "————————————",
            f"🔴 Errors ({err_count})",
            "————————————",
            "",
        ]
    )

    has_err = False
    for country in COUNTRIES:
        items = errors_by_country[country]
        if not items:
            continue
        has_err = True
        lines.append(COUNTRY_TITLES[country])
        for item in items:
            lines.append(
                f"Domain: {item['domain']} [{item['http_code']} | {item['reason']}]"
            )
        lines.append("")
    if not has_err:
        lines.extend(["(none)", ""])

    lines.extend(
        [
            "————————————",
            f"Total: {total_count}",
            f"🟢 Reachable: {ok_count}",
            f"🔴 Errors: {err_count}",
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
