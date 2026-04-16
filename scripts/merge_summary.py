#!/usr/bin/env python3
import argparse
import csv
import re
import sys
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


def load_expected_status_map() -> dict[str, str]:
    """Load expected status for all countries from lists/*.txt files."""
    expected: dict[str, str] = {}
    for country in COUNTRIES:
        list_file = LISTS_DIR / f"{country}.txt"
        if not list_file.exists():
            continue
        for domain, status in load_domains_with_expected(list_file):
            expected[domain] = status
    return expected


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
    expected_map = load_expected_status_map()

    # Deduplicate by (country, domain)
    unique_rows: dict[tuple[str, str], dict[str, str]] = {}
    for row in rows:
        unique_rows[(row["country"], row["domain"])] = row

    # Categorize by priority
    alerts: list[dict[str, str]] = []         # Active domains detected as banned/down
    all_clear: list[dict[str, str]] = []      # Active domains confirmed reachable
    confirmed_ban: list[dict[str, str]] = []  # Expected banned, confirmed banned
    unconfirmed_ban: list[dict[str, str]] = []  # Expected banned, but shows OK (recovered?)
    backup_ok: list[dict[str, str]] = []      # Backup domains reachable
    backup_issue: list[dict[str, str]] = []   # Backup domains with issues
    down_domains: list[dict[str, str]] = []   # Domains that are parked/expired
    suspect: list[dict[str, str]] = []        # WAF, challenge, unknown

    for row in unique_rows.values():
        domain = row["domain"]
        status = row["status"]
        reason = row.get("reason", "")
        expected = expected_map.get(domain, "")

        if status == "DOWN" or reason == "DOMAIN_DOWN":
            down_domains.append(row)
        elif expected == "active":
            if status == "OK":
                all_clear.append(row)
            elif status in ("BAN", "ERROR") or reason in ("TARGETED_BLOCK", "WAF_BLOCK"):
                alerts.append(row)
            else:
                suspect.append(row)
        elif expected == "banned":
            if status == "BAN":
                confirmed_ban.append(row)
            elif status == "OK":
                unconfirmed_ban.append(row)
            else:
                confirmed_ban.append(row)
        elif expected == "backup":
            if status == "OK":
                backup_ok.append(row)
            else:
                backup_issue.append(row)
        else:
            # No expected status annotation
            if status == "OK":
                all_clear.append(row)
            elif status == "BAN":
                confirmed_ban.append(row)
            elif status in ("SUSPECT", "ERROR"):
                suspect.append(row)
            else:
                suspect.append(row)

    for lst in [alerts, all_clear, confirmed_ban, unconfirmed_ban,
                backup_ok, backup_issue, down_domains, suspect]:
        lst.sort(key=lambda x: (x["country"], x["domain"]))

    total = len(unique_rows)
    lines = [
        "\U0001f4ca Domain Check Report",
        f"Date: {day}",
        f"Total: {total} domains checked",
        "",
    ]

    # ALERTS — most important, active domains that are banned
    if alerts:
        lines.append("\u2757\u2757 ALERT \u2014 Active Domains Blocked \u2757\u2757")
        lines.append("\u2500" * 30)
        for item in alerts:
            lines.append(f"\u274c {item['domain']} [{item['reason']}]")
        lines.append("")

    # ALL CLEAR — active domains confirmed OK
    lines.append(f"\u2705 Active Domains OK ({len(all_clear)})")
    lines.append("\u2500" * 30)
    if all_clear:
        by_country: dict[str, list[str]] = {}
        for item in all_clear:
            by_country.setdefault(item["country"], []).append(item["domain"])
        for country in COUNTRIES:
            domains = by_country.get(country, [])
            if domains:
                lines.append(f"{COUNTRY_TITLES.get(country, country)} ({len(domains)})")
                for d in domains:
                    lines.append(f"  {d}")
    else:
        lines.append("(none)")
    lines.append("")

    # BACKUP STATUS
    if backup_ok or backup_issue:
        lines.append(f"\U0001f4e6 Backup Domains ({len(backup_ok)} OK / {len(backup_issue)} issues)")
        lines.append("\u2500" * 30)
        for item in backup_ok:
            lines.append(f"  \u2705 {item['domain']}")
        for item in backup_issue:
            lines.append(f"  \u26a0\ufe0f {item['domain']} [{item['reason']}]")
        lines.append("")

    # EXPECTED BANNED — recovered?
    if unconfirmed_ban:
        lines.append(f"\U0001f914 Expected Banned but Reachable ({len(unconfirmed_ban)})")
        lines.append("\u2500" * 30)
        for item in unconfirmed_ban:
            lines.append(f"  \u2753 {item['domain']}")
        lines.append("")

    # CONFIRMED BANNED
    if confirmed_ban:
        lines.append(f"\U0001f6ab Confirmed Banned ({len(confirmed_ban)})")
        lines.append("\u2500" * 30)
        for item in confirmed_ban:
            lines.append(f"  {item['domain']} [{item['reason']}]")
        lines.append("")

    # DOWN — parked/expired
    if down_domains:
        lines.append(f"\u23f8\ufe0f Domain Down/Parked ({len(down_domains)})")
        lines.append("\u2500" * 30)
        for item in down_domains:
            lines.append(f"  {item['domain']} [{item['reason']}]")
        lines.append("")

    # SUSPECT — needs investigation
    if suspect:
        lines.append(f"\u26a0\ufe0f Needs Investigation ({len(suspect)})")
        lines.append("\u2500" * 30)
        for item in suspect:
            lines.append(f"  {item['domain']} [{item['reason']}]")
        lines.append("")

    # Summary line
    lines.append("\u2500" * 30)
    summary_parts = [f"Total: {total}"]
    if alerts:
        summary_parts.append(f"\u274c Alert: {len(alerts)}")
    summary_parts.append(f"\u2705 OK: {len(all_clear)}")
    if backup_ok:
        summary_parts.append(f"\U0001f4e6 Backup OK: {len(backup_ok)}")
    summary_parts.append(f"\U0001f6ab Banned: {len(confirmed_ban)}")
    if down_domains:
        summary_parts.append(f"\u23f8\ufe0f Down: {len(down_domains)}")
    if suspect:
        summary_parts.append(f"\u26a0\ufe0f Suspect: {len(suspect)}")
    lines.append(" | ".join(summary_parts))

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
