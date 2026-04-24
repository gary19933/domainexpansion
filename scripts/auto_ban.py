#!/usr/bin/env python3
"""Read today's checker results and record confirmed BAN domains to records/banned_domains.csv."""
import argparse
import csv
import json
from pathlib import Path

COUNTRIES = ["my", "sg", "th", "np"]
BANNED_FIELDS = ["date_banned", "country", "domain"]


def load_banned(banned_file: Path) -> set[tuple[str, str]]:
    if not banned_file.exists():
        return set()
    with banned_file.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return {(row["country"], row["domain"]) for row in reader}


def append_banned(banned_file: Path, new_entries: list[dict]) -> None:
    banned_file.parent.mkdir(parents=True, exist_ok=True)
    need_header = not banned_file.exists() or banned_file.stat().st_size == 0
    with banned_file.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=BANNED_FIELDS)
        if need_header:
            writer.writeheader()
        writer.writerows(new_entries)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out-dir", type=Path, default=Path("out"))
    parser.add_argument("--banned-file", type=Path, default=Path("records/banned_domains.csv"))
    parser.add_argument("--date", required=True)
    args = parser.parse_args()

    existing = load_banned(args.banned_file)
    new_entries = []

    for country in COUNTRIES:
        results_file = args.out_dir / f"{country}_node_results.json"
        if not results_file.exists():
            continue
        with results_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
        for result in data.get("results", []):
            domain = result.get("domain", "").strip()
            verdict = result.get("verdict", "").strip()
            if verdict == "BAN" and domain and (country, domain) not in existing:
                new_entries.append({
                    "date_banned": args.date,
                    "country": country,
                    "domain": domain,
                })
                existing.add((country, domain))

    if new_entries:
        append_banned(args.banned_file, new_entries)
        print(f"Recorded {len(new_entries)} newly banned domains")
    else:
        print("No new banned domains")


if __name__ == "__main__":
    main()
