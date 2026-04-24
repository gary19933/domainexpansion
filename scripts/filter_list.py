#!/usr/bin/env python3
"""Filter a domain list by removing domains already confirmed as banned."""
import argparse
import csv
from pathlib import Path


def load_banned_for_country(banned_file: Path, country: str) -> set[str]:
    if not banned_file.exists():
        return set()
    with banned_file.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return {row["domain"] for row in reader if row.get("country") == country}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--list", type=Path, required=True)
    parser.add_argument("--banned-file", type=Path, default=Path("records/banned_domains.csv"))
    parser.add_argument("--country", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    banned = load_banned_for_country(args.banned_file, args.country)

    active = []
    skipped = 0
    with args.list.open("r", encoding="utf-8") as f:
        for line in f:
            domain = line.strip()
            if not domain:
                continue
            if domain in banned:
                skipped += 1
            else:
                active.append(domain)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        f.write("\n".join(active) + "\n" if active else "")

    print(f"country={args.country} active={len(active)} skipped_banned={skipped}")


if __name__ == "__main__":
    main()
