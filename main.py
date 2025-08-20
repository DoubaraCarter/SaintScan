import argparse
import asyncio
import json
import csv
from pathlib import Path
from typing import List, Dict, Any

from scanner.core import crawl_and_scan


def export_json(findings: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)


def export_csv(findings: List[Dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for f in findings:
        evidence = f.get("evidence", [])
        ev_text = "; ".join([f"{e.get('url','')}: {e.get('details','')}" for e in evidence])
        rows.append(
            {
                "url": f.get("url", ""),
                "id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "category": f.get("category", ""),
                "cvss": f.get("cvss", ""),
                "description": f.get("description", ""),
                "recommendation": f.get("recommendation", ""),
                "evidence": ev_text,
            }
        )

    fieldnames = [
        "url",
        "id",
        "title",
        "severity",
        "category",
        "cvss",
        "description",
        "recommendation",
        "evidence",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def parse_args():
    p = argparse.ArgumentParser(
        prog="saintscan",
        description="SaintScan – lightweight web vulnerability assessment (authorized use only)",
    )
    p.add_argument("--url", required=True, help="Target root URL (include scheme, e.g., https://example.com)")
    p.add_argument("--depth", type=int, default=1, help="Crawl depth (0 = just the start page)")
    p.add_argument("--max-pages", type=int, default=30, help="Max pages to crawl")
    p.add_argument("--rate", type=int, default=5, help="Max concurrent requests")
    p.add_argument("--json", type=Path, help="Export findings to JSON path")
    p.add_argument("--csv", type=Path, help="Export findings to CSV path")
    return p.parse_args()


def print_summary(findings: List[Dict[str, Any]]) -> None:
    if not findings:
        print("✅ No findings at selected depth.")
        return
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    findings_sorted = sorted(findings, key=lambda f: sev_order.get(str(f.get("severity", "")).lower(), -1), reverse=True)
    for f in findings_sorted:
        sev = str(f.get("severity", "info")).upper()
        print(f"[{sev}] {f.get('title')} — {f.get('url')}")
        if f.get("evidence"):
            first = f["evidence"][0]
            print(f"   ↳ {first.get('url','')} — {first.get('details','')}")
    print(f"\nTotal findings: {len(findings)}")


async def run():
    args = parse_args()
    print(
        f"\n🔍 Starting scan on {args.url} (depth={args.depth}, max_pages={args.max_pages}, rate={args.rate})\n"
    )
    findings = await crawl_and_scan(args.url, depth=args.depth, max_pages=args.max_pages, rate=args.rate)
    print_summary(findings)

    if args.json:
        export_json(findings, args.json)
        print(f"JSON report written to: {args.json}")
    if args.csv:
        export_csv(findings, args.csv)
        print(f"CSV report written to:  {args.csv}")


if __name__ == "__main__":
    asyncio.run(run())
