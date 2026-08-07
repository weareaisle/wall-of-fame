#!/usr/bin/env python3
import json
import re
import sys
import urllib.request
from pathlib import Path

URL = "https://cve.aisle.cloud/hall-of-fame?output=json"
README = Path(__file__).resolve().parent.parent / "README.md"
START = "<!-- CVE-TABLE:START -->"
END = "<!-- CVE-TABLE:END -->"


def cell(value):
    return re.sub(r"[|\n]", " ", str(value)).strip()


def row(i, cve):
    cve_id = cve["cve_id"]
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        sys.exit(f"unexpected CVE id: {cve_id!r}")
    link = f"[{cve_id}](https://www.cve.org/CVERecord?id={cve_id})"
    return f"| {i} | {link} | {cell(cve.get('product', ''))} | {cell(cve.get('published', ''))} |"


def main():
    with urllib.request.urlopen(URL, timeout=60) as resp:
        data = json.load(resp)

    cves = sorted(data["cves"], key=lambda c: (c.get("published", ""), c["cve_id"]))
    table = "\n".join(
        [
            f"{len(cves)} published CVEs.",
            "",
            "| id | CVE | project | published |",
            "|---|---|---|---|",
            *(row(i, c) for i, c in enumerate(cves, 1)),
        ]
    )

    readme = README.read_text()
    before, start, rest = readme.partition(START)
    _, end, after = rest.partition(END)
    if not (start and end):
        sys.exit(f"table markers not found in {README}")

    updated = f"{before}{START}\n{table}\n{END}{after}"
    if updated != readme:
        README.write_text(updated)
        print(f"README updated with {len(cves)} CVEs")
    else:
        print("No changes")


if __name__ == "__main__":
    main()
