"""Collect Python deserialization CVE candidates from free public feeds.

This is intentionally a candidate collector, not an automatic classifier.
It pulls broad records from OSV's PyPI dump and NVD keyword search, then
filters for pickle-adjacent terms so a human can triage the resulting set.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import time
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


OSV_PYPI_ALL_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
NVD_CVES_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

DEFAULT_KEYWORDS = (
    "pickle",
    "pickle.load",
    "pickle.loads",
    "unpickle",
    "cloudpickle",
    "cloudpickle.load",
    "cloudpickle.loads",
    "jsonpickle",
    "dill",
    "dill.load",
    "dill.loads",
    "joblib",
    "joblib.load",
    "marshal",
    "marshal.load",
    "marshal.loads",
    "shelve",
    "allow_pickle",
    "read_pickle",
    "torch.load",
    "yaml.load",
    "unsafe_load",
)


def fetch_json(url: str) -> Any:
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_bytes(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(flatten_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(flatten_text(v) for v in value)
    return str(value)


def matching_terms(record: dict[str, Any], keywords: tuple[str, ...]) -> list[str]:
    text = flatten_text(record).lower()
    return sorted({term for term in keywords if term.lower() in text})


def cve_ids(record: dict[str, Any]) -> list[str]:
    ids = []
    for candidate in [record.get("id"), *record.get("aliases", [])]:
        if isinstance(candidate, str) and candidate.startswith("CVE-"):
            ids.append(candidate)
    return sorted(set(ids))


def summarize_osv(record: dict[str, Any], terms: list[str]) -> dict[str, Any]:
    affected = record.get("affected") or []
    packages = []
    for item in affected:
        package = item.get("package") or {}
        name = package.get("name")
        ecosystem = package.get("ecosystem")
        if name or ecosystem:
            packages.append({"name": name, "ecosystem": ecosystem})

    return {
        "source": "osv-pypi",
        "id": record.get("id"),
        "cve_ids": cve_ids(record),
        "aliases": record.get("aliases", []),
        "summary": record.get("summary"),
        "details": record.get("details"),
        "modified": record.get("modified"),
        "published": record.get("published"),
        "packages": packages,
        "matched_terms": terms,
        "references": record.get("references", []),
    }


def collect_osv(keywords: tuple[str, ...]) -> list[dict[str, Any]]:
    archive = zipfile.ZipFile(io.BytesIO(fetch_bytes(OSV_PYPI_ALL_ZIP)))
    candidates = []
    for name in archive.namelist():
        if not name.endswith(".json"):
            continue
        record = json.loads(archive.read(name).decode("utf-8"))
        terms = matching_terms(record, keywords)
        if terms:
            candidates.append(summarize_osv(record, terms))
    return candidates


def nvd_query_url(keyword: str) -> str:
    params = urllib.parse.urlencode({"keywordSearch": keyword})
    return f"{NVD_CVES_API}?{params}"


def summarize_nvd(vuln: dict[str, Any], keyword: str) -> dict[str, Any]:
    cve = vuln.get("cve", {})
    descriptions = cve.get("descriptions", [])
    description = next(
        (item.get("value") for item in descriptions if item.get("lang") == "en"),
        "",
    )
    weaknesses = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value:
                weaknesses.append(value)

    return {
        "source": "nvd",
        "id": cve.get("id"),
        "cve_ids": [cve.get("id")] if cve.get("id") else [],
        "summary": description,
        "published": cve.get("published"),
        "modified": cve.get("lastModified"),
        "matched_terms": [keyword],
        "cwes": sorted(set(weaknesses)),
        "references": cve.get("references", {}).get("referenceData", []),
    }


def collect_nvd(keywords: tuple[str, ...], sleep_seconds: float) -> list[dict[str, Any]]:
    candidates = []
    for keyword in keywords:
        data = fetch_json(nvd_query_url(keyword))
        for vuln in data.get("vulnerabilities", []):
            candidates.append(summarize_nvd(vuln, keyword))
        time.sleep(sleep_seconds)
    return candidates


def merge_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for record in records:
        keys = record.get("cve_ids") or [record.get("id")]
        key = next((item for item in keys if item), record.get("id"))
        if key not in merged:
            merged[key] = record
            continue
        existing = merged[key]
        existing["source"] = "+".join(sorted(set(existing["source"].split("+") + [record["source"]])))
        existing["matched_terms"] = sorted(
            set(existing.get("matched_terms", [])) | set(record.get("matched_terms", []))
        )
        for field in ("cve_ids", "aliases", "cwes"):
            existing[field] = sorted(set(existing.get(field, [])) | set(record.get(field, [])))
        if not existing.get("summary") and record.get("summary"):
            existing["summary"] = record["summary"]
        if not existing.get("details") and record.get("details"):
            existing["details"] = record["details"]
    return sorted(merged.values(), key=lambda item: (item.get("cve_ids") or [item.get("id")])[0] or "")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def write_summary(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        handle.write("# Deserialization CVE Candidate Feed\n\n")
        handle.write(f"Candidate records: {len(rows)}\n\n")
        handle.write("| ID | Sources | Terms | Summary |\n")
        handle.write("|---|---|---|---|\n")
        for row in rows:
            ids = row.get("cve_ids") or [row.get("id")]
            summary = (row.get("summary") or row.get("details") or "").replace("\n", " ")
            if len(summary) > 180:
                summary = summary[:177] + "..."
            handle.write(
                f"| {', '.join(ids)} | {row.get('source', '')} | "
                f"{', '.join(row.get('matched_terms', []))} | {summary} |\n"
            )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--osv", action="store_true", help="Collect from OSV PyPI all.zip")
    parser.add_argument("--nvd", action="store_true", help="Collect from NVD keyword search")
    parser.add_argument("--sleep", type=float, default=6.0, help="Seconds between NVD keyword calls")
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("cve_db/generated/deserialization-candidates.jsonl"),
    )
    parser.add_argument(
        "--summary",
        type=Path,
        default=Path("cve_db/generated/deserialization-candidates.md"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    use_osv = args.osv or not args.nvd
    use_nvd = args.nvd
    records: list[dict[str, Any]] = []

    if use_osv:
        records.extend(collect_osv(DEFAULT_KEYWORDS))
    if use_nvd:
        records.extend(collect_nvd(DEFAULT_KEYWORDS, args.sleep))

    rows = merge_records(records)
    write_jsonl(args.out, rows)
    write_summary(args.summary, rows)
    print(f"Wrote {len(rows)} candidates to {args.out}")
    print(f"Wrote summary to {args.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
