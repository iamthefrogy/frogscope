#!/usr/bin/env python3
"""Generate mutated copies of an httpx CSV with a known change manifest.

A diff engine can only be trusted if you know the right answer in advance. This
takes a real scan, applies a precise list of mutations, and writes the manifest
alongside — so a test can assert the diff reports exactly those changes and
nothing else.

The mutations deliberately include the cases most likely to produce *false*
change: a fresh OAuth nonce, a rotated resolved IP, and a byte of content
jitter. Those must NOT appear in the diff.

    python3 tools/make_synthetic_runs.py ion.csv --out /tmp/runs --runs 4
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def read_rows(path: Path) -> tuple[list[dict], list[str]]:
    csv.field_size_limit(2**31 - 1)
    with path.open(newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.DictReader(fh)
        return list(reader), list(reader.fieldnames or [])


def write_rows(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def shift_timestamps(rows: list[dict], days: int) -> None:
    for row in rows:
        raw = row.get("timestamp")
        if not raw:
            continue
        try:
            stamp = datetime.fromisoformat(raw)
        except ValueError:
            continue
        row["timestamp"] = (stamp + timedelta(days=days)).isoformat()


def mutate(rows: list[dict], rng: random.Random, run_index: int) -> dict:
    """Apply a known set of mutations. Returns the manifest."""
    manifest: dict = {
        "run_index": run_index,
        "removed_endpoints": [],
        "added_endpoints": [],
        "status_flips": [],
        "waf_removed": [],
        "tech_added": [],
        "cname_changed": [],
        # These three must NOT show up as changes.
        "noise_nonce": [],
        "noise_ip_rotation": [],
        "noise_content_jitter": [],
    }

    by_key: dict[tuple[str, str], list[dict]] = {}
    for row in rows:
        key = (row["host"].strip().rstrip(".").lower(), row["port"])
        by_key.setdefault(key, []).append(row)
    keys = sorted(by_key)

    def pick(n: int, predicate=None) -> list[tuple[str, str]]:
        pool = [k for k in keys if predicate is None or predicate(by_key[k][0])]
        rng.shuffle(pool)
        return pool[:n]

    # ── Real changes ────────────────────────────────────────────────────────

    # Remove five endpoints entirely.
    for key in pick(5):
        for row in by_key[key]:
            row["_drop"] = "1"
        manifest["removed_endpoints"].append(f"{key[0]}:{key[1]}")

    # Add seven new hosts.
    template = by_key[keys[0]][0]
    for i in range(7):
        host = f"newasset{run_index}-{i}.example-added.com"
        fresh = dict(template)
        fresh.update({
            "host": host, "input": host, "port": "443", "scheme": "https",
            "url": f"https://{host}:443", "status_code": "200",
            "title": "Newly discovered service", "cdn_name": "", "cdn_type": "",
            "cdn": "false", "cname": "null", "host_ip": f"203.0.113.{200 + i}",
            "a": json.dumps([f"203.0.113.{200 + i}"]), "tech": "null",
            "cpe": "null", "final_url": "", "chain_status_codes": "null",
            "content_length": "4096", "words": "300", "lines": "40",
            "webserver": "nginx", "time": "120.5ms",
        })
        rows.append(fresh)
        manifest["added_endpoints"].append(f"{host}:443")

    # Flip three statuses from 403 to 200: a WAF block becoming live content.
    for key in pick(3, lambda r: r.get("status_code") == "403"):
        for row in by_key[key]:
            row["status_code"] = "200"
            row["title"] = "Now serving"
        manifest["status_flips"].append(
            {"endpoint": f"{key[0]}:{key[1]}", "from": 403, "to": 200})

    # Strip the CDN from two endpoints: protection removed.
    for key in pick(2, lambda r: r.get("cdn_name") == "cloudflare"):
        for row in by_key[key]:
            row["cdn_name"] = ""
            row["cdn_type"] = ""
            row["cdn"] = "false"
            row["cname"] = "null"
            row["title"] = "Direct origin"
            row["status_code"] = "200"
        manifest["waf_removed"].append(f"{key[0]}:{key[1]}")

    # Add a technology to two endpoints.
    for key in pick(2, lambda r: r.get("tech") not in (None, "", "null")):
        for row in by_key[key]:
            try:
                tech = json.loads(row["tech"])
            except (json.JSONDecodeError, TypeError):
                tech = []
            if "Grafana" not in tech:
                tech.append("Grafana")
            row["tech"] = json.dumps(tech)
        manifest["tech_added"].append(f"{key[0]}:{key[1]}")

    # Re-delegate one CNAME.
    for key in pick(1, lambda r: r.get("cname") not in (None, "", "null")):
        for row in by_key[key]:
            row["cname"] = json.dumps(["moved.elsewhere.example.net"])
        manifest["cname_changed"].append(f"{key[0]}:{key[1]}")

    # ── Noise that must NOT be reported ─────────────────────────────────────

    # A fresh OAuth nonce on every federated login redirect. Left unnormalised,
    # this alone makes every SSO endpoint report as changed on every run.
    for key in pick(6, lambda r: "microsoftonline" in (r.get("final_url") or "")):
        for row in by_key[key]:
            url = row["final_url"]
            row["final_url"] = url.replace(
                "nonce=", f"nonce={rng.randrange(10**12)}X") \
                if "nonce=" in url else f"{url}&nonce={rng.randrange(10**12)}"
        manifest["noise_nonce"].append(f"{key[0]}:{key[1]}")

    # Rotate the single resolved IP while keeping the A-record set identical:
    # round-robin DNS, not a change.
    for key in pick(8, lambda r: r.get("a") not in (None, "", "null")):
        for row in by_key[key]:
            try:
                addresses = json.loads(row["a"])
            except (json.JSONDecodeError, TypeError):
                continue
            if len(addresses) > 1:
                row["host_ip"] = addresses[-1] if row["host_ip"] == addresses[0] \
                    else addresses[0]
                manifest["noise_ip_rotation"].append(f"{key[0]}:{key[1]}")

    # A couple of bytes of render jitter on a dynamic page.
    for key in pick(10, lambda r: (r.get("content_length") or "").isdigit()):
        for row in by_key[key]:
            row["content_length"] = str(int(row["content_length"]) + rng.choice([1, 2, 3]))
        manifest["noise_content_jitter"].append(f"{key[0]}:{key[1]}")

    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("--out", default="synthetic")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--seed", type=int, default=1234)
    parser.add_argument("--flap", action="store_true",
                        help="make one endpoint disappear and return, to "
                             "exercise flapping detection")
    args = parser.parse_args()

    source = Path(args.source)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    base_rows, fields = read_rows(source)
    rng = random.Random(args.seed)

    # Run 1 is the unmodified baseline, only shifted back in time so the
    # chronological order is unambiguous.
    baseline = [dict(r) for r in base_rows]
    shift_timestamps(baseline, -7 * args.runs)
    write_rows(out_dir / "run1.csv", baseline, fields)

    flapper = None
    if args.flap:
        first = baseline[0]
        flapper = f"{first['host'].strip().rstrip('.').lower()}:{first['port']}"

    manifests = [{"run_index": 1, "file": "run1.csv", "baseline": True}]

    for index in range(2, args.runs + 1):
        rows = [dict(r) for r in base_rows]
        shift_timestamps(rows, -7 * (args.runs - index + 1))
        manifest = mutate(rows, rng, index)

        # Alternate the flapper's presence across runs so flap_count climbs.
        if flapper and index % 2 == 0:
            host, port = flapper.rsplit(":", 1)
            rows = [r for r in rows
                    if not (r["host"].strip().rstrip(".").lower() == host
                            and r["port"] == port)]
            manifest["flapper_absent"] = flapper

        rows = [r for r in rows if not r.pop("_drop", None)]
        name = f"run{index}.csv"
        write_rows(out_dir / name, rows, fields)
        manifest["file"] = name
        manifests.append(manifest)

    (out_dir / "manifest.json").write_text(
        json.dumps({"source": str(source), "seed": args.seed,
                    "flapper": flapper, "runs": manifests}, indent=2))

    print(f"wrote {args.runs} runs to {out_dir}")
    for entry in manifests:
        if entry.get("baseline"):
            print(f"  {entry['file']}: baseline, {len(baseline)} rows")
        else:
            print(f"  {entry['file']}: "
                  f"-{len(entry['removed_endpoints'])} endpoints, "
                  f"+{len(entry['added_endpoints'])}, "
                  f"{len(entry['status_flips'])} status flips, "
                  f"{len(entry['waf_removed'])} WAF removed, "
                  f"noise: {len(entry['noise_nonce'])} nonce / "
                  f"{len(entry['noise_ip_rotation'])} IP / "
                  f"{len(entry['noise_content_jitter'])} jitter")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
