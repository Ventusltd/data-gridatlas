#!/usr/bin/env python3
"""Compare one V8 GeoJSON source with one V9 Parquet partition.

Usage:
  python3 tools/202608301930-fidelity.py PARTITION.parquet ORIGINAL.geojson

The report deliberately separates fidelity from delivery cost. Dropped properties are
reported as a policy surface; they do not by themselves fail geometry fidelity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from typing import Any

import duckdb


def canonical(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("partition", type=Path)
    parser.add_argument("original", type=Path)
    parser.add_argument(
        "--duckdb-runtime-bytes",
        type=int,
        default=int(os.environ.get("DUCKDB_RUNTIME_BYTES", "35700000")),
        help="Estimated browser DuckDB-WASM module + worker bytes.",
    )
    parser.add_argument(
        "--network-mbit",
        type=float,
        default=float(os.environ.get("NETWORK_MBIT", "20")),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    started = time.monotonic()
    if not args.partition.is_file():
        raise FileNotFoundError(args.partition)
    if not args.original.is_file():
        raise FileNotFoundError(args.original)
    if args.network_mbit <= 0:
        raise ValueError("network-mbit must be positive")

    with args.original.open("r", encoding="utf-8") as handle:
        original = json.load(handle)
    features = original.get("features")
    if original.get("type") != "FeatureCollection" or not isinstance(features, list):
        raise ValueError("origin is not a GeoJSON FeatureCollection")

    escaped = str(args.partition).replace("'", "''")
    query = f"""
        SELECT feature_index,
               geometry_json,
               properties_json,
               original_feature_sha256,
               projected_feature_sha256
        FROM read_parquet('{escaped}')
        ORDER BY feature_index
    """
    connection = duckdb.connect(database=":memory:")
    try:
        rows = connection.sql(query).fetchall()
    finally:
        connection.close()

    dropped: set[str] = set()
    added: set[str] = set()
    changed: set[str] = set()
    report: dict[str, Any] = {
        "schema": "data-gridatlas.layer-fidelity.v1",
        "layer": args.partition.stem,
        "partition": str(args.partition),
        "origin": str(args.original),
        "original_features": len(features),
        "partition_rows": len(rows),
        "original_bytes": args.original.stat().st_size,
        "partition_bytes": args.partition.stat().st_size,
        "hash_mismatch": 0,
        "projected_mismatch": 0,
        "coord_mismatch": 0,
    }

    for index, (feature, row) in enumerate(zip(features, rows, strict=False)):
        _, geometry_json, properties_json, original_sha, projected_sha = row
        if sha256_text(canonical(feature)) != original_sha:
            report["hash_mismatch"] += 1

        geometry = json.loads(str(geometry_json))
        properties = json.loads(str(properties_json or "{}"))
        if geometry != feature.get("geometry"):
            report["coord_mismatch"] += 1

        projected = {"type": "Feature", "geometry": geometry, "properties": properties}
        if sha256_text(canonical(projected)) != projected_sha:
            report["projected_mismatch"] += 1

        original_properties = feature.get("properties") or {}
        for key, value in original_properties.items():
            if key not in properties:
                dropped.add(key)
            elif properties[key] != value:
                changed.add(key)
        for key in properties:
            if key not in original_properties:
                added.add(key)

    report["count_match"] = len(features) == len(rows)
    report["missing_partition_rows"] = max(0, len(features) - len(rows))
    report["extra_partition_rows"] = max(0, len(rows) - len(features))
    report["prop_keys_dropped"] = sorted(dropped)
    report["prop_keys_added"] = sorted(added)
    report["prop_keys_changed"] = sorted(changed)
    report["fidelity"] = (
        "PASS"
        if report["count_match"]
        and report["hash_mismatch"] == 0
        and report["projected_mismatch"] == 0
        and report["coord_mismatch"] == 0
        else "FAIL"
    )

    bits_per_second = args.network_mbit * 1_000_000
    report["network_mbit"] = args.network_mbit
    report["duckdb_runtime_bytes"] = args.duckdb_runtime_bytes
    report["delivery_budget_s_at_20mbit"] = round(report["original_bytes"] * 8 / bits_per_second, 1)
    report["on_demand_budget_s_at_20mbit"] = round(
        (args.duckdb_runtime_bytes + report["partition_bytes"]) * 8 / bits_per_second,
        1,
    )
    report["seconds"] = round(time.monotonic() - started, 2)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0 if report["fidelity"] == "PASS" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:  # Fail closed with machine-readable evidence.
        print(
            json.dumps(
                {
                    "schema": "data-gridatlas.layer-fidelity.v1",
                    "fidelity": "ERROR",
                    "error": f"{type(error).__name__}: {error}",
                },
                sort_keys=True,
            )
        )
        raise SystemExit(2)
