#!/usr/bin/env python3
"""Build the inventory-only Atlas V9 dependency catalogue."""

import argparse
import hashlib
import json
from pathlib import Path

import duckdb


GENERATION = "202608290904"
BOOTSTRAP = Path("contracts/202608290904-data-gridatlas-bootstrap.json")
FILES = Path("contracts/202608290904-v8-file-ledger.json")
LAYERS = Path("contracts/202608290904-v8-dependency-ledger.json")
QUARANTINE = Path("contracts/202608290904-v8-quarantine.json")
CONSUMER = Path("contracts/202608290904-gridatlas-consumer.json")


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def contract_digest(path: Path):
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest(path)}


def insert_rows(connection, table, columns, rows):
    placeholders = ",".join("?" for _ in columns)
    connection.executemany(
        f"INSERT INTO {table} ({','.join(columns)}) VALUES ({placeholders})",
        [tuple(row[column] for column in columns) for row in rows],
    )


def write_parquet(connection, query, path: Path):
    escaped = str(path).replace("'", "''")
    connection.execute(
        f"COPY ({query}) TO '{escaped}' "
        "(FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000)"
    )


def quarantine_rows(contract):
    rows = []
    for item in contract["classes"]:
        rows.append(
            {
                "kind": "class",
                "item_id": item["id"],
                "path_or_value": item["id"],
                "disposition": item["disposition"],
                "reason": item["reason"],
                "details_json": json.dumps(item, sort_keys=True, separators=(",", ":")),
            }
        )
    for path in contract["unwired_atlas_data"]:
        rows.append(
            {
                "kind": "unwired_atlas_data",
                "item_id": path,
                "path_or_value": f"repd_grid_atlasv8/data/{path}",
                "disposition": "QUARANTINE_UNTIL_PROVEN",
                "reason": "Present in the V8 data directory but absent from the 60-layer runtime configuration.",
                "details_json": "{}",
            }
        )
    for path in contract["root_absolute_dependencies"]:
        rows.append(
            {
                "kind": "root_absolute_dependency",
                "item_id": path,
                "path_or_value": path,
                "disposition": "QUARANTINE_ROOT_ABSOLUTE",
                "reason": "Runtime path crosses the Atlas subtree boundary and is not an approved V9 source.",
                "details_json": "{}",
            }
        )
    for item in contract["known_defects"]:
        rows.append(
            {
                "kind": "known_defect",
                "item_id": item["id"],
                "path_or_value": item.get("configured_path", item["id"]),
                "disposition": item["disposition"],
                "reason": item.get("reason", item["id"]),
                "details_json": json.dumps(item, sort_keys=True, separators=(",", ":")),
            }
        )
    deep_link = contract["deep_link_dependency"]
    rows.append(
        {
            "kind": "deep_link_dependency",
            "item_id": "v8_pipeline_v9",
            "path_or_value": deep_link["path"],
            "disposition": deep_link["disposition"],
            "reason": "Hard-coded V8 deep-link dependency, separate from the 40 configured layer URLs.",
            "details_json": json.dumps(deep_link, sort_keys=True, separators=(",", ":")),
        }
    )
    for value in contract["external_runtime"]:
        rows.append(
            {
                "kind": "external_runtime",
                "item_id": hashlib.sha256(value.encode()).hexdigest()[:16],
                "path_or_value": value,
                "disposition": "APPLICATION_REVIEW",
                "reason": "Application runtime dependency; not data-repository payload.",
                "details_json": "{}",
            }
        )
    return sorted(rows, key=lambda row: (row["kind"], row["item_id"]))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=".")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    repository = Path(args.repository).resolve()
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)

    paths = [repository / item for item in (BOOTSTRAP, FILES, LAYERS, QUARANTINE, CONSUMER)]
    bootstrap, file_contract, layer_contract, quarantine_contract, consumer = map(load, paths)

    if bootstrap["generation"] != GENERATION or bootstrap["classification"] != "INVENTORY_ONLY":
        raise RuntimeError("bootstrap contract identity mismatch")
    if file_contract["summary"] != {"files": 104, "bytes": 39541206}:
        raise RuntimeError("V8 file ledger closure mismatch")
    summary = layer_contract["summary"]
    expected = {
        "groups": 11,
        "layer_entries": 60,
        "unique_configured_urls": 40,
        "preload_layer_entries": 12,
        "unique_preload_sources": 11,
    }
    if any(summary.get(key) != value for key, value in expected.items()):
        raise RuntimeError(f"V8 layer ledger closure mismatch: {summary}")
    if consumer["accepted_release"]["floating_raw_urls"] is not False:
        raise RuntimeError("consumer permits floating raw URLs")

    file_rows = []
    disposition = {
        ".github": "DO_NOT_COPY",
        "scripts": "REFERENCE_ONLY",
        "root": "DO_NOT_COPY",
        "data": "QUARANTINE_UNTIL_PROVEN",
    }
    for row in file_contract["rows"]:
        file_rows.append({**row, "disposition": disposition[row["class"]]})

    layer_rows = layer_contract["rows"]
    q_rows = quarantine_rows(quarantine_contract)

    connection = duckdb.connect()
    connection.execute("PRAGMA threads=1")
    connection.execute("SET preserve_insertion_order=true")
    connection.execute(
        """CREATE TABLE files(
        path VARCHAR NOT NULL, bytes UBIGINT NOT NULL, git_blob_sha1 VARCHAR NOT NULL,
        class VARCHAR NOT NULL, disposition VARCHAR NOT NULL)"""
    )
    file_columns = ["path", "bytes", "git_blob_sha1", "class", "disposition"]
    insert_rows(connection, "files", file_columns, file_rows)

    connection.execute(
        """CREATE TABLE layers(
        group_name VARCHAR NOT NULL, layer_id VARCHAR NOT NULL, label VARCHAR NOT NULL,
        configured_url VARCHAR NOT NULL, resolved_path VARCHAR NOT NULL,
        git_blob_sha1 VARCHAR NOT NULL, bytes UBIGINT NOT NULL, sha256 VARCHAR NOT NULL,
        expected_geometry VARCHAR NOT NULL, preload BOOLEAN NOT NULL, minzoom DOUBLE,
        selected_features UBIGINT NOT NULL, source_authority_state VARCHAR NOT NULL,
        licence_state VARCHAR NOT NULL, refresh_class VARCHAR NOT NULL,
        disposition VARCHAR NOT NULL, publishable BOOLEAN NOT NULL)"""
    )
    layer_columns = [
        "group_name", "layer_id", "label", "configured_url", "resolved_path",
        "git_blob_sha1", "bytes", "sha256", "expected_geometry", "preload",
        "minzoom", "selected_features", "source_authority_state", "licence_state",
        "refresh_class", "disposition", "publishable",
    ]
    normalized_layers = [
        {**row, "group_name": row["group"]} for row in layer_rows
    ]
    insert_rows(connection, "layers", layer_columns, normalized_layers)

    connection.execute(
        """CREATE TABLE quarantine(
        kind VARCHAR NOT NULL, item_id VARCHAR NOT NULL, path_or_value VARCHAR NOT NULL,
        disposition VARCHAR NOT NULL, reason VARCHAR NOT NULL, details_json VARCHAR NOT NULL)"""
    )
    q_columns = ["kind", "item_id", "path_or_value", "disposition", "reason", "details_json"]
    insert_rows(connection, "quarantine", q_columns, q_rows)

    files_path = output / "files.parquet"
    layers_path = output / "layers.parquet"
    quarantine_path = output / "quarantine.parquet"
    write_parquet(connection, "SELECT * FROM files ORDER BY path", files_path)
    write_parquet(connection, "SELECT * FROM layers ORDER BY group_name, layer_id", layers_path)
    write_parquet(connection, "SELECT * FROM quarantine ORDER BY kind, item_id", quarantine_path)

    for table, path, rows in (
        ("files", files_path, len(file_rows)),
        ("layers", layers_path, len(layer_rows)),
        ("quarantine", quarantine_path, len(q_rows)),
    ):
        escaped = str(path).replace("'", "''")
        readback = connection.execute(f"SELECT count(*) FROM read_parquet('{escaped}')").fetchone()[0]
        if readback != rows:
            raise RuntimeError(f"{table} typed readback mismatch: {readback} != {rows}")
    connection.close()

    artifacts = []
    for path, schema, rows in (
        (files_path, "data-gridatlas.files.v1", len(file_rows)),
        (layers_path, "data-gridatlas.layers.v1", len(layer_rows)),
        (quarantine_path, "data-gridatlas.quarantine.v1", len(q_rows)),
    ):
        artifacts.append(
            {"path": path.name, "bytes": path.stat().st_size, "sha256": digest(path), "schema": schema, "rows": rows}
        )

    manifest = {
        "schema": "data-gridatlas.bootstrap-manifest.v1",
        "generation": GENERATION,
        "classification": "BOOTSTRAP_CANDIDATE",
        "v8_oracle": bootstrap["v8_oracle"],
        "contracts": [contract_digest(path.relative_to(repository)) for path in paths],
        "runtime": {"python": "3.12", "duckdb": duckdb.__version__, "threads": 1, "parquet_compression": "ZSTD"},
        "artifacts": artifacts,
        "release": False,
        "current_pointer": False,
        "raw_payloads_copied": 0,
        "v8_untouched": True,
    }
    (output / "manifest.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({"classification": manifest["classification"], "artifacts": artifacts}, sort_keys=True))


if __name__ == "__main__":
    main()
