#!/usr/bin/env python3
"""Independent verifier for the inventory-only data-gridatlas bootstrap."""

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path, PurePosixPath


GENERATION = "202608290904"
CONTRACT_PATHS = {
    "bootstrap": "contracts/202608290904-data-gridatlas-bootstrap.json",
    "consumer": "contracts/202608290904-gridatlas-consumer.json",
    "layers": "contracts/202608290904-v8-dependency-ledger.json",
    "files": "contracts/202608290904-v8-file-ledger.json",
    "quarantine": "contracts/202608290904-v8-quarantine.json",
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)


def digest(path: Path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def safe_relative(value):
    path = PurePosixPath(value)
    return not path.is_absolute() and ".." not in path.parts and value not in {"", "."}


def inventory(repository: Path):
    contracts = {name: load(repository / path) for name, path in CONTRACT_PATHS.items()}
    bootstrap = contracts["bootstrap"]
    files = contracts["files"]
    layers = contracts["layers"]
    quarantine = contracts["quarantine"]
    consumer = contracts["consumer"]

    require(bootstrap["schema"] == "data-gridatlas.bootstrap-contract.v1", "bootstrap schema mismatch")
    require(bootstrap["generation"] == GENERATION, "bootstrap generation mismatch")
    require(bootstrap["classification"] == "INVENTORY_ONLY", "bootstrap is not inventory-only")
    require(bootstrap["v8_oracle"]["v8_untouched"] is True, "V8 immutability gate missing")
    require(bootstrap["promotion"] == {
        "release_allowed": False,
        "current_pointer_allowed": False,
        "pages_publication_allowed": False,
        "raw_dumps_allowed": False,
        "next_gate": "verified bootstrap artifact and exact consumer contract",
    }, "bootstrap promotion boundary mismatch")

    file_rows = files["rows"]
    require(files["schema"] == "data-gridatlas.v8-file-ledger.v1", "file ledger schema mismatch")
    require(len(file_rows) == 104, f"expected 104 V8 files, found {len(file_rows)}")
    require(sum(row["bytes"] for row in file_rows) == 39541206, "V8 subtree byte closure mismatch")
    require(len({row["path"] for row in file_rows}) == len(file_rows), "duplicate V8 file path")
    require(all(safe_relative(row["path"]) for row in file_rows), "unsafe V8 file path")
    require(all(HEX40.fullmatch(row["git_blob_sha1"]) for row in file_rows), "invalid V8 blob OID")
    class_summary = {
        key: {
            "files": sum(row["class"] == key for row in file_rows),
            "bytes": sum(row["bytes"] for row in file_rows if row["class"] == key),
        }
        for key in (".github", "data", "root", "scripts")
    }
    require(class_summary == bootstrap["v8_oracle"]["class_summary"], f"class closure mismatch: {class_summary}")
    for row in file_rows:
        expected_class = row["path"].split("/", 1)[0] if "/" in row["path"] else "root"
        require(row["class"] == expected_class, f"bad class for {row['path']}")

    layer_rows = layers["rows"]
    require(layers["schema"] == "data-gridatlas.v8-dependency-ledger.v1", "layer ledger schema mismatch")
    require(len(layer_rows) == 60, f"expected 60 layer entries, found {len(layer_rows)}")
    require(len({row["layer_id"] for row in layer_rows}) == 60, "duplicate layer id")
    require(len({row["group"] for row in layer_rows}) == 11, "group closure mismatch")
    require(len({row["configured_url"] for row in layer_rows}) == 40, "URL closure mismatch")
    require(sum(row["preload"] for row in layer_rows) == 12, "preload layer closure mismatch")
    require(len({row["resolved_path"] for row in layer_rows if row["preload"]}) == 11, "preload source closure mismatch")
    require(all(safe_relative(row["resolved_path"]) for row in layer_rows), "unsafe resolved path")
    require(all(HEX40.fullmatch(row["git_blob_sha1"]) for row in layer_rows), "invalid layer blob OID")
    require(all(HEX64.fullmatch(row["sha256"]) for row in layer_rows), "invalid layer SHA-256")
    require(all(row["publishable"] is False for row in layer_rows), "bootstrap layer marked publishable")
    require(all(row["source_authority_state"] == "UNVERIFIED" for row in layer_rows), "unverified authority state lost")
    require(all(row["licence_state"] == "UNVERIFIED" for row in layer_rows), "unverified licence state lost")

    by_url = {}
    for row in layer_rows:
        identity = tuple(row[key] for key in ("resolved_path", "git_blob_sha1", "bytes", "sha256"))
        if row["configured_url"] in by_url:
            require(by_url[row["configured_url"]] == identity, f"inconsistent source identity for {row['configured_url']}")
        by_url[row["configured_url"]] = identity

    local_paths = {f"repd_grid_atlasv8/{row['path']}": row for row in file_rows}
    wired_local = {row["resolved_path"] for row in layer_rows if row["configured_url"].startswith("data/")}
    require(len(wired_local) == 33, "wired local source closure mismatch")
    for row in layer_rows:
        if row["resolved_path"].startswith("repd_grid_atlasv8/"):
            source = local_paths.get(row["resolved_path"])
            require(source is not None, f"configured local path missing from file ledger: {row['resolved_path']}")
            require(source["git_blob_sha1"] == row["git_blob_sha1"], f"blob mismatch: {row['resolved_path']}")
            require(source["bytes"] == row["bytes"], f"byte mismatch: {row['resolved_path']}")

    unwired = quarantine["unwired_atlas_data"]
    require(len(unwired) == 16 and len(set(unwired)) == 16, "unwired quarantine closure mismatch")
    for name in unwired:
        path = f"repd_grid_atlasv8/data/{name}"
        require(path in local_paths, f"unwired file missing from oracle ledger: {name}")
        require(path not in wired_local, f"unwired file is actually configured: {name}")
    root_urls = quarantine["root_absolute_dependencies"]
    require(len(root_urls) == 7 and set(root_urls) == {row["configured_url"] for row in layer_rows if row["configured_url"].startswith("/")}, "root dependency closure mismatch")
    metro = next(item for item in quarantine["known_defects"] if item["id"] == "metro_tram_geometry_mismatch")
    require(metro["disposition"] == "DO_NOT_SILENTLY_SWAP", "metro/tram defect not quarantined")
    for layer_id in metro["layer_ids"]:
        row = next(row for row in layer_rows if row["layer_id"] == layer_id)
        require(row["disposition"] == "QUARANTINE_GEOMETRY_MISMATCH", f"{layer_id} is not quarantined")

    require(consumer["accepted_release"]["immutable"] is True, "consumer permits mutable releases")
    require(consumer["accepted_release"]["floating_raw_urls"] is False, "consumer permits floating raw URLs")
    require(consumer["truth"]["proximity_establishes_identity"] is False, "consumer truth contract drift")

    return contracts


def verify_repository(repository: Path, bootstrap):
    command = ["git", "-C", str(repository), "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    files = sorted(filter(None, subprocess.check_output(command).decode().split("\0")))
    expected = sorted(bootstrap["source_boundary"]["expected_tracked_files"])
    require(files == expected, f"source allowlist mismatch: expected={expected}, observed={files}")
    total = 0
    forbidden_suffixes = tuple(bootstrap["source_boundary"]["forbidden_suffixes"])
    forbidden_roots = set(bootstrap["source_boundary"]["forbidden_roots"])
    for value in files:
        path = repository / value
        require(path.is_file() and not path.is_symlink(), f"non-regular source file: {value}")
        size = path.stat().st_size
        total += size
        require(size <= bootstrap["source_boundary"]["maximum_file_bytes"], f"oversize source file: {value}")
        require(not value.lower().endswith(forbidden_suffixes), f"raw/generated suffix in source: {value}")
        require(PurePosixPath(value).parts[0] not in forbidden_roots, f"forbidden source root: {value}")
    require(total <= bootstrap["source_boundary"]["maximum_repository_bytes"], f"source repository too large: {total}")

    workflow_path = repository / ".github/workflows/202608290904-bootstrap-verify-data-gridatlas.yml"
    workflow = workflow_path.read_text(encoding="utf-8")
    require("contents: read" in workflow, "workflow is not read-only")
    for forbidden in ("contents: write", "pages: write", "id-token: write", "pull_request_target", "git push"):
        require(forbidden not in workflow, f"forbidden workflow capability: {forbidden}")
    for line in workflow.splitlines():
        if line.strip().startswith("uses:"):
            action = line.split("@", 1)
            require(len(action) == 2 and HEX40.fullmatch(action[1].strip()), f"unpinned Action: {line.strip()}")
    require((repository / "requirements.lock").read_text(encoding="utf-8") == "duckdb==1.3.2\n", "dependency lock drift")
    return {"tracked_files": len(files), "tracked_bytes": total}


def parse_oracle_tree(path: Path):
    rows = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        head, value = line.split("\t", 1)
        mode, kind, oid = head.split()
        if kind == "blob":
            rows[value] = {"mode": mode, "oid": oid}
    return rows


def verify_oracle(tree_path: Path, contracts):
    remote = parse_oracle_tree(tree_path)
    file_rows = contracts["files"]["rows"]
    expected_subtree = {f"repd_grid_atlasv8/{row['path']}": row["git_blob_sha1"] for row in file_rows}
    observed_subtree = {path: item["oid"] for path, item in remote.items() if path.startswith("repd_grid_atlasv8/")}
    require(observed_subtree == expected_subtree, "pinned V8 subtree path/blob closure mismatch")
    for row in contracts["layers"]["rows"]:
        item = remote.get(row["resolved_path"])
        require(item is not None, f"resolved dependency absent from pinned oracle: {row['resolved_path']}")
        require(item["oid"] == row["git_blob_sha1"], f"resolved dependency OID drift: {row['resolved_path']}")
    return {"verified_subtree_blobs": len(observed_subtree), "verified_layer_paths": len({row['resolved_path'] for row in contracts['layers']['rows']})}


def verify_catalog(repository: Path, catalog: Path, contracts):
    import duckdb

    expected_names = {"files.parquet", "layers.parquet", "quarantine.parquet", "manifest.json"}
    observed_names = {path.name for path in catalog.iterdir() if path.is_file()}
    require(observed_names == expected_names, f"catalog allowlist mismatch: {observed_names}")
    manifest = load(catalog / "manifest.json")
    require(manifest["schema"] == "data-gridatlas.bootstrap-manifest.v1", "manifest schema mismatch")
    require(manifest["generation"] == GENERATION, "manifest generation mismatch")
    require(manifest["classification"] == "BOOTSTRAP_CANDIDATE", "candidate classification mismatch")
    require(manifest["release"] is False and manifest["current_pointer"] is False, "bootstrap attempts promotion")
    require(manifest["raw_payloads_copied"] == 0 and manifest["v8_untouched"] is True, "bootstrap data boundary drift")
    require(manifest["runtime"]["duckdb"] == "1.3.2", "DuckDB runtime drift")

    manifest_contracts = {item["path"]: item for item in manifest["contracts"]}
    for relative in CONTRACT_PATHS.values():
        path = repository / relative
        item = manifest_contracts.get(relative)
        require(item is not None, f"contract absent from manifest: {relative}")
        require(item["bytes"] == path.stat().st_size and item["sha256"] == digest(path), f"contract identity mismatch: {relative}")

    artifacts = {item["path"]: item for item in manifest["artifacts"]}
    require(set(artifacts) == expected_names - {"manifest.json"}, "manifest artifact allowlist mismatch")
    expected_rows = {"files.parquet": 104, "layers.parquet": 60, "quarantine.parquet": 34}
    connection = duckdb.connect()
    connection.execute("PRAGMA threads=1")
    for name, rows in expected_rows.items():
        path = catalog / name
        item = artifacts[name]
        require(item["bytes"] == path.stat().st_size and item["sha256"] == digest(path), f"artifact identity mismatch: {name}")
        escaped = str(path).replace("'", "''")
        count = connection.execute(f"SELECT count(*) FROM read_parquet('{escaped}')").fetchone()[0]
        require(count == rows == item["rows"], f"typed row closure mismatch: {name}")
        compressions = {row[0] for row in connection.execute(f"SELECT DISTINCT compression FROM parquet_metadata('{escaped}')").fetchall()}
        require(compressions == {"ZSTD"}, f"Parquet compression mismatch for {name}: {compressions}")

    files_path = str(catalog / "files.parquet").replace("'", "''")
    layers_path = str(catalog / "layers.parquet").replace("'", "''")
    quarantine_path = str(catalog / "quarantine.parquet").replace("'", "''")
    file_closure = connection.execute(
        f"SELECT count(*), count(DISTINCT path), sum(bytes) FROM read_parquet('{files_path}')"
    ).fetchone()
    require(tuple(file_closure) == (104, 104, 39541206), f"file Parquet closure mismatch: {file_closure}")
    layer_closure = connection.execute(
        f"SELECT count(*), count(DISTINCT layer_id), count(DISTINCT configured_url), "
        f"count(DISTINCT group_name), count(*) FILTER (WHERE preload), "
        f"count(*) FILTER (WHERE publishable OR source_authority_state <> 'UNVERIFIED' OR licence_state <> 'UNVERIFIED') "
        f"FROM read_parquet('{layers_path}')"
    ).fetchone()
    require(tuple(layer_closure) == (60, 60, 40, 11, 12, 0), f"layer Parquet closure mismatch: {layer_closure}")
    q_closure = connection.execute(
        f"SELECT count(*), count(*) FILTER (WHERE kind='unwired_atlas_data'), "
        f"count(*) FILTER (WHERE kind='root_absolute_dependency') FROM read_parquet('{quarantine_path}')"
    ).fetchone()
    require(tuple(q_closure) == (34, 16, 7), f"quarantine Parquet closure mismatch: {q_closure}")
    connection.close()

    total = sum(path.stat().st_size for path in catalog.iterdir() if path.is_file())
    require(total < 2_000_000, f"bootstrap artifact exceeds 2 MB: {total}")
    return {"artifact_files": 4, "artifact_bytes": total, "typed_rows": sum(expected_rows.values())}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=".")
    parser.add_argument("--oracle-tree")
    parser.add_argument("--catalog")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    repository = Path(args.repository).resolve()
    contracts = inventory(repository)
    checks = {"inventory": {
        "v8_files": len(contracts["files"]["rows"]),
        "layers": len(contracts["layers"]["rows"]),
        "configured_urls": len({row["configured_url"] for row in contracts["layers"]["rows"]}),
        "quarantined_unwired_files": len(contracts["quarantine"]["unwired_atlas_data"]),
    }}
    checks["repository"] = verify_repository(repository, contracts["bootstrap"])
    classification = "VERIFIED_SOURCE_BOUNDARY"
    if args.oracle_tree:
        checks["oracle"] = verify_oracle(Path(args.oracle_tree), contracts)
        classification = "VERIFIED_ORACLE"
    if args.catalog:
        checks["catalog"] = verify_catalog(repository, Path(args.catalog).resolve(), contracts)
        classification = "VERIFIED_BOOTSTRAP_CANDIDATE"

    proof = {
        "schema": "data-gridatlas.bootstrap-verification.v1",
        "generation": GENERATION,
        "classification": classification,
        "checks": checks,
        "failed": 0,
        "v8_untouched": True,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    main()
