#!/usr/bin/env python3
"""Read-only resolver, sharded verifier and watchdog probes for live Data Grid Atlas."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


SCHEMA = "data-gridatlas.current-integrity.v1"
SHARD_SCHEMA = "data-gridatlas.current-integrity-shard.v1"
GENERATION = "202608291507"
CONTRACT = "contracts/202608291507-automation.json"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ROLES = [
    "consumer",
    "full_release",
    "pointer",
    "manifest",
    "privacy",
    "provenance",
    "cors",
    "runtime",
]
FEATURE_COLUMNS = [
    ("source_id", "VARCHAR"),
    ("feature_index", "INTEGER"),
    ("feature_id", "VARCHAR"),
    ("geometry_type", "VARCHAR"),
    ("geometry_json", "VARCHAR"),
    ("properties_json", "VARCHAR"),
    ("original_feature_sha256", "VARCHAR"),
    ("projected_feature_sha256", "VARCHAR"),
    ("min_x", "DOUBLE"),
    ("min_y", "DOUBLE"),
    ("max_x", "DOUBLE"),
    ("max_y", "DOUBLE"),
]
MEMBERSHIP_COLUMNS = [
    ("layer_id", "VARCHAR"),
    ("source_id", "VARCHAR"),
    ("feature_index", "INTEGER"),
]
RETAINED_KEYS = {
    "name", "SiteName", "Site Name", "type", "street", "city", "postcode", "area_m2",
    "area_ha", "colour", "brand", "operator", "club", "capacity", "sport",
    "emission_tco2e", "datatype", "sector", "country", "tech", "raw_tech", "voltage",
    "power_kw", "connectors", "status", "mounting", "source",
}
FORBIDDEN_KEYS = {"phone", "operator:phone", "payment:phone", "owner", "owner:wikidata", "ownership"}


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read_json(path: Path) -> dict:
    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def git(repository: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repository), *args], text=True).strip()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def write_outputs(path: Path | None, values: dict[str, object]) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            if isinstance(value, (dict, list)):
                value = json.dumps(value, sort_keys=True, separators=(",", ":"))
            handle.write(f"{key}={value}\n")


def load_contract(repository: Path, relative: str) -> dict:
    contract = read_json(repository / relative)
    require(contract.get("schema") == "data-gridatlas.automation-contract.v1", "automation contract schema mismatch")
    require(contract.get("generation") == GENERATION, "automation generation mismatch")
    require(contract.get("repository") == "Ventusltd/data-gridatlas", "repository contract mismatch")
    require(contract["closure"]["shards"] == 8, "integrity shard count must be eight")
    require(contract["runtime"]["maximum_parallel_shards"] == 8, "parallel shard ceiling mismatch")
    require(contract["rules"]["mutate_main"] is False, "automation must be read-only")
    return contract


def assign_parquet(artifacts: list[dict], shards: int) -> list[list[dict]]:
    lanes: list[list[dict]] = [[] for _ in range(shards)]
    totals = [0 for _ in range(shards)]
    for item in sorted(artifacts, key=lambda value: (-value["bytes"], value["path"])):
        lane = min(range(shards), key=lambda index: (totals[index], index))
        lanes[lane].append(item)
        totals[lane] += item["bytes"]
    for lane in lanes:
        lane.sort(key=lambda value: value["path"])
    return lanes


def resolve_state(repository: Path, contract_relative: str, expected_head: str = "", expected_pointer: str = "") -> dict:
    repository = repository.resolve()
    contract = load_contract(repository, contract_relative)
    baseline = contract["baseline"]
    head = git(repository, "rev-parse", "HEAD")
    require(HEX40.fullmatch(head) is not None, "malformed HEAD")
    if expected_head:
        require(HEX40.fullmatch(expected_head) is not None, "malformed expected HEAD")
        require(head == expected_head, f"HEAD compare-and-swap mismatch: {head}")
    subprocess.run(
        ["git", "-C", str(repository), "merge-base", "--is-ancestor", baseline["main_commit"], head],
        check=True,
    )

    pointer_paths = [repository / "state/live-set.json", repository / "releases/current.json"]
    require(all(path.is_file() and not path.is_symlink() for path in pointer_paths), "pointer file missing or symlinked")
    pointer_bytes = [path.read_bytes() for path in pointer_paths]
    require(pointer_bytes[0] == pointer_bytes[1], "pointer files are not byte-identical")
    pointer_sha = bytes_sha256(pointer_bytes[0])
    require(pointer_sha == baseline["pointer_sha256"], "stable pointer SHA-256 mismatch")
    if expected_pointer:
        require(HEX64.fullmatch(expected_pointer) is not None, "malformed expected pointer SHA-256")
        require(pointer_sha == expected_pointer, "pointer compare-and-swap mismatch")
    pointer = json.loads(pointer_bytes[0], object_pairs_hook=reject_duplicate_keys)
    require(pointer.get("schema") == "data-gridatlas.live-set.v1", "pointer schema mismatch")
    require(pointer.get("classification") == "VERIFIED_LIVE_DATA_GRIDATLAS_V9", "pointer classification mismatch")
    require((pointer.get("verification") or {}).get("promotion_eligible") is True, "pointer is not promotion eligible")
    require((pointer.get("verification") or {}).get("initial_v8_parquet_requests") == 0, "initial Parquet invariant mismatch")

    current = pointer.get("current") or {}
    consumer = pointer.get("consumer") or {}
    release_id = baseline["release_id"]
    expected_current = {
        "release_id": release_id,
        "publication_commit": baseline["release_commit"],
        "release_sha256": baseline["release_sha256"],
        "data_manifest_sha256": baseline["manifest_sha256"],
        "browser_registry_sha256": baseline["browser_registry_sha256"],
        "ledger_sha256": baseline["ledger_sha256"],
        "packaging_source_commit": baseline["packaging_source_commit"],
        "candidate_source_commit": baseline["candidate_source_commit"],
    }
    for key, value in expected_current.items():
        require(current.get(key) == value, f"pointer data binding mismatch: {key}")
    expected_consumer = {
        "release_id": contract["consumer"]["release_id"],
        "publication_commit": contract["consumer"]["publication_commit"],
        "app_pointer_commit": contract["consumer"]["pointer_commit"],
        "release_manifest_sha256": contract["consumer"]["release_manifest_sha256"],
        "build_manifest_sha256": contract["consumer"]["build_manifest_sha256"],
        "pointer_sha256": contract["consumer"]["pointer_sha256"],
    }
    for key, value in expected_consumer.items():
        require(consumer.get(key) == value, f"pointer consumer binding mismatch: {key}")

    release_root = repository / release_id
    require(release_root.is_dir() and not release_root.is_symlink(), "immutable release root missing")
    require(git(repository, "rev-parse", f"HEAD:{release_id}") == baseline["release_tree"], "immutable release tree changed")
    exact_hashes = {
        release_root / "release.json": baseline["release_sha256"],
        release_root / "data/manifest.json": baseline["manifest_sha256"],
        release_root / "browser-layer-registry.json": baseline["browser_registry_sha256"],
        release_root / "sha256sums.txt": baseline["ledger_sha256"],
    }
    for path, expected in exact_hashes.items():
        require(path.is_file() and sha256(path) == expected, f"immutable release hash mismatch: {path.name}")

    routing = baseline.get("routing_release") or {}
    routing_id = routing.get("release_id", "")
    require(routing_id == "202608291410-repd-routing", "REPD routing release identity mismatch")
    routing_root = repository / routing_id
    require(routing_root.is_dir() and not routing_root.is_symlink(), "immutable REPD routing release missing")
    require(
        git(repository, "rev-parse", f"HEAD:{routing_id}") == routing.get("release_tree"),
        "immutable REPD routing release tree changed",
    )
    routing_hashes = {
        routing_root / "projects.json": routing.get("projects_sha256"),
        routing_root / "release.json": routing.get("release_sha256"),
        routing_root / "sha256sums.txt": routing.get("ledger_sha256"),
    }
    for path, expected in routing_hashes.items():
        require(HEX64.fullmatch(str(expected)) is not None, f"malformed routing hash contract: {path.name}")
        require(path.is_file() and not path.is_symlink(), f"immutable routing file missing: {path.name}")
        require(sha256(path) == expected, f"immutable routing hash mismatch: {path.name}")
    routing_release = read_json(routing_root / "release.json")
    require(routing_release.get("schema") == "data-gridatlas.repd-routing-release.v1", "routing release schema mismatch")
    require(routing_release.get("classification") == "IMMUTABLE_REPD_ROUTING_RELEASE", "routing release classification mismatch")
    require(routing_release.get("release_id") == routing_id, "routing release ID mismatch")
    require(routing_release.get("source_commit") == routing.get("source_commit"), "routing source commit mismatch")

    manifest = read_json(release_root / "data/manifest.json")
    require(manifest.get("schema") == "data-gridatlas.v8-transplant-manifest.v1", "candidate manifest schema mismatch")
    require(manifest.get("classification") == "FULL_V8_TRANSPLANT_CANDIDATE", "candidate manifest classification mismatch")
    require(manifest.get("raw_geojson_outputs") == 0, "raw GeoJSON output invariant failed")
    closure = manifest.get("closure") or {}
    for source, target in (("layers", "layers"), ("sources", "sources"), ("features", "features"), ("layer_membership_rows", "memberships")):
        require(closure.get(source) == contract["closure"][target], f"manifest closure mismatch: {source}")
    parquet = [item for item in manifest.get("artifacts", []) if item.get("path", "").endswith(".parquet")]
    require(len(parquet) == contract["closure"]["parquet_files"], "Parquet file count mismatch")
    require(sum(item["bytes"] for item in parquet) == contract["closure"]["parquet_bytes"], "Parquet byte closure mismatch")
    require(len({item["path"] for item in parquet}) == len(parquet), "duplicate Parquet manifest path")
    for item in parquet:
        require(HEX64.fullmatch(item.get("sha256", "")) is not None, f"malformed Parquet SHA-256: {item.get('path')}")
        require(not Path(item["path"]).is_absolute() and ".." not in Path(item["path"]).parts, "unsafe Parquet path")

    lanes = assign_parquet(parquet, contract["closure"]["shards"])
    return {
        "repository": repository,
        "contract": contract,
        "head": head,
        "pointer_sha256": pointer_sha,
        "pointer": pointer,
        "release_root": release_root,
        "manifest": manifest,
        "parquet": parquet,
        "lanes": lanes,
    }


def fetch(url: str, *, byte_range: str | None = None, attempts: int = 4) -> tuple[int, dict[str, str], bytes]:
    headers = {
        "Accept-Encoding": "identity",
        "User-Agent": "data-gridatlas-202608291507-integrity",
    }
    if byte_range:
        headers["Range"] = byte_range
    error: Exception | None = None
    for attempt in range(attempts):
        try:
            request = Request(url, headers=headers)
            with urlopen(request, timeout=30) as response:
                return response.status, {key.lower(): value for key, value in response.headers.items()}, response.read()
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            error = exc
            if attempt + 1 < attempts:
                time.sleep(attempt + 1)
    raise SystemExit(f"public fetch failed after {attempts} attempts: {url}: {error!r}")


def require_public_response(status: int, headers: dict[str, str], expected_status: int, url: str) -> None:
    require(status == expected_status, f"public status mismatch: {url}:{status}")
    require(headers.get("access-control-allow-origin") == "*", f"public CORS mismatch: {url}")
    require(headers.get("content-encoding") in (None, "identity"), f"public encoding mismatch: {url}")


def verify_public_parquet(state: dict, item: dict) -> dict:
    contract = state["contract"]
    release_id = contract["baseline"]["release_id"]
    relative = item["path"]
    url = contract["public"]["data_root"] + release_id + "/data/" + quote(relative, safe="/")
    size = item["bytes"]
    status, headers, payload = fetch(url, byte_range="bytes=0-3")
    require_public_response(status, headers, 206, url)
    require(payload == b"PAR1", f"public Parquet prefix mismatch: {relative}")
    require(headers.get("content-range") == f"bytes 0-3/{size}", f"public prefix range mismatch: {relative}")
    status, headers, payload = fetch(url, byte_range=f"bytes={size - 4}-{size - 1}")
    require_public_response(status, headers, 206, url)
    require(payload == b"PAR1", f"public Parquet suffix mismatch: {relative}")
    require(headers.get("content-range") == f"bytes {size - 4}-{size - 1}/{size}", f"public suffix range mismatch: {relative}")
    return {"url": url, "prefix": True, "suffix": True, "cors": True, "identity": True}


def parquet_schema(connection, path: Path) -> list[tuple[str, str]]:
    return [(row[0], row[1]) for row in connection.execute("DESCRIBE SELECT * FROM read_parquet(?)", [str(path)]).fetchall()]


def verify_local_parquet(connection, state: dict, item: dict, scan_privacy: bool) -> dict:
    path = state["release_root"] / "data" / item["path"]
    require(path.is_file() and not path.is_symlink(), f"local Parquet missing or symlinked: {item['path']}")
    require(path.stat().st_size == item["bytes"], f"local Parquet byte mismatch: {item['path']}")
    require(sha256(path) == item["sha256"], f"local Parquet SHA-256 mismatch: {item['path']}")
    rows = connection.execute("SELECT count(*) FROM read_parquet(?)", [str(path)]).fetchone()[0]
    require(rows == item["rows"], f"local Parquet row mismatch: {item['path']}")
    codecs = {row[0] for row in connection.execute("SELECT DISTINCT compression FROM parquet_metadata(?)", [str(path)]).fetchall()}
    require(codecs == ({"ZSTD"} if rows else set()), f"local Parquet compression mismatch: {item['path']}:{codecs}")
    schema = parquet_schema(connection, path)
    if item["schema"] in {"data-gridatlas.v8-parity-features.v1", "data-gridatlas.v8-snapped-topology.v1"}:
        require(schema == FEATURE_COLUMNS, f"feature Parquet schema mismatch: {item['path']}")
    elif item["schema"] == "data-gridatlas.v8-layer-membership.v1":
        require(schema == MEMBERSHIP_COLUMNS, f"membership Parquet schema mismatch: {item['path']}")
    else:
        require(bool(schema), f"empty Parquet schema: {item['path']}")

    privacy_rows = 0
    if scan_privacy and item["schema"] in {"data-gridatlas.v8-parity-features.v1", "data-gridatlas.v8-snapped-topology.v1"}:
        cursor = connection.execute("SELECT properties_json FROM read_parquet(?)", [str(path)])
        while True:
            batch = cursor.fetchmany(5000)
            if not batch:
                break
            for (raw,) in batch:
                properties = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
                require(isinstance(properties, dict) and canonical(properties) == raw, f"non-canonical properties: {item['path']}")
                keys = set(properties)
                require(keys.issubset(RETAINED_KEYS), f"property allowlist escape: {item['path']}:{sorted(keys - RETAINED_KEYS)}")
                require(keys.isdisjoint(FORBIDDEN_KEYS), f"forbidden property escaped: {item['path']}:{sorted(keys & FORBIDDEN_KEYS)}")
                privacy_rows += 1
    return {
        "path": item["path"],
        "bytes": item["bytes"],
        "rows": rows,
        "sha256": item["sha256"],
        "schema": item["schema"],
        "compression": sorted(codecs),
        "privacy_rows": privacy_rows,
    }


def verify_data_pointer(state: dict) -> dict:
    contract = state["contract"]
    expected = (state["repository"] / "state/live-set.json").read_bytes()
    urls = [
        contract["public"]["data_root"] + "state/live-set.json",
        contract["public"]["data_root"] + "releases/current.json",
    ]
    payloads = []
    for url in urls:
        status, headers, payload = fetch(url)
        require_public_response(status, headers, 200, url)
        require(payload == expected, f"public data pointer differs: {url}")
        payloads.append(payload)
    require(payloads[0] == payloads[1], "public data pointers are not identical")
    return {"urls": urls, "sha256": bytes_sha256(payloads[0]), "verified": True}


def verify_data_release_sentinels(state: dict, include_ranges: bool = True) -> dict:
    contract = state["contract"]
    baseline = contract["baseline"]
    base = contract["public"]["data_root"] + baseline["release_id"] + "/"
    checks = {
        "release.json": baseline["release_sha256"],
        "browser-layer-registry.json": baseline["browser_registry_sha256"],
        "data/manifest.json": baseline["manifest_sha256"],
        "sha256sums.txt": baseline["ledger_sha256"],
    }
    for relative, expected in checks.items():
        url = base + relative
        status, headers, payload = fetch(url)
        require_public_response(status, headers, 200, url)
        require(bytes_sha256(payload) == expected, f"public release sentinel mismatch: {relative}")
    ranges = []
    if include_ranges:
        by_path = {item["path"]: item for item in state["parquet"]}
        sentinels = [
            "partitions/uk_primary_roads.parquet",
            "partitions/repd_master_v8_oracle.parquet",
            "layer_membership.parquet",
        ]
        ranges = [verify_public_parquet(state, by_path[path]) for path in sentinels]
    return {"files": checks, "range_sentinels": ranges, "verified": True}


def verify_consumer(state: dict) -> dict:
    contract = state["contract"]
    expected = contract["consumer"]
    root = contract["public"]["app_root"]
    pointer_urls = [root + "state/live-set.json", root + "releases/current-v3.json"]
    payloads = []
    for url in pointer_urls:
        status, headers, payload = fetch(url)
        require_public_response(status, headers, 200, url)
        payloads.append(payload)
    require(payloads[0] == payloads[1], "public app pointers are not byte-identical")
    require(bytes_sha256(payloads[0]) == expected["pointer_sha256"], "public app pointer SHA-256 mismatch")
    pointer = json.loads(payloads[0], object_pairs_hook=reject_duplicate_keys)
    require(pointer.get("schema") == "gridatlas.live-set.v3", "public app pointer schema mismatch")
    require(pointer.get("classification") == "VERIFIED_LIVE_ATLAS_V9", "public app pointer classification mismatch")
    current = pointer.get("current") or {}
    exact = {
        "release_id": expected["release_id"],
        "publication_commit": expected["publication_commit"],
        "release_manifest_sha256": expected["release_manifest_sha256"],
        "build_manifest_sha256": expected["build_manifest_sha256"],
        "data_release_id": contract["baseline"]["release_id"],
        "data_release_commit": contract["baseline"]["release_commit"],
        "data_release_sha256": contract["baseline"]["release_sha256"],
    }
    for key, value in exact.items():
        require(current.get(key) == value, f"public app binding mismatch: {key}")
    query = expected["query"]
    require((current.get("query_contract") or {}).get("parameter") == query["parameter"], "app query parameter mismatch")
    require((current.get("query_contract") or {}).get("golden_value") == query["value"], "app query value mismatch")

    release = root + expected["release_id"] + "/"
    release_checks = {
        "release-manifest.json": expected["release_manifest_sha256"],
        "build-manifest.json": expected["build_manifest_sha256"],
        "index.html": expected["index_sha256"],
    }
    index_payload = None
    for relative, digest in release_checks.items():
        url = release + relative
        status, headers, payload = fetch(url)
        require_public_response(status, headers, 200, url)
        require(bytes_sha256(payload) == digest, f"public app release mismatch: {relative}")
        if relative == "index.html":
            index_payload = payload
    deep_link = release + "?" + quote(query["parameter"]) + "=" + quote(query["value"])
    status, headers, payload = fetch(deep_link)
    require_public_response(status, headers, 200, deep_link)
    require(payload == index_payload, "deep-link index differs from release index")

    raw_pointer = (
        "https://raw.githubusercontent.com/" + expected["repository"] + "/" + expected["pointer_commit"] + "/state/live-set.json"
    )
    status, _, payload = fetch(raw_pointer)
    require(status == 200 and payload == payloads[0], "public app pointer differs from pinned Git commit")
    return {
        "pointer_urls": pointer_urls,
        "pointer_sha256": expected["pointer_sha256"],
        "release_id": expected["release_id"],
        "deep_link": deep_link,
        "golden_value": query["value"],
        "verified": True,
    }


def run_full_release_verifier(state: dict, output: Path) -> dict:
    command = [
        sys.executable,
        str(state["repository"] / "atman/202608291237-verify-live-data-release.py"),
        "--repository", str(state["repository"]),
        "--release", str(state["release_root"]),
        "--source-commit", state["contract"]["baseline"]["packaging_source_commit"],
        "--output", str(output),
    ]
    subprocess.run(command, check=True)
    proof = read_json(output)
    require(proof.get("classification") == "VERIFIED_IMMUTABLE_LIVE_DATA_RELEASE", "full release verifier rejected release")
    require(proof.get("failed") == 0, "full release verifier reported failures")
    return proof


def command_resolve(args: argparse.Namespace) -> None:
    state = resolve_state(args.repository, args.contract, args.expected_head, args.expected_pointer_sha256)
    matrix = {
        "include": [
            {"lane": index, "role": ROLES[index], "declared_bytes": sum(item["bytes"] for item in lane)}
            for index, lane in enumerate(state["lanes"])
        ]
    }
    result = {
        "schema": "data-gridatlas.current-integrity-plan.v1",
        "classification": "RESOLVED_VERIFIED_LIVE_POINTER",
        "generation": GENERATION,
        "head_sha": state["head"],
        "pointer_sha256": state["pointer_sha256"],
        "release_id": state["contract"]["baseline"]["release_id"],
        "parquet_files": len(state["parquet"]),
        "parquet_bytes": sum(item["bytes"] for item in state["parquet"]),
        "matrix": matrix,
        "assignments": [
            {"lane": index, "role": ROLES[index], "bytes": sum(item["bytes"] for item in lane), "paths": [item["path"] for item in lane]}
            for index, lane in enumerate(state["lanes"])
        ],
        "rebuild_required": False,
        "main_mutated": False,
        "failed": 0,
    }
    write_json(args.output, result)
    write_outputs(args.github_output, {
        "head_sha": state["head"],
        "pointer_sha256": state["pointer_sha256"],
        "release_id": state["contract"]["baseline"]["release_id"],
        "matrix": matrix,
    })
    print(json.dumps(result, sort_keys=True))


def command_shard(args: argparse.Namespace) -> None:
    state = resolve_state(args.repository, args.contract, args.expected_head, args.expected_pointer_sha256)
    require(0 <= args.lane < len(state["lanes"]), "invalid shard lane")
    require(args.role == ROLES[args.lane], "shard role mismatch")
    import duckdb

    require(duckdb.__version__ == state["contract"]["runtime"]["duckdb"], "DuckDB runtime mismatch")
    connection = duckdb.connect(":memory:")
    connection.execute("SET threads=1")
    files = []
    try:
        for item in state["lanes"][args.lane]:
            local = verify_local_parquet(connection, state, item, scan_privacy=True)
            local["public"] = None if args.skip_public else verify_public_parquet(state, item)
            files.append(local)
    finally:
        connection.close()

    consumer = None
    full_release = None
    if args.lane == 0 and not args.skip_public:
        verify_data_pointer(state)
        verify_data_release_sentinels(state, include_ranges=False)
        consumer = verify_consumer(state)
    if args.lane == 1:
        full_release = run_full_release_verifier(state, args.output.parent / "full-release-verification.json")

    result = {
        "schema": SHARD_SCHEMA,
        "classification": "VERIFIED_CURRENT_INTEGRITY_SHARD",
        "generation": GENERATION,
        "head_sha": state["head"],
        "pointer_sha256": state["pointer_sha256"],
        "lane": args.lane,
        "role": args.role,
        "files": files,
        "file_count": len(files),
        "bytes": sum(item["bytes"] for item in files),
        "rows": sum(item["rows"] for item in files),
        "privacy_rows": sum(item["privacy_rows"] for item in files),
        "public_verified": not args.skip_public,
        "consumer": consumer,
        "full_release": full_release,
        "runtime": {"python": ".".join(map(str, sys.version_info[:3])), "duckdb": duckdb.__version__},
        "rebuild_performed": False,
        "main_mutated": False,
        "failed": 0,
    }
    write_json(args.output, result)
    print(json.dumps(result, sort_keys=True))


def command_reduce(args: argparse.Namespace) -> None:
    state = resolve_state(args.repository, args.contract, args.expected_head, args.expected_pointer_sha256)
    paths = sorted(args.attestations.rglob("shard-*.json"))
    require(len(paths) == 8, f"expected eight shard attestations, found {len(paths)}")
    shards = [read_json(path) for path in paths]
    require({item.get("lane") for item in shards} == set(range(8)), "shard lane closure mismatch")
    require({item.get("role") for item in shards} == set(ROLES), "shard role closure mismatch")
    declared = {item["path"] for item in state["parquet"]}
    observed: list[str] = []
    for shard in shards:
        require(shard.get("schema") == SHARD_SCHEMA, "shard schema mismatch")
        require(shard.get("classification") == "VERIFIED_CURRENT_INTEGRITY_SHARD", "shard classification mismatch")
        require(shard.get("head_sha") == state["head"], "shard HEAD mismatch")
        require(shard.get("pointer_sha256") == state["pointer_sha256"], "shard pointer mismatch")
        require(shard.get("failed") == 0 and shard.get("rebuild_performed") is False and shard.get("main_mutated") is False, "shard safety mismatch")
        require(shard.get("public_verified") is True, "shard public verification missing")
        observed.extend(item["path"] for item in shard["files"])
    require(len(observed) == len(set(observed)), "Parquet file verified by multiple shards")
    require(set(observed) == declared, "Parquet shard closure mismatch")
    consumer = next(item for item in shards if item["lane"] == 0).get("consumer") or {}
    release = next(item for item in shards if item["lane"] == 1).get("full_release") or {}
    require(consumer.get("verified") is True, "consumer proof missing")
    require(release.get("classification") == "VERIFIED_IMMUTABLE_LIVE_DATA_RELEASE", "full release proof missing")
    result = {
        "schema": SCHEMA,
        "classification": "VERIFIED_CURRENT_DATA_GRIDATLAS_INTEGRITY",
        "generation": GENERATION,
        "head_sha": state["head"],
        "pointer_sha256": state["pointer_sha256"],
        "release_id": state["contract"]["baseline"]["release_id"],
        "shards": 8,
        "parquet_files": len(observed),
        "parquet_bytes": sum(item["bytes"] for item in state["parquet"]),
        "parquet_rows": sum(item["rows"] for item in state["parquet"]),
        "privacy_rows": sum(item["privacy_rows"] for shard in shards for item in shard["files"]),
        "consumer_release_id": consumer["release_id"],
        "deep_link": consumer["deep_link"],
        "rebuild_required": False,
        "rebuild_performed": False,
        "main_mutated": False,
        "failed": 0,
    }
    write_json(args.output, result)
    print(json.dumps(result, sort_keys=True))


def command_probe(args: argparse.Namespace) -> None:
    state = resolve_state(args.repository, args.contract, args.expected_head, args.expected_pointer_sha256)
    if args.mode == "data-pointer":
        proof = verify_data_pointer(state)
    elif args.mode == "data-release":
        proof = verify_data_release_sentinels(state, include_ranges=True)
    elif args.mode == "consumer":
        proof = verify_consumer(state)
    else:
        raise SystemExit(f"unknown probe mode: {args.mode}")
    result = {
        "schema": "data-gridatlas.watchdog-probe.v1",
        "classification": "VERIFIED_WATCHDOG_PROBE",
        "generation": GENERATION,
        "mode": args.mode,
        "head_sha": state["head"],
        "pointer_sha256": state["pointer_sha256"],
        "proof": proof,
        "main_mutated": False,
        "failed": 0,
    }
    write_json(args.output, result)
    print(json.dumps(result, sort_keys=True))


def changed_since_baseline(repository: Path, baseline: str, include_working_tree: bool) -> dict[str, str]:
    changed: dict[str, str] = {}

    def consume(raw: str) -> None:
        for line in raw.splitlines():
            fields = line.split("\t")
            require(len(fields) == 2, f"unsupported changed-path record: {line!r}")
            status, path = fields
            require(status == "A", f"only added successor files are allowed: {status}:{path}")
            require(path not in changed, f"duplicate changed path: {path}")
            changed[path] = status

    consume(git(repository, "diff", "--name-status", f"{baseline}..HEAD"))
    if include_working_tree:
        consume(git(repository, "diff", "--name-status"))
        untracked = git(repository, "ls-files", "--others", "--exclude-standard")
        for path in untracked.splitlines():
            require(path not in changed, f"duplicate untracked path: {path}")
            changed[path] = "A"
    return changed


def verify_workflow_source(path: Path, contract: dict) -> dict:
    source = path.read_text(encoding="utf-8")
    require("permissions: {}" in source, f"top-level deny-all permissions missing: {path}")
    require("contents: write" not in source, f"repository-content write permission forbidden: {path}")
    require("pull_request_target:" not in source, f"pull_request_target forbidden: {path}")
    require("secrets: inherit" not in source, f"inherited secrets forbidden: {path}")
    require("workflow_dispatch:" in source, f"manual recovery trigger missing: {path}")

    use_lines = re.findall(r"(?m)^\s*uses:\s*([^\s]+)\s*$", source)
    pins = contract["action_pins"]
    for item in use_lines:
        require("@" in item, f"unversioned action: {path}:{item}")
        action, reference = item.rsplit("@", 1)
        require(action in pins, f"unapproved action: {path}:{action}")
        require(reference == pins[action] and HEX40.fullmatch(reference) is not None, f"floating or wrong action pin: {path}:{item}")
    require(source.count("uses:") == len(use_lines), f"unparsed action use: {path}")
    require(source.count("actions/checkout@") == source.count("persist-credentials: false"), f"checkout credential persistence mismatch: {path}")

    timeouts = [int(value) for value in re.findall(r"timeout-minutes:\s*(\d+)", source)]
    require(timeouts and max(timeouts) <= contract["runtime"]["maximum_job_minutes"], f"workflow timeout exceeds contract: {path}")
    require(all(value > 0 for value in timeouts), f"non-positive workflow timeout: {path}")

    name = path.name
    if name == Path(contract["workflow"]["watchdog"]).name:
        require(source.count("actions: write") == 1, "watchdog router requires exactly one actions:write job")
        require(f"cron: '{contract['workflow']['schedule_utc']}'" in source, "watchdog schedule mismatch")
        require("max-parallel: 3" in source, "watchdog public probe ceiling mismatch")
    else:
        require("actions: write" not in source, f"actions write permission forbidden outside router: {path}")
        require("schedule:" not in source, f"unexpected schedule outside watchdog: {path}")
    if name == Path(contract["workflow"]["integrity"]).name:
        require("max-parallel: 8" in source, "integrity parallel ceiling mismatch")
        require("fail-fast: false" in source, "integrity evidence lanes must not fail fast")
    if name == Path(contract["workflow"]["guard"]).name:
        require("pull_request:" in source and "push:" in source, "guard push/PR trigger mismatch")

    return {
        "path": path.as_posix(),
        "sha256": sha256(path),
        "actions": len(use_lines),
        "jobs": len(timeouts),
        "maximum_timeout_minutes": max(timeouts),
        "actions_write_grants": source.count("actions: write"),
        "contents_write_grants": source.count("contents: write"),
    }


def command_guard(args: argparse.Namespace) -> None:
    state = resolve_state(args.repository, args.contract, args.expected_head, args.expected_pointer_sha256)
    contract = state["contract"]
    repository = state["repository"]
    expected_files = set(contract["first_checkpoint_files"])
    changed = changed_since_baseline(repository, contract["baseline"]["main_commit"], args.include_working_tree)
    require(set(changed) == expected_files, f"automation source boundary mismatch: expected={sorted(expected_files)} actual={sorted(changed)}")

    for relative in sorted(expected_files):
        path = repository / relative
        require(path.is_file() and not path.is_symlink(), f"automation successor missing or symlinked: {relative}")
    workflow_paths = sorted((repository / ".github/workflows").glob("202608291507-*.yml"))
    expected_workflows = {
        repository / contract["workflow"]["watchdog"],
        repository / contract["workflow"]["integrity"],
        repository / contract["workflow"]["guard"],
    }
    require(set(workflow_paths) == expected_workflows, "automation workflow file closure mismatch")
    workflows = []
    for path in workflow_paths:
        proof = verify_workflow_source(path, contract)
        proof["path"] = path.relative_to(repository).as_posix()
        workflows.append(proof)

    forbidden_suffixes = {".geojson", ".csv", ".tsv", ".xlsx", ".duckdb", ".zip", ".tar", ".gz"}
    tracked = git(repository, "ls-files").splitlines()
    if args.include_working_tree:
        tracked += git(repository, "ls-files", "--others", "--exclude-standard").splitlines()
    release_prefix = contract["baseline"]["release_id"] + "/"
    escaped = [path for path in tracked if Path(path).suffix.lower() in forbidden_suffixes and not path.startswith(release_prefix)]
    require(not escaped, f"forbidden analytical output outside immutable release: {escaped}")

    result = {
        "schema": "data-gridatlas.automation-contract-guard.v1",
        "classification": "VERIFIED_READ_ONLY_AUTOMATION_CONTRACT",
        "generation": GENERATION,
        "head_sha": state["head"],
        "baseline_commit": contract["baseline"]["main_commit"],
        "pointer_sha256": state["pointer_sha256"],
        "release_tree": git(repository, "rev-parse", f"HEAD:{contract['baseline']['release_id']}"),
        "successor_files": sorted(expected_files),
        "changed_files": changed,
        "workflows": workflows,
        "maximum_job_minutes": contract["runtime"]["maximum_job_minutes"],
        "contents_write_grants": sum(item["contents_write_grants"] for item in workflows),
        "actions_write_grants": sum(item["actions_write_grants"] for item in workflows),
        "immutable_release_mutated": False,
        "pointer_mutated": False,
        "main_mutated_by_guard": False,
        "failed": 0,
    }
    write_json(args.output, result)
    print(json.dumps(result, sort_keys=True))


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--contract", default=CONTRACT)
    parser.add_argument("--expected-head", default="")
    parser.add_argument("--expected-pointer-sha256", default="")


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)

    resolve = commands.add_parser("resolve")
    add_common(resolve)
    resolve.add_argument("--output", type=Path, required=True)
    resolve.add_argument("--github-output", type=Path)
    resolve.set_defaults(handler=command_resolve)

    shard = commands.add_parser("shard")
    add_common(shard)
    shard.add_argument("--lane", type=int, required=True)
    shard.add_argument("--role", required=True, choices=ROLES)
    shard.add_argument("--skip-public", action="store_true")
    shard.add_argument("--output", type=Path, required=True)
    shard.set_defaults(handler=command_shard)

    reduce = commands.add_parser("reduce")
    add_common(reduce)
    reduce.add_argument("--attestations", type=Path, required=True)
    reduce.add_argument("--output", type=Path, required=True)
    reduce.set_defaults(handler=command_reduce)

    probe = commands.add_parser("probe")
    add_common(probe)
    probe.add_argument("--mode", choices=["data-pointer", "data-release", "consumer"], required=True)
    probe.add_argument("--output", type=Path, required=True)
    probe.set_defaults(handler=command_probe)

    guard = commands.add_parser("guard")
    add_common(guard)
    guard.add_argument("--include-working-tree", action="store_true")
    guard.add_argument("--output", type=Path, required=True)
    guard.set_defaults(handler=command_guard)

    args = parser.parse_args()
    args.handler(args)


if __name__ == "__main__":
    main()
