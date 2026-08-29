#!/usr/bin/env python3
"""Independent verifier for the full V8 parity transplant candidate."""

import argparse
import copy
import hashlib
import json
import math
import os
import platform
import re
import subprocess
from collections import Counter
from pathlib import Path, PurePosixPath

import duckdb


GENERATION = "202608291015"
PLAN = "contracts/202608291015-v8-transplant-plan.json"
LAYERS = "contracts/202608291015-v8-layer-config.json"
RUNTIME = "contracts/202608291015-v8-runtime-dependencies.json"
BOUNDARY = "contracts/202608291015-repository-boundary.json"
SCHEMA = "schemas/202608291015-v8-transplant-parquet.json"
LEDGER = "contracts/202608290904-v8-dependency-ledger.json"
COMPUTE_INPUTS = [
    PLAN, LAYERS, RUNTIME, BOUNDARY, SCHEMA, LEDGER,
    "contracts/202608290904-v8-file-ledger.json",
    "contracts/202608290904-v8-quarantine.json",
    "compiler/202608291015-build-v8-transplant.py",
    "atman/202608291015-verify-v8-transplant.py",
    ".github/workflows/202608291015-build-v8-transplant-candidate.yml",
    "requirements.lock",
]
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
SNAP_EXPECTED = {
    "grid_400kv": (4528, 2679), "grid_275kv": (3806, 2212),
    "grid_220kv": (150, 93), "grid_132kv": (7218, 4342), "grid_66kv": (1353, 828),
}
EXPECTED_CLOSURE = {
    "sources": 56, "wired_sources": 40, "unwired_sources": 16, "layers": 60,
    "features": 541282, "wired_features": 530263, "unwired_features": 11019,
    "input_bytes": 262709675,
    "geometry_counts": {"LineString": 437288, "MultiLineString": 23, "Point": 103971},
    "coordinate_tuples": 3812791, "raw_property_pairs": 5088905,
    "retained_property_pairs": 1064163, "dropped_property_pairs": 4024742,
    "layer_membership_rows": 526388,
}
FEATURE_COLUMNS = [
    ("source_id", "VARCHAR"), ("feature_index", "INTEGER"), ("feature_id", "VARCHAR"),
    ("geometry_type", "VARCHAR"), ("geometry_json", "VARCHAR"), ("properties_json", "VARCHAR"),
    ("original_feature_sha256", "VARCHAR"), ("projected_feature_sha256", "VARCHAR"),
    ("min_x", "DOUBLE"), ("min_y", "DOUBLE"), ("max_x", "DOUBLE"), ("max_y", "DOUBLE"),
]
MEMBERSHIP_COLUMNS = [("layer_id", "VARCHAR"), ("source_id", "VARCHAR"), ("feature_index", "INTEGER")]
EXPECTED_RETAINED_KEYS = [
    "name", "SiteName", "Site Name", "type", "street", "city", "postcode", "area_m2", "area_ha",
    "colour", "brand", "operator", "club", "capacity", "sport", "emission_tco2e", "datatype",
    "sector", "country", "tech", "raw_tech", "voltage", "power_kw", "connectors", "status",
    "mounting", "source",
]
EXPECTED_FORBIDDEN_KEYS = ["phone", "operator:phone", "payment:phone", "owner", "owner:wikidata", "ownership"]


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load(path):
    return json.loads(
        Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
    )


def digest(path):
    value = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def digest_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def git_blob_oid(payload):
    return hashlib.sha1(f"blob {len(payload)}\0".encode() + payload).hexdigest()


def expected_compute_identity(repository):
    inputs = [
        {"path": path, "bytes": (repository / path).stat().st_size, "sha256": digest(repository / path)}
        for path in COMPUTE_INPUTS
    ]
    identity = {
        "repository": "Ventusltd/data-gridatlas",
        "v8_repository": "Ventusltd/globalgrid2050",
        "v8_commit": "f2f343a92ee972cc74ed23b4b99d8a22896791ad",
        "runtime": {
            "python": platform.python_version(), "duckdb": duckdb.__version__, "threads": 1,
            "runner_image_os": os.environ.get("ImageOS"), "runner_image_version": os.environ.get("ImageVersion"),
        },
        "inputs": inputs,
    }
    identity["key_sha256"] = digest_bytes(canonical(identity).encode())
    return identity


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def safe_relative(value):
    path = PurePosixPath(value)
    return value not in {"", "."} and not path.is_absolute() and ".." not in path.parts


def sql_string(value):
    return str(value).replace("'", "''")


def loads_strict(value):
    return json.loads(
        value,
        object_pairs_hook=reject_duplicate_keys,
        parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
    )


def read_oracle_source(source, source_root):
    path = source_root / source["resolved_path"]
    require(path.is_file() and not path.is_symlink(), f"pinned source not materialised: {source['source_id']}")
    payload = path.read_bytes()
    require(len(payload) == source["bytes"], f"source byte drift: {source['source_id']}")
    require(digest_bytes(payload) == source["sha256"], f"source SHA-256 drift: {source['source_id']}")
    require(git_blob_oid(payload) == source["git_blob_sha1"], f"source Git blob drift: {source['source_id']}")
    obj = loads_strict(payload)
    require(obj.get("type") == "FeatureCollection" and isinstance(obj.get("features"), list), f"not FeatureCollection: {source['source_id']}")
    return obj


def collect_coordinates(node, output):
    if isinstance(node, list) and len(node) >= 2 and all(
        isinstance(value, (int, float)) and not isinstance(value, bool) for value in node[:2]
    ):
        require(len(node) == 2, "non-2D coordinate")
        x, y = float(node[0]), float(node[1])
        require(math.isfinite(x) and math.isfinite(y), "non-finite coordinate")
        require(-180 <= x <= 180 and -90 <= y <= 90, f"coordinate outside WGS84 range: {(x, y)}")
        output.append((x, y))
    elif isinstance(node, list):
        for child in node:
            collect_coordinates(child, output)


def evaluate_filter(expression, properties):
    if not isinstance(expression, list):
        return expression
    operation = expression[0]
    if operation == "get":
        return properties.get(expression[1])
    if operation == "==":
        return evaluate_filter(expression[1], properties) == evaluate_filter(expression[2], properties)
    if operation == "!=":
        return evaluate_filter(expression[1], properties) != evaluate_filter(expression[2], properties)
    if operation == "all":
        return all(bool(evaluate_filter(item, properties)) for item in expression[1:])
    if operation == "any":
        return any(bool(evaluate_filter(item, properties)) for item in expression[1:])
    if operation == "!":
        return not bool(evaluate_filter(expression[1], properties))
    if operation == "in":
        needle = evaluate_filter(expression[1], properties)
        haystack = evaluate_filter(expression[2], properties)
        try:
            return needle in haystack
        except TypeError:
            return False
    raise RuntimeError(f"unsupported filter operation: {operation}")


def snap_feature_independently(feature, substations):
    tolerance = 0.001 * 0.001
    radians = math.pi / 180

    def snap(coordinate):
        best = coordinate
        minimum = math.inf
        latitude_cosine = math.cos(coordinate[1] * radians)
        for candidate in substations:
            dx = (coordinate[0] - candidate[0]) * latitude_cosine
            dy = coordinate[1] - candidate[1]
            distance = dx * dx + dy * dy
            if distance < minimum and distance <= tolerance:
                minimum = distance
                best = candidate
        return list(best)

    transformed = copy.deepcopy(feature)
    geometry = transformed.get("geometry") or {}
    coordinates = geometry.get("coordinates")
    if geometry.get("type") == "LineString" and coordinates:
        coordinates[0] = snap(coordinates[0])
        coordinates[-1] = snap(coordinates[-1])
    elif geometry.get("type") == "MultiLineString":
        for line in coordinates or []:
            if line:
                line[0] = snap(line[0])
                line[-1] = snap(line[-1])
    return transformed


def verify_rows_against_features(connection, path, source, features, retained_keys, original_features=None):
    require(len(features) == source["expected_features"], f"raw feature closure mismatch: {source['source_id']}")
    escaped = sql_string(path)
    rows = connection.execute(
        f"SELECT source_id, feature_index, feature_id, geometry_type, geometry_json, properties_json, "
        f"original_feature_sha256, projected_feature_sha256, min_x, min_y, max_x, max_y "
        f"FROM read_parquet('{escaped}') ORDER BY feature_index"
    ).fetchall()
    require(len(rows) == len(features), f"projected row closure mismatch: {source['source_id']}")
    geometry_counts = Counter()
    property_keys = set()
    coordinate_count = raw_pairs = retained_pairs = 0
    all_coordinates = []
    for index, (row, feature) in enumerate(zip(rows, features, strict=True)):
        require(feature.get("type") == "Feature", f"non-Feature: {source['source_id']}:{index}")
        geometry = feature.get("geometry")
        require(isinstance(geometry, dict) and geometry.get("type") in {"Point", "LineString", "MultiLineString"}, f"bad geometry: {source['source_id']}:{index}")
        coordinates = []
        collect_coordinates(geometry.get("coordinates"), coordinates)
        require(coordinates, f"empty geometry: {source['source_id']}:{index}")
        properties = feature.get("properties") or {}
        require(isinstance(properties, dict), f"bad properties: {source['source_id']}:{index}")
        projected_properties = {key: properties[key] for key in retained_keys if key in properties}
        projected = {"type": "Feature", "geometry": geometry, "properties": projected_properties}
        if feature.get("id") is not None:
            projected["id"] = feature["id"]
        original = feature if original_features is None else original_features[index]
        xs = [item[0] for item in coordinates]
        ys = [item[1] for item in coordinates]
        expected = (
            source["source_id"], index, None if feature.get("id") is None else str(feature["id"]),
            geometry["type"], canonical(geometry), canonical(projected_properties),
            digest_bytes(canonical(original).encode()), digest_bytes(canonical(projected).encode()),
            min(xs), min(ys), max(xs), max(ys),
        )
        require(tuple(row) == expected, f"projected feature mismatch: {source['source_id']}:{index}")
        geometry_counts[geometry["type"]] += 1
        property_keys.update(properties)
        coordinate_count += len(coordinates)
        raw_pairs += len((original.get("properties") or {}))
        retained_pairs += len(projected_properties)
        all_coordinates.extend(coordinates)
    bbox = None
    if all_coordinates:
        bbox = [
            min(item[0] for item in all_coordinates), min(item[1] for item in all_coordinates),
            max(item[0] for item in all_coordinates), max(item[1] for item in all_coordinates),
        ]
    return {
        "geometry_counts": dict(sorted(geometry_counts.items())),
        "coordinate_tuples": coordinate_count,
        "bbox": bbox,
        "property_key_count": len(property_keys),
        "property_schema_sha256": digest_bytes(canonical(sorted(property_keys)).encode()),
        "raw_property_pairs": raw_pairs,
        "retained_property_pairs": retained_pairs,
        "dropped_property_pairs": raw_pairs - retained_pairs,
    }


def validate_contracts(repository):
    plan = load(repository / PLAN)
    layers = load(repository / LAYERS)
    runtime = load(repository / RUNTIME)
    boundary = load(repository / BOUNDARY)
    schema = load(repository / SCHEMA)
    ledger = load(repository / LEDGER)
    require(plan["schema"] == "data-gridatlas.v8-transplant-plan.v1" and plan["generation"] == GENERATION, "plan identity mismatch")
    require(plan["classification"] == "FULL_V8_PARITY_CANDIDATE_ONLY", "plan classification mismatch")
    require(plan["compute"]["python"] == "3.12.13" and plan["compute"]["runner_image"] == "ubuntu-24.04", "compute runtime contract drift")
    for key, value in EXPECTED_CLOSURE.items():
        require(plan["closure"][key] == value, f"plan closure drift: {key}")
    require(len(plan["sources"]) == 56 and len({row["source_id"] for row in plan["sources"]}) == 56, "source ID closure mismatch")
    require(len({row["resolved_path"] for row in plan["sources"]}) == 56, "source path closure mismatch")
    require(sum(row["publishable"] for row in plan["sources"]) == 0, "candidate source marked publishable")
    require(all(HEX40.fullmatch(row["git_blob_sha1"]) and HEX64.fullmatch(row["sha256"]) for row in plan["sources"]), "invalid source identity")
    require(all(safe_relative(row["resolved_path"]) and safe_relative(row["output_partition"]) for row in plan["sources"]), "unsafe source/partition path")
    require(sum(row["wiring"] == "wired" for row in plan["sources"]) == 40, "wired source count mismatch")
    require(sum(row["phase"] == "quarantine" for row in plan["sources"]) == 19, "quarantine source count mismatch")
    by_id = {row["source_id"]: row for row in plan["sources"]}
    require(by_id["grid_11kv_ukpn"]["disposition"] == "QUARANTINED_SYNTHETIC_UKPN_11KV_IDENTITY", "11kV identity not quarantined")
    require(by_id["industrial_offtakers"]["disposition"] == "QUARANTINED_OUTPUT_NOT_REPRODUCIBLE_FROM_ADJACENT_FETCHER", "industry mismatch not quarantined")
    require(by_id["uk_metros_trams_root"]["disposition"] == "QUARANTINED_GEOMETRY_MISMATCH", "metro geometry not quarantined")
    require(by_id["repd_master_v8_oracle"]["disposition"] == "ORACLE_ONLY_REPLACED_BY_OFFICIAL_REPD_V9", "old REPD not oracle-only")
    require(set(plan["property_policy"]["retained_keys"]).isdisjoint(plan["property_policy"]["forbidden_keys"]), "privacy allowlist overlap")
    require(plan["property_policy"]["retained_keys"] == EXPECTED_RETAINED_KEYS, "retained property allowlist drift")
    require(plan["property_policy"]["forbidden_keys"] == EXPECTED_FORBIDDEN_KEYS, "forbidden property policy drift")

    require(layers["schema"] == "data-gridatlas.declarative-layer-config.v1", "layer config schema mismatch")
    flat_layers = [layer for group in layers["groups"] for layer in group["layers"]]
    require(len(layers["groups"]) == 11 and len(flat_layers) == 60, "declarative layer closure mismatch")
    require(len({layer["id"] for layer in flat_layers}) == 60 and len({layer["url"] for layer in flat_layers}) == 40, "layer ID/URL closure mismatch")
    require(sum(bool(layer.get("preload")) for layer in flat_layers) == 12, "preload closure mismatch")
    require(all(layer["v9_data"]["source_id"] in by_id for layer in flat_layers), "layer source mapping gap")
    require(all(layer.get("color") and layer.get("type") in {"point", "line"} for layer in flat_layers), "style contract incomplete")
    require(layers["closure"]["layer_membership_rows"] == 526388, "membership contract drift")
    require(sum(row["selected_features"] for row in ledger["rows"]) == 526388, "legacy membership baseline drift")

    require(runtime["schema"] == "data-gridatlas.v8-runtime-dependencies.v1" and len(runtime["dependencies"]) == 7, "runtime dependency closure mismatch")
    require(runtime["data_repository_payload"] is False and runtime["rules"]["copy_tiles_or_external_payloads"] is False, "runtime copied into data plane")
    require(schema["partition"]["compression"] == "ZSTD" and schema["forbidden_outputs"], "Parquet schema contract mismatch")
    require(
        schema["derived"]["parent_column"] == "original_feature_sha256"
        and schema["derived"]["derived_column"] == "projected_feature_sha256",
        "derived lineage schema mismatch",
    )
    return {"plan": plan, "layers": layers, "runtime": runtime, "boundary": boundary, "schema": schema, "ledger": ledger}


def validate_repository(repository, contracts):
    command = ["git", "-C", str(repository), "ls-files", "--cached", "--others", "--exclude-standard", "-z"]
    observed = sorted(filter(None, subprocess.check_output(command).decode().split("\0")))
    boundary = contracts["boundary"]
    required = set(boundary["expected_tracked_files"])
    successors = set(boundary["allowed_successor_files"])
    release_roots = set(boundary["allowed_live_release_roots"])
    pointers = set(boundary["allowed_pointer_files"])
    observed_set = set(observed)
    require(required <= observed_set, f"required repository source missing: {sorted(required - observed_set)}")
    source_files = {
        relative for relative in observed
        if PurePosixPath(relative).parts[0] not in release_roots and relative not in pointers
    }
    require(source_files <= required | successors, f"repository source allowlist mismatch: {sorted(source_files - required - successors)}")
    total = 0
    forbidden_suffixes = tuple(boundary["forbidden_suffixes"])
    forbidden_roots = set(boundary["forbidden_roots"])
    for relative in sorted(source_files):
        path = repository / relative
        require(path.is_file() and not path.is_symlink(), f"non-regular source: {relative}")
        size = path.stat().st_size
        total += size
        require(size <= boundary["maximum_file_bytes"], f"oversize source: {relative}")
        require(not relative.lower().endswith(forbidden_suffixes), f"generated/raw source: {relative}")
        require(PurePosixPath(relative).parts[0] not in forbidden_roots, f"forbidden source root: {relative}")
    require(total <= boundary["maximum_repository_bytes"], f"repository source too large: {total}")

    release_files = [
        relative for relative in observed
        if PurePosixPath(relative).parts[0] in release_roots
    ]
    release_bytes = 0
    if release_files:
        require(len(release_roots) == 1, "ambiguous live release root")
        release_root = next(iter(release_roots))
        ledger_path = repository / release_root / "sha256sums.txt"
        require(ledger_path.is_file(), "live release SHA ledger missing")
        ledger = {}
        for line in ledger_path.read_text(encoding="utf-8").splitlines():
            digest, relative = line.split(maxsplit=1)
            relative = relative.lstrip("*")
            require(HEX64.fullmatch(digest) and relative not in ledger, "invalid live release SHA ledger")
            ledger[relative] = digest
        expected_release = {f"{release_root}/{relative}" for relative in ledger} | {f"{release_root}/sha256sums.txt"}
        require(set(release_files) == expected_release, "live release file allowlist mismatch")
        for relative in release_files:
            path = repository / relative
            require(path.is_file() and not path.is_symlink(), f"non-regular live release file: {relative}")
            size = path.stat().st_size
            release_bytes += size
            require(size <= boundary["maximum_live_release_file_bytes"], f"oversize live release file: {relative}")
            if path.name != "sha256sums.txt":
                logical = PurePosixPath(relative).relative_to(release_root).as_posix()
                require(hashlib.sha256(path.read_bytes()).hexdigest() == ledger[logical], f"live release SHA mismatch: {relative}")
        require(release_bytes <= boundary["maximum_live_release_bytes"], "live release repository budget exceeded")

    for relative in sorted(observed_set & pointers):
        pointer = load_json(repository / relative)
        require(pointer.get("generation") == "202608291237", f"pointer generation mismatch: {relative}")
        require(pointer.get("release_path") == "202608291237-data-gridatlas/", f"pointer release mismatch: {relative}")

    historical = (repository / ".github/workflows/202608290904-bootstrap-verify-data-gridatlas.yml").read_text(encoding="utf-8")
    historical_trigger_lines = {
        line.strip().removeprefix("- ").strip("'\"")
        for line in historical.splitlines()
        if line.strip().startswith("-")
    }
    for broad in ("contracts/**", "README.md", "requirements.lock", ".gitignore"):
        require(broad not in historical_trigger_lines, f"historical workflow still has broad successor trigger: {broad}")
    current = (repository / ".github/workflows/202608291015-build-v8-transplant-candidate.yml").read_text(encoding="utf-8")
    require("contents: read" in current, "candidate workflow is not read-only")
    for forbidden in ("contents: write", "pages: write", "id-token: write", "pull_request_target", "git push"):
        require(forbidden not in current, f"forbidden workflow capability: {forbidden}")
    action_refs = []
    for line in current.splitlines():
        if line.strip().startswith("uses:"):
            pieces = line.split("@", 1)
            require(len(pieces) == 2 and HEX40.fullmatch(pieces[1].strip()), f"unpinned Action: {line.strip()}")
            action_refs.append(line.strip().removeprefix("uses: "))
    require(
        set(action_refs)
        == {
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
            "actions/cache@55cc8345863c7cc4c66a329aec7e433d2d1c52a9",
            "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131",
        },
        "candidate Action dependency closure mismatch",
    )
    require(current.count("runs-on: ubuntu-24.04") == 3, "hosted runner pin drift")
    require(current.count("python-version: '3.12.13'") == 3, "Python patch pin drift")
    require(current.count("persist-credentials: false") == 3, "checkout credential persistence drift")
    require(current.count("--require-hashes -r requirements.lock") == 3, "hashed install policy drift")
    require(current.count("github.workflow_sha") == 5, "workflow execution identity gap")
    require("push:\n    branches: [main]\n    paths:" in current, "timestamped candidate trigger missing")
    for required_trigger in (
        "'.github/workflows/202608291015-build-v8-transplant-candidate.yml'",
        "'atman/202608291015-verify-v8-transplant.py'",
        "'compiler/202608291015-build-v8-transplant.py'",
        "'contracts/202608291015-repository-boundary.json'",
        "'contracts/202608291015-v8-transplant-plan.json'",
        "'schemas/202608291015-v8-transplant-parquet.json'",
    ):
        require(required_trigger in current, f"candidate trigger input missing: {required_trigger}")
    require("REJECTED-data-gridatlas-202608291015-${{ inputs.expected_source_sha || github.sha }}" in current, "rejected evidence classification missing")
    require("if: steps.atman.outcome == 'success' && steps.final_cas.outcome == 'success'" in current, "accepted artifact gate missing")
    require(
        (repository / "requirements.lock").read_text(encoding="utf-8")
        == "duckdb==1.3.2 \\\n    --hash=sha256:36abdfe0d1704fe09b08d233165f312dad7d7d0ecaaca5fb3bb869f4838a2d0b\n",
        "dependency lock drift",
    )
    return {"tracked_files": len(observed), "tracked_bytes": total, "live_release_bytes": release_bytes}


def parquet_compression(connection, path):
    escaped = sql_string(path)
    return {row[0] for row in connection.execute(f"SELECT DISTINCT compression FROM parquet_metadata('{escaped}')").fetchall()}


def parquet_schema(connection, path):
    escaped = sql_string(path)
    return [(row[0], row[1]) for row in connection.execute(f"DESCRIBE SELECT * FROM read_parquet('{escaped}')").fetchall()]


def validate_partition(connection, path, source, forbidden_keys, scan_privacy=True):
    require(path.is_file(), f"missing partition: {path}")
    require(parquet_schema(connection, path) == FEATURE_COLUMNS, f"partition schema mismatch: {path}")
    escaped = sql_string(path)
    closure = connection.execute(
        f"SELECT count(*), count(DISTINCT feature_index), min(feature_index), max(feature_index), "
        f"count(DISTINCT source_id), min(source_id), count(*) FILTER (WHERE geometry_type NOT IN ('Point','LineString','MultiLineString')), "
        f"count(*) FILTER (WHERE min_x < -180 OR max_x > 180 OR min_y < -90 OR max_y > 90), "
        f"count(*) FILTER (WHERE length(original_feature_sha256)<>64 OR length(projected_feature_sha256)<>64) "
        f"FROM read_parquet('{escaped}')"
    ).fetchone()
    expected = source["expected_features"]
    compression = parquet_compression(connection, path)
    require(
        compression == {"ZSTD"} or (expected == 0 and compression == set()),
        f"partition compression mismatch: {path}",
    )
    expected_min = 0 if expected else None
    expected_max = expected - 1 if expected else None
    require(tuple(closure) == (expected, expected, expected_min, expected_max, 1 if expected else 0, source["source_id"] if expected else None, 0, 0, 0), f"partition closure mismatch: {source['source_id']} {closure}")
    geometry = dict(connection.execute(f"SELECT geometry_type, count(*) FROM read_parquet('{escaped}') GROUP BY 1 ORDER BY 1").fetchall())
    require(geometry == source["geometry_counts"], f"partition geometry mismatch: {source['source_id']}")
    if scan_privacy:
        cursor = connection.execute(f"SELECT properties_json FROM read_parquet('{escaped}')")
        while True:
            batch = cursor.fetchmany(5000)
            if not batch:
                break
            for (value,) in batch:
                properties = loads_strict(value)
                require(isinstance(properties, dict) and canonical(properties) == value, f"non-canonical properties: {source['source_id']}")
                keys = set(properties)
                require(keys.issubset(EXPECTED_RETAINED_KEYS), f"property allowlist escape: {source['source_id']} {keys - set(EXPECTED_RETAINED_KEYS)}")
                require(keys.isdisjoint(forbidden_keys), f"forbidden property escaped: {source['source_id']} {keys & forbidden_keys}")
    return expected


def verify_projected_partition_internal(connection, path, source):
    escaped = sql_string(path)
    cursor = connection.execute(
        f"SELECT source_id, feature_index, geometry_type, geometry_json, properties_json, "
        f"original_feature_sha256, projected_feature_sha256, min_x, min_y, max_x, max_y "
        f"FROM read_parquet('{escaped}') ORDER BY feature_index"
    )
    coordinates_total = retained_pairs = 0
    all_coordinates = []
    expected_index = 0
    allowed = set(EXPECTED_RETAINED_KEYS)
    while True:
        batch = cursor.fetchmany(5000)
        if not batch:
            break
        for row in batch:
            (
                source_id, feature_index, geometry_type, geometry_json, properties_json,
                original_sha256, projected_sha256, min_x, min_y, max_x, max_y,
            ) = row
            require(source_id == source["source_id"] and feature_index == expected_index, f"partition identity mismatch: {source['source_id']}:{expected_index}")
            geometry = loads_strict(geometry_json)
            properties = loads_strict(properties_json)
            require(isinstance(properties, dict) and set(properties).issubset(allowed), f"property allowlist escape: {source['source_id']}:{expected_index}")
            require(canonical(geometry) == geometry_json and canonical(properties) == properties_json, f"non-canonical projected JSON: {source['source_id']}:{expected_index}")
            require(isinstance(geometry, dict) and geometry.get("type") == geometry_type, f"geometry role mismatch: {source['source_id']}:{expected_index}")
            coordinates = []
            collect_coordinates(geometry.get("coordinates"), coordinates)
            require(coordinates, f"empty projected geometry: {source['source_id']}:{expected_index}")
            xs = [item[0] for item in coordinates]
            ys = [item[1] for item in coordinates]
            require((min_x, min_y, max_x, max_y) == (min(xs), min(ys), max(xs), max(ys)), f"projected bbox mismatch: {source['source_id']}:{expected_index}")
            require(HEX64.fullmatch(original_sha256) and HEX64.fullmatch(projected_sha256), f"feature hash format mismatch: {source['source_id']}:{expected_index}")
            coordinates_total += len(coordinates)
            retained_pairs += len(properties)
            all_coordinates.extend(coordinates)
            expected_index += 1
    bbox = None
    if all_coordinates:
        bbox = [
            min(item[0] for item in all_coordinates), min(item[1] for item in all_coordinates),
            max(item[0] for item in all_coordinates), max(item[1] for item in all_coordinates),
        ]
    return {"coordinate_tuples": coordinates_total, "retained_property_pairs": retained_pairs, "bbox": bbox}


def verify_artifact_list(root, manifest):
    artifacts = {row["path"]: row for row in manifest["artifacts"]}
    require(len(artifacts) == len(manifest["artifacts"]), "duplicate artifact path in manifest")
    for relative, item in artifacts.items():
        require(set(item) == {"path", "bytes", "sha256", "schema", "rows"}, f"artifact fields mismatch: {relative}")
        require(safe_relative(relative), f"unsafe artifact path: {relative}")
        require(isinstance(item["bytes"], int) and item["bytes"] > 0, f"invalid artifact bytes: {relative}")
        require(isinstance(item["rows"], int) and item["rows"] >= 0, f"invalid artifact rows: {relative}")
        require(HEX64.fullmatch(item["sha256"]), f"invalid artifact SHA-256: {relative}")
        path = root / relative
        require(path.is_file(), f"manifest artifact missing: {relative}")
        require(path.stat().st_size == item["bytes"] and digest(path) == item["sha256"], f"artifact identity mismatch: {relative}")
    return artifacts


def require_exact_artifact_contract(artifacts, expected):
    require(set(artifacts) == set(expected), f"artifact allowlist mismatch: {sorted(set(artifacts) ^ set(expected))}")
    for path, (schema, rows) in expected.items():
        require(artifacts[path]["schema"] == schema, f"artifact schema mismatch: {path}")
        require(artifacts[path]["rows"] == rows, f"artifact row claim mismatch: {path}")


def changed_snap_counts(raw_rows, derived_rows):
    endpoints = features = 0
    for (raw_value,), (derived_value,) in zip(raw_rows, derived_rows, strict=True):
        raw = loads_strict(raw_value)
        derived = loads_strict(derived_value)
        changed = 0
        if raw["type"] == "LineString":
            changed += raw["coordinates"][0] != derived["coordinates"][0]
            changed += raw["coordinates"][-1] != derived["coordinates"][-1]
        elif raw["type"] == "MultiLineString":
            for raw_line, derived_line in zip(raw["coordinates"], derived["coordinates"], strict=True):
                changed += raw_line[0] != derived_line[0]
                changed += raw_line[-1] != derived_line[-1]
        endpoints += changed
        features += changed > 0
    return endpoints, features


def verify_candidate_derived(connection, output, source, substation_coordinates):
    raw_path = output / source["output_partition"]
    derived_path = output / "derived" / f"{source['source_id']}_snapped.parquet"
    columns = (
        "feature_index, feature_id, geometry_json, properties_json, "
        "original_feature_sha256, projected_feature_sha256"
    )
    raw_rows = connection.execute(
        f"SELECT {columns} FROM read_parquet('{sql_string(raw_path)}') ORDER BY feature_index"
    ).fetchall()
    derived_rows = connection.execute(
        f"SELECT {columns} FROM read_parquet('{sql_string(derived_path)}') ORDER BY feature_index"
    ).fetchall()
    require(len(raw_rows) == len(derived_rows) == source["expected_features"], f"derived row closure mismatch: {source['source_id']}")
    changed_endpoints = changed_features = 0
    substations = {tuple(item) for item in substation_coordinates}
    for raw_row, derived_row in zip(raw_rows, derived_rows, strict=True):
        require(raw_row[0] == derived_row[0] and raw_row[1] == derived_row[1], f"derived identity mismatch: {source['source_id']}:{raw_row[0]}")
        require(raw_row[3] == derived_row[3], f"derived property mutation: {source['source_id']}:{raw_row[0]}")
        require(raw_row[4] == derived_row[4], f"derived parent hash mismatch: {source['source_id']}:{raw_row[0]}")
        raw_geometry = loads_strict(raw_row[2])
        derived_geometry = loads_strict(derived_row[2])
        require(raw_geometry["type"] == derived_geometry["type"], f"derived geometry type mismatch: {source['source_id']}:{raw_row[0]}")
        changed = 0
        raw_lines = [raw_geometry["coordinates"]] if raw_geometry["type"] == "LineString" else raw_geometry["coordinates"]
        derived_lines = [derived_geometry["coordinates"]] if derived_geometry["type"] == "LineString" else derived_geometry["coordinates"]
        require(len(raw_lines) == len(derived_lines), f"derived line closure mismatch: {source['source_id']}:{raw_row[0]}")
        for raw_line, derived_line in zip(raw_lines, derived_lines, strict=True):
            require(len(raw_line) == len(derived_line) and raw_line[1:-1] == derived_line[1:-1], f"derived interior mutation: {source['source_id']}:{raw_row[0]}")
            for position in (0, -1):
                if raw_line[position] != derived_line[position]:
                    require(tuple(derived_line[position]) in substations, f"derived endpoint is not a substation: {source['source_id']}:{raw_row[0]}")
                    changed += 1
        require((raw_row[5] == derived_row[5]) == (changed == 0), f"derived projected hash lineage mismatch: {source['source_id']}:{raw_row[0]}")
        changed_endpoints += changed
        changed_features += changed > 0
    return changed_endpoints, changed_features


def validate_phase_output(output, source_root, repository, contracts):
    manifests = list((output / "phase-manifests").glob("*.json"))
    require(len(manifests) == 1, f"phase manifest count mismatch: {len(manifests)}")
    manifest = load(manifests[0])
    require(manifest["classification"] == "V8_TRANSPLANT_PHASE_CANDIDATE" and manifest["generation"] == GENERATION, "phase classification mismatch")
    require(manifest["release"] is False and manifest["current_pointer"] is False and manifest["raw_outputs"] == 0, "phase attempts publication")
    identity = expected_compute_identity(repository)
    require(manifest["compute_identity"] == identity, "phase compute identity mismatch")
    require(manifest["runtime"] == {**identity["runtime"], "compression": "ZSTD"}, "phase runtime identity mismatch")
    phase = manifest["phase"]
    expected_sources = [row for row in contracts["plan"]["sources"] if row["phase"] == phase]
    require({row["source_id"] for row in manifest["sources"]} == {row["source_id"] for row in expected_sources}, "phase source closure mismatch")
    artifacts = verify_artifact_list(output, manifest)
    expected_artifacts = {}
    for source in expected_sources:
        expected_artifacts[source["output_partition"]] = (
            "data-gridatlas.v8-parity-features.v1", source["expected_features"]
        )
        membership_rows = sum(
            row["selected_features"] for row in contracts["ledger"]["rows"]
            if row["layer_id"] in source["layer_ids"]
        )
        expected_artifacts[f"memberships/{source['source_id']}.parquet"] = (
            "data-gridatlas.v8-layer-membership.v1", membership_rows
        )
        if source["source_id"] in SNAP_EXPECTED:
            expected_artifacts[f"derived/{source['source_id']}_snapped.parquet"] = (
                "data-gridatlas.v8-snapped-topology.v1", source["expected_features"]
            )
    require_exact_artifact_contract(artifacts, expected_artifacts)
    observed_files = {path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()}
    require(observed_files == set(artifacts) | {manifests[0].relative_to(output).as_posix()}, "phase output allowlist mismatch")
    require(not any(path.lower().endswith((".geojson", ".csv", ".duckdb")) for path in observed_files), "raw phase output")

    connection = duckdb.connect()
    connection.execute("PRAGMA threads=1")
    forbidden_keys = set(contracts["plan"]["property_policy"]["forbidden_keys"])
    retained_keys = contracts["plan"]["property_policy"]["retained_keys"]
    layers_by_source = {}
    for group in contracts["layers"]["groups"]:
        for layer in group["layers"]:
            layers_by_source.setdefault(layer["v9_data"]["source_id"], []).append(layer)
    ledger_counts = {row["layer_id"]: row["selected_features"] for row in contracts["ledger"]["rows"]}
    total_features = total_memberships = 0
    total_coordinates = total_raw_pairs = total_retained_pairs = total_dropped_pairs = 0
    raw_objects = {}
    expected_manifest_sources = []
    expected_layer_counts = {}
    for source in expected_sources:
        raw = read_oracle_source(source, source_root)
        raw_objects[source["source_id"]] = raw
        total_features += validate_partition(connection, output / source["output_partition"], source, forbidden_keys)
        metrics = verify_rows_against_features(
            connection, output / source["output_partition"], source, raw["features"], retained_keys
        )
        for key in (
            "geometry_counts", "coordinate_tuples", "bbox", "property_key_count", "property_schema_sha256",
            "raw_property_pairs", "retained_property_pairs", "dropped_property_pairs",
        ):
            require(metrics[key] == source[key], f"raw/projected source contract mismatch: {source['source_id']} {key}")
        total_coordinates += metrics["coordinate_tuples"]
        total_raw_pairs += metrics["raw_property_pairs"]
        total_retained_pairs += metrics["retained_property_pairs"]
        total_dropped_pairs += metrics["dropped_property_pairs"]

        membership = output / "memberships" / f"{source['source_id']}.parquet"
        escaped = sql_string(membership)
        observed_schema = [
            (row[0], row[1])
            for row in connection.execute(f"DESCRIBE SELECT * FROM read_parquet('{escaped}')").fetchall()
        ]
        require(observed_schema == MEMBERSHIP_COLUMNS, f"membership schema mismatch: {source['source_id']}")
        observed_memberships = connection.execute(
            f"SELECT layer_id, source_id, feature_index FROM read_parquet('{escaped}') "
            "ORDER BY layer_id, source_id, feature_index"
        ).fetchall()
        rows = len(observed_memberships)
        compression = parquet_compression(connection, membership)
        require(
            compression == {"ZSTD"} or (rows == 0 and compression == set()),
            f"membership compression mismatch: {source['source_id']}",
        )
        total_memberships += rows
        expected_memberships = []
        for layer in layers_by_source.get(source["source_id"], []):
            selected = 0
            for index, feature in enumerate(raw["features"]):
                properties = feature.get("properties") or {}
                if layer.get("filter") is None or bool(evaluate_filter(layer["filter"], properties)):
                    expected_memberships.append((layer["id"], source["source_id"], index))
                    selected += 1
            require(selected == ledger_counts[layer["id"]], f"independent layer filter drift: {layer['id']} {selected}")
            expected_layer_counts[layer["id"]] = selected
        expected_memberships.sort()
        require(observed_memberships == expected_memberships, f"membership identity mismatch: {source['source_id']}")
        expected_manifest_sources.append(
            {
                "source_id": source["source_id"], "input_bytes": source["bytes"],
                "input_sha256": source["sha256"], "input_git_blob_sha1": source["git_blob_sha1"],
                "features": source["expected_features"], "memberships": len(expected_memberships),
                "retained_property_pairs": source["retained_property_pairs"],
                "dropped_property_pairs": source["dropped_property_pairs"], "disposition": source["disposition"],
            }
        )
    require(manifest["sources"] == sorted(expected_manifest_sources, key=lambda row: row["source_id"]), "phase manifest source evidence mismatch")
    require(manifest["layer_counts"] == dict(sorted(expected_layer_counts.items())), "phase manifest layer evidence mismatch")

    expected_snap_manifest = {}
    for source_id, expected in SNAP_EXPECTED.items():
        if any(row["source_id"] == source_id for row in expected_sources):
            source = next(row for row in expected_sources if row["source_id"] == source_id)
            derived = output / "derived" / f"{source_id}_snapped.parquet"
            validate_partition(connection, derived, source, forbidden_keys, scan_privacy=False)
            substations = [
                feature["geometry"]["coordinates"]
                for feature in raw_objects["grid_substations"]["features"]
            ]
            independently_snapped = [
                snap_feature_independently(feature, substations)
                for feature in raw_objects[source_id]["features"]
            ]
            verify_rows_against_features(
                connection, derived, source, independently_snapped, retained_keys,
                original_features=raw_objects[source_id]["features"],
            )
            raw_path = output / source["output_partition"]
            raw = connection.execute(f"SELECT geometry_json FROM read_parquet('{sql_string(raw_path)}') ORDER BY feature_index").fetchall()
            transformed = connection.execute(f"SELECT geometry_json FROM read_parquet('{sql_string(derived)}') ORDER BY feature_index").fetchall()
            require(changed_snap_counts(raw, transformed) == expected, f"independent snap parity mismatch: {source_id}")
            expected_snap_manifest[source_id] = {"changed_endpoints": expected[0], "changed_features": expected[1]}
    require(manifest["snap_counts"] == expected_snap_manifest, "phase manifest snap evidence mismatch")
    connection.close()
    expected_summary = contracts["plan"]["closure"]["phase_summary"][phase]
    require(total_features == expected_summary["features"], f"phase feature closure mismatch: {phase}")
    return {
        "phase": phase, "sources": len(expected_sources), "features": total_features,
        "memberships": total_memberships, "coordinate_tuples": total_coordinates,
        "raw_property_pairs": total_raw_pairs, "retained_property_pairs": total_retained_pairs,
        "dropped_property_pairs": total_dropped_pairs, "artifacts": len(artifacts),
    }


def validate_candidate(output, phase_input, repository, contracts):
    manifest = load(output / "manifest.json")
    require(manifest["classification"] == "FULL_V8_TRANSPLANT_CANDIDATE" and manifest["generation"] == GENERATION, "candidate classification mismatch")
    require(manifest["release"] is False and manifest["current_pointer"] is False and manifest["pages_publication"] is False, "candidate attempts promotion")
    require(manifest["raw_geojson_outputs"] == 0 and manifest["v8_untouched"] is True, "candidate boundary mismatch")
    identity = expected_compute_identity(repository)
    require(manifest["compute_identity"] == identity, "candidate compute identity mismatch")
    require(manifest["runtime"] == {**identity["runtime"], "compression": "ZSTD"}, "candidate runtime identity mismatch")
    require(manifest["contracts"] == identity["inputs"], "candidate input closure mismatch")
    repository_commit = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    require(manifest["repository_source_commit"] == repository_commit, "candidate repository source mismatch")
    for key, value in EXPECTED_CLOSURE.items():
        require(manifest["closure"][key] == value, f"candidate closure drift: {key}")
    artifacts = verify_artifact_list(output, manifest)
    expected_artifacts = {
        source["output_partition"]: ("data-gridatlas.v8-parity-features.v1", source["expected_features"])
        for source in contracts["plan"]["sources"]
    }
    expected_artifacts.update(
        {
            f"derived/{source_id}_snapped.parquet": (
                "data-gridatlas.v8-snapped-topology.v1",
                next(row["expected_features"] for row in contracts["plan"]["sources"] if row["source_id"] == source_id),
            )
            for source_id in SNAP_EXPECTED
        }
    )
    expected_artifacts.update(
        {
            "layer_membership.parquet": ("data-gridatlas.v8-layer-membership.v1", 526388),
            "sources.parquet": ("data-gridatlas.sources.v1", 56),
            "layers.parquet": ("data-gridatlas.layers.v2", 60),
            "quarantine.parquet": ("data-gridatlas.quarantine.v2", 20),
            "browser-layer-registry.json": ("data-gridatlas.browser-layer-registry.v1", 60),
        }
    )
    for phase_name, summary in contracts["plan"]["closure"]["phase_summary"].items():
        expected_artifacts[f"phase-manifests/{phase_name}.json"] = (
            "data-gridatlas.v8-transplant-phase-manifest.v1", summary["sources"]
        )
    require_exact_artifact_contract(artifacts, expected_artifacts)
    observed_files = {path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()}
    require(observed_files == set(artifacts) | {"manifest.json"}, "candidate output allowlist mismatch")
    require(not any(path.lower().endswith((".geojson", ".csv", ".xlsx", ".duckdb", ".zip")) for path in observed_files), "raw/generated candidate escape")
    for item in manifest["contracts"]:
        path = repository / item["path"]
        require(path.is_file() and path.stat().st_size == item["bytes"] and digest(path) == item["sha256"], f"candidate contract mismatch: {item['path']}")

    connection = duckdb.connect()
    connection.execute("PRAGMA threads=1")
    forbidden_keys = set(contracts["plan"]["property_policy"]["forbidden_keys"])
    total_features = total_coordinates = total_retained_pairs = 0
    partition_paths = []
    for source in contracts["plan"]["sources"]:
        path = output / source["output_partition"]
        total_features += validate_partition(connection, path, source, forbidden_keys)
        metrics = verify_projected_partition_internal(connection, path, source)
        require(metrics["coordinate_tuples"] == source["coordinate_tuples"], f"candidate coordinate closure mismatch: {source['source_id']}")
        require(metrics["retained_property_pairs"] == source["retained_property_pairs"], f"candidate property closure mismatch: {source['source_id']}")
        require(metrics["bbox"] == source["bbox"], f"candidate bbox closure mismatch: {source['source_id']}")
        total_coordinates += metrics["coordinate_tuples"]
        total_retained_pairs += metrics["retained_property_pairs"]
        partition_paths.append(path)
    require(total_features == 541282, "candidate feature closure mismatch")
    require(total_coordinates == 3812791, "candidate coordinate tuple closure mismatch")
    require(total_retained_pairs == 1064163, "candidate retained property closure mismatch")
    union_sql = ",".join(f"'{sql_string(path)}'" for path in partition_paths)
    geometry = dict(connection.execute(f"SELECT geometry_type, count(*) FROM read_parquet([{union_sql}]) GROUP BY 1 ORDER BY 1").fetchall())
    require(geometry == EXPECTED_CLOSURE["geometry_counts"], f"candidate geometry closure mismatch: {geometry}")
    substation_source = next(row for row in contracts["plan"]["sources"] if row["source_id"] == "grid_substations")
    substation_rows = connection.execute(
        f"SELECT geometry_json FROM read_parquet('{sql_string(output / substation_source['output_partition'])}') ORDER BY feature_index"
    ).fetchall()
    substation_coordinates = [loads_strict(row[0])["coordinates"] for row in substation_rows]
    for source_id, expected_snap in SNAP_EXPECTED.items():
        source = next(row for row in contracts["plan"]["sources"] if row["source_id"] == source_id)
        derived = output / "derived" / f"{source_id}_snapped.parquet"
        validate_partition(connection, derived, source, forbidden_keys)
        derived_metrics = verify_projected_partition_internal(connection, derived, source)
        require(derived_metrics["coordinate_tuples"] == source["coordinate_tuples"], f"derived coordinate closure mismatch: {source_id}")
        require(derived_metrics["retained_property_pairs"] == source["retained_property_pairs"], f"derived property closure mismatch: {source_id}")
        require(verify_candidate_derived(connection, output, source, substation_coordinates) == expected_snap, f"derived topology parity mismatch: {source_id}")

    membership = output / "layer_membership.parquet"
    require(parquet_compression(connection, membership) == {"ZSTD"}, "candidate membership compression mismatch")
    expected_phase_memberships = {
        f"memberships/{source['source_id']}.parquet" for source in contracts["plan"]["sources"]
    }
    observed_phase_memberships = {
        path.relative_to(phase_input).as_posix() for path in (phase_input / "memberships").glob("*.parquet")
    }
    require(observed_phase_memberships == expected_phase_memberships, "phase membership input closure mismatch")
    phase_membership_paths = sorted(phase_input / relative for relative in expected_phase_memberships)
    phase_membership_sql = ",".join(f"'{sql_string(path)}'" for path in phase_membership_paths)
    membership_difference = connection.execute(
        f"SELECT count(*) FROM ("
        f"SELECT c.present AS candidate_present, p.present AS phase_present FROM "
        f"(SELECT layer_id, source_id, feature_index, 1 AS present FROM read_parquet('{sql_string(membership)}')) c "
        f"FULL OUTER JOIN "
        f"(SELECT layer_id, source_id, feature_index, 1 AS present FROM read_parquet([{phase_membership_sql}])) p "
        f"ON c.layer_id=p.layer_id AND c.source_id=p.source_id AND c.feature_index=p.feature_index "
        f"WHERE c.present IS NULL OR p.present IS NULL)"
    ).fetchone()[0]
    require(membership_difference == 0, "candidate membership is not the exact phase union")
    membership_closure = connection.execute(
        f"SELECT count(*), count(DISTINCT layer_id), count(DISTINCT source_id) FROM read_parquet('{sql_string(membership)}')"
    ).fetchone()
    require(tuple(membership_closure) == (526388, 59, 40), f"candidate membership closure mismatch: {membership_closure}")
    observed_membership_layers = {
        row[0]
        for row in connection.execute(
            f"SELECT DISTINCT layer_id FROM read_parquet('{sql_string(membership)}')"
        ).fetchall()
    }
    expected_membership_layers = {
        row["layer_id"] for row in contracts["ledger"]["rows"] if row["selected_features"] > 0
    }
    require(observed_membership_layers == expected_membership_layers, "candidate membership layer set mismatch")
    sources = output / "sources.parquet"
    layers = output / "layers.parquet"
    quarantine = output / "quarantine.parquet"
    for path in (sources, layers, quarantine):
        require(parquet_compression(connection, path) == {"ZSTD"}, f"registry compression mismatch: {path.name}")
    source_closure = connection.execute(
        f"SELECT count(*), count(DISTINCT source_id), sum(features), count(*) FILTER (WHERE publishable) FROM read_parquet('{sql_string(sources)}')"
    ).fetchone()
    require(tuple(source_closure) == (56, 56, 541282, 0), f"source registry closure mismatch: {source_closure}")
    observed_source_rows = connection.execute(
        f"SELECT source_id, phase, wiring, resolved_path, input_bytes, input_sha256, input_git_blob_sha1, "
        f"features, geometry_counts_json, bbox_json, partition_path, authority_state, licence_state, disposition, publishable "
        f"FROM read_parquet('{sql_string(sources)}') ORDER BY source_id"
    ).fetchall()
    expected_source_rows = sorted(
        [
            (
                source["source_id"], source["phase"], source["wiring"], source["resolved_path"], source["bytes"],
                source["sha256"], source["git_blob_sha1"], source["expected_features"],
                canonical(source["geometry_counts"]), canonical(source["bbox"]), source["output_partition"],
                source["authority_state"], source["licence_state"], source["disposition"], source["publishable"],
            )
            for source in contracts["plan"]["sources"]
        ],
        key=lambda row: row[0],
    )
    require(observed_source_rows == expected_source_rows, "source registry row mismatch")
    layer_closure = connection.execute(
        f"SELECT count(*), count(DISTINCT layer_id), count(DISTINCT source_id), count(*) FILTER (WHERE preload), count(*) FILTER (WHERE publishable) FROM read_parquet('{sql_string(layers)}')"
    ).fetchone()
    require(tuple(layer_closure) == (60, 60, 40, 12, 0), f"layer registry closure mismatch: {layer_closure}")
    observed_layer_rows = connection.execute(
        f"SELECT group_index, group_name, layer_index, layer_id, label, geometry_role, color, source_id, "
        f"parquet_path, preload, minzoom, width, radius_json, filter_json, snap, is_substations, disposition, publishable "
        f"FROM read_parquet('{sql_string(layers)}') ORDER BY group_index, layer_index"
    ).fetchall()
    expected_layer_rows = []
    for group_index, group in enumerate(contracts["layers"]["groups"]):
        for layer_index, layer in enumerate(group["layers"]):
            parquet_path = layer["v9_data"]["parquet_path"]
            if layer.get("snap"):
                parquet_path = f"derived/{layer['v9_data']['source_id']}_snapped.parquet"
            expected_layer_rows.append(
                (
                    group_index, group["group"], layer_index, layer["id"], layer["label"], layer["type"],
                    layer["color"], layer["v9_data"]["source_id"], parquet_path, bool(layer.get("preload")),
                    layer.get("minzoom"), layer.get("width"), canonical(layer.get("radius")),
                    canonical(layer.get("filter")), bool(layer.get("snap")), bool(layer.get("isSubs")),
                    layer["v9_data"]["disposition"], False,
                )
            )
    require(observed_layer_rows == expected_layer_rows, "layer registry row mismatch")
    quarantine_count = connection.execute(f"SELECT count(*) FROM read_parquet('{sql_string(quarantine)}')").fetchone()[0]
    require(quarantine_count == 20, f"quarantine registry closure mismatch: {quarantine_count}")
    observed_quarantine_rows = connection.execute(
        f"SELECT source_id, phase, disposition, reason FROM read_parquet('{sql_string(quarantine)}') ORDER BY source_id"
    ).fetchall()
    expected_quarantine_rows = sorted(
        [
            (source["source_id"], source["phase"], source["disposition"], source["provenance_note"])
            for source in contracts["plan"]["sources"]
            if source["phase"] == "quarantine" or source["disposition"].startswith("ORACLE_ONLY")
        ],
        key=lambda row: row[0],
    )
    require(observed_quarantine_rows == expected_quarantine_rows, "quarantine registry row mismatch")

    membership_counts = dict(
        connection.execute(
            f"SELECT layer_id, count(*) FROM read_parquet('{sql_string(membership)}') GROUP BY layer_id ORDER BY layer_id"
        ).fetchall()
    )
    expected_membership_counts = {
        row["layer_id"]: row["selected_features"] for row in contracts["ledger"]["rows"]
        if row["selected_features"] > 0
    }
    require(membership_counts == expected_membership_counts, "candidate per-layer membership count mismatch")
    duplicate_memberships = connection.execute(
        f"SELECT count(*) FROM (SELECT layer_id, source_id, feature_index, count(*) AS n "
        f"FROM read_parquet('{sql_string(membership)}') GROUP BY 1,2,3 HAVING n <> 1)"
    ).fetchone()[0]
    require(duplicate_memberships == 0, "duplicate candidate membership")
    observed_layer_sources = set(
        connection.execute(
            f"SELECT DISTINCT layer_id, source_id FROM read_parquet('{sql_string(membership)}')"
        ).fetchall()
    )
    expected_layer_sources = {
        (layer["id"], layer["v9_data"]["source_id"])
        for group in contracts["layers"]["groups"] for layer in group["layers"]
        if expected_membership_counts.get(layer["id"], 0) > 0
    }
    require(observed_layer_sources == expected_layer_sources, "candidate membership layer/source mapping mismatch")
    for path in output.rglob("*.parquet"):
        compression = parquet_compression(connection, path)
        if compression == set():
            rows = connection.execute(
                f"SELECT count(*) FROM read_parquet('{sql_string(path)}')"
            ).fetchone()[0]
            require(rows == 0, f"Parquet has no codec metadata but is not empty: {path}")
        else:
            require(compression == {"ZSTD"}, f"non-ZSTD Parquet: {path}")
    connection.close()

    browser = load(output / "browser-layer-registry.json")
    flat = [layer for group in browser["groups"] for layer in group["layers"]]
    require(browser["classification"] == "CANDIDATE_NOT_LIVE" and browser["raw_urls"] is False, "browser registry classification mismatch")
    require(len(browser["groups"]) == 11 and len(flat) == 60, "browser registry layer closure mismatch")
    require(all(layer["url"] is None and safe_relative(layer["v9_data"]["parquet_path"]) and layer["v9_data"]["parquet_path"].endswith(".parquet") for layer in flat), "browser registry has floating/raw URL")
    require(all(layer["enabled"] is False and layer["publishable"] is False for layer in flat), "browser candidate layer activation escaped")
    expected_browser_groups = copy.deepcopy(contracts["layers"]["groups"])
    expected_paths = {row[3]: row[8] for row in expected_layer_rows}
    for group in expected_browser_groups:
        for layer in group["layers"]:
            layer["v9_data"]["parquet_path"] = expected_paths[layer["id"]]
            layer["url"] = None
            layer["enabled"] = False
            layer["publishable"] = False
    expected_browser = {
        "schema": "data-gridatlas.browser-layer-registry.v1", "generation": GENERATION,
        "classification": "CANDIDATE_NOT_LIVE", "map": contracts["layers"]["map"],
        "groups": expected_browser_groups, "raw_urls": False, "release": False, "current_pointer": False,
    }
    require(browser == expected_browser, "browser registry row mismatch")
    phase_paths = sorted((output / "phase-manifests").glob("*.json"))
    require({path.stem for path in phase_paths} == set(contracts["plan"]["compute"]["phases"]), "candidate phase manifest closure mismatch")
    base_identity = expected_compute_identity(repository)
    ledger_counts = {row["layer_id"]: row["selected_features"] for row in contracts["ledger"]["rows"]}
    for path in phase_paths:
        phase_manifest = load(path)
        phase = path.stem
        require(
            phase_manifest["schema"] == "data-gridatlas.v8-transplant-phase-manifest.v1"
            and phase_manifest["generation"] == GENERATION
            and phase_manifest["classification"] == "V8_TRANSPLANT_PHASE_CANDIDATE"
            and phase_manifest["phase"] == phase,
            f"embedded phase identity mismatch: {phase}",
        )
        require(
            phase_manifest["release"] is False and phase_manifest["current_pointer"] is False
            and phase_manifest["raw_outputs"] == 0 and phase_manifest["v8_untouched"] is True,
            f"embedded phase publication mismatch: {phase}",
        )
        phase_identity = copy.deepcopy(phase_manifest["compute_identity"])
        key = phase_identity.pop("key_sha256")
        require(key == digest_bytes(canonical(phase_identity).encode()), f"embedded phase compute key mismatch: {phase}")
        require(
            phase_identity["repository"] == base_identity["repository"]
            and phase_identity["v8_repository"] == base_identity["v8_repository"]
            and phase_identity["v8_commit"] == base_identity["v8_commit"]
            and phase_identity["inputs"] == base_identity["inputs"],
            f"embedded phase input identity mismatch: {phase}",
        )
        require(
            phase_identity["runtime"]["python"] == "3.12.13"
            and phase_identity["runtime"]["duckdb"] == "1.3.2"
            and phase_identity["runtime"]["threads"] == 1,
            f"embedded phase runtime mismatch: {phase}",
        )
        require(phase_manifest["runtime"] == {**phase_identity["runtime"], "compression": "ZSTD"}, f"embedded phase runtime receipt mismatch: {phase}")
        expected_sources = [source for source in contracts["plan"]["sources"] if source["phase"] == phase]
        expected_phase_sources = sorted(
            [
                {
                    "source_id": source["source_id"], "input_bytes": source["bytes"],
                    "input_sha256": source["sha256"], "input_git_blob_sha1": source["git_blob_sha1"],
                    "features": source["expected_features"],
                    "memberships": sum(ledger_counts[layer_id] for layer_id in source["layer_ids"]),
                    "retained_property_pairs": source["retained_property_pairs"],
                    "dropped_property_pairs": source["dropped_property_pairs"], "disposition": source["disposition"],
                }
                for source in expected_sources
            ],
            key=lambda row: row["source_id"],
        )
        require(phase_manifest["sources"] == expected_phase_sources, f"embedded phase source mismatch: {phase}")
        phase_layer_ids = {layer_id for source in expected_sources for layer_id in source["layer_ids"]}
        expected_phase_layer_counts = {layer_id: ledger_counts[layer_id] for layer_id in sorted(phase_layer_ids)}
        require(phase_manifest["layer_counts"] == expected_phase_layer_counts, f"embedded phase layer mismatch: {phase}")
        expected_phase_snaps = {
            source_id: {"changed_endpoints": values[0], "changed_features": values[1]}
            for source_id, values in SNAP_EXPECTED.items()
            if any(source["source_id"] == source_id for source in expected_sources)
        }
        require(phase_manifest["snap_counts"] == expected_phase_snaps, f"embedded phase snap mismatch: {phase}")
        phase_artifacts = {item["path"]: item for item in phase_manifest["artifacts"]}
        require(len(phase_artifacts) == len(phase_manifest["artifacts"]), f"embedded duplicate artifact: {phase}")
        expected_phase_artifacts = {}
        for source in expected_sources:
            expected_phase_artifacts[source["output_partition"]] = ("data-gridatlas.v8-parity-features.v1", source["expected_features"])
            expected_phase_artifacts[f"memberships/{source['source_id']}.parquet"] = (
                "data-gridatlas.v8-layer-membership.v1", sum(ledger_counts[layer_id] for layer_id in source["layer_ids"])
            )
            if source["source_id"] in SNAP_EXPECTED:
                expected_phase_artifacts[f"derived/{source['source_id']}_snapped.parquet"] = (
                    "data-gridatlas.v8-snapped-topology.v1", source["expected_features"]
                )
        require_exact_artifact_contract(phase_artifacts, expected_phase_artifacts)
        for relative, item in phase_artifacts.items():
            require(HEX64.fullmatch(item["sha256"]), f"embedded phase artifact hash mismatch: {phase}:{relative}")
            if relative in artifacts:
                require(item == artifacts[relative], f"embedded/candidate artifact mismatch: {phase}:{relative}")
    total_bytes = sum(path.stat().st_size for path in output.rglob("*") if path.is_file())
    require(total_bytes < 350_000_000, f"candidate exceeds 350 MB: {total_bytes}")
    return {"sources": 56, "features": total_features, "memberships": 526388, "artifacts": len(artifacts), "bytes": total_bytes}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=".")
    parser.add_argument("--phase-output")
    parser.add_argument("--source-root")
    parser.add_argument("--candidate")
    parser.add_argument("--phase-input")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    repository = Path(args.repository).resolve()
    contracts = validate_contracts(repository)
    checks = {"repository": validate_repository(repository, contracts), "contracts": {"sources": 56, "layers": 60, "features": 541282}}
    classification = "VERIFIED_V8_TRANSPLANT_SOURCE"
    if args.phase_output:
        require(args.source_root, "--source-root is required with --phase-output")
        checks["phase"] = validate_phase_output(
            Path(args.phase_output).resolve(), Path(args.source_root).resolve(), repository, contracts
        )
        classification = "VERIFIED_V8_TRANSPLANT_PHASE"
    if args.candidate:
        require(args.phase_input, "--phase-input is required with --candidate")
        checks["candidate"] = validate_candidate(
            Path(args.candidate).resolve(), Path(args.phase_input).resolve(), repository, contracts
        )
        classification = "VERIFIED_FULL_V8_TRANSPLANT_CANDIDATE"
    proof = {
        "schema": "data-gridatlas.v8-transplant-verification.v1", "generation": GENERATION,
        "classification": classification, "checks": checks, "failed": 0,
        "runtime": {"python": platform.python_version(), "duckdb": duckdb.__version__},
        "repository_source_commit": subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
        ).strip(),
        "release": False, "current_pointer": False, "v8_untouched": True,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(proof, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(proof, sort_keys=True))


if __name__ == "__main__":
    main()
