#!/usr/bin/env python3
"""Build the full, evidence-only V8 dependency transplant candidate."""

import argparse
import copy
import hashlib
import json
import math
import os
import platform
import shutil
import struct
import subprocess
import tempfile
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

import duckdb


GENERATION = "202608291015"
PLAN_PATH = Path("contracts/202608291015-v8-transplant-plan.json")
LAYERS_PATH = Path("contracts/202608291015-v8-layer-config.json")
SCHEMA_PATH = Path("schemas/202608291015-v8-transplant-parquet.json")
LEDGER_PATH = Path("contracts/202608290904-v8-dependency-ledger.json")
COMPUTE_INPUT_PATHS = [
    PLAN_PATH,
    LAYERS_PATH,
    Path("contracts/202608291015-v8-runtime-dependencies.json"),
    Path("contracts/202608291015-repository-boundary.json"),
    SCHEMA_PATH,
    LEDGER_PATH,
    Path("contracts/202608290904-v8-file-ledger.json"),
    Path("contracts/202608290904-v8-quarantine.json"),
    Path("compiler/202608291015-build-v8-transplant.py"),
    Path("atman/202608291015-verify-v8-transplant.py"),
    Path(".github/workflows/202608291015-build-v8-transplant-candidate.yml"),
    Path("requirements.lock"),
]
V8_REPOSITORY = "Ventusltd/globalgrid2050"
V8_COMMIT = "f2f343a92ee972cc74ed23b4b99d8a22896791ad"
SNAP_EXPECTED = {
    "grid_400kv": (4528, 2679),
    "grid_275kv": (3806, 2212),
    "grid_220kv": (150, 93),
    "grid_132kv": (7218, 4342),
    "grid_66kv": (1353, 828),
}


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def git_blob_oid(payload):
    return hashlib.sha1(f"blob {len(payload)}\0".encode() + payload).hexdigest()


def load(path):
    return json.loads(path.read_text(encoding="utf-8"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sql_string(value):
    return str(value).replace("'", "''")


def artifact(path, root, schema, rows):
    return {
        "path": path.relative_to(root).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": digest(path),
        "schema": schema,
        "rows": rows,
    }


def compute_identity(repository):
    inputs = [
        {"path": path.as_posix(), "bytes": (repository / path).stat().st_size, "sha256": digest(repository / path)}
        for path in COMPUTE_INPUT_PATHS
    ]
    identity = {
        "repository": "Ventusltd/data-gridatlas",
        "v8_repository": V8_REPOSITORY,
        "v8_commit": V8_COMMIT,
        "runtime": {
            "python": platform.python_version(), "duckdb": duckdb.__version__, "threads": 1,
            "runner_image_os": os.environ.get("ImageOS"), "runner_image_version": os.environ.get("ImageVersion"),
        },
        "inputs": inputs,
    }
    identity["key_sha256"] = digest_bytes(canonical(identity).encode())
    return identity


def fetch_phase_sources(plan, phase, source_root):
    source_root.mkdir(parents=True, exist_ok=True)
    fetched = []
    for source in [row for row in plan["sources"] if row["phase"] == phase]:
        target = source_root / source["resolved_path"]
        if target.exists():
            payload = target.read_bytes()
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            quoted = urllib.parse.quote(source["resolved_path"], safe="/")
            url = f"https://raw.githubusercontent.com/{V8_REPOSITORY}/{V8_COMMIT}/{quoted}"
            request = urllib.request.Request(url, headers={"User-Agent": "data-gridatlas-pinned-transplant/1"})
            with urllib.request.urlopen(request, timeout=180) as response:
                payload = response.read()
            target.write_bytes(payload)
        verify_source_bytes(source, payload)
        fetched.append({"source_id": source["source_id"], "bytes": len(payload), "sha256": digest_bytes(payload)})
    print(canonical({"classification": "FETCHED_PINNED_PHASE", "phase": phase, "sources": fetched}))


def verify_source_bytes(source, payload):
    require(len(payload) == source["bytes"], f"source byte drift: {source['source_id']}")
    require(digest_bytes(payload) == source["sha256"], f"source SHA-256 drift: {source['source_id']}")
    require(git_blob_oid(payload) == source["git_blob_sha1"], f"source Git blob drift: {source['source_id']}")


def read_source(source, source_root, git_repository=None):
    path = source_root / source["resolved_path"]
    if path.is_file():
        payload = path.read_bytes()
    elif git_repository:
        payload = subprocess.check_output(
            ["git", "-C", str(git_repository), "show", f"{V8_COMMIT}:{source['resolved_path']}"]
        )
    else:
        raise RuntimeError(f"source not materialised: {source['resolved_path']}")
    verify_source_bytes(source, payload)
    obj = json.loads(payload, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    require(obj.get("type") == "FeatureCollection" and isinstance(obj.get("features"), list), f"not FeatureCollection: {source['source_id']}")
    return obj


def coordinate_tuples(node, output):
    if isinstance(node, list) and len(node) >= 2 and all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in node[:2]):
        require(len(node) == 2, "non-2D coordinate in V8 candidate")
        x, y = float(node[0]), float(node[1])
        require(math.isfinite(x) and math.isfinite(y), "non-finite coordinate")
        require(-180 <= x <= 180 and -90 <= y <= 90, f"coordinate outside WGS84 range: {(x, y)}")
        output.append((x, y))
    elif isinstance(node, list):
        for child in node:
            coordinate_tuples(child, output)


def evaluate(expression, properties):
    if not isinstance(expression, list):
        return expression
    operation = expression[0]
    if operation == "get":
        return properties.get(expression[1])
    if operation == "==":
        return evaluate(expression[1], properties) == evaluate(expression[2], properties)
    if operation == "!=":
        return evaluate(expression[1], properties) != evaluate(expression[2], properties)
    if operation == "all":
        return all(bool(evaluate(item, properties)) for item in expression[1:])
    if operation == "any":
        return any(bool(evaluate(item, properties)) for item in expression[1:])
    if operation == "!":
        return not bool(evaluate(expression[1], properties))
    if operation == "in":
        needle = evaluate(expression[1], properties)
        haystack = evaluate(expression[2], properties)
        try:
            return needle in haystack
        except TypeError:
            return False
    raise RuntimeError(f"unsupported V8 filter operation: {operation}")


def feature_row(source_id, feature_index, feature, retained_keys, original_feature=None):
    require(feature.get("type") == "Feature", f"non-Feature at {source_id}:{feature_index}")
    geometry = feature.get("geometry")
    require(isinstance(geometry, dict) and geometry.get("type") in {"Point", "LineString", "MultiLineString"}, f"bad geometry at {source_id}:{feature_index}")
    coordinates = []
    coordinate_tuples(geometry.get("coordinates"), coordinates)
    require(coordinates, f"empty geometry at {source_id}:{feature_index}")
    properties = feature.get("properties") or {}
    require(isinstance(properties, dict), f"bad properties at {source_id}:{feature_index}")
    projected_properties = {key: properties[key] for key in retained_keys if key in properties}
    projected = {"type": "Feature", "geometry": geometry, "properties": projected_properties}
    if feature.get("id") is not None:
        projected["id"] = feature["id"]
    xs = [item[0] for item in coordinates]
    ys = [item[1] for item in coordinates]
    return {
        "source_id": source_id,
        "feature_index": feature_index,
        "feature_id": None if feature.get("id") is None else str(feature["id"]),
        "geometry_type": geometry["type"],
        "geometry_json": canonical(geometry),
        "properties_json": canonical(projected_properties),
        "original_feature_sha256": digest_bytes(canonical(original_feature if original_feature is not None else feature).encode()),
        "projected_feature_sha256": digest_bytes(canonical(projected).encode()),
        "min_x": min(xs),
        "min_y": min(ys),
        "max_x": max(xs),
        "max_y": max(ys),
    }


FEATURE_DDL = """CREATE TABLE features(
source_id VARCHAR NOT NULL, feature_index INTEGER NOT NULL, feature_id VARCHAR,
geometry_type VARCHAR NOT NULL, geometry_json VARCHAR NOT NULL, properties_json VARCHAR NOT NULL,
original_feature_sha256 VARCHAR NOT NULL, projected_feature_sha256 VARCHAR NOT NULL,
min_x DOUBLE NOT NULL, min_y DOUBLE NOT NULL, max_x DOUBLE NOT NULL, max_y DOUBLE NOT NULL)"""
MEMBERSHIP_DDL = """CREATE TABLE memberships(
layer_id VARCHAR NOT NULL, source_id VARCHAR NOT NULL, feature_index INTEGER NOT NULL)"""


def write_feature_parquet(rows, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        ndjson = Path(temporary) / "features.ndjson"
        with ndjson.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(canonical(row) + "\n")
        connection = duckdb.connect()
        connection.execute("PRAGMA threads=1")
        connection.execute("SET preserve_insertion_order=true")
        connection.execute(FEATURE_DDL)
        if rows:
            escaped = sql_string(ndjson)
            connection.execute(
                f"INSERT INTO features SELECT CAST(source_id AS VARCHAR), CAST(feature_index AS INTEGER), "
                f"CAST(feature_id AS VARCHAR), CAST(geometry_type AS VARCHAR), CAST(geometry_json AS VARCHAR), "
                f"CAST(properties_json AS VARCHAR), CAST(original_feature_sha256 AS VARCHAR), "
                f"CAST(projected_feature_sha256 AS VARCHAR), CAST(min_x AS DOUBLE), CAST(min_y AS DOUBLE), "
                f"CAST(max_x AS DOUBLE), CAST(max_y AS DOUBLE) FROM read_json_auto('{escaped}', "
                "format='newline_delimited', maximum_object_size=100000000)"
            )
        escaped_target = sql_string(target)
        connection.execute(
            f"COPY (SELECT * FROM features ORDER BY feature_index) TO '{escaped_target}' "
            "(FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000)"
        )
        count = connection.execute(f"SELECT count(*) FROM read_parquet('{escaped_target}')").fetchone()[0]
        connection.close()
    require(count == len(rows), f"feature Parquet readback mismatch: {target}")


def write_membership_parquet(rows, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    connection = duckdb.connect()
    connection.execute("PRAGMA threads=1")
    connection.execute(MEMBERSHIP_DDL)
    if rows:
        connection.executemany(
            "INSERT INTO memberships VALUES (?, ?, ?)",
            [(row["layer_id"], row["source_id"], row["feature_index"]) for row in rows],
        )
    escaped = sql_string(target)
    connection.execute(
        f"COPY (SELECT * FROM memberships ORDER BY layer_id, feature_index) TO '{escaped}' "
        "(FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000)"
    )
    count = connection.execute(f"SELECT count(*) FROM read_parquet('{escaped}')").fetchone()[0]
    connection.close()
    require(count == len(rows), f"membership Parquet readback mismatch: {target}")


def snap_feature(feature, substations):
    tolerance = 0.001 * 0.001
    radians = math.pi / 180
    changed_endpoints = 0

    def snap(coord):
        nonlocal changed_endpoints
        best = coord
        minimum = math.inf
        latitude_cosine = math.cos(coord[1] * radians)
        for candidate in substations:
            dx = (coord[0] - candidate[0]) * latitude_cosine
            dy = coord[1] - candidate[1]
            distance = dx * dx + dy * dy
            if distance < minimum and distance <= tolerance:
                minimum = distance
                best = candidate
        if list(best) != list(coord):
            changed_endpoints += 1
        return list(best)

    result = copy.deepcopy(feature)
    geometry = result.get("geometry") or {}
    coordinates = geometry.get("coordinates")
    if geometry.get("type") == "LineString" and coordinates:
        coordinates[0] = snap(coordinates[0])
        coordinates[-1] = snap(coordinates[-1])
    elif geometry.get("type") == "MultiLineString":
        for line in coordinates or []:
            if line:
                line[0] = snap(line[0])
                line[-1] = snap(line[-1])
    return result, changed_endpoints


def build_phase(repository, plan, layer_config, ledger, phase, source_root, output, git_repository=None):
    require(not output.exists() or not any(output.iterdir()), f"non-empty output: {output}")
    output.mkdir(parents=True, exist_ok=True)
    sources = [row for row in plan["sources"] if row["phase"] == phase]
    require(sources, f"unknown/empty phase: {phase}")
    retained_keys = plan["property_policy"]["retained_keys"]
    forbidden_keys = set(plan["property_policy"]["forbidden_keys"])
    require(not forbidden_keys.intersection(retained_keys), "forbidden property in retained allowlist")
    expected_layer_counts = {row["layer_id"]: row["selected_features"] for row in ledger["rows"]}
    layers_by_source = defaultdict(list)
    for group in layer_config["groups"]:
        for layer in group["layers"]:
            layers_by_source[layer["v9_data"]["source_id"]].append(layer)

    source_objects = {}
    substation_source = next(row for row in plan["sources"] if row["source_id"] == "grid_substations")
    if phase == "p1_foundation":
        source_objects["grid_substations"] = read_source(substation_source, source_root, git_repository)
    phase_artifacts = []
    phase_sources = []
    phase_layer_counts = Counter()
    snap_counts = {}

    for source in sources:
        obj = source_objects.get(source["source_id"]) or read_source(source, source_root, git_repository)
        features = obj["features"]
        geometry_counts = Counter(((item.get("geometry") or {}).get("type") or "NULL") for item in features)
        property_keys = sorted({key for item in features for key in (item.get("properties") or {})})
        require(len(features) == source["expected_features"], f"feature drift: {source['source_id']}")
        require(dict(sorted(geometry_counts.items())) == source["geometry_counts"], f"geometry drift: {source['source_id']}")
        require(digest_bytes(canonical(property_keys).encode()) == source["property_schema_sha256"], f"property schema drift: {source['source_id']}")

        rows = [feature_row(source["source_id"], index, feature, retained_keys) for index, feature in enumerate(features)]
        partition = output / source["output_partition"]
        write_feature_parquet(rows, partition)
        phase_artifacts.append(artifact(partition, output, "data-gridatlas.v8-parity-features.v1", len(rows)))

        membership_rows = []
        for layer in layers_by_source[source["source_id"]]:
            selected = 0
            expression = layer.get("filter")
            for index, feature in enumerate(features):
                properties = feature.get("properties") or {}
                if expression is None or bool(evaluate(expression, properties)):
                    membership_rows.append({"layer_id": layer["id"], "source_id": source["source_id"], "feature_index": index})
                    selected += 1
            require(selected == expected_layer_counts[layer["id"]], f"layer membership drift: {layer['id']} {selected}")
            phase_layer_counts[layer["id"]] = selected
        membership = output / "memberships" / f"{source['source_id']}.parquet"
        write_membership_parquet(membership_rows, membership)
        phase_artifacts.append(artifact(membership, output, "data-gridatlas.v8-layer-membership.v1", len(membership_rows)))

        if source["source_id"] in SNAP_EXPECTED:
            substations = [item["geometry"]["coordinates"] for item in source_objects["grid_substations"]["features"]]
            snapped_features = []
            changed_endpoints = changed_features = 0
            for feature in features:
                transformed, changed = snap_feature(feature, substations)
                snapped_features.append(transformed)
                changed_endpoints += changed
                changed_features += changed > 0
            require((changed_endpoints, changed_features) == SNAP_EXPECTED[source["source_id"]], f"snap parity drift: {source['source_id']}")
            snapped_rows = [
                feature_row(source["source_id"], index, feature, retained_keys, features[index])
                for index, feature in enumerate(snapped_features)
            ]
            derived = output / "derived" / f"{source['source_id']}_snapped.parquet"
            write_feature_parquet(snapped_rows, derived)
            phase_artifacts.append(artifact(derived, output, "data-gridatlas.v8-snapped-topology.v1", len(snapped_rows)))
            snap_counts[source["source_id"]] = {"changed_endpoints": changed_endpoints, "changed_features": changed_features}

        phase_sources.append(
            {
                "source_id": source["source_id"],
                "input_bytes": source["bytes"],
                "input_sha256": source["sha256"],
                "input_git_blob_sha1": source["git_blob_sha1"],
                "features": len(features),
                "memberships": len(membership_rows),
                "retained_property_pairs": source["retained_property_pairs"],
                "dropped_property_pairs": source["dropped_property_pairs"],
                "disposition": source["disposition"],
            }
        )

    identity = compute_identity(repository)
    manifest = {
        "schema": "data-gridatlas.v8-transplant-phase-manifest.v1",
        "generation": GENERATION,
        "classification": "V8_TRANSPLANT_PHASE_CANDIDATE",
        "phase": phase,
        "v8_commit": V8_COMMIT,
        "runtime": {**identity["runtime"], "compression": "ZSTD"},
        "compute_identity": identity,
        "sources": sorted(phase_sources, key=lambda row: row["source_id"]),
        "layer_counts": dict(sorted(phase_layer_counts.items())),
        "snap_counts": snap_counts,
        "artifacts": sorted(phase_artifacts, key=lambda row: row["path"]),
        "raw_outputs": 0,
        "release": False,
        "current_pointer": False,
        "v8_untouched": True,
    }
    manifest_path = output / "phase-manifests" / f"{phase}.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(canonical({"classification": manifest["classification"], "phase": phase, "sources": len(sources), "features": sum(row["features"] for row in phase_sources)}))


def write_registry_parquet(rows, columns, ddl, order, target):
    connection = duckdb.connect()
    connection.execute("PRAGMA threads=1")
    connection.execute(ddl)
    if rows:
        placeholders = ",".join("?" for _ in columns)
        connection.executemany(
            f"INSERT INTO registry ({','.join(columns)}) VALUES ({placeholders})",
            [tuple(row[column] for column in columns) for row in rows],
        )
    escaped = sql_string(target)
    connection.execute(
        f"COPY (SELECT * FROM registry ORDER BY {order}) TO '{escaped}' "
        "(FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000)"
    )
    connection.close()


def merge_candidate(repository, plan, layer_config, merge_input, output):
    require(not output.exists() or not any(output.iterdir()), f"non-empty merge output: {output}")
    output.mkdir(parents=True, exist_ok=True)
    phase_paths = sorted((merge_input / "phase-manifests").glob("*.json"))
    require({path.stem for path in phase_paths} == set(plan["compute"]["phases"]), "phase manifest closure mismatch")
    phase_manifests = [load(path) for path in phase_paths]
    observed_sources = [row["source_id"] for manifest in phase_manifests for row in manifest["sources"]]
    require(len(observed_sources) == 56 and len(set(observed_sources)) == 56, "phase source gap/duplicate")

    copied_artifacts = []
    for source in plan["sources"]:
        source_path = merge_input / source["output_partition"]
        require(source_path.is_file(), f"missing source partition: {source['source_id']}")
        target = output / source["output_partition"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target)
        copied_artifacts.append(artifact(target, output, "data-gridatlas.v8-parity-features.v1", source["expected_features"]))
    for source_id in SNAP_EXPECTED:
        source_path = merge_input / "derived" / f"{source_id}_snapped.parquet"
        require(source_path.is_file(), f"missing snapped topology: {source_id}")
        target = output / "derived" / source_path.name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target)
        rows = next(row["expected_features"] for row in plan["sources"] if row["source_id"] == source_id)
        copied_artifacts.append(artifact(target, output, "data-gridatlas.v8-snapped-topology.v1", rows))

    membership_paths = sorted((merge_input / "memberships").glob("*.parquet"))
    require(len(membership_paths) == 56, f"membership source closure mismatch: {len(membership_paths)}")
    membership_target = output / "layer_membership.parquet"
    connection = duckdb.connect()
    connection.execute("PRAGMA threads=1")
    sources_sql = ",".join(f"'{sql_string(path)}'" for path in membership_paths)
    escaped_target = sql_string(membership_target)
    connection.execute(
        f"COPY (SELECT * FROM read_parquet([{sources_sql}]) ORDER BY layer_id, source_id, feature_index) "
        f"TO '{escaped_target}' (FORMAT PARQUET, COMPRESSION ZSTD, ROW_GROUP_SIZE 100000)"
    )
    membership_rows = connection.execute(f"SELECT count(*) FROM read_parquet('{escaped_target}')").fetchone()[0]
    connection.close()
    require(membership_rows == plan["closure"]["layer_membership_rows"], f"membership closure mismatch: {membership_rows}")
    copied_artifacts.append(artifact(membership_target, output, "data-gridatlas.v8-layer-membership.v1", membership_rows))

    source_rows = []
    for source in plan["sources"]:
        source_rows.append(
            {
                "source_id": source["source_id"], "phase": source["phase"], "wiring": source["wiring"],
                "resolved_path": source["resolved_path"], "input_bytes": source["bytes"], "input_sha256": source["sha256"],
                "input_git_blob_sha1": source["git_blob_sha1"], "features": source["expected_features"],
                "geometry_counts_json": canonical(source["geometry_counts"]), "bbox_json": canonical(source["bbox"]),
                "partition_path": source["output_partition"], "authority_state": source["authority_state"],
                "licence_state": source["licence_state"], "disposition": source["disposition"], "publishable": source["publishable"],
            }
        )
    sources_target = output / "sources.parquet"
    source_columns = ["source_id", "phase", "wiring", "resolved_path", "input_bytes", "input_sha256", "input_git_blob_sha1", "features", "geometry_counts_json", "bbox_json", "partition_path", "authority_state", "licence_state", "disposition", "publishable"]
    source_ddl = """CREATE TABLE registry(source_id VARCHAR NOT NULL, phase VARCHAR NOT NULL, wiring VARCHAR NOT NULL,
    resolved_path VARCHAR NOT NULL, input_bytes UBIGINT NOT NULL, input_sha256 VARCHAR NOT NULL,
    input_git_blob_sha1 VARCHAR NOT NULL, features UBIGINT NOT NULL, geometry_counts_json VARCHAR NOT NULL,
    bbox_json VARCHAR NOT NULL, partition_path VARCHAR NOT NULL, authority_state VARCHAR NOT NULL,
    licence_state VARCHAR NOT NULL, disposition VARCHAR NOT NULL, publishable BOOLEAN NOT NULL)"""
    write_registry_parquet(source_rows, source_columns, source_ddl, "source_id", sources_target)
    copied_artifacts.append(artifact(sources_target, output, "data-gridatlas.sources.v1", len(source_rows)))

    layer_rows = []
    group_index = 0
    for group in layer_config["groups"]:
        for layer_index, layer in enumerate(group["layers"]):
            parquet_path = layer["v9_data"]["parquet_path"]
            if layer.get("snap"):
                parquet_path = f"derived/{layer['v9_data']['source_id']}_snapped.parquet"
            layer_rows.append(
                {
                    "group_index": group_index, "group_name": group["group"], "layer_index": layer_index,
                    "layer_id": layer["id"], "label": layer["label"], "geometry_role": layer["type"],
                    "color": layer["color"], "source_id": layer["v9_data"]["source_id"], "parquet_path": parquet_path,
                    "preload": bool(layer.get("preload")), "minzoom": layer.get("minzoom"), "width": layer.get("width"),
                    "radius_json": canonical(layer.get("radius")), "filter_json": canonical(layer.get("filter")),
                    "snap": bool(layer.get("snap")), "is_substations": bool(layer.get("isSubs")),
                    "disposition": layer["v9_data"]["disposition"], "publishable": False,
                }
            )
        group_index += 1
    layers_target = output / "layers.parquet"
    layer_columns = ["group_index", "group_name", "layer_index", "layer_id", "label", "geometry_role", "color", "source_id", "parquet_path", "preload", "minzoom", "width", "radius_json", "filter_json", "snap", "is_substations", "disposition", "publishable"]
    layer_ddl = """CREATE TABLE registry(group_index INTEGER NOT NULL, group_name VARCHAR NOT NULL,
    layer_index INTEGER NOT NULL, layer_id VARCHAR NOT NULL, label VARCHAR NOT NULL, geometry_role VARCHAR NOT NULL,
    color VARCHAR NOT NULL, source_id VARCHAR NOT NULL, parquet_path VARCHAR NOT NULL, preload BOOLEAN NOT NULL,
    minzoom DOUBLE, width DOUBLE, radius_json VARCHAR NOT NULL, filter_json VARCHAR NOT NULL, snap BOOLEAN NOT NULL,
    is_substations BOOLEAN NOT NULL, disposition VARCHAR NOT NULL, publishable BOOLEAN NOT NULL)"""
    write_registry_parquet(layer_rows, layer_columns, layer_ddl, "group_index, layer_index", layers_target)
    copied_artifacts.append(artifact(layers_target, output, "data-gridatlas.layers.v2", len(layer_rows)))

    quarantine_rows = [
        {"source_id": row["source_id"], "phase": row["phase"], "disposition": row["disposition"], "reason": row["provenance_note"]}
        for row in plan["sources"] if row["phase"] == "quarantine" or row["disposition"].startswith("ORACLE_ONLY")
    ]
    quarantine_target = output / "quarantine.parquet"
    quarantine_columns = ["source_id", "phase", "disposition", "reason"]
    quarantine_ddl = "CREATE TABLE registry(source_id VARCHAR NOT NULL, phase VARCHAR NOT NULL, disposition VARCHAR NOT NULL, reason VARCHAR NOT NULL)"
    write_registry_parquet(quarantine_rows, quarantine_columns, quarantine_ddl, "source_id", quarantine_target)
    copied_artifacts.append(artifact(quarantine_target, output, "data-gridatlas.quarantine.v2", len(quarantine_rows)))

    browser_groups = copy.deepcopy(layer_config["groups"])
    for group in browser_groups:
        for layer in group["layers"]:
            layer["v9_data"]["parquet_path"] = next(row["parquet_path"] for row in layer_rows if row["layer_id"] == layer["id"])
            layer["url"] = None
            layer["enabled"] = False
            layer["publishable"] = False
    browser_registry = {
        "schema": "data-gridatlas.browser-layer-registry.v1", "generation": GENERATION,
        "classification": "CANDIDATE_NOT_LIVE", "map": layer_config["map"], "groups": browser_groups,
        "raw_urls": False, "release": False, "current_pointer": False,
    }
    browser_target = output / "browser-layer-registry.json"
    browser_target.write_text(json.dumps(browser_registry, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    copied_artifacts.append(artifact(browser_target, output, "data-gridatlas.browser-layer-registry.v1", 60))

    phase_output = output / "phase-manifests"
    phase_output.mkdir(parents=True, exist_ok=True)
    for path in phase_paths:
        target = phase_output / path.name
        shutil.copyfile(path, target)
        copied_artifacts.append(artifact(target, output, "data-gridatlas.v8-transplant-phase-manifest.v1", len(load(path)["sources"])))

    identity = compute_identity(repository)
    manifest = {
        "schema": "data-gridatlas.v8-transplant-manifest.v1", "generation": GENERATION,
        "classification": "FULL_V8_TRANSPLANT_CANDIDATE", "source": plan["source"], "closure": plan["closure"],
        "runtime": {**identity["runtime"], "compression": "ZSTD"},
        "compute_identity": identity,
        "contracts": identity["inputs"],
        "repository_source_commit": subprocess.check_output(
            ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
        ).strip(),
        "artifacts": sorted(copied_artifacts, key=lambda row: row["path"]),
        "release": False, "current_pointer": False, "pages_publication": False,
        "raw_geojson_outputs": 0, "v8_untouched": True,
    }
    manifest_target = output / "manifest.json"
    manifest_target.write_text(json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(canonical({"classification": manifest["classification"], "sources": 56, "features": plan["closure"]["features"], "artifacts": len(copied_artifacts)}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", default=".")
    parser.add_argument("--source-root")
    parser.add_argument("--git-repository")
    parser.add_argument("--phase")
    parser.add_argument("--output")
    parser.add_argument("--fetch-only", action="store_true")
    parser.add_argument("--merge-input")
    args = parser.parse_args()

    repository = Path(args.repository).resolve()
    plan = load(repository / PLAN_PATH)
    layer_config = load(repository / LAYERS_PATH)
    ledger = load(repository / LEDGER_PATH)
    require(plan["generation"] == GENERATION and plan["source"]["commit"] == V8_COMMIT, "plan identity mismatch")
    require(plan["closure"]["sources"] == 56 and plan["closure"]["features"] == 541282, "plan closure mismatch")

    if args.merge_input:
        require(args.output, "--output required for merge")
        merge_candidate(repository, plan, layer_config, Path(args.merge_input).resolve(), Path(args.output).resolve())
        return
    require(args.phase and args.source_root, "--phase and --source-root required")
    source_root = Path(args.source_root).resolve()
    if args.fetch_only:
        fetch_phase_sources(plan, args.phase, source_root)
        return
    require(args.output, "--output required for build")
    build_phase(
        repository, plan, layer_config, ledger, args.phase, source_root,
        Path(args.output).resolve(), Path(args.git_repository).resolve() if args.git_repository else None,
    )


if __name__ == "__main__":
    main()
