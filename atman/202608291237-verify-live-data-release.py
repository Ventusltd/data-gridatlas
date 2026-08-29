#!/usr/bin/env python3
"""Independently verify the immutable 202608291237 live data release."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import duckdb


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def find_placeholders(value: object) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for item in value.values():
            found.extend(find_placeholders(item))
    elif isinstance(value, list):
        for item in value:
            found.extend(find_placeholders(item))
    elif isinstance(value, str) and value.startswith("__NEW_CANDIDATE_"):
        found.append(value)
    return found


def verify(args: argparse.Namespace) -> dict:
    repository = args.repository.resolve()
    release_root = args.release.resolve()
    contract = read_json(repository / args.contract)
    require(not find_placeholders(contract), "live release contract still contains candidate placeholders")
    require(release_root.name == contract["release_id"], "timestamp folder mismatch")
    require(not any(path.is_symlink() for path in release_root.rglob("*")), "symlink forbidden")

    actual_top_files = {path.name for path in release_root.iterdir() if path.is_file()}
    actual_top_directories = {path.name for path in release_root.iterdir() if path.is_dir()}
    require(actual_top_files == set(contract["layout"]["required_top_level_files"]), "top-level file closure mismatch")
    require(actual_top_directories == set(contract["layout"]["required_top_level_directories"]), "top-level directory closure mismatch")

    release = read_json(release_root / "release.json")
    candidate = read_json(release_root / "data" / "manifest.json")
    candidate_proof = read_json(release_root / "proof" / "full-candidate-verification.json")
    live_registry = read_json(release_root / "browser-layer-registry.json")
    candidate_registry = read_json(release_root / "data" / "browser-layer-registry.json")

    require(release.get("schema") == "data-gridatlas.immutable-live-data-release.v1", "release schema mismatch")
    require(release.get("classification") == "LIVE_IMMUTABLE_DATA_RELEASE", "release classification mismatch")
    require(release.get("release") is True and release.get("immutable") is True, "release flags mismatch")
    require(release.get("current_pointer") is False, "current pointer advanced before consumer proof")
    require(release.get("release_id") == contract["release_id"], "release id mismatch")
    require(release.get("incepted_at") == contract["incepted_at"], "release inception mismatch")
    require(release.get("repository") == contract["repository"], "release repository mismatch")
    require(release.get("repository_path") == contract["publication"]["repository_path"], "release path mismatch")
    require(release.get("packaging_source_commit") == args.source_commit, "packaging source commit mismatch")
    require(release.get("pages_url") == contract["publication"]["pages_url"], "Pages URL mismatch")
    require(release.get("v8_untouched") is True, "V8 untouched assertion missing")
    require(release.get("authority_licence_and_quarantine_labels_preserved") is True, "evidence labels not preserved")
    require(release.get("candidate") == contract["candidate"], "release candidate receipt mismatch")
    require(release.get("candidate_proof_sha256") == contract["candidate"]["candidate_proof_sha256"], "release proof receipt mismatch")
    require(release.get("candidate_closure") == candidate.get("closure"), "release candidate closure mismatch")
    require(release.get("oracle") == contract["oracle"], "release oracle receipt mismatch")
    require(release.get("runtime") == candidate.get("runtime"), "release runtime receipt mismatch")

    require(sha256(release_root / "data" / "manifest.json") == contract["candidate"]["candidate_manifest_sha256"], "candidate manifest SHA-256 mismatch")
    require(sha256(release_root / "proof" / "full-candidate-verification.json") == contract["candidate"]["candidate_proof_sha256"], "candidate proof SHA-256 mismatch")
    require(candidate.get("classification") == "FULL_V8_TRANSPLANT_CANDIDATE", "candidate classification mismatch")
    require(candidate.get("release") is False, "candidate release flag was rewritten")
    require(candidate.get("pages_publication") is False, "candidate Pages flag was rewritten")
    require(candidate.get("current_pointer") is False, "candidate pointer flag was rewritten")
    require(candidate.get("source", {}).get("commit") == contract["oracle"]["commit"], "V8 oracle commit mismatch")
    require(candidate.get("source", {}).get("commit_tree_sha1") == contract["oracle"]["tree_sha1"], "V8 oracle tree mismatch")
    require(candidate_proof.get("classification") == contract["candidate"]["proof_classification"], "candidate proof classification mismatch")
    require(candidate_proof.get("failed") == 0, "candidate proof contains failures")
    require(candidate_proof.get("repository_source_commit") == contract["candidate"]["source_commit"], "candidate proof source mismatch")

    candidate_closure = candidate.get("closure", {})
    for key in ("sources", "layers", "features", "layer_membership_rows", "coordinate_tuples"):
        require(candidate_closure.get(key) == contract["closure"][key], f"candidate closure mismatch: {key}")
    require(candidate.get("raw_geojson_outputs") == contract["closure"]["raw_geojson_outputs"], "raw GeoJSON output mismatch")

    actual_files = {
        path.relative_to(release_root).as_posix()
        for path in release_root.rglob("*")
        if path.is_file()
    }
    release_items = release.get("files", [])
    released = {item["path"]: item for item in release_items}
    require(len(released) == len(release_items), "duplicate release file path")
    require(actual_files == set(released) | {"release.json", "sha256sums.txt"}, "release file closure mismatch")
    for relative, item in released.items():
        path = release_root / relative
        require(path.stat().st_size == item["bytes"], f"release byte mismatch: {relative}")
        require(sha256(path) == item["sha256"], f"release SHA-256 mismatch: {relative}")

    checksum_lines = (release_root / "sha256sums.txt").read_text(encoding="utf-8").splitlines()
    checksums: dict[str, str] = {}
    for line in checksum_lines:
        parts = line.split("  ", 1)
        require(len(parts) == 2, "malformed SHA-256 ledger line")
        value, relative = parts
        require(len(value) == 64 and all(character in "0123456789abcdef" for character in value), "malformed SHA-256 value")
        require(relative not in checksums, f"duplicate SHA-256 ledger path: {relative}")
        checksums[relative] = value
    require(set(checksums) == actual_files - {"sha256sums.txt"}, "SHA-256 ledger closure mismatch")
    for relative, value in checksums.items():
        require(sha256(release_root / relative) == value, f"SHA-256 ledger mismatch: {relative}")

    candidate_items = candidate.get("artifacts", [])
    declared_candidate = {item["path"]: item for item in candidate_items}
    require(len(declared_candidate) == len(candidate_items), "duplicate candidate artifact path")
    actual_candidate = {
        path.relative_to(release_root / "data").as_posix()
        for path in (release_root / "data").rglob("*")
        if path.is_file()
    }
    require(actual_candidate == set(declared_candidate) | {"manifest.json"}, "candidate payload closure mismatch")
    require(len(actual_candidate) == contract["candidate"]["candidate_files"], "candidate file count mismatch")
    require(sum((release_root / "data" / relative).stat().st_size for relative in actual_candidate) == contract["candidate"]["candidate_bytes"], "candidate byte closure mismatch")
    for relative, item in declared_candidate.items():
        path = release_root / "data" / relative
        require(path.stat().st_size == item["bytes"], f"candidate byte mismatch: {relative}")
        require(sha256(path) == item["sha256"], f"candidate SHA-256 mismatch: {relative}")

    require(live_registry.get("schema") == "data-gridatlas.live-browser-layer-registry.v1", "live registry schema mismatch")
    require(live_registry.get("classification") == "LIVE_IMMUTABLE_DATA_RELEASE", "live registry classification mismatch")
    require(live_registry.get("release") is True and live_registry.get("pages_publication") is True, "live registry flags mismatch")
    require(live_registry.get("current_pointer") is False, "live registry pointer advanced")
    require(live_registry.get("candidate_generation") == candidate_registry.get("generation"), "live registry candidate generation mismatch")
    require(live_registry.get("base_url") == contract["publication"]["pages_url"], "live registry base URL mismatch")
    require(live_registry.get("layer_membership_url") == "data/layer_membership.parquet", "membership URL mismatch")
    require(live_registry.get("load_policy") == {
        "initial_fetches": 0,
        "default_visible_layers": [],
        "fetch_on_user_enable_only": True,
    }, "zero-initial-fetch policy mismatch")
    require(live_registry.get("receipt_semantics") == {
        "enabled": "selectable",
        "publishable": "available_in_this_immutable_public_release",
        "default_visible": False,
        "browser_initial_fetches": 0,
    }, "registry receipt semantics mismatch")

    live_top = dict(live_registry)
    candidate_top = dict(candidate_registry)
    live_groups = live_top.pop("groups", [])
    candidate_groups = candidate_top.pop("groups", [])
    for key in (
        "candidate_generation", "schema", "classification", "generation", "release",
        "pages_publication", "current_pointer", "base_url", "data_base_path",
        "candidate_manifest_url", "layers_url", "sources_url", "layer_membership_url",
        "load_policy", "receipt_semantics",
    ):
        live_top.pop(key, None)
    for key in ("schema", "classification", "generation", "release", "current_pointer"):
        candidate_top.pop(key, None)
    require(live_top == candidate_top, "registry top-level allowed-diff violation")
    require(len(live_groups) == len(candidate_groups), "registry group count mismatch")
    for live_group, candidate_group in zip(live_groups, candidate_groups, strict=True):
        live_group_copy = dict(live_group)
        candidate_group_copy = dict(candidate_group)
        live_group_copy.pop("layers", None)
        candidate_group_copy.pop("layers", None)
        require(live_group_copy == candidate_group_copy, "registry group metadata drift")

    live_layers = [layer for group in live_groups for layer in group.get("layers", [])]
    candidate_layers = [layer for group in candidate_groups for layer in group.get("layers", [])]
    require(len(live_layers) == contract["closure"]["layers"], "live registry layer count mismatch")
    require([layer.get("id") for layer in live_layers] == [layer.get("id") for layer in candidate_layers], "live registry layer order mismatch")
    require(len({layer.get("id") for layer in live_layers}) == len(live_layers), "duplicate live registry layer id")
    for live_layer, candidate_layer in zip(live_layers, candidate_layers, strict=True):
        live_layer_copy = dict(live_layer)
        candidate_layer_copy = dict(candidate_layer)
        live_data = live_layer_copy.pop("v9_data", {})
        candidate_data = candidate_layer_copy.pop("v9_data", {})
        for key in ("available", "publishable", "enabled", "default_visible", "preload", "url"):
            live_layer_copy.pop(key, None)
        for key in ("publishable", "enabled", "preload", "url"):
            candidate_layer_copy.pop(key, None)
        require(live_layer_copy == candidate_layer_copy, f"registry style/filter drift: {live_layer.get('id')}")
        require(live_data.get("parquet_path") == candidate_data.get("parquet_path"), f"registry partition mismatch: {live_layer.get('id')}")
        expected_url = f"data/{candidate_data['parquet_path']}"
        require(live_layer.get("available") is True, f"registry availability mismatch: {live_layer.get('id')}")
        require(live_layer.get("publishable") is True, f"registry publication mismatch: {live_layer.get('id')}")
        require(live_layer.get("enabled") is True, f"registry enablement mismatch: {live_layer.get('id')}")
        require(live_layer.get("default_visible") is False, f"registry default visibility mismatch: {live_layer.get('id')}")
        require(live_layer.get("preload") is False, f"registry preload mismatch: {live_layer.get('id')}")
        require(live_layer.get("url") is None, f"registry legacy URL must remain null: {live_layer.get('id')}")
        require(live_data.get("parquet_url") == expected_url, f"registry Parquet URL mismatch: {live_layer.get('id')}")
        require(live_data.get("membership_url") == "data/layer_membership.parquet", f"registry membership URL mismatch: {live_layer.get('id')}")
        require(live_data.get("data_live") is True, f"registry live flag mismatch: {live_layer.get('id')}")
        require(candidate_data["parquet_path"] in declared_candidate, f"registry partition absent: {live_layer.get('id')}")
        for preserved, value in candidate_data.items():
            require(live_data.get(preserved) == value, f"registry evidence mapping mismatch: {live_layer.get('id')}:{preserved}")
        require(set(live_data) == set(candidate_data) | {
            "candidate_enabled",
            "candidate_publishable",
            "candidate_preload",
            "parquet_url",
            "membership_url",
            "data_live",
        }, f"registry V9 mapping closure mismatch: {live_layer.get('id')}")
        require(live_data.get("candidate_enabled") == candidate_layer.get("enabled"), f"candidate enablement receipt mismatch: {live_layer.get('id')}")
        require(live_data.get("candidate_publishable") == candidate_layer.get("publishable"), f"candidate publication receipt mismatch: {live_layer.get('id')}")
        require(live_data.get("candidate_preload") == candidate_layer.get("preload"), f"candidate preload receipt mismatch: {live_layer.get('id')}")

    for relative in contract["contract_snapshots"]:
        source = repository / relative
        snapshot = release_root / "contracts" / Path(relative).name
        require(snapshot.is_file(), f"missing contract snapshot: {relative}")
        require(sha256(source) == sha256(snapshot), f"contract snapshot mismatch: {relative}")

    parquet_files = 0
    parquet_rows = 0
    connection = duckdb.connect(":memory:")
    connection.execute("SET threads=1")
    try:
        for relative, item in sorted(declared_candidate.items()):
            if not relative.endswith(".parquet"):
                continue
            parquet_files += 1
            path = release_root / "data" / relative
            rows = connection.execute("SELECT count(*) FROM read_parquet(?)", [str(path)]).fetchone()[0]
            require(rows == item["rows"], f"Parquet row mismatch: {relative}")
            parquet_rows += rows
            codecs = {row[0] for row in connection.execute("SELECT DISTINCT compression FROM parquet_metadata(?)", [str(path)]).fetchall()}
            if rows:
                require(codecs == {"ZSTD"}, f"Parquet codec mismatch: {relative}:{codecs}")
            else:
                require(not codecs, f"empty Parquet metadata mismatch: {relative}")
    finally:
        connection.close()

    index = (release_root / "index.html").read_text(encoding="utf-8")
    require("<script" not in index.lower() and "fetch(" not in index.lower(), "timestamp index must not load data")
    for expected in (
        contract["release_id"],
        "LIVE",
        "release.json",
        "browser-layer-registry.json",
        f"{contract['closure']['features']:,}",
        f"{contract['closure']['layer_membership_rows']:,}",
    ):
        require(expected in index, f"timestamp index missing receipt value: {expected}")
    readme = (release_root / "readme.md").read_text(encoding="utf-8")
    require(contract["release_id"] in readme and "current pointer" in readme.lower(), "release readme mismatch")

    return {
        "schema": "data-gridatlas.live-data-release-verification.v1",
        "classification": "VERIFIED_IMMUTABLE_LIVE_DATA_RELEASE",
        "release_id": contract["release_id"],
        "source_commit": args.source_commit,
        "files": len(actual_files),
        "bytes": sum((release_root / relative).stat().st_size for relative in actual_files),
        "parquet_files": parquet_files,
        "parquet_rows": parquet_rows,
        "features": candidate_closure["features"],
        "layer_membership_rows": candidate_closure["layer_membership_rows"],
        "failed": 0,
        "v8_untouched": True,
        "current_pointer": False,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--contract", default="contracts/202608291237-live-data-release.json")
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = verify(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
