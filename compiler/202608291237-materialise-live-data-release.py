#!/usr/bin/env python3
"""Materialise the immutable 202608291237 Data Grid Atlas live release."""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
import json
import shutil
from pathlib import Path


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def find_placeholders(value: object, path: str = "contract") -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            found.extend(find_placeholders(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(find_placeholders(item, f"{path}[{index}]"))
    elif isinstance(value, str) and value.startswith("__NEW_CANDIDATE_"):
        found.append(f"{path}={value}")
    return found


def validate_candidate(candidate: Path, proof_path: Path, contract: dict) -> tuple[dict, dict]:
    candidate_contract = contract["candidate"]
    manifest_path = candidate / "manifest.json"
    manifest = read_json(manifest_path)
    proof = read_json(proof_path)

    require(sha256(manifest_path) == candidate_contract["candidate_manifest_sha256"], "candidate manifest SHA-256 mismatch")
    require(sha256(proof_path) == candidate_contract["candidate_proof_sha256"], "candidate proof SHA-256 mismatch")
    require(manifest.get("classification") == "FULL_V8_TRANSPLANT_CANDIDATE", "candidate classification mismatch")
    require(manifest.get("release") is False, "input candidate release flag changed")
    require(manifest.get("pages_publication") is False, "input candidate Pages flag changed")
    require(manifest.get("current_pointer") is False, "input candidate current pointer changed")
    require(manifest.get("v8_untouched") is True, "input candidate does not preserve V8")
    require(manifest.get("source", {}).get("commit") == contract["oracle"]["commit"], "V8 oracle commit mismatch")
    require(manifest.get("source", {}).get("commit_tree_sha1") == contract["oracle"]["tree_sha1"], "V8 oracle tree mismatch")
    require(proof.get("classification") == candidate_contract["proof_classification"], "candidate proof classification mismatch")
    require(proof.get("failed") == 0, "candidate proof contains failures")
    require(proof.get("repository_source_commit") == candidate_contract["source_commit"], "candidate proof source commit mismatch")
    require(proof.get("v8_untouched") is True, "candidate proof does not preserve V8")

    closure = manifest.get("closure", {})
    for key in ("sources", "layers", "features", "layer_membership_rows", "coordinate_tuples"):
        require(closure.get(key) == contract["closure"][key], f"candidate closure mismatch: {key}")
    require(manifest.get("raw_geojson_outputs") == contract["closure"]["raw_geojson_outputs"], "raw GeoJSON output mismatch")

    declared_items = manifest.get("artifacts", [])
    declared = {item["path"]: item for item in declared_items}
    require(len(declared) == len(declared_items), "duplicate candidate artifact path")
    actual = {
        path.relative_to(candidate).as_posix()
        for path in candidate.rglob("*")
        if path.is_file()
    }
    require(actual == set(declared) | {"manifest.json"}, "candidate file closure mismatch")
    require(len(actual) == candidate_contract["candidate_files"], "candidate file count mismatch")
    require(sum((candidate / relative).stat().st_size for relative in actual) == candidate_contract["candidate_bytes"], "candidate byte closure mismatch")
    for relative, item in declared.items():
        path = candidate / relative
        require(path.stat().st_size == item["bytes"], f"candidate byte mismatch: {relative}")
        require(sha256(path) == item["sha256"], f"candidate SHA-256 mismatch: {relative}")
    return manifest, proof


def copy_tree(source: Path, destination: Path) -> None:
    for path in sorted(item for item in source.rglob("*") if item.is_file()):
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)


def make_live_browser_registry(candidate_registry: dict, contract: dict) -> dict:
    registry = copy.deepcopy(candidate_registry)
    registry["candidate_generation"] = registry.get("generation")
    registry["schema"] = "data-gridatlas.live-browser-layer-registry.v1"
    registry["classification"] = "LIVE_IMMUTABLE_DATA_RELEASE"
    registry["generation"] = contract["release_id"]
    registry["release"] = True
    registry["pages_publication"] = True
    registry["current_pointer"] = False
    registry["base_url"] = contract["publication"]["pages_url"]
    registry["data_base_path"] = "data/"
    registry["candidate_manifest_url"] = "data/manifest.json"
    registry["layers_url"] = "data/layers.parquet"
    registry["sources_url"] = "data/sources.parquet"
    registry["layer_membership_url"] = "data/layer_membership.parquet"
    registry["load_policy"] = {
        "initial_fetches": 0,
        "default_visible_layers": [],
        "fetch_on_user_enable_only": True,
    }
    registry["receipt_semantics"] = {
        "enabled": "selectable",
        "publishable": "available_in_this_immutable_public_release",
        "default_visible": False,
        "browser_initial_fetches": 0,
    }
    for group in registry.get("groups", []):
        for layer in group.get("layers", []):
            v9_data = layer.get("v9_data")
            require(isinstance(v9_data, dict), f"missing V9 data mapping: {layer.get('id')}")
            parquet_path = v9_data.get("parquet_path")
            require(isinstance(parquet_path, str), f"missing Parquet path: {layer.get('id')}")
            require(parquet_path.startswith(("partitions/", "derived/")), f"forbidden Parquet path: {parquet_path}")
            v9_data["candidate_enabled"] = layer.get("enabled")
            v9_data["candidate_publishable"] = layer.get("publishable")
            v9_data["candidate_preload"] = layer.get("preload")
            v9_data["parquet_url"] = f"data/{parquet_path}"
            v9_data["membership_url"] = "data/layer_membership.parquet"
            v9_data["data_live"] = True
            layer["available"] = True
            layer["publishable"] = True
            layer["enabled"] = True
            layer["default_visible"] = False
            layer["preload"] = False
            layer["url"] = None
    return registry


def make_index(contract: dict, candidate_manifest: dict) -> str:
    candidate = contract["candidate"]
    closure = contract["closure"]
    release_id = html.escape(contract["release_id"])
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{release_id} — Data Grid Atlas V9</title>
  <style>
    :root {{ color-scheme:dark; font-family:ui-sans-serif,system-ui,sans-serif; }}
    body {{ max-width:880px; margin:auto; padding:2rem 1.25rem 4rem; background:#07111f; color:#eaf2ff; }}
    .live {{ color:#78e6a2; font-weight:800; letter-spacing:.08em; }}
    .card {{ background:#101f33; border:1px solid #29415f; border-radius:12px; padding:1rem 1.2rem; margin:1rem 0; }}
    dl {{ display:grid; grid-template-columns:max-content 1fr; gap:.45rem 1rem; }} dt {{ color:#9fb7d3; }} dd {{ margin:0; }}
    a {{ color:#8bc7ff; }} code {{ overflow-wrap:anywhere; }}
  </style>
</head>
<body>
  <p class="live">LIVE · IMMUTABLE · TIMESTAMPED</p>
  <h1>Data Grid Atlas V9</h1>
  <p>Release <code>{release_id}</code>. This receipt does not load the Parquet payload.</p>
  <div class="card"><dl>
    <dt>Sources</dt><dd>{closure['sources']:,}</dd>
    <dt>Layers</dt><dd>{closure['layers']:,}</dd>
    <dt>Features</dt><dd>{closure['features']:,}</dd>
    <dt>Memberships</dt><dd>{closure['layer_membership_rows']:,}</dd>
    <dt>Artifact</dt><dd><code>{html.escape(str(candidate['artifact_digest']))}</code></dd>
    <dt>Candidate manifest</dt><dd><code>{html.escape(str(candidate['candidate_manifest_sha256']))}</code></dd>
    <dt>V8 oracle</dt><dd><code>{html.escape(contract['oracle']['commit'])}</code> (untouched)</dd>
    <dt>Consumer</dt><dd>Timestamp-bound verification required; current pointer deferred.</dd>
  </dl></div>
  <p>All authority, licence and quarantine labels are preserved. Public availability does not rewrite those evidence states.</p>
  <ul>
    <li><a href="release.json">Release manifest</a></li>
    <li><a href="browser-layer-registry.json">Browser layer registry</a></li>
    <li><a href="sha256sums.txt">SHA-256 ledger</a></li>
    <li><a href="data/manifest.json">Exact CI candidate manifest</a></li>
    <li><a href="readme.md">Release readme</a></li>
  </ul>
</body>
</html>
"""


def make_readme(contract: dict) -> str:
    closure = contract["closure"]
    return f"""# {contract['release_id']}

Immutable live Data Grid Atlas V9 data release.

- Sources: {closure['sources']:,}
- Layers: {closure['layers']:,}
- Features: {closure['features']:,}
- Layer memberships: {closure['layer_membership_rows']:,}
- Format: DuckDB-readable ZSTD Parquet
- V8 oracle: `{contract['oracle']['repository']}@{contract['oracle']['commit']}` (untouched)
- Candidate run: `{contract['candidate']['workflow_run_id']}`
- Candidate artifact: `{contract['candidate']['artifact_id']}`
- Current pointer: deferred until exact Atlas V9 consumer and rendered-browser proof

The exact verified candidate is retained under `data/`. The top-level browser registry adds timestamp-bound Parquet URLs without rewriting the candidate registry. Authority, licence and quarantine labels remain visible and unchanged.
"""


def materialise(args: argparse.Namespace) -> None:
    repository = args.repository.resolve()
    contract = read_json(repository / args.contract)
    placeholders = find_placeholders(contract)
    require(not placeholders, "unresolved live-release placeholders: " + ", ".join(placeholders))
    require(args.source_commit != contract["candidate"]["source_commit"], "promotion source must succeed candidate source")

    candidate = args.candidate.resolve()
    proof_path = args.proof.resolve()
    output = args.output.resolve()
    require(not output.exists(), f"refusing existing output: {output}")
    require(output.name == contract["release_id"], "output folder must equal release id")
    candidate_manifest, candidate_proof = validate_candidate(candidate, proof_path, contract)

    output.mkdir(parents=True)
    copy_tree(candidate, output / "data")
    proof_target = output / "proof" / "full-candidate-verification.json"
    proof_target.parent.mkdir(parents=True)
    shutil.copyfile(proof_path, proof_target)
    for relative in contract["contract_snapshots"]:
        source = repository / relative
        target = output / "contracts" / Path(relative).name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)

    live_registry = make_live_browser_registry(read_json(candidate / "browser-layer-registry.json"), contract)
    (output / "browser-layer-registry.json").write_bytes(canonical_json(live_registry))
    (output / "index.html").write_text(make_index(contract, candidate_manifest), encoding="utf-8", newline="\n")
    (output / "readme.md").write_text(make_readme(contract), encoding="utf-8", newline="\n")

    payload_files = []
    for path in sorted(item for item in output.rglob("*") if item.is_file()):
        payload_files.append({
            "path": path.relative_to(output).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        })
    release = {
        "schema": "data-gridatlas.immutable-live-data-release.v1",
        "release_id": contract["release_id"],
        "incepted_at": contract["incepted_at"],
        "classification": "LIVE_IMMUTABLE_DATA_RELEASE",
        "release": True,
        "immutable": True,
        "current_pointer": False,
        "repository": contract["repository"],
        "repository_path": contract["publication"]["repository_path"],
        "pages_url": contract["publication"]["pages_url"],
        "packaging_source_commit": args.source_commit,
        "candidate": contract["candidate"],
        "candidate_proof_sha256": sha256(proof_path),
        "candidate_closure": candidate_manifest["closure"],
        "oracle": contract["oracle"],
        "runtime": candidate_manifest["runtime"],
        "authority_licence_and_quarantine_labels_preserved": True,
        "v8_untouched": candidate_manifest["v8_untouched"] and candidate_proof["v8_untouched"],
        "files": payload_files,
    }
    (output / "release.json").write_bytes(canonical_json(release))

    checksums = []
    for path in sorted(item for item in output.rglob("*") if item.is_file()):
        checksums.append(f"{sha256(path)}  {path.relative_to(output).as_posix()}")
    (output / "sha256sums.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8", newline="\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--contract", default="contracts/202608291237-live-data-release.json")
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--proof", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    materialise(parser.parse_args())


if __name__ == "__main__":
    main()
