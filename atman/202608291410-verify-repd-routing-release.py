#!/usr/bin/env python3
"""Fail-closed verification for the immutable REPD routing folder."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re


GENERATION = "202608291410"
RELEASE_ID = f"{GENERATION}-repd-routing"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def set_hash(values: list[str]) -> str:
    ordered = sorted(values, key=int)
    return sha256((json.dumps(ordered, separators=(",", ":")) + "\n").encode("utf-8"))


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-committed-at", required=True)
    args = parser.parse_args()
    require(SHA40.fullmatch(args.source_commit) is not None, "source commit must be exact SHA-1")
    require(re.fullmatch(r"\d{4}-\d{2}-\d{2}T[^\r\n]+", args.source_committed_at) is not None, "source timestamp is invalid")
    contract = json.loads(args.contract.read_text(encoding="utf-8"))
    require(contract.get("schema") == "data-gridatlas.repd-routing-source.v1", "source contract schema drift")
    require(contract.get("generation") == GENERATION and contract.get("release_id") == RELEASE_ID, "source contract generation drift")
    root = args.release
    require(root.name == RELEASE_ID and root.is_dir(), "release folder identity drift")
    entries = list(root.iterdir())
    require(all(path.is_file() for path in entries), "directory or special entry in routing release")
    actual = sorted(path.name for path in entries)
    require(actual == ["index.html", "projects.json", "release.json", "sha256sums.txt"], f"release closure drift: {actual}")
    require(not any(path.is_symlink() for path in entries), "symlink in routing release")

    projects_raw = (root / "projects.json").read_bytes()
    source = contract["source"]
    require(len(projects_raw) == source["bytes"] and sha256(projects_raw) == source["sha256"], "projects bytes are not exact source")
    payload = json.loads(projects_raw)
    fields = {name: index for index, name in enumerate(payload["fields"])}
    refs = [str(row[fields["repd_ref"]]) for row in payload["rows"]]
    geometry = payload["dictionaries"]["geometry_status"]
    map_refs = [str(row[fields["repd_ref"]]) for row in payload["rows"] if geometry[row[fields["geometry_status"]]] == "valid"]
    no_map_refs = [str(row[fields["repd_ref"]]) for row in payload["rows"] if geometry[row[fields["geometry_status"]]] != "valid"]
    closure = contract["closure"]
    require(len(refs) == closure["projects"] and len(set(refs)) == closure["unique_numeric_repd_refs"], "project identity closure drift")
    require(all(re.fullmatch(r"\d+", value) for value in refs), "non-numeric REPD identity")
    require(len(map_refs) == closure["map_identities"] and len(no_map_refs) == closure["no_map_identities"], "map/no-map closure drift")
    require(set_hash(map_refs) == closure["map_set_sha256"], "MAP set hash drift")
    require(set_hash(no_map_refs) == closure["no_map_set_sha256"], "NO MAP set hash drift")

    release_raw = (root / "release.json").read_bytes()
    release = json.loads(release_raw)
    require(release_raw == canonical_json(release), "release JSON is not canonical")
    require(release.get("schema") == "data-gridatlas.repd-routing-release.v1", "release schema drift")
    require(release.get("generation") == GENERATION and release.get("release_id") == RELEASE_ID, "release identity drift")
    require(release.get("incepted_at") == contract["incepted_at"] and release.get("public_url") == contract["folder_contract"]["public_url"], "release timestamp/URL drift")
    require(release.get("source_commit") == args.source_commit and release.get("source_committed_at") == args.source_committed_at, "release source commit binding drift")
    require(release.get("source_parent_commit") == contract["source_parent_commit"], "release source parent binding drift")
    require(release.get("source") == contract["source"], "release routing provenance drift")
    require(release.get("immutable") is True, "release immutability drift")
    require(release.get("classification") == "IMMUTABLE_REPD_ROUTING_RELEASE", "release classification drift")
    require(release.get("coverage") == closure, "release coverage drift")
    index_raw = (root / "index.html").read_bytes()
    expected_files = {
        "index": {"path": "index.html", "bytes": len(index_raw), "sha256": sha256(index_raw)},
        "projects": {"path": "projects.json", "bytes": len(projects_raw), "sha256": sha256(projects_raw)},
    }
    require(release.get("files") == expected_files, "release file bindings drift")
    expected_consumer = {
        "decode_geometry_status": True,
        "select_only_geometry_status_valid": True,
        "identity_key": "repd_ref",
        "existing_layer_release_pointer_unchanged": True,
    }
    require(release.get("consumer_contract") == expected_consumer, "consumer contract drift")
    require(f'<time datetime="{contract["incepted_at"]}">'.encode() in index_raw, "timestamp missing from index")
    for target in (b'href="projects.json"', b'href="release.json"', b'href="sha256sums.txt"'):
        require(target in index_raw, f"index dependency link missing: {target!r}")
    sums = (root / "sha256sums.txt").read_text(encoding="utf-8").splitlines()
    expected_sums = [
        f"{sha256((root / name).read_bytes())}  {name}"
        for name in ("index.html", "projects.json", "release.json")
    ]
    require(sums == expected_sums, "sha256sums closure drift")
    print(json.dumps({
        "classification": "VERIFIED_REPD_ROUTING_RELEASE",
        "release_id": RELEASE_ID,
        "files": 4,
        "projects": len(refs),
        "map_identities": len(map_refs),
        "no_map_identities": len(no_map_refs),
        "projects_sha256": sha256(projects_raw),
        "release_sha256": sha256(release_raw),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
