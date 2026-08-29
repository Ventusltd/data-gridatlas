#!/usr/bin/env python3
"""Compile the immutable PipelineNews/V8 deep-link routing dependency."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
from pathlib import Path
import re


GENERATION = "202608291410"
RELEASE_ID = f"{GENERATION}-repd-routing"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def record(name: str, raw: bytes) -> dict:
    return {"path": name, "bytes": len(raw), "sha256": sha256(raw)}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-parent-commit", required=True)
    parser.add_argument("--source-committed-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    require(SHA40.fullmatch(args.source_commit) is not None, "source commit must be exact SHA-1")
    require(SHA40.fullmatch(args.source_parent_commit) is not None, "source parent commit must be exact SHA-1")
    require(re.match(r"^\d{4}-\d{2}-\d{2}T", args.source_committed_at) is not None, "source timestamp is invalid")
    contract = json.loads(args.contract.read_text(encoding="utf-8"))
    require(contract.get("schema") == "data-gridatlas.repd-routing-source.v1", "source contract schema drift")
    require(contract.get("generation") == GENERATION and contract.get("release_id") == RELEASE_ID, "source contract generation drift")
    require(contract.get("source_parent_commit") == args.source_parent_commit, "source parent commit drift")
    source_raw = args.source.read_bytes()
    source = contract["source"]
    require(len(source_raw) == source["bytes"] and sha256(source_raw) == source["sha256"], "routing source bytes drift")
    payload = json.loads(source_raw)
    require(payload.get("schema") == source["schema"], "routing source schema drift")
    require(payload.get("generation") == "202608270055", "routing source generation drift")
    require(len(payload.get("rows", [])) == contract["closure"]["projects"], "routing source project count drift")

    require(not args.output.exists(), f"refusing existing output: {args.output}")
    require(args.output.name == RELEASE_ID, "output folder identity drift")
    args.output.mkdir(parents=True)
    projects_raw = source_raw
    (args.output / "projects.json").write_bytes(projects_raw)

    index_raw = f"""<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Data Grid Atlas · REPD routing {GENERATION}</title><style>body{{font:16px/1.5 system-ui;max-width:860px;margin:3rem auto;padding:0 1rem;color:#132}}code{{word-break:break-all}}a{{color:#0563c1}}</style></head><body><main><h1>REPD deep-link routing data</h1><p>Immutable timestamped release <strong>{GENERATION}</strong>.</p><dl><dt>Incepted</dt><dd><time datetime=\"{html.escape(contract['incepted_at'])}\">{html.escape(contract['incepted_at'])}</time></dd><dt>Working V8 projects</dt><dd>{contract['closure']['projects']:,}</dd><dt>MAP identities</dt><dd>{contract['closure']['map_identities']:,}</dd><dt>NO MAP identities</dt><dd>{contract['closure']['no_map_identities']:,}</dd><dt>Source commit</dt><dd><code>{html.escape(source['commit'])}</code></dd></dl><p><a href=\"projects.json\">projects.json</a> · <a href=\"release.json\">release.json</a> · <a href=\"sha256sums.txt\">sha256sums.txt</a></p></main></body></html>
""".encode("utf-8")
    (args.output / "index.html").write_bytes(index_raw)

    release = {
        "schema": "data-gridatlas.repd-routing-release.v1",
        "generation": GENERATION,
        "release_id": RELEASE_ID,
        "incepted_at": contract["incepted_at"],
        "source_commit": args.source_commit,
        "source_parent_commit": args.source_parent_commit,
        "source_committed_at": args.source_committed_at,
        "classification": "IMMUTABLE_REPD_ROUTING_RELEASE",
        "immutable": True,
        "public_url": contract["folder_contract"]["public_url"],
        "source": source,
        "coverage": contract["closure"],
        "files": {
            "index": record("index.html", index_raw),
            "projects": record("projects.json", projects_raw),
        },
        "consumer_contract": {
            "decode_geometry_status": True,
            "select_only_geometry_status_valid": True,
            "identity_key": "repd_ref",
            "existing_layer_release_pointer_unchanged": True,
        },
    }
    release_raw = canonical_json(release)
    (args.output / "release.json").write_bytes(release_raw)
    sums = "".join(
        f"{sha256(raw)}  {name}\n"
        for name, raw in sorted({"index.html": index_raw, "projects.json": projects_raw, "release.json": release_raw}.items())
    ).encode("utf-8")
    (args.output / "sha256sums.txt").write_bytes(sums)
    print(json.dumps({
        "classification": release["classification"],
        "release_id": RELEASE_ID,
        "files": 4,
        "projects_sha256": sha256(projects_raw),
        "release_sha256": sha256(release_raw),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
