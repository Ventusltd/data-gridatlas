#!/usr/bin/env python3
"""Verify the complete repository after adding a second immutable release root."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess


LEDGER_LINE = re.compile(r"^([0-9a-f]{64})  ([^\0\r\n]+)$")
RELEASE_ROOT = re.compile(r"^\d{12}-[a-z0-9-]+$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tracked_files(repository: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repository), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return sorted(value.decode("utf-8") for value in result.stdout.split(b"\0") if value)


def verify_release(repository: Path, root_name: str, limits: dict, tracked: set[str]) -> dict:
    root = repository / root_name
    require(root.is_dir() and not root.is_symlink(), f"release root missing or unsafe: {root_name}")
    entries = list(root.rglob("*"))
    require(not any(path.is_symlink() for path in entries), f"release symlink forbidden: {root_name}")
    actual = sorted(path.relative_to(root).as_posix() for path in entries if path.is_file())
    tracked_actual = sorted(
        PurePosixPath(value).relative_to(root_name).as_posix()
        for value in tracked
        if PurePosixPath(value).parts[0] == root_name
    )
    require(actual == tracked_actual, f"untracked or missing release file: {root_name}")
    require(len(actual) == limits["files"], f"release file count drift: {root_name}")
    require("sha256sums.txt" in actual, f"release ledger missing: {root_name}")

    lines = (root / "sha256sums.txt").read_text(encoding="utf-8").splitlines()
    ledger: dict[str, str] = {}
    for line in lines:
        match = LEDGER_LINE.fullmatch(line)
        require(match is not None, f"malformed ledger line: {root_name}")
        expected, relative = match.groups()
        require(relative not in ledger and relative != "sha256sums.txt", f"duplicate/self ledger path: {root_name}/{relative}")
        require(PurePosixPath(relative).as_posix() == relative and not relative.startswith("/"), f"unsafe ledger path: {root_name}/{relative}")
        require(".." not in PurePosixPath(relative).parts, f"escaping ledger path: {root_name}/{relative}")
        ledger[relative] = expected
    require(set(ledger) | {"sha256sums.txt"} == set(actual), f"release ledger closure drift: {root_name}")

    release_bytes = 0
    for relative in actual:
        path = root / relative
        size = path.stat().st_size
        require(size <= limits["maximum_file_bytes"], f"oversize release file: {root_name}/{relative}")
        release_bytes += size
        if relative != "sha256sums.txt":
            require(sha256(path) == ledger[relative], f"release hash drift: {root_name}/{relative}")
    require(release_bytes <= limits["maximum_release_bytes"], f"release byte budget exceeded: {root_name}")
    return {"root": root_name, "files": len(actual), "bytes": release_bytes, "ledger_entries": len(ledger)}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--mode", choices=("source", "release"), required=True)
    args = parser.parse_args()

    repository = args.repository.resolve()
    contract = json.loads(args.contract.read_text(encoding="utf-8"))
    require(contract.get("schema") == "data-gridatlas.repository-boundary.v3", "boundary schema drift")
    require(contract.get("generation") == "202608291410", "boundary generation drift")
    require(contract.get("historical_contracts_immutable") is True, "historical immutability not asserted")
    require(contract.get("multiple_timestamp_release_roots_verified_independently") is True, "multi-release verification not asserted")

    tracked_list = tracked_files(repository)
    tracked = set(tracked_list)
    source_files = set(contract["required_source_files"])
    pointer_files = set(contract["pointer_files"])
    expected_roots = set(contract["release_roots_by_mode"][args.mode])
    actual_roots = {
        PurePosixPath(value).parts[0]
        for value in tracked
        if RELEASE_ROOT.fullmatch(PurePosixPath(value).parts[0])
    }
    require(actual_roots == expected_roots, f"timestamp release roots drift: {sorted(actual_roots)}")

    release_files = {value for value in tracked if PurePosixPath(value).parts[0] in actual_roots}
    actual_sources = tracked - release_files - pointer_files
    require(actual_sources == source_files, f"source closure drift: missing={sorted(source_files - actual_sources)} extra={sorted(actual_sources - source_files)}")
    require(pointer_files.issubset(tracked), "pointer file closure drift")
    require(tracked == source_files | pointer_files | release_files, "repository boundary escape")

    forbidden = tuple(contract["forbidden_source_suffixes"])
    source_bytes = 0
    for relative in sorted(source_files):
        path = repository / relative
        require(path.is_file() and not path.is_symlink(), f"source missing or unsafe: {relative}")
        require(not relative.endswith(forbidden), f"forbidden source payload: {relative}")
        size = path.stat().st_size
        require(size <= contract["maximum_source_file_bytes"], f"oversize source file: {relative}")
        source_bytes += size
    require(source_bytes <= contract["maximum_source_bytes"], "source byte budget exceeded")

    pointer_payloads = [(repository / relative).read_bytes() for relative in sorted(pointer_files)]
    require(len(set(pointer_payloads)) == 1, "stable data pointers are not byte-identical")
    require(hashlib.sha256(pointer_payloads[0]).hexdigest() == contract["pointer_sha256"], "stable data pointer drift")

    release_reports = [
        verify_release(repository, root, contract["release_ledgers"][root], tracked)
        for root in sorted(actual_roots)
    ]
    print(json.dumps({
        "classification": "VERIFIED_CURRENT_REPOSITORY_BOUNDARY",
        "generation": contract["generation"],
        "mode": args.mode,
        "tracked_files": len(tracked),
        "source_files": len(source_files),
        "source_bytes": source_bytes,
        "release_roots": release_reports,
        "pointer_files": len(pointer_files),
        "failed": 0,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
