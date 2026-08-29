# Data Grid Atlas

`data-gridatlas` is the evidence-gated data plane for Atlas V9. It owns source
contracts, deterministic data compilation, immutable release manifests and
small browser registries. [`Ventusltd/gridatlas`](https://github.com/Ventusltd/gridatlas)
owns the application, rendered tests and deployment.

Atlas V8 remains an immutable oracle at
`Ventusltd/globalgrid2050@f2f343a92ee972cc74ed23b4b99d8a22896791ad`.
No V8 payload, workflow or monolithic engine is copied into this repository.

## Bootstrap checkpoint

The first checkpoint is deliberately inventory-only:

- 104 V8 subtree files are pinned by path, byte count and Git blob OID.
- 60 configured layers and 40 unique runtime URLs are recorded.
- 16 unwired files, seven root-absolute dependencies and the metro/tram
  geometry mismatch are quarantined.
- CI builds a compact DuckDB/ZSTD Parquet dependency catalogue twice, verifies
  byte identity and uploads it as evidence only.
- There is no release, raw data dump, Pages publication or `state/current.json`.

Promotion will be a later compare-and-swap checkpoint: immutable
`releases/<generation>/manifest.json` first, an exact consumer verification in
`gridatlas` second, and only then a movable current pointer.

## Repository split

| Concern | Owner |
|---|---|
| Source identity, provenance, schemas, transforms, Parquet and manifests | `data-gridatlas` |
| UI, layer styling, lazy loading, search, fly-to and rendered browser tests | `gridatlas` |
| Historical behaviour and parity evidence | pinned V8 oracle, read-only |

Presence in V8 is not approval for V9. Every source needs an authority,
licence, schema, geometry and refresh decision before ingestion.
