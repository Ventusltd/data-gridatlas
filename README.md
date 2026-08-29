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
- There is no release, raw data dump, generated-data Pages publication or
  `state/current.json`.

Promotion will be a later compare-and-swap checkpoint: immutable
`releases/<generation>/manifest.json` first, an exact consumer verification in
`gridatlas` second, and only then a movable current pointer.

## Full V8 parity candidate

Generation `202608291015` uses an eight-shard GitHub Actions matrix to verify
and compile all 56 pinned V8 FeatureCollections: 40 wired sources plus 16
unwired quarantine sources. It preserves the 60-layer declarative style and
filter contract, emits per-source ZSTD Parquet, proves 541,282 feature rows and
526,388 layer memberships, and derives the five endpoint-snapped topology
partitions deterministically. Raw GeoJSON and excess source properties are
never uploaded.

This remains a parity candidate, not V9 truth. Estimated 11 kV/UKPN identity,
the unreproducible industrial-offtaker blob, metro/tram geometry, unwired files
and the old REPD master are explicitly blocked from promotion. Active sources
must be reacquired from their declared owners with licence and attribution
evidence before a release can be made live.

## Repository split

| Concern | Owner |
|---|---|
| Source identity, provenance, schemas, transforms, Parquet and manifests | `data-gridatlas` |
| UI, layer styling, lazy loading, search, fly-to and rendered browser tests | `gridatlas` |
| Historical behaviour and parity evidence | pinned V8 oracle, read-only |

Presence in V8 is not approval for V9. Every source needs an authority,
licence, schema, geometry and refresh decision before ingestion.
