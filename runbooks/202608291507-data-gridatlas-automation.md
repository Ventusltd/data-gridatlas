# Data Grid Atlas automation runbook — 202608291507

## Stable recovery anchor

- Original live-data anchor: `fd1c49eece37d1a8035d8fcdc6c08d20a5cdbd13`
- Reconciled automation parent: `b8668b4d5f34880158aeed2eab5c4a1e678a467d`
- Immutable REPD routing dependency: `202608291410-repd-routing` (tree `cef0fffc848fb4b04ed94b0ec1f8cbaed3877a17`)
- Pointer SHA-256: `08664a2fab1f2a6442a866b43abe3748fe4418e6bf0892630850a6edfd3f2283`
- Live data: `202608291237-data-gridatlas` at `32459230b958ff6ddbdb24365f56da83ab1cdc93`
- Live app: `202608291239-atlas-v9` at `1898184ccbf52ca836cf1482362fc5933baf3e8d`
- Golden query: `?repd_ref=16135` (`MK430ZY`)

The live data release and the separately timestamped REPD routing dependency are already complete. Recovery verifies the checked-in releases; it never rebuilds either one.

## Hourly state machine

The watchdog starts at minute 17 UTC and may also be run manually.

1. Resolve the exact default-branch HEAD and both byte-identical pointer files.
2. Probe the public data pointer, immutable release sentinels and Grid Atlas consumer in parallel.
3. Find the current-integrity run for that exact HEAD.
4. If it is queued or running, return `WAITING`.
5. If it is green, return `NOOP_ALREADY_VERIFIED`.
6. If failed and its attempt is below three, rerun only failed jobs.
7. If no matching run exists, dispatch current-integrity with the exact HEAD and pointer hash.
8. After three failed attempts, fail closed and preserve all evidence.

## Integrity lanes

Eight read-only lanes are balanced by declared Parquet byte size. Every Parquet file is assigned once. Each lane verifies local size, SHA-256, row count, compression, schema and retained-property privacy, then checks public prefix/suffix byte ranges, identity encoding and CORS. Lane 0 also proves the public data and app pointers and the golden deep link. Lane 1 reruns the existing full immutable-release verifier. The reducer rejects missing, duplicate or inconsistent lanes.

## Contract guard

The guard runs on relevant pushes, pull requests and manual dispatches. It accepts only the six timestamped automation checkpoint files added above the stable baseline, verifies exact action pins and least-privilege workflow permissions, rejects any job timeout above 20 minutes, and re-proves the immutable release tree and both pointer hashes. It has no write permission.

## Failure routing

| Failure | Safe action |
|---|---|
| Matching integrity run still active | Wait; do not overlap |
| Transient public/CORS/range failure | Rerun failed verification jobs only |
| Grid Atlas consumer mismatch | Let Grid Atlas's own workflow repair or supersede it; do not use a cross-repository token here |
| Local immutable byte/hash mismatch | Stop and quarantine; never regenerate in place |
| Pointer mismatch | Stop; require a new timestamped compare-and-swap promotion |
| New source generation requested | Create a new contract/compiler/workflow generation; never dispatch the 202608291015 build against current main |

## Non-negotiable boundaries

- Do not edit `202608291237-data-gridatlas/**`.
- Do not edit `state/live-set.json` or `releases/current.json` in this checkpoint.
- Do not edit predecessor timestamped workflows, contracts, compilers or verifiers.
- Do not emit raw GeoJSON, CSV, XLSX or DuckDB database files.
- Preserve every authority, licence and quarantine disposition.
- Workflows have no repository-content write permission. Only the small router receives `actions: write`, solely to dispatch or rerun the integrity workflow.

## Resume command

Run **202608291507 Data Grid Atlas watchdog and router**. Its summary reports the exact anchor, probe status and one of `WAITING`, `NOOP_ALREADY_VERIFIED`, `DISPATCHED`, `RERUN_FAILED_JOBS` or `BLOCKED_AFTER_THREE_ATTEMPTS`.
