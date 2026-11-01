# v17: Proactive Refresh end-to-end benchmark

Benchmarks thesis Phase 8.

If private administrator refresh-share state does not yet exist for the selected ACTIVE enrollment,
`bootstrap-refresh-shares.js` is run once before the benchmark. That setup is excluded from all timings.

Each sample:
1. Restores the exact same baseline private shares/epoch.
2. Runs one real proactive refresh.
3. Requires all shares to change.
4. Requires x_anchor and y_hash to remain unchanged.
5. Requires mixed-epoch reconstruction to be rejected.
6. Requires BAS registry, Enroll_Package and SignedRoot state to remain byte-for-byte unchanged.
7. Restores the original private shares after the sample.

Smoke test:

```powershell
node benchmarks\refresh-e2e-benchmark.js --warmup 1 --runs 2
```

Final run:

```powershell
node benchmarks\refresh-e2e-benchmark.js --warmup 5 --runs 50
```
