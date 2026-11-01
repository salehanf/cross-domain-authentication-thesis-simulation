# v18: Full Phase-1 Domain Setup benchmark

This benchmark follows the thesis Phase-1 boundary rather than only `src/setup.js`.

It includes:

1. System/domain parameter setup and empty SMT.
2. FROST 3-of-5 DKG + self-test.
3. PVSS administrator encryption-key generation + self-tests.
4. Groth16 trusted setup for:
   - authentication circuit,
   - link circuit,
   - PVSS share circuit.
5. Initial threshold-signed root version 0.

Important safety behavior:

- Existing project ZKeys under `build/` are read-only and are never overwritten.
- Temporary Groth16 setup artifacts are generated under `benchmarks/.phase1-zk-temp-*` and deleted.
- Existing `private/frost`, `private/pvss`, `state/frost`, `state/pvss`, `state/roots`,
  `results/system_setup.json`, `results/frost_setup.json`, and `results/pvss_setup.json`
  are snapshotted and restored byte-for-byte after every sample.
- Each sample uses a fresh Node worker process.

Smoke test:

```powershell
node benchmarks\phase1-setup-e2e-benchmark.js --warmup 1 --runs 2
```

Final benchmark:

```powershell
node benchmarks\phase1-setup-e2e-benchmark.js --warmup 5 --runs 50
```

Because Phase 1 is a one-time/offline operation, the report exposes all component timings separately,
including `zk_all_circuits_setup_ms` and `phase1_setup_e2e_wall_ms`.
