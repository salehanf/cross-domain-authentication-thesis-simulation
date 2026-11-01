# v15: AAT end-to-end benchmark

Benchmarks thesis Phase 3 only.

Measures:
- `aat_issue_wall_ms`: full AAT issuance wall-clock time (Node process + nonce + FROST sign/verify + JSON artifacts).
- `aat_frost_internal_ms`: internal FROST cryptographic timing reported by the existing implementation.
- `aat_signature_bytes`: should remain 64 bytes.

Generated AAT/report files are deleted after every sample. No BAS membership state is changed.

Smoke test:

```powershell
node benchmarks\aat-e2e-benchmark.js --warmup 1 --runs 2
```

Final run:

```powershell
node benchmarks\aat-e2e-benchmark.js --warmup 5 --runs 50
```
