# v16: Revocation end-to-end benchmark

Benchmarks thesis Phase 7.

Default share source is the original PVSS material:

```powershell
node benchmarks\revocation-e2e-benchmark.js --warmup 1 --runs 2
node benchmarks\revocation-e2e-benchmark.js --warmup 5 --runs 50
```

Optional:
```powershell
node benchmarks\revocation-e2e-benchmark.js --source current --warmup 5 --runs 50
node benchmarks\revocation-e2e-benchmark.js --enrollment <ACTIVE_ID> --warmup 5 --runs 50
```

The organizational decision that triggers revocation is a thesis precondition and is excluded.

The timer covers:
- threshold reconstruction,
- y_hash derivation,
- Revoke_Message creation + FROST,
- BAS/SMT revocation,
- active -> revoked,
- new SignedRoot generation, signing, persistence, and verification.

BAS registry and root files are restored after every sample, so all samples are independent.
