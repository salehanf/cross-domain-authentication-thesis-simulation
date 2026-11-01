# v14: Enrollment end-to-end benchmark

Benchmarks thesis Phase 4 only.

A fresh AAT is issued before every sample, but AAT issuance is excluded because it is thesis Phase 3.

The measured Phase-4 interval contains:
- PVSS enrollment
- PVSS proof-input generation
- all per-admin PVSS Groth16 proofs
- PVSS finalization
- link-proof input generation
- link Groth16 proof
- Enroll_Package construction
- BAS enrollment verification
- SMT insertion and new SignedRoot creation

Persistent BAS state is rolled back after every iteration.

First smoke test:

```powershell
node benchmarks\enrollment-e2e-benchmark.js --warmup 1 --runs 2
```

Final run:

```powershell
node benchmarks\enrollment-e2e-benchmark.js --warmup 5 --runs 50
```
