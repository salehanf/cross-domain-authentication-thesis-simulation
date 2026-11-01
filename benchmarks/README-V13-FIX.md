# v13 fix

Fixes the v12 process-isolated Groth16 benchmark hanging on the first sample.

Changes:
- The isolated worker now explicitly exits after its JSON result is flushed.
- Errors also exit explicitly after stderr is flushed.
- Parent process has a 120-second safety timeout per isolated sample.
- Measurement boundaries are unchanged from v12.

Recommended first smoke test:

```powershell
node benchmarks\zk-crypto-isolated-benchmark.js --circuit auth --warmup 1 --runs 2
```

If that completes, run the final benchmark:

```powershell
node benchmarks\zk-crypto-isolated-benchmark.js --circuit auth --warmup 5 --runs 50
node benchmarks\zk-crypto-isolated-benchmark.js --circuit link --warmup 5 --runs 50
node benchmarks\zk-crypto-isolated-benchmark.js --circuit pvss --warmup 5 --runs 50
```
