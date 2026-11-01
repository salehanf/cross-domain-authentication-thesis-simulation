# v12: Process-isolated Groth16 crypto-core benchmark

Use this benchmark when repeated in-process `groth16.prove()` calls show high variance.

Each measured sample runs in a fresh Node process. Inside that process:
1. Input/WASM/ZKey/VKey are loaded (excluded).
2. WitnessCalculator is built (excluded).
3. One full correctness/warm-up pass is executed (excluded).
4. GC is requested (excluded).
5. Only witness generation, prove-from-witness, and verify are measured.

Commands:

```powershell
node benchmarks\zk-crypto-isolated-benchmark.js --circuit auth --warmup 5 --runs 50
node benchmarks\zk-crypto-isolated-benchmark.js --circuit link --warmup 5 --runs 50
node benchmarks\zk-crypto-isolated-benchmark.js --circuit pvss --warmup 5 --runs 50
```
