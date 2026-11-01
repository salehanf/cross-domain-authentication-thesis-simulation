# Thesis benchmark framework v2

## Default repetition policy
Defaults come from `src/config.js`:
- warm-up: `config.experiment.warmupRuns` (currently 5)
- measured runs: `config.experiment.repetitions` (currently 30)

CLI values override the defaults without editing source files.

## Single-depth SMT benchmark

```powershell
node benchmarks\smt-benchmark.js --warmup 5 --runs 30 --depth 20
```

For 50 measured runs:

```powershell
node benchmarks\smt-benchmark.js --warmup 5 --runs 50 --depth 20
```

Version 2 initializes Poseidon once outside the measured samples. This avoids contaminating SMT scalability measurements with repeated cryptographic library startup cost.

## Automatic depth sweep

```powershell
node benchmarks\smt-depth-sweep.js --warmup 5 --runs 30 --depths 8,12,16,20,24,28,32
```

You can change both the repetitions and depth set directly from the command line:

```powershell
node benchmarks\smt-depth-sweep.js --warmup 5 --runs 50 --depths 16,32,64,128,256
```

Each depth gets a separate JSON report. The sweep also writes `aggregate.json` and `aggregate.csv`, suitable for later plots and thesis tables.

## Reported statistics
Measured samples only:
- mean
- median
- sample standard deviation
- min
- max
- p95
- coefficient of variation (CV)
- raw samples

Warm-up samples are never included in the reported statistics.

## SMT active-user (N) scalability

Measures incremental SMT latency at a fixed depth while the tree already contains N active leaves. Base-tree population and Poseidon setup are excluded from measured samples.

Example:

```powershell
node benchmarks\smt-user-sweep.js --warmup 5 --runs 50 --depth 20 --users 1,10,100,1000,5000
```

Outputs one JSON file per N plus aggregate.json and aggregate.csv. The aggregate also records stored_non_default_nodes and one_time_population_ms so state growth can be discussed separately from online per-operation latency.

## Threshold / proactive-refresh core scalability

Single configuration:

```powershell
node benchmarks\threshold-core-benchmark.js --warmup 5 --runs 50 --n 5 --t 3
```

Sweep threshold `t` while holding `n=10`:

```powershell
node benchmarks\threshold-sweep.js --mode t --n 10 --values 2,3,5,7,9 --warmup 5 --runs 50
```

Sweep administrator count `n` while holding `t=3`:

```powershell
node benchmarks\threshold-sweep.js --mode n --t 3 --values 3,5,7,10,15 --warmup 5 --runs 50
```

These are isolated core-operation benchmarks. BabyJub initialization is one-time and excluded from samples. The refresh core mirrors the zero-constant polynomial generation, BabyJub commitments, n^2 delta/Feldman verification, share update, and Lagrange reconstruction used by `src/proactive-refresh.js` and `src/reconstruct-revocation-target.js`.

## Interleaved threshold sweep (recommended for final t results)
To reduce time-order/thermal bias, values are executed in cyclically rotated order on every round.

```powershell
node benchmarks\\threshold-interleaved-sweep.js --mode t --n 10 --values 2,3,5,7,9 --warmup 5 --runs 50
```

Here, `--runs 50` means 50 measured samples **per t value**. Each round executes every t once, with the order rotated across rounds.

## Groth16 proof benchmark
Measures the actual `snarkjs.groth16.fullProve` and `groth16.verify` calls used by the project. A correctness check is performed once before warm-up. Verification-key parsing is excluded; proof generation includes the normal snarkjs proving call with the project's WASM and ZKey files.

Authentication proof:
```powershell
node benchmarks\zk-proof-benchmark.js --circuit auth --warmup 5 --runs 50
```

Enrollment link proof:
```powershell
node benchmarks\zk-proof-benchmark.js --circuit link --warmup 5 --runs 50
```

One PVSS-share correctness proof:
```powershell
node benchmarks\zk-proof-benchmark.js --circuit pvss --warmup 5 --runs 50
```

Use `--input <file>` to explicitly select a valid circuit input JSON instead of automatic discovery.

## FROST baseline benchmark

Measures the configured threshold signature implementation (default 3-of-5) over random 32-byte messages. It records both the internal Rust FROST timings and wrapper wall-clock timings. For thesis protocol-cost reporting, prefer `frost_internal_total_ms`; wall-clock fields include process launch and file I/O.

```powershell
node benchmarks\frost-benchmark.js --warmup 5 --runs 50
```

## Authentication end-to-end benchmark (v8)

Runs a fresh destination challenge for every sample, generates the authentication witness/input, creates the real Groth16 proof, builds Auth_Request, and verifies it at the destination. The active BAS enrollment is auto-discovered, or can be selected explicitly with `--enrollment`.

Default/config-driven run:

    node benchmarks\auth-e2e-benchmark.js

Recommended thesis run:

    node benchmarks\auth-e2e-benchmark.js --warmup 5 --runs 50

Optional explicit active enrollment:

    node benchmarks\auth-e2e-benchmark.js --warmup 5 --runs 50 --enrollment <ACTIVE_ENROLLMENT_ID>

This benchmark does not modify BAS membership. It deletes the per-run challenge, authentication artifacts, input, and report after each sample, and restores the pre-existing generic auth proof/public files when it exits.

## Secure-session end-to-end benchmark

Measures Phase 6 after a fresh accepted authentication has been prepared for each sample. Authentication preparation is excluded from session timings.

```powershell
node benchmarks\\session-e2e-benchmark.js --warmup 5 --runs 50
```

## Groth16 crypto-core split (v11)

This benchmark separates witness generation, proving from an already generated witness, and verification while excluding OS process startup and disk I/O from measured samples.

```powershell
node benchmarks\zk-crypto-core-benchmark.js --circuit auth --warmup 5 --runs 50
node benchmarks\zk-crypto-core-benchmark.js --circuit link --warmup 5 --runs 50
node benchmarks\zk-crypto-core-benchmark.js --circuit pvss --warmup 5 --runs 50
```

Metrics:
- `witness_generation_core_ms`: witness computation on a pre-built WitnessCalculator.
- `groth16_prove_from_witness_ms`: Groth16 prove from an in-memory witness and in-memory ZKey.
- `groth16_verify_core_ms`: Groth16 verify with VKey/proof/public signals already in memory.
- `groth16_crypto_core_total_ms`: sum of the three measured library-level core operations.

Important interpretation: this removes process startup and filesystem I/O. It is a library-level crypto-core benchmark, not a decomposition of every internal elliptic-curve/FFT primitive inside snarkjs.
