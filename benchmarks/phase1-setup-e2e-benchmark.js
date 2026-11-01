const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const crypto = require('crypto');
const config = require('../src/config');
const {
  executeBenchmark,
  timestampForFilename
} = require('./benchmark-utils');

function parseArgs(argv) {
  const args = {
    warmup: config.experiment.warmupRuns,
    runs: config.experiment.repetitions,
    output: null
  };

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i];
    if (!token.startsWith('--')) continue;

    const key = token.slice(2);
    const value = argv[++i];

    if (value === undefined || value.startsWith('--')) {
      throw new Error(`Missing value for --${key}`);
    }

    if (key === 'warmup' || key === 'runs') {
      const n = Number(value);
      if (!Number.isInteger(n) || n < (key === 'runs' ? 1 : 0)) {
        throw new Error(`Invalid --${key}: ${value}`);
      }
      args[key] = n;
    } else if (key === 'output') {
      args.output = value;
    } else {
      throw new Error(`Unknown option: --${key}`);
    }
  }

  return args;
}

function exists(p) {
  return fs.existsSync(p);
}

function remove(p) {
  try {
    fs.rmSync(p, { recursive: true, force: true });
  } catch (_) {}
}

function snapshotTree(dir) {
  const out = new Map();

  function walk(current, relBase) {
    if (!exists(current)) return;

    for (const name of fs.readdirSync(current)) {
      const full = path.join(current, name);
      const rel = path.join(relBase, name);
      const stat = fs.statSync(full);

      if (stat.isDirectory()) {
        walk(full, rel);
      } else {
        out.set(rel, fs.readFileSync(full));
      }
    }
  }

  walk(dir, '');
  return out;
}

function restoreTree(dir, snapshot) {
  remove(dir);

  if (snapshot.size === 0) return;

  fs.mkdirSync(dir, { recursive: true });

  for (const [rel, bytes] of snapshot.entries()) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, bytes);
  }
}

function snapshotFile(file) {
  return exists(file) ? fs.readFileSync(file) : null;
}

function restoreFile(file, bytes) {
  if (bytes === null) {
    remove(file);
    return;
  }

  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, bytes);
}

function digestTree(snapshot) {
  const h = crypto.createHash('sha256');
  for (const key of Array.from(snapshot.keys()).sort()) {
    h.update(key);
    h.update('\0');
    h.update(snapshot.get(key));
    h.update('\0');
  }
  return h.digest('hex');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = config.paths.projectRoot;

  const trackedDirs = [
    path.join(root, 'private', 'frost'),
    path.join(root, 'private', 'pvss'),
    path.join(root, 'state', 'frost'),
    path.join(root, 'state', 'pvss'),
    path.join(root, 'state', 'roots')
  ];

  const trackedFiles = [
    path.join(root, 'results', 'system_setup.json'),
    path.join(root, 'results', 'frost_setup.json'),
    path.join(root, 'results', 'pvss_setup.json')
  ];

  const dirSnapshots = new Map(
    trackedDirs.map(dir => [dir, snapshotTree(dir)])
  );
  const fileSnapshots = new Map(
    trackedFiles.map(file => [file, snapshotFile(file)])
  );

  const baselineDigests = new Map(
    Array.from(dirSnapshots.entries()).map(
      ([dir, snap]) => [dir, digestTree(snap)]
    )
  );

  function restoreBaseline() {
    for (const [dir, snap] of dirSnapshots.entries()) {
      restoreTree(dir, snap);
    }
    for (const [file, bytes] of fileSnapshots.entries()) {
      restoreFile(file, bytes);
    }
  }

  function prepareFreshSetupState() {
    for (const dir of trackedDirs) remove(dir);
    for (const file of trackedFiles) remove(file);
  }

  function validateRestoredBaseline() {
    for (const [dir, expectedDigest] of baselineDigests.entries()) {
      const actual = digestTree(snapshotTree(dir));
      if (actual !== expectedDigest) {
        throw new Error(`Baseline restore verification failed for ${dir}`);
      }
    }

    for (const [file, bytes] of fileSnapshots.entries()) {
      const now = snapshotFile(file);
      const beforeHash = bytes === null
        ? null
        : crypto.createHash('sha256').update(bytes).digest('hex');
      const afterHash = now === null
        ? null
        : crypto.createHash('sha256').update(now).digest('hex');

      if (beforeHash !== afterHash) {
        throw new Error(`Baseline file restore verification failed for ${file}`);
      }
    }
  }

  const resultsDir = path.join(root, 'benchmarks', 'results');
  const outputFile = args.output
    ? path.resolve(args.output)
    : path.join(
        resultsDir,
        `phase1_setup_e2e_${timestampForFilename()}.json`
      );

  console.log(`Administrators              : ${config.admins.t}-of-${config.admins.n}`);
  console.log(`SMT depth                   : ${config.smt.depth}`);
  console.log('Groth16 circuits            : auth, link, pvss');
  console.log('Groth16 PTAU                : build/ptau/pot15_final.ptau');
  console.log('Original build ZKeys        : read-only / untouched');
  console.log('Setup state                 : restored byte-for-byte after every sample');
  console.log('');

  async function operation() {
    restoreBaseline();
    prepareFreshSetupState();

    const worker = path.join(__dirname, 'phase1-setup-worker.js');

    try {
      const child = spawnSync(
        process.execPath,
        [worker],
        {
          cwd: root,
          encoding: 'utf8',
          windowsHide: true,
          maxBuffer: 64 * 1024 * 1024,
          timeout: 600000
        }
      );

      if (child.error) {
        throw new Error(
          `Phase-1 worker process error: ${child.error.message}\n` +
          `STDOUT: ${child.stdout || ''}\nSTDERR: ${child.stderr || ''}`
        );
      }

      if (child.status !== 0) {
        throw new Error(
          `Phase-1 worker failed (exit ${child.status}).\n` +
          `STDOUT: ${child.stdout || ''}\nSTDERR: ${child.stderr || ''}`
        );
      }

      const text = String(child.stdout || '').trim();
      let metrics;

      try {
        metrics = JSON.parse(text);
      } catch (_) {
        throw new Error(`Could not parse Phase-1 worker output:\n${text}`);
      }

      return metrics;
    } finally {
      restoreBaseline();
      validateRestoredBaseline();
    }
  }

  try {
    await executeBenchmark({
      name: 'Domain setup end-to-end (Phase 1, full thesis boundary)',
      warmup: args.warmup,
      runs: args.runs,
      operation,
      outputFile,
      metadata: {
        thesis_phase: 1,
        phase_name: 'Domain/System Setup',
        admins_n: config.admins.n,
        threshold_t: config.admins.t,
        smt_depth: config.smt.depth,
        includes: [
          'public/domain cryptographic parameter setup',
          'empty Sparse Merkle Tree initialization',
          'FROST distributed key generation and self-test',
          'PVSS administrator encryption-key setup and ECDH self-tests',
          'Groth16 trusted setup for auth, link, and PVSS circuits',
          'initial SignedRoot version 0 creation and threshold-signature verification'
        ],
        groth16_note:
          'The current src/setup.js records ZK artifacts as pending. This benchmark explicitly performs the Groth16 per-circuit key-generation step because the thesis defines that step as part of Phase 1. Existing project build ZKeys are never overwritten.',
        state_isolation:
          'private/frost, private/pvss, state/frost, state/pvss, state/roots and setup result files are snapshotted and restored byte-for-byte after every sample.',
        worker_isolation:
          'Each sample executes in a fresh Node worker process to avoid cross-sample crypto backend/GC contamination.'
      }
    });
  } finally {
    restoreBaseline();
    validateRestoredBaseline();
  }
}

main()
  .then(() => process.exit(0))
  .catch(err => {
    console.error('');
    console.error('Phase-1 setup benchmark failed:');
    console.error(err.stack || err.message);
    process.exit(1);
  });
