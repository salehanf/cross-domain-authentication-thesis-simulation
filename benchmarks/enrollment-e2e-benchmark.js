const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { execFileSync } = require('child_process');
const snarkjs = require('snarkjs');
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

function exists(file) {
  return fs.existsSync(file);
}

function loadJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function saveJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

function remove(target) {
  try {
    fs.rmSync(target, { recursive: true, force: true });
  } catch (_) {}
}

function backupFile(file) {
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

function runNode(root, script, args = []) {
  return execFileSync(
    process.execPath,
    [path.join(root, 'src', script), ...args.map(String)],
    {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 32 * 1024 * 1024
    }
  );
}

function parseAatArtifact(stdout) {
  const m = /AAT artifact:\s*[\r\n]+([^\r\n]+)/.exec(stdout);
  if (!m) {
    throw new Error(`Could not parse AAT artifact path.\n${stdout}`);
  }

  const aatFile = m[1].trim();
  const base = path.basename(aatFile);
  const id = /^aat_([0-9a-fA-F]{16})\.json$/.exec(base);

  if (!id) {
    throw new Error(`Could not derive enrollment ID from AAT artifact: ${aatFile}`);
  }

  return { aatFile, enrollmentId: id[1] };
}

function snapshotRoots(rootsDir) {
  if (!exists(rootsDir)) return new Set();
  return new Set(fs.readdirSync(rootsDir));
}

function restoreRoots(rootsDir, originalNames) {
  if (!exists(rootsDir)) return;
  for (const name of fs.readdirSync(rootsDir)) {
    if (!originalNames.has(name)) {
      remove(path.join(rootsDir, name));
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = config.paths.projectRoot;

  const registryFile = path.join(root, 'state', 'bas', 'enrollment_registry.json');
  const consumedFile = path.join(root, 'state', 'bas', 'consumed_aat_nullifiers.json');
  const rootsDir = path.join(root, 'state', 'roots');

  if (!exists(registryFile)) {
    throw new Error(`BAS registry not found: ${registryFile}`);
  }
  if (!exists(rootsDir)) {
    throw new Error(`SignedRoot directory not found: ${rootsDir}`);
  }

  const baselineRegistry = backupFile(registryFile);
  const baselineConsumed = backupFile(consumedFile);
  const baselineRoots = snapshotRoots(rootsDir);

  const pvssWasm = path.join(
    root, 'build', 'pvss_share',
    'pvss-share-proof_js', 'pvss-share-proof.wasm'
  );
  const pvssZkey = path.join(
    root, 'build', 'pvss_share', 'pvss-share-proof_final.zkey'
  );
  const pvssProofDir = path.join(root, 'build', 'pvss_share');

  const linkWasm = path.join(
    root, 'build', 'link_proof',
    'link-proof_js', 'link-proof.wasm'
  );
  const linkZkey = path.join(
    root, 'build', 'link_proof', 'link-proof_final.zkey'
  );
  const linkProofFile = path.join(root, 'build', 'link_proof', 'link-proof.json');
  const linkPublicFile = path.join(root, 'build', 'link_proof', 'link-public.json');

  for (const [label, file] of [
    ['PVSS WASM', pvssWasm],
    ['PVSS ZKey', pvssZkey],
    ['Link WASM', linkWasm],
    ['Link ZKey', linkZkey]
  ]) {
    if (!exists(file)) {
      throw new Error(`${label} not found: ${file}`);
    }
  }

  // Global generated proof files are restored after the whole benchmark.
  const globalBackups = new Map();
  globalBackups.set(linkProofFile, backupFile(linkProofFile));
  globalBackups.set(linkPublicFile, backupFile(linkPublicFile));

  for (let adminId = 1; adminId <= config.admins.n; adminId++) {
    const id = String(adminId).padStart(2, '0');
    const proofFile = path.join(pvssProofDir, `admin_${id}_proof.json`);
    const publicFile = path.join(pvssProofDir, `admin_${id}_public.json`);
    globalBackups.set(proofFile, backupFile(proofFile));
    globalBackups.set(publicFile, backupFile(publicFile));
  }

  const resultsDir = path.join(root, 'benchmarks', 'results');
  const outputFile = args.output
    ? path.resolve(args.output)
    : path.join(
        resultsDir,
        `enrollment_e2e_${timestampForFilename()}.json`
      );

  console.log('Phase boundary               : thesis Phase 4 (User Enrollment)');
  console.log('AAT issuance                 : fresh per sample, EXCLUDED (Phase 3)');
  console.log('BAS/root state               : restored after every sample');
  console.log(`PVSS proofs per enrollment   : ${config.admins.n}`);
  console.log('');

  async function operation() {
    let enrollmentId = null;
    let aatFile = null;

    // Every sample needs an unused AAT, but AAT issuance belongs to Phase 3,
    // so it is intentionally outside the Phase-4 timer.
    const aatOut = runNode(root, 'aat.js', ['issue']);
    ({ aatFile, enrollmentId } = parseAatArtifact(aatOut));

    const e2eStart = performance.now();

    try {
      let start = performance.now();
      runNode(root, 'pvss_enrollment.js', [aatFile]);
      const pvssEnrollmentMs = performance.now() - start;

      start = performance.now();
      runNode(root, 'generate-pvss-proof-inputs.js', [enrollmentId]);
      const pvssInputGenerationMs = performance.now() - start;

      const pvssInputDir = path.join(
        root, 'build', 'pvss_share_inputs', enrollmentId
      );

      start = performance.now();
      let pvssProofGenerationSumMs = 0;

      for (let adminId = 1; adminId <= config.admins.n; adminId++) {
        const id = String(adminId).padStart(2, '0');
        const inputFile = path.join(pvssInputDir, `admin_${id}.json`);

        if (!exists(inputFile)) {
          throw new Error(`PVSS proof input not found: ${inputFile}`);
        }

        const input = loadJson(inputFile);
        const p0 = performance.now();
        const { proof, publicSignals } =
          await snarkjs.groth16.fullProve(input, pvssWasm, pvssZkey);
        const p1 = performance.now();

        pvssProofGenerationSumMs += p1 - p0;

        saveJson(
          path.join(pvssProofDir, `admin_${id}_proof.json`),
          proof
        );
        saveJson(
          path.join(pvssProofDir, `admin_${id}_public.json`),
          publicSignals
        );
      }

      const pvssProofBatchWallMs = performance.now() - start;

      start = performance.now();
      runNode(root, 'finalize-pvss-data.js', [enrollmentId]);
      const pvssFinalizeMs = performance.now() - start;

      start = performance.now();
      runNode(root, 'generate-link-proof-input.js', [enrollmentId]);
      const linkInputGenerationMs = performance.now() - start;

      const linkInputFile = path.join(
        root, 'build', 'link_proof_inputs', `${enrollmentId}.json`
      );

      if (!exists(linkInputFile)) {
        throw new Error(`Link proof input not found: ${linkInputFile}`);
      }

      const linkInput = loadJson(linkInputFile);

      start = performance.now();
      const linkResult =
        await snarkjs.groth16.fullProve(linkInput, linkWasm, linkZkey);
      const linkProofGenerationMs = performance.now() - start;

      saveJson(linkProofFile, linkResult.proof);
      saveJson(linkPublicFile, linkResult.publicSignals);

      start = performance.now();
      runNode(root, 'build-enroll-package.js', [enrollmentId, aatFile]);
      const enrollPackageBuildMs = performance.now() - start;

      start = performance.now();
      runNode(root, 'bas-verify-enrollment.js', [enrollmentId]);
      const basEnrollmentVerifyMs = performance.now() - start;

      const reportFile = path.join(
        root,
        'results',
        'enrollment',
        enrollmentId,
        'bas_verification_report.json'
      );

      if (!exists(reportFile)) {
        throw new Error(
          `BAS enrollment report not found: ${reportFile}`
        );
      }

      const report = loadJson(reportFile);
      if (report.accepted !== true) {
        throw new Error('BAS enrollment did not return accepted=true.');
      }

      const enrollmentE2eMs = performance.now() - e2eStart;

      return {
        pvss_enrollment_wall_ms: pvssEnrollmentMs,
        pvss_proof_input_generation_wall_ms: pvssInputGenerationMs,
        pvss_groth16_proofs_sum_ms: pvssProofGenerationSumMs,
        pvss_groth16_batch_wall_ms: pvssProofBatchWallMs,
        pvss_finalize_wall_ms: pvssFinalizeMs,
        link_proof_input_generation_wall_ms: linkInputGenerationMs,
        link_groth16_proof_generation_ms: linkProofGenerationMs,
        enroll_package_build_wall_ms: enrollPackageBuildMs,
        bas_enrollment_verify_wall_ms: basEnrollmentVerifyMs,
        enrollment_e2e_wall_ms: enrollmentE2eMs
      };
    } finally {
      // Restore persistent protocol state so every iteration begins from
      // exactly the same BAS membership/root state.
      restoreFile(registryFile, baselineRegistry);
      restoreFile(consumedFile, baselineConsumed);
      restoreRoots(rootsDir, baselineRoots);

      if (enrollmentId) {
        remove(path.join(root, 'artifacts', 'enrollment', enrollmentId));
        remove(path.join(root, 'private', 'users', enrollmentId));
        remove(path.join(root, 'build', 'pvss_share_inputs', enrollmentId));
        remove(path.join(root, 'build', 'link_proof_inputs', `${enrollmentId}.json`));
        remove(path.join(root, 'results', 'enrollment', enrollmentId));
      }

      if (aatFile) {
        remove(aatFile);
        remove(`${aatFile}.report.json`);
        const parsed = path.parse(aatFile);
        remove(path.join(parsed.dir, `${parsed.name}.report.json`));
      }
    }
  }

  try {
    await executeBenchmark({
      name: 'User Enrollment end-to-end (Phase 4)',
      warmup: args.warmup,
      runs: args.runs,
      operation,
      outputFile,
      metadata: {
        thesis_phase: 4,
        phase_name: 'User Enrollment',
        admins_n: config.admins.n,
        threshold_t: config.admins.t,
        aat_issuance_included: false,
        aat_exclusion_reason:
          'AAT issuance is thesis Phase 3 and is benchmarked separately.',
        state_reset:
          'BAS registry, consumed AAT nullifiers, and SignedRoot files are restored after every sample.',
        pvss_proof_system: 'Groth16',
        link_proof_system: 'Groth16',
        note: [
          'enrollment_e2e_wall_ms starts immediately after a fresh valid AAT has been issued.',
          'It includes PVSS enrollment, PVSS proof-input generation, all per-admin PVSS Groth16 proofs, PVSS finalization, link-proof input generation, link Groth16 proof generation, Enroll_Package construction, and BAS verification/SMT insertion/new SignedRoot creation.',
          'Per-sample cleanup and BAS/root rollback are excluded from the measured interval.'
        ].join(' ')
      }
    });
  } finally {
    restoreFile(registryFile, baselineRegistry);
    restoreFile(consumedFile, baselineConsumed);
    restoreRoots(rootsDir, baselineRoots);

    for (const [file, bytes] of globalBackups.entries()) {
      restoreFile(file, bytes);
    }
  }
}

main()
  .then(() => process.exit(0))
  .catch(err => {
    console.error('');
    console.error('Enrollment end-to-end benchmark failed:');
    console.error(err.stack || err.message);
    process.exit(1);
  });
