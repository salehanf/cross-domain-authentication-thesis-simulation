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
    enrollment: null,
    service: 'benchmark-service',
    output: null,
    bootstrap: true
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
    } else if (key === 'enrollment') {
      args.enrollment = value;
    } else if (key === 'service') {
      args.service = value;
    } else if (key === 'output') {
      args.output = value;
    } else {
      throw new Error(`Unknown option: --${key}`);
    }
  }
  return args;
}

function loadJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function saveJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

function exists(file) {
  return fs.existsSync(file);
}

function remove(target) {
  try { fs.rmSync(target, { recursive: true, force: true }); } catch (_) {}
}

function runNode(root, script, args = []) {
  return execFileSync(
    process.execPath,
    [path.join(root, 'src', script), ...args.map(String)],
    {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 16 * 1024 * 1024
    }
  );
}

function findActiveEnrollment(root, requested) {
  const registryFile = path.join(root, 'state', 'bas', 'enrollment_registry.json');
  if (!exists(registryFile)) throw new Error(`BAS registry not found: ${registryFile}`);
  const registry = loadJson(registryFile);
  const enrollmentBase = path.join(root, 'artifacts', 'enrollment');

  function validate(id) {
    const pkgFile = path.join(enrollmentBase, id, 'enroll_package.json');
    const witnessFile = path.join(root, 'private', 'users', id, 'pvss_witness.json');
    if (!exists(pkgFile) || !exists(witnessFile)) return null;
    const pkg = loadJson(pkgFile);
    const rec = registry.entries?.[String(pkg.y_hash)];
    if (!rec || String(rec.status).toLowerCase() !== 'active') return null;
    if (String(rec.idx) !== String(pkg.idx) || String(rec.L) !== String(pkg.L)) return null;
    return { id, pkg, record: rec };
  }

  if (requested) {
    const selected = validate(requested);
    if (!selected) {
      throw new Error(`Requested enrollment is not a complete ACTIVE BAS record: ${requested}`);
    }
    return selected;
  }

  if (!exists(enrollmentBase)) throw new Error('No enrollment artifacts directory found.');
  for (const id of fs.readdirSync(enrollmentBase).sort()) {
    const selected = validate(id);
    if (selected) return selected;
  }
  throw new Error('No complete ACTIVE enrollment was found. Use --enrollment <id> after enrolling an active user.');
}


async function bootstrapBenchmarkEnrollment(root) {
  console.log('No complete ACTIVE enrollment found.');
  console.log('Creating one benchmark enrollment (excluded from benchmark timings)...');
  console.log('');

  const aatOut = runNode(root, 'aat.js', ['issue']);
  const aatMatch = /AAT artifact:\s*[\r\n]+([^\r\n]+)/.exec(aatOut);
  if (!aatMatch) {
    throw new Error(`Could not parse AAT artifact from issuance output.\n${aatOut}`);
  }

  const aatFile = aatMatch[1].trim();
  const base = path.basename(aatFile);
  const idMatch = /^aat_([0-9a-fA-F]{16})\.json$/.exec(base);
  if (!idMatch) {
    throw new Error(`Could not derive enrollment ID from AAT artifact: ${aatFile}`);
  }
  const enrollmentId = idMatch[1];

  runNode(root, 'pvss_enrollment.js', [aatFile]);
  runNode(root, 'generate-pvss-proof-inputs.js', [enrollmentId]);

  const pvssWasm = path.join(root, 'build', 'pvss_share', 'pvss-share-proof_js', 'pvss-share-proof.wasm');
  const pvssZkey = path.join(root, 'build', 'pvss_share', 'pvss-share-proof_final.zkey');
  const pvssProofDir = path.join(root, 'build', 'pvss_share');
  const pvssInputDir = path.join(root, 'build', 'pvss_share_inputs', enrollmentId);

  for (const file of [pvssWasm, pvssZkey]) {
    if (!exists(file)) throw new Error(`PVSS proving artifact not found: ${file}`);
  }

  for (let adminId = 1; adminId <= config.admins.n; adminId++) {
    const id = String(adminId).padStart(2, '0');
    const inputFile = path.join(pvssInputDir, `admin_${id}.json`);
    if (!exists(inputFile)) throw new Error(`PVSS proof input not found: ${inputFile}`);
    const input = loadJson(inputFile);
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, pvssWasm, pvssZkey);
    saveJson(path.join(pvssProofDir, `admin_${id}_proof.json`), proof);
    saveJson(path.join(pvssProofDir, `admin_${id}_public.json`), publicSignals);
  }

  runNode(root, 'finalize-pvss-data.js', [enrollmentId]);
  runNode(root, 'generate-link-proof-input.js', [enrollmentId]);

  const linkInputFile = path.join(root, 'build', 'link_proof_inputs', `${enrollmentId}.json`);
  const linkWasm = path.join(root, 'build', 'link_proof', 'link-proof_js', 'link-proof.wasm');
  const linkZkey = path.join(root, 'build', 'link_proof', 'link-proof_final.zkey');
  for (const file of [linkInputFile, linkWasm, linkZkey]) {
    if (!exists(file)) throw new Error(`Link proving artifact not found: ${file}`);
  }

  const linkInput = loadJson(linkInputFile);
  const linkResult = await snarkjs.groth16.fullProve(linkInput, linkWasm, linkZkey);
  saveJson(path.join(root, 'build', 'link_proof', 'link-proof.json'), linkResult.proof);
  saveJson(path.join(root, 'build', 'link_proof', 'link-public.json'), linkResult.publicSignals);

  runNode(root, 'build-enroll-package.js', [enrollmentId]);
  runNode(root, 'bas-verify-enrollment.js', [enrollmentId]);

  const selected = findActiveEnrollment(root, enrollmentId);
  console.log(`Benchmark enrollment created: ${enrollmentId}`);
  console.log(`BAS root version after setup: v${selected.record.version}`);
  console.log('Benchmark setup is excluded from all warm-up/measured samples.');
  console.log('');
  return selected;
}

function backupFile(file) {
  return exists(file) ? fs.readFileSync(file) : null;
}

function restoreFile(file, bytes) {
  if (bytes === null) {
    remove(file);
  } else {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, bytes);
  }
}

function parseChallengeId(stdout) {
  const m = /Challenge ID\s*:\s*([0-9a-fA-F]+)/.exec(stdout);
  if (!m) throw new Error(`Could not parse Challenge ID from issue-auth-challenge output.\n${stdout}`);
  return m[1];
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = config.paths.projectRoot;
  let selected;
  try {
    selected = findActiveEnrollment(root, args.enrollment);
  } catch (err) {
    if (args.enrollment) throw err;
    selected = await bootstrapBenchmarkEnrollment(root);
  }

  const wasm = path.join(root, 'build', 'auth_proof', 'auth-proof_js', 'auth-proof.wasm');
  const zkey = path.join(root, 'build', 'auth_proof', 'auth-proof_final.zkey');
  const proofFile = path.join(root, 'build', 'auth_proof', 'auth-proof.json');
  const publicFile = path.join(root, 'build', 'auth_proof', 'auth-public.json');
  const vkeyFile = path.join(root, 'build', 'auth_proof', 'verification_key.json');

  for (const [label, file] of [['WASM', wasm], ['ZKey', zkey], ['Verification key', vkeyFile]]) {
    if (!exists(file)) throw new Error(`${label} not found: ${file}`);
  }

  const originalProof = backupFile(proofFile);
  const originalPublic = backupFile(publicFile);

  console.log(`Selected ACTIVE enrollment: ${selected.id}`);
  console.log(`Service                   : ${args.service}`);
  console.log('Proof generation           : snarkjs.groth16.fullProve');
  console.log('');

  const resultsDir = path.join(root, 'benchmarks', 'results');
  const outputFile = args.output
    ? path.resolve(args.output)
    : path.join(resultsDir, `auth_e2e_${timestampForFilename()}.json`);

  async function operation() {
    let challengeId = null;
    const e2eStart = performance.now();

    try {
      let start = performance.now();
      const issueOut = runNode(root, 'issue-auth-challenge.js', [args.service]);
      const challengeIssueMs = performance.now() - start;
      challengeId = parseChallengeId(issueOut);

      start = performance.now();
      runNode(root, 'generate-auth-proof-input.js', [selected.id, challengeId]);
      const inputGenerationMs = performance.now() - start;

      const inputFile = path.join(root, 'build', 'auth_proof_inputs', `${challengeId}.json`);
      if (!exists(inputFile)) throw new Error(`Authentication circuit input not created: ${inputFile}`);
      const input = loadJson(inputFile);

      start = performance.now();
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, wasm, zkey);
      const proofGenerationMs = performance.now() - start;
      saveJson(proofFile, proof);
      saveJson(publicFile, publicSignals);

      start = performance.now();
      runNode(root, 'build-auth-request.js', [challengeId]);
      const requestBuildMs = performance.now() - start;

      start = performance.now();
      runNode(root, 'destination-verify-auth.js', [challengeId]);
      const destinationVerifyWallMs = performance.now() - start;

      const reportFile = path.join(
        root,
        'results',
        'authentication',
        challengeId,
        'destination_verification_report.json'
      );
      if (!exists(reportFile)) throw new Error(`Destination verification report not found: ${reportFile}`);
      const report = loadJson(reportFile);
      if (report.AuthResult !== 'ACCEPT') throw new Error(`Authentication was not ACCEPT: ${report.AuthResult}`);

      const timings = report.timings_ms || {};
      const authE2eMs = performance.now() - e2eStart;

      return {
        challenge_issue_wall_ms: challengeIssueMs,
        auth_input_generation_wall_ms: inputGenerationMs,
        groth16_proof_generation_ms: proofGenerationMs,
        auth_request_build_wall_ms: requestBuildMs,
        destination_verify_wall_ms: destinationVerifyWallMs,
        destination_signed_root_verify_ms: Number(timings.signed_root_verify_ms),
        destination_groth16_verify_ms: Number(timings.groth16_verify_ms),
        destination_internal_total_ms: Number(timings.total_verification_ms),
        auth_e2e_wall_ms: authE2eMs
      };
    } finally {
      if (challengeId) {
        remove(path.join(root, 'state', 'auth_challenges', `${challengeId}.json`));
        remove(path.join(root, 'build', 'auth_proof_inputs', `${challengeId}.json`));
        remove(path.join(root, 'artifacts', 'auth', challengeId));
        remove(path.join(root, 'results', 'authentication', challengeId));
      }
    }
  }

  try {
    await executeBenchmark({
      name: 'Authentication end-to-end',
      warmup: args.warmup,
      runs: args.runs,
      operation,
      outputFile,
      metadata: {
        enrollment_id: selected.id,
        service: args.service,
        root_version_at_start: selected.record.version,
        proof_system: 'Groth16',
        circuit: 'AuthProof-v1',
        benchmark_enrollment_auto_bootstrap: true,
        note: [
          'Each sample issues a fresh challenge and consumes it exactly once.',
          'BAS membership state is not mutated by this benchmark.',
          'auth_e2e_wall_ms includes Node child-process startup, file I/O, proof generation, request packaging, SignedRoot verification, and destination verification.',
          'destination_internal_total_ms is read from destination_verification_report.json and excludes outer Node process startup.'
        ].join(' ')
      }
    });
  } finally {
    restoreFile(proofFile, originalProof);
    restoreFile(publicFile, originalPublic);
  }
}

main()
  .then(() => process.exit(0))
  .catch(err => {
    console.error('');
    console.error('Authentication end-to-end benchmark failed:');
    console.error(err.stack || err.message);
    process.exit(1);
  });
