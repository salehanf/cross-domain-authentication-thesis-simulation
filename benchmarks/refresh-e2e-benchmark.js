const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { execFileSync } = require('child_process');
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
    enrollment: null,
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
    } else if (key === 'enrollment') {
      args.enrollment = value;
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

function remove(target) {
  try {
    fs.rmSync(target, { recursive: true, force: true });
  } catch (_) {}
}

function runNode(root, script, args = []) {
  const start = performance.now();

  const stdout = execFileSync(
    process.execPath,
    [path.join(root, 'src', script), ...args.map(String)],
    {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 32 * 1024 * 1024
    }
  );

  return {
    stdout,
    wall_ms: performance.now() - start
  };
}

function hashBytes(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function hashFile(file) {
  return hashBytes(fs.readFileSync(file));
}

function snapshotTree(dir) {
  const snapshot = new Map();

  function walk(current, relativeBase) {
    if (!exists(current)) return;

    for (const name of fs.readdirSync(current)) {
      const full = path.join(current, name);
      const rel = path.join(relativeBase, name);
      const stat = fs.statSync(full);

      if (stat.isDirectory()) {
        walk(full, rel);
      } else {
        snapshot.set(rel, fs.readFileSync(full));
      }
    }
  }

  walk(dir, '');
  return snapshot;
}

function restoreTree(dir, snapshot) {
  remove(dir);
  fs.mkdirSync(dir, { recursive: true });

  for (const [rel, bytes] of snapshot.entries()) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, bytes);
  }
}

function treeDigest(snapshot) {
  const h = crypto.createHash('sha256');
  const keys = Array.from(snapshot.keys()).sort();

  for (const key of keys) {
    h.update(key);
    h.update('\0');
    h.update(snapshot.get(key));
    h.update('\0');
  }

  return h.digest('hex');
}

function findActiveEnrollment(root, explicitId) {
  const registryFile = path.join(root, 'state', 'bas', 'enrollment_registry.json');
  const enrollDir = path.join(root, 'artifacts', 'enrollment');

  if (!exists(registryFile)) {
    throw new Error(`BAS registry not found: ${registryFile}`);
  }
  if (!exists(enrollDir)) {
    throw new Error(`Enrollment artifact directory not found: ${enrollDir}`);
  }

  const registry = loadJson(registryFile);
  const candidates = [];

  for (const id of fs.readdirSync(enrollDir).sort()) {
    if (explicitId && id !== explicitId) continue;

    const pkgFile = path.join(enrollDir, id, 'enroll_package.json');
    const pvssFile = path.join(enrollDir, id, 'pvss_data.json');

    if (!exists(pkgFile) || !exists(pvssFile)) continue;

    const pkg = loadJson(pkgFile);
    const yHash = String(pkg.y_hash ?? '');
    const entry = registry.entries?.[yHash];

    if (!entry || String(entry.status).toLowerCase() !== 'active') continue;

    candidates.push({
      id,
      y_hash: yHash,
      version: Number(entry.version)
    });
  }

  if (!candidates.length) {
    if (explicitId) {
      throw new Error(`Enrollment ${explicitId} is not a complete ACTIVE enrollment.`);
    }
    throw new Error('No complete ACTIVE enrollment was found.');
  }

  return candidates[0];
}

function readShareEpoch(shareDir) {
  if (!exists(shareDir)) return null;

  const files = fs.readdirSync(shareDir)
    .filter(name => /^admin_\d+\.json$/i.test(name))
    .sort();

  if (!files.length) return null;

  const epochs = new Set(
    files.map(name => Number(loadJson(path.join(shareDir, name)).share_epoch))
  );

  if (epochs.size !== 1) {
    throw new Error('Baseline administrator shares contain mixed epochs.');
  }

  return Array.from(epochs)[0];
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = config.paths.projectRoot;

  const selected = findActiveEnrollment(root, args.enrollment);
  const enrollmentId = selected.id;

  const shareDir = path.join(root, 'private', 'admin_shares', enrollmentId);
  const refreshResultsDir = path.join(root, 'results', 'refresh', enrollmentId);

  const registryFile = path.join(root, 'state', 'bas', 'enrollment_registry.json');
  const rootsDir = path.join(root, 'state', 'roots');
  const enrollPackageFile = path.join(
    root, 'artifacts', 'enrollment', enrollmentId, 'enroll_package.json'
  );

  // Phase-8 prerequisite setup: create epoch-0/current private administrator
  // shares if they do not exist. This is excluded from all benchmark timings.
  let bootstrapPerformed = false;
  if (!exists(shareDir) || readShareEpoch(shareDir) === null) {
    console.log('Administrator refresh-share state not found.');
    console.log('Bootstrapping refresh shares once (excluded from timings)...');
    runNode(root, 'bootstrap-refresh-shares.js', [enrollmentId]);
    bootstrapPerformed = true;
  }

  const baselineEpoch = readShareEpoch(shareDir);
  if (!Number.isInteger(baselineEpoch)) {
    throw new Error('Could not determine baseline refresh-share epoch.');
  }

  const baselineShares = snapshotTree(shareDir);
  const baselineShareDigest = treeDigest(baselineShares);

  const registryHashBefore = hashFile(registryFile);
  const enrollHashBefore = hashFile(enrollPackageFile);
  const rootSnapshotBefore = snapshotTree(rootsDir);
  const rootDigestBefore = treeDigest(rootSnapshotBefore);

  const resultsDir = path.join(root, 'benchmarks', 'results');
  const outputFile = args.output
    ? path.resolve(args.output)
    : path.join(
        resultsDir,
        `proactive_refresh_e2e_${timestampForFilename()}.json`
      );

  console.log(`Selected ACTIVE enrollment : ${enrollmentId}`);
  console.log(`Threshold                  : ${config.admins.t}-of-${config.admins.n}`);
  console.log(`Baseline epoch             : ${baselineEpoch}`);
  console.log(`Bootstrap performed        : ${bootstrapPerformed ? 'yes (excluded)' : 'no'}`);
  console.log('Private share state        : restored after every sample');
  console.log('Public BAS/Root state      : required to remain byte-for-byte unchanged');
  console.log('');

  async function operation() {
    // Every sample starts from exactly the same private-share epoch.
    restoreTree(shareDir, baselineShares);
    remove(refreshResultsDir);

    const run = runNode(root, 'proactive-refresh.js', [enrollmentId]);

    const nextEpoch = baselineEpoch + 1;
    const reportFile = path.join(
      refreshResultsDir,
      `epoch_${nextEpoch}_report.json`
    );

    if (!exists(reportFile)) {
      throw new Error(`Refresh report not found: ${reportFile}`);
    }

    const report = loadJson(reportFile);

    if (Number(report.epoch?.from) !== baselineEpoch ||
        Number(report.epoch?.to) !== nextEpoch) {
      throw new Error('Refresh report epoch transition is incorrect.');
    }

    if (report.x_anchor_unchanged !== true ||
        report.y_hash_unchanged !== true ||
        report.mixed_epoch_self_test !== true) {
      throw new Error('Refresh secret/invariant checks did not all pass.');
    }

    const inv = report.public_state_invariants || {};
    if (inv.signed_root_unchanged !== true ||
        inv.bas_registry_unchanged !== true ||
        inv.enrollment_package_unchanged !== true ||
        inv.L_unchanged !== true ||
        inv.idx_unchanged !== true ||
        inv.y_hash_unchanged !== true) {
      throw new Error('Refresh public-state invariants did not all pass.');
    }

    if (Number(report.shares_changed) !== Number(report.threshold?.n)) {
      throw new Error('Not all administrator shares changed.');
    }

    const committedEpoch = readShareEpoch(shareDir);
    if (committedEpoch !== nextEpoch) {
      throw new Error(
        `Committed share epoch mismatch: expected ${nextEpoch}, got ${committedEpoch}`
      );
    }

    // Independent byte-level checks outside the protocol report.
    const registryHashAfter = hashFile(registryFile);
    const enrollHashAfter = hashFile(enrollPackageFile);
    const rootDigestAfter = treeDigest(snapshotTree(rootsDir));

    if (registryHashAfter !== registryHashBefore) {
      throw new Error('BAS registry changed during proactive refresh.');
    }
    if (enrollHashAfter !== enrollHashBefore) {
      throw new Error('Enroll_Package changed during proactive refresh.');
    }
    if (rootDigestAfter !== rootDigestBefore) {
      throw new Error('SignedRoot state changed during proactive refresh.');
    }

    const t = report.timings_ms || {};

    return {
      refresh_wall_ms: run.wall_ms,
      refresh_polynomial_commitments_internal_ms:
        Number(t.polynomial_and_commitments ?? 0),
      refresh_delta_generation_verification_internal_ms:
        Number(t.delta_generation_and_verification ?? 0),
      refresh_share_update_internal_ms:
        Number(t.share_update ?? 0),
      refresh_threshold_invariant_verification_internal_ms:
        Number(t.threshold_and_invariant_verification ?? 0),
      refresh_private_share_commit_internal_ms:
        Number(t.private_share_commit ?? 0),
      refresh_internal_total_ms:
        Number(t.total_refresh ?? 0),
      refresh_public_commitment_count:
        Number(report.public_commitment_count ?? 0),
      refresh_delta_evaluations:
        Number(report.delta_evaluations ?? 0),
      refresh_peer_delta_messages:
        Number(report.peer_delta_messages ?? 0)
    };
  }

  try {
    await executeBenchmark({
      name: 'Proactive share refresh end-to-end (Phase 8)',
      warmup: args.warmup,
      runs: args.runs,
      operation,
      outputFile,
      metadata: {
        thesis_phase: 8,
        phase_name: 'Proactive Share Refresh',
        enrollment_id: enrollmentId,
        admins_n: config.admins.n,
        threshold_t: config.admins.t,
        baseline_epoch: baselineEpoch,
        bootstrap_performed_before_benchmark: bootstrapPerformed,
        bootstrap_included_in_timings: false,
        private_state_reset:
          'Administrator share files are restored from a byte-for-byte baseline after every sample.',
        public_state_requirement:
          'BAS registry, Enroll_Package and SignedRoot directory must remain byte-for-byte unchanged.',
        measurement_boundary:
          'refresh_wall_ms is the full proactive-refresh.js process wall-clock time; refresh_internal_total_ms is the implementation internal timer beginning after crypto setup/loading and ending after invariant checks and private share commit.'
      }
    });
  } finally {
    // Preserve the user's original pre-benchmark private share state.
    restoreTree(shareDir, baselineShares);
    remove(refreshResultsDir);

    // Safety restore public state even though it should never change.
    const currentRootDigest = treeDigest(snapshotTree(rootsDir));
    if (currentRootDigest !== rootDigestBefore) {
      restoreTree(rootsDir, rootSnapshotBefore);
    }
  }

  const finalShareDigest = treeDigest(snapshotTree(shareDir));
  if (finalShareDigest !== baselineShareDigest) {
    throw new Error('Final administrator-share state was not restored exactly.');
  }
}

main()
  .then(() => process.exit(0))
  .catch(err => {
    console.error('');
    console.error('Proactive refresh end-to-end benchmark failed:');
    console.error(err.stack || err.message);
    process.exit(1);
  });
