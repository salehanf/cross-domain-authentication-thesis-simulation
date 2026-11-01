const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');
const { execFileSync } = require('child_process');
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

function remove(target) {
  try {
    fs.rmSync(target, { recursive: true, force: true });
  } catch (_) {}
}

function runIssue(root) {
  const start = performance.now();

  const stdout = execFileSync(
    process.execPath,
    [path.join(root, 'src', 'aat.js'), 'issue'],
    {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 16 * 1024 * 1024
    }
  );

  const end = performance.now();

  const artifactMatch = /AAT artifact:\s*[\r\n]+([^\r\n]+)/.exec(stdout);
  if (!artifactMatch) {
    throw new Error(`Could not parse AAT artifact path.\n${stdout}`);
  }

  const artifactFile = artifactMatch[1].trim();
  const base = path.basename(artifactFile, '.json');

  const reportCandidates = [
    path.join(root, 'results', 'aat', `${base}.report.json`),
    `${artifactFile}.report.json`
  ];

  const reportFile = reportCandidates.find(fs.existsSync);
  if (!reportFile) {
    throw new Error(`AAT report not found for ${artifactFile}`);
  }

  const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));

  if (report.signature_valid !== true) {
    throw new Error('AAT signature_valid was not true.');
  }

  const internal =
    Number(
      report?.frost_timing?.total_ms ??
      report?.frost_timing?.total ??
      NaN
    );

  const signatureBytes = Number(report.signature_bytes);

  return {
    wall_ms: end - start,
    frost_internal_ms: Number.isFinite(internal) ? internal : null,
    signature_bytes: signatureBytes,
    artifactFile,
    reportFile
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = config.paths.projectRoot;
  const resultsDir = path.join(root, 'benchmarks', 'results');

  const outputFile = args.output
    ? path.resolve(args.output)
    : path.join(
        resultsDir,
        `aat_e2e_${timestampForFilename()}.json`
      );

  console.log(`Threshold                  : ${config.admins.t}-of-${config.admins.n}`);
  console.log('Phase boundary             : thesis Phase 3 (AAT issuance)');
  console.log('Persistent BAS state change: none');
  console.log('');

  await executeBenchmark({
    name: 'AAT issuance end-to-end (Phase 3)',
    warmup: args.warmup,
    runs: args.runs,
    outputFile,
    metadata: {
      thesis_phase: 3,
      phase_name: 'Admin Approval Token issuance',
      admins_n: config.admins.n,
      threshold_t: config.admins.t,
      threshold_signature: config.admins.thresholdSignature?.scheme || 'FROST',
      includes_process_startup: true,
      includes_artifact_serialization: true,
      internal_frost_timing_reported_separately: true,
      persistent_state_change: false
    },
    operation: async () => {
      const result = runIssue(root);

      try {
        return {
          aat_issue_wall_ms: result.wall_ms,
          aat_frost_internal_ms: result.frost_internal_ms,
          aat_signature_bytes: result.signature_bytes
        };
      } finally {
        remove(result.artifactFile);
        remove(result.reportFile);
      }
    }
  });
}

main()
  .then(() => process.exit(0))
  .catch(err => {
    console.error('');
    console.error('AAT end-to-end benchmark failed:');
    console.error(err.stack || err.message);
    process.exit(1);
  });
