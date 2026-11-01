const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const config = require('../src/config');
const {
  parseArgs,
  executeBenchmark,
  timestampForFilename
} = require('./benchmark-utils');

const args = parseArgs(process.argv.slice(2));
const projectRoot = config.paths.projectRoot;
const executable = path.join(
  projectRoot,
  'rust',
  'frost-admin',
  'target',
  'release',
  'frost-sign.exe'
);

if (!fs.existsSync(executable)) {
  throw new Error(`FROST executable not found: ${executable}`);
}

const signers = Array.from(
  { length: config.admins.t },
  (_, i) => i + 1
);

const workDir = path.join(
  projectRoot,
  'benchmarks',
  '.tmp-frost'
);
fs.mkdirSync(workDir, { recursive: true });

function nowNs() {
  return process.hrtime.bigint();
}

function elapsedMs(start) {
  return Number(process.hrtime.bigint() - start) / 1e6;
}

function cleanup(files) {
  for (const f of files) {
    try { fs.rmSync(f, { force: true }); } catch (_) {}
  }
}

async function operation({ measured, index }) {
  const nonce = `${process.pid}_${measured ? 'm' : 'w'}_${index}_${crypto.randomBytes(6).toString('hex')}`;
  const messageFile = path.join(workDir, `${nonce}.msg.bin`);
  const signatureFile = path.join(workDir, `${nonce}.sig.bin`);
  const reportFile = path.join(workDir, `${nonce}.report.json`);
  const message = crypto.randomBytes(32);
  fs.writeFileSync(messageFile, message);

  try {
    const signStart = nowNs();
    execFileSync(
      executable,
      ['sign', messageFile, signatureFile, signers.join(','), reportFile],
      { cwd: projectRoot, stdio: 'pipe' }
    );
    const signWallMs = elapsedMs(signStart);

    const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
    if (!report.verified) {
      throw new Error('FROST signer self-verification failed.');
    }

    const verifyStart = nowNs();
    execFileSync(
      executable,
      ['verify', messageFile, signatureFile],
      { cwd: projectRoot, stdio: 'pipe' }
    );
    const verifyWallMs = elapsedMs(verifyStart);

    const t = report.timing || {};
    return {
      frost_round1_ms: Number(t.round1_ms),
      frost_round2_ms: Number(t.round2_ms),
      frost_aggregate_ms: Number(t.aggregate_ms),
      frost_internal_verify_ms: Number(t.verify_ms),
      frost_internal_total_ms: Number(t.total_ms),
      sign_process_wall_ms: signWallMs,
      verify_process_wall_ms: verifyWallMs,
      sign_verify_process_wall_ms: signWallMs + verifyWallMs
    };
  } finally {
    cleanup([messageFile, signatureFile, reportFile]);
  }
}

const outputFile = args.output
  ? path.resolve(args.output)
  : path.join(
      projectRoot,
      'benchmarks',
      'results',
      `frost_n${config.admins.n}_t${config.admins.t}_${timestampForFilename()}.json`
    );

executeBenchmark({
  name: `FROST ${config.admins.t}-of-${config.admins.n} sign/verify`,
  warmup: args.warmup,
  runs: args.runs,
  operation,
  metadata: {
    n: config.admins.n,
    t: config.admins.t,
    signers,
    ciphersuite: config.admins.thresholdSignature.ciphersuite,
    message_bytes: 32,
    note: 'Internal FROST timings exclude Node/Rust process startup. Wall timings include process launch and file I/O.'
  },
  outputFile
}).finally(() => {
  try { fs.rmSync(workDir, { recursive: true, force: true }); } catch (_) {}
}).catch(err => {
  console.error(err);
  process.exit(1);
});
