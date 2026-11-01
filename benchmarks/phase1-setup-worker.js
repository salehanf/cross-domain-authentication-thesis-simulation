const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { performance } = require('perf_hooks');
const { execFileSync } = require('child_process');
const snarkjs = require('snarkjs');
const config = require('../src/config');

function exists(file) {
  return fs.existsSync(file);
}

function loadJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2));
}

function runNode(root, script, args = []) {
  const start = performance.now();

  execFileSync(
    process.execPath,
    [path.join(root, 'src', script), ...args.map(String)],
    {
      cwd: root,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 64 * 1024 * 1024
    }
  );

  return performance.now() - start;
}

async function setupCircuit(root, tempRoot, circuit) {
  const ptau = path.join(root, 'build', 'ptau', 'pot15_final.ptau');

  const spec = {
    auth: {
      r1cs: path.join(root, 'build', 'auth_proof', 'auth-proof.r1cs'),
      label: 'auth'
    },
    link: {
      r1cs: path.join(root, 'build', 'link_proof', 'link-proof.r1cs'),
      label: 'link'
    },
    pvss: {
      r1cs: path.join(root, 'build', 'pvss_share', 'pvss-share-proof.r1cs'),
      label: 'pvss'
    }
  }[circuit];

  if (!spec) throw new Error(`Unknown circuit: ${circuit}`);
  if (!exists(ptau)) throw new Error(`PTAU not found: ${ptau}`);
  if (!exists(spec.r1cs)) throw new Error(`R1CS not found: ${spec.r1cs}`);

  const dir = path.join(tempRoot, circuit);
  fs.mkdirSync(dir, { recursive: true });

  const initialZkey = path.join(dir, `${circuit}_0000.zkey`);
  const finalZkey = path.join(dir, `${circuit}_final.zkey`);
  const vkeyFile = path.join(dir, 'verification_key.json');

  let start = performance.now();
  await snarkjs.zKey.newZKey(spec.r1cs, ptau, initialZkey);
  const newZkeyMs = performance.now() - start;

  start = performance.now();
  const entropy = crypto.randomBytes(32).toString('hex');
  await snarkjs.zKey.contribute(
    initialZkey,
    finalZkey,
    `phase1-benchmark-${circuit}`,
    entropy
  );
  const contributionMs = performance.now() - start;

  start = performance.now();
  const vkey = await snarkjs.zKey.exportVerificationKey(finalZkey);
  writeJson(vkeyFile, vkey);
  const exportVkeyMs = performance.now() - start;

  if (!vkey || vkey.protocol !== 'groth16') {
    throw new Error(`Groth16 verification key export failed for ${circuit}.`);
  }

  return {
    new_zkey_ms: newZkeyMs,
    contribution_ms: contributionMs,
    export_vkey_ms: exportVkeyMs,
    total_ms: newZkeyMs + contributionMs + exportVkeyMs
  };
}

async function main() {
  const root = config.paths.projectRoot;
  const tempRoot = path.join(
    root,
    'benchmarks',
    '.phase1-zk-temp-' + process.pid + '-' + Date.now()
  );

  const phaseStart = performance.now();

  try {
    // 1) Public crypto/domain parameters + empty SMT
    const systemSetupWall = runNode(root, 'setup.js');

    const systemSetupFile = path.join(root, 'results', 'system_setup.json');
    if (!exists(systemSetupFile)) {
      throw new Error('system_setup.json was not created.');
    }
    const systemSetup = loadJson(systemSetupFile);

    if (Number(systemSetup.state?.version) !== 0 ||
        Number(systemSetup.state?.smt?.activeLeaves) !== 0) {
      throw new Error('Initial system/SMT state is not version 0 with zero active leaves.');
    }

    // 2) FROST threshold key generation / DKG
    const frostSetupWall = runNode(root, 'admin_setup.js');

    const frostSetupFile = path.join(root, 'results', 'frost_setup.json');
    if (!exists(frostSetupFile)) {
      throw new Error('frost_setup.json was not created.');
    }
    const frostSetup = loadJson(frostSetupFile);

    if (frostSetup.self_test !== true ||
        Number(frostSetup.n) !== Number(config.admins.n) ||
        Number(frostSetup.t) !== Number(config.admins.t)) {
      throw new Error('FROST DKG self-test/threshold validation failed.');
    }

    // 3) Independent PVSS administrator encryption keys
    const pvssSetupWall = runNode(root, 'pvss_setup.js');

    const pvssSetupFile = path.join(root, 'results', 'pvss_setup.json');
    if (!exists(pvssSetupFile)) {
      throw new Error('pvss_setup.json was not created.');
    }
    const pvssSetup = loadJson(pvssSetupFile);

    if (pvssSetup.all_self_tests_passed !== true ||
        Number(pvssSetup.generated_key_pairs) !== Number(config.admins.n)) {
      throw new Error('PVSS administrator key setup self-test failed.');
    }

    // 4) Groth16 per-circuit trusted setup.
    // The main project's build artifacts are READ-ONLY here.
    const authZk = await setupCircuit(root, tempRoot, 'auth');
    const linkZk = await setupCircuit(root, tempRoot, 'link');
    const pvssZk = await setupCircuit(root, tempRoot, 'pvss');

    // 5) Initial threshold-signed root (version 0)
    const initialRootWall = runNode(root, 'signed_root.js');

    const signedRootFile = path.join(
      root, 'state', 'roots', 'signed_root_v0.json'
    );
    const signedRootReportFile = path.join(
      root, 'state', 'frost', 'signatures', 'signed_root_v0.report.json'
    );

    if (!exists(signedRootFile) || !exists(signedRootReportFile)) {
      throw new Error('Initial SignedRoot artifacts were not created.');
    }

    const signedRoot = loadJson(signedRootFile);
    const signedRootReport = loadJson(signedRootReportFile);

    if (Number(signedRoot.version) !== 0 ||
        signedRootReport.verified !== true ||
        Number(signedRootReport.signature_bytes) !== 64) {
      throw new Error('Initial SignedRoot validation failed.');
    }

    const phaseTotal = performance.now() - phaseStart;

    const st = systemSetup.timing_ms || {};
    const ft = frostSetup.timing || {};
    const pt = pvssSetup.timing || {};
    const rt = signedRootReport.timing || {};

    const zkTotal =
      authZk.total_ms +
      linkZk.total_ms +
      pvssZk.total_ms;

    process.stdout.write(JSON.stringify({
      system_setup_wall_ms: systemSetupWall,
      system_poseidon_init_internal_ms: Number(st.poseidonInitialization ?? 0),
      system_babyjub_init_internal_ms: Number(st.babyjubInitialization ?? 0),
      system_smt_init_internal_ms: Number(st.smtInitialization ?? 0),
      system_setup_internal_total_ms: Number(st.totalSetup ?? 0),

      frost_dkg_wall_ms: frostSetupWall,
      frost_dkg_internal_ms: Number(ft.dkg_total_ms ?? 0),
      frost_self_test_sign_internal_ms: Number(ft.self_test_sign_ms ?? 0),

      pvss_admin_key_setup_wall_ms: pvssSetupWall,
      pvss_admin_key_setup_internal_ms: Number(pt.total_ms ?? 0),

      zk_auth_setup_ms: authZk.total_ms,
      zk_auth_new_zkey_ms: authZk.new_zkey_ms,
      zk_auth_contribution_ms: authZk.contribution_ms,
      zk_auth_export_vkey_ms: authZk.export_vkey_ms,

      zk_link_setup_ms: linkZk.total_ms,
      zk_link_new_zkey_ms: linkZk.new_zkey_ms,
      zk_link_contribution_ms: linkZk.contribution_ms,
      zk_link_export_vkey_ms: linkZk.export_vkey_ms,

      zk_pvss_setup_ms: pvssZk.total_ms,
      zk_pvss_new_zkey_ms: pvssZk.new_zkey_ms,
      zk_pvss_contribution_ms: pvssZk.contribution_ms,
      zk_pvss_export_vkey_ms: pvssZk.export_vkey_ms,

      zk_all_circuits_setup_ms: zkTotal,

      initial_signed_root_wall_ms: initialRootWall,
      initial_signed_root_frost_internal_ms: Number(rt.total_ms ?? 0),
      initial_signed_root_signature_bytes: Number(
        signedRootReport.signature_bytes ?? 0
      ),

      phase1_setup_e2e_wall_ms: phaseTotal
    }), () => process.exit(0));
  } catch (err) {
    try {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } catch (_) {}

    process.stderr.write((err.stack || err.message) + '\n', () => process.exit(1));
    return;
  } finally {
    try {
      fs.rmSync(tempRoot, { recursive: true, force: true });
    } catch (_) {}
  }
}

main();
