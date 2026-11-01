const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const { performance } = require("perf_hooks");

const { buildPoseidon, buildBabyjub } = require("circomlibjs");
const {SparseMerkleTree} = require("./smt");
const config = require("./config");


function getCommandVersion(command, args = ["--version"]) {
    try {
        return execFileSync(command, args, {
            encoding: "utf8"
        }).trim();
    } catch {
        return "unavailable";
    }
}


function validateConfig() {
    const { n, t } = config.admins;

    if (!Number.isInteger(n) || n < 1) {
        throw new Error("admins.n must be a positive integer.");
    }

    if (!Number.isInteger(t) || t < 1 || t > n) {
        throw new Error("admins.t must satisfy 1 <= t <= n.");
    }

    if (
        !Number.isInteger(config.smt.depth) ||
        config.smt.depth < 1
    ) {
        throw new Error("SMT depth must be a positive integer.");
    }
}


async function main() {

    console.log("============================================");
    console.log(" Thesis Protocol - System Setup");
    console.log("============================================");

    validateConfig();

    const setupStart = performance.now();

    // --------------------------------------------------
    // 1. Initialize Poseidon
    // --------------------------------------------------

    const poseidonStart = performance.now();

    const poseidon = await buildPoseidon();
    const F = poseidon.F;

    const poseidonEnd = performance.now();


    // --------------------------------------------------
    // 2. Initialize BabyJub
    // --------------------------------------------------

    const babyjubStart = performance.now();

    const babyjub = await buildBabyjub();

    const babyjubEnd = performance.now();


    // --------------------------------------------------
    // 3. Domain configuration
    // --------------------------------------------------

    const schemeId = BigInt(config.protocol.schemeId);
    const domainId = BigInt(config.domain.domainId);

    /*
        domainTag binds all cryptographic values to
        both the protocol instance and the source domain.
    */

    const domainTagField = poseidon([
        schemeId,
        domainId
    ]);

    const domainTag =
        F.toObject(domainTagField).toString();


    // --------------------------------------------------
    // 4. SMT configuration
    // --------------------------------------------------

    const smtDepth = config.smt.depth;

    const smtCapacity =
        (2n ** BigInt(smtDepth)).toString();


    // --------------------------------------------------
    // 5. BabyJub public parameters
    // --------------------------------------------------

    let base8 = null;
    let subgroupOrder = null;

    if (babyjub.Base8) {
        base8 = [
            babyjub.F.toObject(babyjub.Base8[0]).toString(),
            babyjub.F.toObject(babyjub.Base8[1]).toString()
        ];
    }

    if (babyjub.subOrder) {
        subgroupOrder = babyjub.subOrder.toString();
    }


    // --------------------------------------------------
    // 6. Software environment
    // --------------------------------------------------

    const snarkjsPackage =
        require(path.join(
            config.paths.projectRoot,
            "node_modules",
            "snarkjs",
            "package.json"
        ));

    const circomlibjsPackage =
        require(path.join(
            config.paths.projectRoot,
            "node_modules",
            "circomlibjs",
            "package.json"
        ));

    // --------------------------------------------------
    // 7. Initialize Sparse Merkle Tree
    // --------------------------------------------------

    const smtStart = performance.now();

    const smt =
        new SparseMerkleTree(
            smtDepth,
            poseidon,
            F
        );

    const initialRoot =
        smt.getRoot();

    const smtEnd =
        performance.now();


// --------------------------------------------------
// 8. Initial domain state
// --------------------------------------------------

    const initialState = {

        version: 0,

        smt: {

            depth:
                smtDepth,

            capacity:
                smtCapacity,

            root:
                initialRoot.toString(),

            activeLeaves:
                0,

            storedNonDefaultNodes:
                0
        },

        signedRoot:
            null,

        enrollmentCount:
            0,

        revokedCount:
            0
    };


    // --------------------------------------------------
    // 9. ZK setup state
    // --------------------------------------------------

    /*
        Groth16 proving/verifying keys depend on each
        final circuit, so they will be generated after
        enrollment_link.circom and authentication.circom
        are finalized.
    */

    const zkArtifacts = {

        enrollmentLink: {
            circuit: "pending",
            provingKey: "pending",
            verificationKey: "pending"
        },

        authentication: {
            circuit: "pending",
            provingKey: "pending",
            verificationKey: "pending"
        }

    };


    const setupEnd = performance.now();


    // --------------------------------------------------
    // 10. Produce reproducible setup snapshot
    // --------------------------------------------------

    const snapshot = {

        experiment: config.experiment,

        environment: {
            platform: process.platform,
            architecture: process.arch,
            node: process.version,
            circom: getCommandVersion("circom"),
            snarkjs: snarkjsPackage.version,
            circomlibjs: circomlibjsPackage.version
        },

        cryptography: {
            proofSystem: config.zk.proofSystem,
            curve: config.zk.curve,
            hash: config.zk.hash,

            babyjub: {
                base8,
                subgroupOrder
            }
        },

        protocol: {
            schemeId: config.protocol.schemeId,
            domainId: config.domain.domainId,
            domainTag,

            tags: config.protocol.tags
        },

        administrators: {
            n: config.admins.n,
            t: config.admins.t
        },

        state: initialState,

        zkArtifacts,

        timing_ms: {

            poseidonInitialization:
                poseidonEnd - poseidonStart,

            babyjubInitialization:
                babyjubEnd - babyjubStart,

            smtInitialization:
                smtEnd - smtStart,

            totalSetup:
                setupEnd - setupStart
        }
    };


    // --------------------------------------------------
    // 11. Save result
    // --------------------------------------------------

    fs.mkdirSync(
        config.paths.results,
        { recursive: true }
    );

    const outputFile =
        path.join(
            config.paths.results,
            "system_setup.json"
        );

    fs.writeFileSync(
        outputFile,
        JSON.stringify(snapshot, null, 2)
    );


    // --------------------------------------------------
    // Display
    // --------------------------------------------------

    console.log("");
    console.log("System setup completed successfully.");
    console.log("");

    console.log("Scheme ID :", config.protocol.schemeId);
    console.log("Domain ID :", config.domain.domainId);

    console.log(
        "Administrators:",
        `${config.admins.t}-of-${config.admins.n}`
    );

    console.log("SMT depth :", smtDepth);
    console.log("SMT capacity :", smtCapacity);
    console.log( "Initial SMT root :", initialRoot.toString() );


    console.log("Proof system :", config.zk.proofSystem);
    console.log("Curve :", config.zk.curve);
    console.log("Hash :", config.zk.hash);

    console.log("");
    console.log("Domain tag:");
    console.log(domainTag);

    console.log("");
    console.log(
        "SMT initialization:",
        (smtEnd - smtStart).toFixed(3),
        "ms"
    );
    console.log(
        "Poseidon initialization:",
        (poseidonEnd - poseidonStart).toFixed(3),
        "ms"
    );

    console.log(
        "BabyJub initialization:",
        (babyjubEnd - babyjubStart).toFixed(3),
        "ms"
    );

    console.log(
        "Total setup:",
        (setupEnd - setupStart).toFixed(3),
        "ms"
    );

    console.log("");
    console.log("Setup snapshot written to:");
    console.log(outputFile);

    console.log("");
    console.log("============================================");
}


main().catch((error) => {
    console.error("System setup failed:");
    console.error(error);
    process.exit(1);
});