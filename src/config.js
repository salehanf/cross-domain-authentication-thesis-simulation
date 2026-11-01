const path = require("path");

const PROJECT_ROOT = path.resolve(__dirname, "..");

const config = {
    experiment: {
        name: "MSc Thesis Cross-Domain Authentication",
        profile: "baseline",
        repetitions: 30,
        warmupRuns: 5
    },

    protocol: {
        schemeId: 42,

        // Numeric encodings of domain-separation labels used inside Circom.
        tags: {
            anchor: 1,
            leaf: 2,
            idx: 3,
            revoke: 4,
            node: 5,
            empty: 6,

            pvssCoeffCommit: 7,
            pvssMask: 8,
            pvssCipherTag: 9,
            
            authKey: 10,
            authTag: 11
        }
    },

    domain: {
        domainId: 12345
    },

    admins: {
        n: 5,
        t: 3,

        thresholdSignature: {
            scheme: "FROST",
            ciphersuite: "FROST(Ed25519, SHA-512)",
            keyVersion: 1,
            messageHash: "sha256"
        }
    },

    pvss: {
        curve: "BabyJubJub",
        generator: "Base8",
        keyVersion: 1
    },

    aat: {
        purpose: "enroll",

        // Experimental implementation parameter.
        // The thesis requires a time-limited token
        // but does not mandate a specific lifetime.
        validitySeconds: 600,

        messageHash: "sha256",
        nullifierTag: "AAT-null"
    },
    smt: {
        depth: 20
    },

    zk: {
        proofSystem: "groth16",
        curve: "bn128",
        hash: "poseidon"
    },

    paths: {
        projectRoot: PROJECT_ROOT,
        circuits: path.join(PROJECT_ROOT, "circuits"),
        build: path.join(PROJECT_ROOT, "build"),
        results: path.join(PROJECT_ROOT, "results")
    }
};

module.exports = config;