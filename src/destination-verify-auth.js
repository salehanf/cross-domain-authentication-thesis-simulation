const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const config = require("./config");

const {
    verifySignedRoot
} = require("./signed_root");


// ======================================================
// Helpers
// ======================================================

function loadJson(filePath) {

    if (!fs.existsSync(filePath)) {
        throw new Error(
            `File not found: ${filePath}`
        );
    }

    return JSON.parse(
        fs.readFileSync(
            filePath,
            "utf8"
        )
    );
}


function saveJson(filePath, data) {

    fs.mkdirSync(
        path.dirname(filePath),
        { recursive: true }
    );

    fs.writeFileSync(
        filePath,
        JSON.stringify(
            data,
            null,
            2
        )
    );
}


function assertEqual(
    label,
    actual,
    expected
) {

    if (
        String(actual) !==
        String(expected)
    ) {

        throw new Error(
            `${label} mismatch\n` +
            `Actual   : ${actual}\n` +
            `Expected : ${expected}`
        );
    }
}


function getLatestSignedRoot(
    rootsDir
) {

    const candidates =
        fs.readdirSync(
            rootsDir
        )
        .map(file => {

            const match =
                /^signed_root_v(\d+)\.json$/
                    .exec(file);

            if (!match) {
                return null;
            }

            return {
                version:
                    Number(match[1]),

                file:
                    path.join(
                        rootsDir,
                        file
                    )
            };
        })
        .filter(Boolean)
        .sort(
            (a, b) =>
                b.version -
                a.version
        );


    if (
        candidates.length === 0
    ) {

        throw new Error(
            "No SignedRoot found."
        );
    }


    const latest =
        candidates[0];


    return {

        file:
            latest.file,

        data:
            loadJson(
                latest.file
            )
    };
}


function signedRootVerificationSucceeded(
    result
) {

    /*
     * Compatible with the helper styles we have used
     * during the prototype:
     *
     * true
     *
     * or:
     * { valid: true }
     *
     * or:
     * { verified: true }
     */

    if (
        result === true
    ) {
        return true;
    }


    if (
        result &&
        typeof result ===
            "object"
    ) {

        return (
            result.valid === true ||
            result.verified === true
        );
    }


    return false;
}


// ======================================================
// Main
// ======================================================

async function main() {

    const challengeId =
        process.argv[2];


    if (!challengeId) {

        throw new Error(
            "Usage: node src\\destination-verify-auth.js <challenge-id>"
        );
    }


    const projectRoot =
        config.paths.projectRoot;


    // ==================================================
    // Paths
    // ==================================================

    const authRequestFile =
        path.join(
            projectRoot,
            "artifacts",
            "auth",
            challengeId,
            "auth_request.json"
        );


    const challengeFile =
        path.join(
            projectRoot,
            "state",
            "auth_challenges",
            `${challengeId}.json`
        );


    const rootsDir =
        path.join(
            projectRoot,
            "state",
            "roots"
        );


    const verificationKeyFile =
        path.join(
            projectRoot,
            "build",
            "auth_proof",
            "verification_key.json"
        );


    const reportFile =
        path.join(
            projectRoot,
            "results",
            "authentication",
            challengeId,
            "destination_verification_report.json"
        );


    // ==================================================
    // Load request and service state
    // ==================================================

    const authRequest =
        loadJson(
            authRequestFile
        );


    const challengeRecord =
        loadJson(
            challengeFile
        );


    const verificationKey =
        loadJson(
            verificationKeyFile
        );


    // ==================================================
    // Timing
    // ==================================================

    const totalStart =
        process.hrtime.bigint();


    const timings = {};


    // ==================================================
    // 1. Challenge status
    // ==================================================

    if (
        challengeRecord.status !==
        "pending"
    ) {

        throw new Error(
            `Authentication challenge already ${challengeRecord.status}.`
        );
    }


    console.log(
        "Challenge status              : PENDING"
    );


    // ==================================================
    // 2. Challenge temporal validity
    // ==================================================

    const timeStart =
        process.hrtime.bigint();


    const now =
        Date.now();


    const issuedAt =
        Date.parse(
            challengeRecord.issued_at
        );


    const expiresAt =
        Date.parse(
            challengeRecord.expires_at
        );


    if (
        !Number.isFinite(
            issuedAt
        ) ||
        !Number.isFinite(
            expiresAt
        )
    ) {

        throw new Error(
            "Invalid challenge timestamps."
        );
    }


    if (
        now < issuedAt
    ) {

        throw new Error(
            "Authentication challenge is not valid yet."
        );
    }


    if (
        now > expiresAt
    ) {

        throw new Error(
            `Authentication challenge expired at ${challengeRecord.expires_at}`
        );
    }


    timings.challenge_time_check_ms =
        Number(
            process.hrtime.bigint() -
            timeStart
        ) / 1e6;


    console.log(
        "Challenge temporal validity   : VALID"
    );


    // ==================================================
    // 3. Request <-> issued challenge binding
    // ==================================================

    const bindingStart =
        process.hrtime.bigint();


    assertEqual(
        "D_id",
        authRequest.D_id,
        challengeRecord.D_id
    );


    assertEqual(
        "scheme_id",
        authRequest.scheme_id,
        challengeRecord.scheme_id
    );


    assertEqual(
        "root",
        authRequest.SignedRoot.root,
        challengeRecord.root
    );


    assertEqual(
        "root_version",
        authRequest.root_version,
        challengeRecord.root_version
    );


    assertEqual(
        "challenge",
        authRequest.challenge,
        challengeRecord.challenge
    );


    assertEqual(
        "sid",
        authRequest.sid,
        challengeRecord.sid
    );


    assertEqual(
        "ctx",
        authRequest.ctx,
        challengeRecord.ctx
    );


    timings.challenge_binding_ms =
        Number(
            process.hrtime.bigint() -
            bindingStart
        ) / 1e6;


    console.log(
        "Request / challenge binding   : MATCH"
    );


    // ==================================================
    // 4. SignedRoot cryptographic verification
    // ==================================================

    const signedRootStart =
        process.hrtime.bigint();


    const signedRootResult =
        await verifySignedRoot(
            authRequest.SignedRoot
        );


    if (
        !signedRootVerificationSucceeded(
            signedRootResult
        )
    ) {

        throw new Error(
            "SignedRoot signature verification failed."
        );
    }


    timings.signed_root_verify_ms =
        Number(
            process.hrtime.bigint() -
            signedRootStart
        ) / 1e6;


    console.log(
        "SignedRoot signature          : VALID"
    );


    // ==================================================
    // 5. Latest-root policy
    //
    // Experimental policy:
    //
    // only the latest valid SignedRoot is accepted.
    // ==================================================

    const latest =
        getLatestSignedRoot(
            rootsDir
        );


    assertEqual(
        "latest SignedRoot D_id",
        authRequest.SignedRoot.D_id,
        latest.data.D_id
    );


    assertEqual(
        "latest SignedRoot scheme_id",
        authRequest.SignedRoot.scheme_id,
        latest.data.scheme_id
    );


    assertEqual(
        "latest SignedRoot version",
        authRequest.SignedRoot.version,
        latest.data.version
    );


    assertEqual(
        "latest SignedRoot root",
        authRequest.SignedRoot.root,
        latest.data.root
    );


    assertEqual(
        "latest SignedRoot key_id",
        authRequest.SignedRoot.key_id,
        latest.data.key_id
    );


    console.log(
        `SignedRoot freshness          : v${latest.data.version} LATEST`
    );


    // ==================================================
    // 6. root_version consistency
    // ==================================================

    assertEqual(
        "root_version / SignedRoot.version",
        authRequest.root_version,
        authRequest.SignedRoot.version
    );


    console.log(
        "Root version consistency      : VALID"
    );


    // ==================================================
    // 7. Proof metadata
    // ==================================================

    const proofObject =
        authRequest.proof_auth_ZK;


    if (!proofObject) {

        throw new Error(
            "proof_auth_ZK missing."
        );
    }


    if (
        proofObject.proof_system !==
        "Groth16"
    ) {

        throw new Error(
            "Unexpected proof system."
        );
    }


    if (
        proofObject.curve !==
        "bn128"
    ) {

        throw new Error(
            "Unexpected proof curve."
        );
    }


    if (
        proofObject.circuit !==
        "AuthProof-v1"
    ) {

        throw new Error(
            "Unexpected authentication circuit."
        );
    }


    // ==================================================
    // 8. Exact public statement binding
    //
    // Must match auth-proof.circom public order.
    // ==================================================

    const expectedPublicSignals = [

        String(
            authRequest.SignedRoot.root
        ),

        String(
            authRequest.root_version
        ),

        String(
            authRequest.D_id
        ),

        String(
            authRequest.scheme_id
        ),

        String(
            authRequest.challenge
        ),

        String(
            authRequest.ctx
        ),

        String(
            authRequest.sid
        ),

        String(
            authRequest.auth_nonce
        ),

        String(
            authRequest.tag
        )
    ];


    const publicSignals =
        proofObject.public_signals;


    if (
        !Array.isArray(
            publicSignals
        )
    ) {

        throw new Error(
            "Authentication public signals missing."
        );
    }


    if (
        publicSignals.length !==
        expectedPublicSignals.length
    ) {

        throw new Error(
            `Expected 9 public signals, got ${publicSignals.length}.`
        );
    }


    for (
        let i = 0;
        i <
        expectedPublicSignals.length;
        i++
    ) {

        assertEqual(
            `public signal [${i}]`,
            publicSignals[i],
            expectedPublicSignals[i]
        );
    }


    console.log(
        "Groth16 public statement      : MATCH"
    );


    // ==================================================
    // 9. Groth16 verification
    // ==================================================

    const zkStart =
        process.hrtime.bigint();


    const proofValid =
        await snarkjs.groth16.verify(
            verificationKey,
            publicSignals,
            proofObject.proof
        );


    timings.groth16_verify_ms =
        Number(
            process.hrtime.bigint() -
            zkStart
        ) / 1e6;


    if (!proofValid) {

        throw new Error(
            "proof_auth_ZK verification failed."
        );
    }


    console.log(
        "proof_auth_ZK                : VALID"
    );


    // ==================================================
    // 10. ACCEPT
    //
    // Only now is challenge consumed.
    // ==================================================

    const acceptedAt =
        new Date()
            .toISOString();


    challengeRecord.status =
        "consumed";


    challengeRecord.consumed_at =
        acceptedAt;


    challengeRecord.auth_result =
        "ACCEPT";


    saveJson(
        challengeFile,
        challengeRecord
    );


    const totalEnd =
        process.hrtime.bigint();


    timings.total_verification_ms =
        Number(
            totalEnd -
            totalStart
        ) / 1e6;


    // ==================================================
    // Experiment report
    // ==================================================

    const report = {

        challenge_id:
            challengeId,

        service:
            challengeRecord.service,

        D_id:
            String(
                authRequest.D_id
            ),

        scheme_id:
            String(
                authRequest.scheme_id
            ),

        root_version:
            Number(
                authRequest.root_version
            ),

        root:
            String(
                authRequest.SignedRoot.root
            ),

        proof_system:
            "Groth16",

        curve:
            "bn128",

        signed_root_valid:
            true,

        latest_root_policy:
            true,

        public_statement_match:
            true,

        proof_auth_ZK_valid:
            true,

        challenge_consumed:
            true,

        AuthResult:
            "ACCEPT",

        accepted_at:
            acceptedAt,

        timings_ms:
            timings
    };


    saveJson(
        reportFile,
        report
    );


    // ==================================================
    // Output
    // ==================================================

    console.log("");

    console.log(
        "--------------------------------------------"
    );

    console.log(
        "AUTHENTICATION RESULT: ACCEPT"
    );

    console.log(
        "--------------------------------------------"
    );

    console.log(
        `Challenge ID     : ${challengeId}`
    );

    console.log(
        `SignedRoot       : v${authRequest.root_version}`
    );

    console.log(
        `Groth16 verify   : ${timings.groth16_verify_ms.toFixed(3)} ms`
    );

    console.log(
        `Total verify     : ${timings.total_verification_ms.toFixed(3)} ms`
    );

    console.log(
        "Challenge consumed: true"
    );

    console.log("");

    console.log(
        "Experiment report:"
    );

    console.log(
        reportFile
    );
}


// ======================================================
// Error -> REJECT
// ======================================================

main()
    .then(() => {

        process.exit(0);

    })
    .catch(error => {

        console.log("");

        console.log(
            "============================================"
        );

        console.log(
            "AUTHENTICATION RESULT: REJECT"
        );

        console.log(
            "============================================"
        );

        console.log(
            error.message
        );

        console.log(
            "============================================"
        );

        process.exit(1);
    });