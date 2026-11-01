const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const config = require("./config");


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


function assertStringEqual(
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


// ======================================================
// Main
// ======================================================

async function main() {

    const challengeId =
        process.argv[2];


    if (!challengeId) {

        throw new Error(
            "Usage: node src\\build-auth-request.js <challenge-id>"
        );
    }


    const projectRoot =
        config.paths.projectRoot;


    // ==================================================
    // Paths
    // ==================================================

    const authDir =
        path.join(
            projectRoot,
            "artifacts",
            "auth",
            challengeId
        );


    const contextFile =
        path.join(
            authDir,
            "auth_context.json"
        );


    const challengeFile =
        path.join(
            projectRoot,
            "state",
            "auth_challenges",
            `${challengeId}.json`
        );


    const proofFile =
        path.join(
            projectRoot,
            "build",
            "auth_proof",
            "auth-proof.json"
        );


    const publicFile =
        path.join(
            projectRoot,
            "build",
            "auth_proof",
            "auth-public.json"
        );


    const verificationKeyFile =
        path.join(
            projectRoot,
            "build",
            "auth_proof",
            "verification_key.json"
        );


    // ==================================================
    // Load
    // ==================================================

    const context =
        loadJson(
            contextFile
        );


    const challengeRecord =
        loadJson(
            challengeFile
        );


    const proof =
        loadJson(
            proofFile
        );


    const publicSignals =
        loadJson(
            publicFile
        );


    const verificationKey =
        loadJson(
            verificationKeyFile
        );


    // ==================================================
    // Challenge state
    // ==================================================

    if (
        challengeRecord.status !==
        "pending"
    ) {

        throw new Error(
            `Challenge status is ${challengeRecord.status}, expected pending.`
        );
    }


    // ==================================================
    // Bind Auth context to Destination Service challenge
    // ==================================================

    assertStringEqual(
        "D_id",
        context.D_id,
        challengeRecord.D_id
    );


    assertStringEqual(
        "scheme_id",
        context.scheme_id,
        challengeRecord.scheme_id
    );


    assertStringEqual(
        "root",
        context.SignedRoot.root,
        challengeRecord.root
    );


    assertStringEqual(
        "root_version",
        context.root_version,
        challengeRecord.root_version
    );


    assertStringEqual(
        "challenge",
        context.challenge,
        challengeRecord.challenge
    );


    assertStringEqual(
        "ctx",
        context.ctx,
        challengeRecord.ctx
    );


    assertStringEqual(
        "sid",
        context.sid,
        challengeRecord.sid
    );


    // ==================================================
    // Expected Groth16 public statement
    //
    // Must exactly match the public input order in:
    //
    // auth-proof.circom
    // ==================================================

    const expectedPublicSignals = [

        String(
            challengeRecord.root
        ),

        String(
            challengeRecord.root_version
        ),

        String(
            challengeRecord.D_id
        ),

        String(
            challengeRecord.scheme_id
        ),

        String(
            challengeRecord.challenge
        ),

        String(
            challengeRecord.ctx
        ),

        String(
            challengeRecord.sid
        ),

        String(
            context.auth_nonce
        ),

        String(
            context.tag
        )
    ];


    if (
        !Array.isArray(
            publicSignals
        )
    ) {

        throw new Error(
            "auth-public.json is not an array."
        );
    }


    if (
        publicSignals.length !==
        expectedPublicSignals.length
    ) {

        throw new Error(
            `Unexpected public signal count: ${publicSignals.length}`
        );
    }


    for (
        let i = 0;
        i < expectedPublicSignals.length;
        i++
    ) {

        assertStringEqual(
            `public signal [${i}]`,
            publicSignals[i],
            expectedPublicSignals[i]
        );
    }


    // ==================================================
    // Verify Groth16 proof one more time before packaging
    // ==================================================

    const proofValid =
        await snarkjs.groth16.verify(
            verificationKey,
            publicSignals,
            proof
        );


    if (!proofValid) {

        throw new Error(
            "Groth16 authentication proof is INVALID."
        );
    }


    // ==================================================
    // Build thesis Auth_Request
    //
    // IMPORTANT:
    //
    // No x
    // No x_anchor
    // No Y
    // No L
    // No idx
    // No Merkle path
    // ==================================================

    const authRequest = {

        D_id:
            String(
                challengeRecord.D_id
            ),

        scheme_id:
            String(
                challengeRecord.scheme_id
            ),

        SignedRoot:
            context.SignedRoot,

        root_version:
            Number(
                challengeRecord.root_version
            ),

        sid:
            String(
                challengeRecord.sid
            ),

        challenge:
            String(
                challengeRecord.challenge
            ),

        ctx:
            String(
                challengeRecord.ctx
            ),

        auth_nonce:
            String(
                context.auth_nonce
            ),

        tag:
            String(
                context.tag
            ),

        proof_auth_ZK: {

            proof_system:
                "Groth16",

            curve:
                "bn128",

            circuit:
                "AuthProof-v1",

            verification_key_id:
                "auth-proof-v1",

            proof:
                proof,

            public_signals:
                publicSignals,

            verified_before_packaging:
                true
        }
    };


    // ==================================================
    // Save
    // ==================================================

    const outputFile =
        path.join(
            authDir,
            "auth_request.json"
        );


    saveJson(
        outputFile,
        authRequest
    );


    // ==================================================
    // Privacy check
    // ==================================================

    const serialized =
        JSON.stringify(
            authRequest
        );


    const forbiddenNames = [
        "\"x\"",
        "\"x_anchor\"",
        "\"Y\"",
        "\"L\"",
        "\"idx\"",
        "\"path_siblings\""
    ];


    for (
        const name
        of forbiddenNames
    ) {

        if (
            serialized.includes(name)
        ) {

            throw new Error(
                `Private field unexpectedly found in Auth_Request: ${name}`
            );
        }
    }


    // ==================================================
    // Output
    // ==================================================

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - Build Auth_Request"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Challenge ID : ${challengeId}`
    );

    console.log(
        `Service      : ${challengeRecord.service}`
    );

    console.log(
        `SignedRoot   : v${challengeRecord.root_version}`
    );

    console.log("");

    console.log(
        "Challenge binding          : MATCH"
    );

    console.log(
        "Groth16 public statement   : MATCH"
    );

    console.log(
        "proof_auth_ZK              : VALID"
    );

    console.log("");

    console.log(
        "Private witness in request:"
    );

    console.log(
        "x            : NO"
    );

    console.log(
        "x_anchor     : NO"
    );

    console.log(
        "Y            : NO"
    );

    console.log(
        "L            : NO"
    );

    console.log(
        "idx          : NO"
    );

    console.log(
        "Merkle path  : NO"
    );

    console.log("");

    console.log(
        "Auth_Request:"
    );

    console.log(
        outputFile
    );

    console.log(
        "============================================"
    );
}


main()
    .then(() => {

        process.exit(0);

    })
    .catch(error => {

        console.error("");

        console.error(
            "Auth_Request build failed:"
        );

        console.error(
            error.message
        );

        process.exit(1);
    });