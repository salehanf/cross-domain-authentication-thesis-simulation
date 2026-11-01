const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const {
    buildBabyjub
} = require("circomlibjs");

const config = require("./config");


// ======================================================
// BabyJub subgroup order
// ======================================================

const BABYJUB_Q =
    2736030358979909402780800718157159386076813972158567259200215660948447373041n;


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


function canonicalize(value) {

    if (
        value === null ||
        typeof value !== "object"
    ) {
        return value;
    }


    if (
        Array.isArray(value)
    ) {

        return value.map(
            canonicalize
        );
    }


    const result = {};


    for (
        const key
        of Object.keys(value).sort()
    ) {

        result[key] =
            canonicalize(
                value[key]
            );
    }


    return result;
}


function canonicalJson(value) {

    return JSON.stringify(
        canonicalize(value)
    );
}


function sha256Buffer(data) {

    return crypto
        .createHash("sha256")
        .update(data)
        .digest();
}


function sha256Hex(data) {

    return crypto
        .createHash("sha256")
        .update(data)
        .digest("hex");
}


function randomScalar() {

    while (true) {

        const candidate =
            BigInt(
                "0x" +
                crypto
                    .randomBytes(32)
                    .toString("hex")
            );


        if (
            candidate > 0n &&
            candidate < BABYJUB_Q
        ) {

            return candidate;
        }
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
            "Usage: node src\\create-session-response.js <challenge-id>"
        );
    }


    const projectRoot =
        config.paths.projectRoot;


    // ==================================================
    // Paths
    // ==================================================

    const sessionDir =
        path.join(
            projectRoot,
            "artifacts",
            "sessions",
            challengeId
        );


    const sessionInitFile =
        path.join(
            sessionDir,
            "session_init.json"
        );


    const sessionResponseFile =
        path.join(
            sessionDir,
            "session_response.json"
        );


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


    // ==================================================
    // Load service/auth/session state
    // ==================================================

    const sessionInit =
        loadJson(
            sessionInitFile
        );


    const authRequest =
        loadJson(
            authRequestFile
        );


    const challengeRecord =
        loadJson(
            challengeFile
        );


    const serviceId =
        String(
            sessionInit.service_id
        );


    const servicePrivateKeyFile =
        path.join(
            projectRoot,
            "private",
            "services",
            serviceId,
            "service_private_key.pem"
        );


    const serviceIdentityFile =
        path.join(
            projectRoot,
            "state",
            "services",
            serviceId,
            "service_identity.json"
        );


    const servicePrivateStateFile =
        path.join(
            projectRoot,
            "private",
            "sessions",
            challengeId,
            "service_ephemeral.json"
        );


    const serviceIdentity =
        loadJson(
            serviceIdentityFile
        );


    if (
        !fs.existsSync(
            servicePrivateKeyFile
        )
    ) {

        throw new Error(
            `Service private key not found: ${servicePrivateKeyFile}`
        );
    }


    if (
        fs.existsSync(
            sessionResponseFile
        ) ||
        fs.existsSync(
            servicePrivateStateFile
        )
    ) {

        throw new Error(
            "SessionResponse already exists. Refusing to reuse or overwrite service ephemeral key."
        );
    }


    // ==================================================
    // 1. Authentication must already be ACCEPT
    // ==================================================

    if (
        challengeRecord.status !==
        "consumed" ||
        challengeRecord.auth_result !==
        "ACCEPT"
    ) {

        throw new Error(
            "SessionResponse requires a previously accepted authentication."
        );
    }


    // ==================================================
    // 2. Bind SessionInit to accepted authentication
    // ==================================================

    if (
        String(sessionInit.D_id_src) !==
        String(authRequest.D_id)
    ) {

        throw new Error(
            "SessionInit D_id_src mismatch."
        );
    }


    if (
        String(sessionInit.service_id) !==
        String(challengeRecord.service)
    ) {

        throw new Error(
            "SessionInit service_id mismatch."
        );
    }


    if (
        String(sessionInit.sid) !==
        String(authRequest.sid)
    ) {

        throw new Error(
            "SessionInit sid mismatch."
        );
    }


    if (
        String(sessionInit.challenge) !==
        String(authRequest.challenge)
    ) {

        throw new Error(
            "SessionInit challenge mismatch."
        );
    }


    if (
        String(sessionInit.ctx) !==
        String(authRequest.ctx)
    ) {

        throw new Error(
            "SessionInit ctx mismatch."
        );
    }


    if (
        String(sessionInit.tag) !==
        String(authRequest.tag)
    ) {

        throw new Error(
            "SessionInit tag mismatch."
        );
    }


    // ==================================================
    // 3. Verify reference_auth
    // ==================================================

    const expectedReferenceAuth =
        sha256Hex(
            Buffer.from(
                canonicalJson(
                    authRequest
                ),
                "utf8"
            )
        );


    if (
        sessionInit.reference_auth !==
        expectedReferenceAuth
    ) {

        throw new Error(
            "reference_auth does not match accepted Auth_Request."
        );
    }


    // ==================================================
    // 4. Load and validate service signing identity
    // ==================================================

    if (
        serviceIdentity.signature_scheme !==
        "Ed25519"
    ) {

        throw new Error(
            "Unexpected service signature scheme."
        );
    }


    const privateKeyPem =
        fs.readFileSync(
            servicePrivateKeyFile,
            "utf8"
        );


    const privateKey =
        crypto.createPrivateKey(
            privateKeyPem
        );


    const publicKey =
        crypto.createPublicKey(
            privateKey
        );


    const publicDer =
        publicKey.export({
            type: "spki",
            format: "der"
        });


    const derivedKeyId =
        sha256Hex(
            publicDer
        );


    if (
        derivedKeyId !==
        serviceIdentity.key_id
    ) {

        throw new Error(
            "Service private key does not match registered key_id."
        );
    }


    // ==================================================
    // 5. BabyJub setup
    // ==================================================

    const babyJub =
        await buildBabyjub();


    const F =
        babyJub.F;


    // ==================================================
    // Validate user's public A
    // ==================================================

    const A = [
        F.e(
            BigInt(
                sessionInit.A.x
            )
        ),
        F.e(
            BigInt(
                sessionInit.A.y
            )
        )
    ];


    if (
        !babyJub.inCurve(A)
    ) {

        throw new Error(
            "User ephemeral public key A is not on BabyJub curve."
        );
    }


    if (
        !babyJub.inSubgroup(A)
    ) {

        throw new Error(
            "User ephemeral public key A is not in BabyJub subgroup."
        );
    }


    if (
        BigInt(sessionInit.A.x) === 0n &&
        BigInt(sessionInit.A.y) === 1n
    ) {

        throw new Error(
            "User ephemeral public key A is identity."
        );
    }


    // ==================================================
    // 6. Service ephemeral key
    //
    // b <-R Zq
    // B = g^b
    // ==================================================

    const ephemeralStart =
        process.hrtime.bigint();


    const b =
        randomScalar();


    const B =
        babyJub.mulPointEscalar(
            babyJub.Base8,
            b
        );


    const Bx =
        BigInt(
            F.toString(
                B[0]
            )
        );


    const By =
        BigInt(
            F.toString(
                B[1]
            )
        );


    const ephemeralEnd =
        process.hrtime.bigint();


    const ephemeralGenerationMs =
        Number(
            ephemeralEnd -
            ephemeralStart
        ) / 1e6;


    // ==================================================
    // 7. KEX-S signature statement
    //
    // Thesis:
    //
    // H(
    //   "KEX-S" ||
    //   A ||
    //   B ||
    //   sid ||
    //   challenge ||
    //   ctx ||
    //   tag ||
    //   D_id_src ||
    //   service_id
    // )
    //
    // Empirical encoding:
    // canonical JSON array -> SHA-256
    // ==================================================

    const signatureStatement = [

        "KEX-S",

        {
            x:
                String(
                    sessionInit.A.x
                ),

            y:
                String(
                    sessionInit.A.y
                )
        },

        {
            x:
                Bx.toString(),

            y:
                By.toString()
        },

        String(
            sessionInit.sid
        ),

        String(
            sessionInit.challenge
        ),

        String(
            sessionInit.ctx
        ),

        String(
            sessionInit.tag
        ),

        String(
            sessionInit.D_id_src
        ),

        String(
            sessionInit.service_id
        )
    ];


    const signatureDigest =
        sha256Buffer(
            Buffer.from(
                canonicalJson(
                    signatureStatement
                ),
                "utf8"
            )
        );


    const signingStart =
        process.hrtime.bigint();


    const signature =
        crypto.sign(
            null,
            signatureDigest,
            privateKey
        );


    const signingEnd =
        process.hrtime.bigint();


    const signingMs =
        Number(
            signingEnd -
            signingStart
        ) / 1e6;


    // ==================================================
    // Self-verify service signature
    // ==================================================

    const signatureValid =
        crypto.verify(
            null,
            signatureDigest,
            publicKey,
            signature
        );


    if (!signatureValid) {

        throw new Error(
            "Service KEX signature self-verification failed."
        );
    }


    // ==================================================
    // 8. Save PRIVATE service ephemeral state
    // ==================================================

    const privateState = {

        version:
            1,

        challenge_id:
            challengeId,

        service_id:
            serviceId,

        b:
            b.toString(),

        B: {
            x:
                Bx.toString(),

            y:
                By.toString()
        },

        created_at:
            new Date()
                .toISOString()
    };


    saveJson(
        servicePrivateStateFile,
        privateState
    );


    // ==================================================
    // 9. Public SessionResponse
    //
    // Thesis:
    // SessionResponse = { B, sigma_S }
    // ==================================================

    const sessionResponse = {

        version:
            1,

        B: {
            x:
                Bx.toString(),

            y:
                By.toString()
        },

        sigma_S: {

            scheme:
                "Ed25519",

            key_id:
                serviceIdentity.key_id,

            digest:
                signatureDigest.toString(
                    "hex"
                ),

            signature:
                signature.toString(
                    "base64"
                )
        }
    };


    saveJson(
        sessionResponseFile,
        sessionResponse
    );


    // ==================================================
    // Output
    // ==================================================

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - SessionResponse"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Challenge ID     : ${challengeId}`
    );

    console.log(
        `Service ID       : ${serviceId}`
    );

    console.log(
        `reference_auth   : VALID`
    );

    console.log(
        `User A           : VALID BABYJUB POINT`
    );

    console.log("");

    console.log(
        "Service ephemeral DH:"
    );

    console.log(
        "b                : PRIVATE"
    );

    console.log(
        `B.x              : ${Bx}`
    );

    console.log(
        `B.y              : ${By}`
    );

    console.log("");

    console.log(
        `Service key ID   : ${serviceIdentity.key_id}`
    );

    console.log(
        "KEX-S signature  : VALID"
    );

    console.log("");

    console.log(
        `Ephemeral generation : ${ephemeralGenerationMs.toFixed(3)} ms`
    );

    console.log(
        `Ed25519 signing      : ${signingMs.toFixed(3)} ms`
    );

    console.log("");

    console.log(
        "Private service state:"
    );

    console.log(
        servicePrivateStateFile
    );

    console.log("");

    console.log(
        "SessionResponse:"
    );

    console.log(
        sessionResponseFile
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
            "SessionResponse generation failed:"
        );

        console.error(
            error.message
        );

        process.exit(1);
    });