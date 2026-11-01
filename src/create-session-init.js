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


function sha256Hex(data) {

    return crypto
        .createHash("sha256")
        .update(data)
        .digest("hex");
}


// ======================================================
// Uniform scalar in [1, q-1]
// ======================================================

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
            "Usage: node src\\create-session-init.js <challenge-id>"
        );
    }


    const projectRoot =
        config.paths.projectRoot;


    // ==================================================
    // Paths
    // ==================================================

    const challengeFile =
        path.join(
            projectRoot,
            "state",
            "auth_challenges",
            `${challengeId}.json`
        );


    const authRequestFile =
        path.join(
            projectRoot,
            "artifacts",
            "auth",
            challengeId,
            "auth_request.json"
        );


    const privateDir =
        path.join(
            projectRoot,
            "private",
            "sessions",
            challengeId
        );


    const artifactDir =
        path.join(
            projectRoot,
            "artifacts",
            "sessions",
            challengeId
        );


    const privateFile =
        path.join(
            privateDir,
            "user_ephemeral.json"
        );


    const sessionInitFile =
        path.join(
            artifactDir,
            "session_init.json"
        );


    // ==================================================
    // Prevent accidental ephemeral-key reuse
    // ==================================================

    if (
        fs.existsSync(privateFile) ||
        fs.existsSync(sessionInitFile)
    ) {

        throw new Error(
            "SessionInit already exists for this authentication. Refusing to reuse or overwrite ephemeral key."
        );
    }


    // ==================================================
    // Load accepted authentication
    // ==================================================

    const challengeRecord =
        loadJson(
            challengeFile
        );


    const authRequest =
        loadJson(
            authRequestFile
        );


    // ==================================================
    // Must originate from successful authentication
    // ==================================================

    if (
        challengeRecord.status !==
        "consumed"
    ) {

        throw new Error(
            `Authentication status is ${challengeRecord.status}, expected consumed.`
        );
    }


    if (
        challengeRecord.auth_result !==
        "ACCEPT"
    ) {

        throw new Error(
            "Secure session cannot start without AuthResult = ACCEPT."
        );
    }


    // ==================================================
    // Bind auth request to accepted service record
    // ==================================================

    if (
        String(authRequest.D_id) !==
        String(challengeRecord.D_id)
    ) {

        throw new Error(
            "Auth_Request D_id mismatch."
        );
    }


    if (
        String(authRequest.sid) !==
        String(challengeRecord.sid)
    ) {

        throw new Error(
            "Auth_Request sid mismatch."
        );
    }


    if (
        String(authRequest.challenge) !==
        String(challengeRecord.challenge)
    ) {

        throw new Error(
            "Auth_Request challenge mismatch."
        );
    }


    if (
        String(authRequest.ctx) !==
        String(challengeRecord.ctx)
    ) {

        throw new Error(
            "Auth_Request ctx mismatch."
        );
    }


    // ==================================================
    // reference_auth
    //
    // Thesis permits a digest of the accepted
    // authentication package.
    // ==================================================

    const referenceAuth =
        sha256Hex(
            Buffer.from(
                canonicalJson(
                    authRequest
                ),
                "utf8"
            )
        );


    // ==================================================
    // BabyJub
    // ==================================================

    const babyJub =
        await buildBabyjub();


    const F =
        babyJub.F;


    // ==================================================
    // User ephemeral key
    //
    // a <-R Zq
    // A = g^a
    // ==================================================

    const start =
        process.hrtime.bigint();


    const a =
        randomScalar();


    const A =
        babyJub.mulPointEscalar(
            babyJub.Base8,
            a
        );


    const Ax =
        BigInt(
            F.toString(
                A[0]
            )
        );


    const Ay =
        BigInt(
            F.toString(
                A[1]
            )
        );


    const end =
        process.hrtime.bigint();


    const ephemeralGenerationMs =
        Number(
            end - start
        ) / 1e6;


    // ==================================================
    // Private ephemeral state
    //
    // NEVER sent to destination service.
    // ==================================================

    const privateState = {

        version:
            1,

        challenge_id:
            challengeId,

        a:
            a.toString(),

        A: {
            x:
                Ax.toString(),

            y:
                Ay.toString()
        },

        created_at:
            new Date()
                .toISOString()
    };


    saveJson(
        privateFile,
        privateState
    );


    // ==================================================
    // SessionInit
    //
    // No identity, x, x_anchor, L, idx, Merkle path,
    // or registration secret.
    // ==================================================

    const sessionInit = {

        version:
            1,

        A: {
            x:
                Ax.toString(),

            y:
                Ay.toString()
        },

        D_id_src:
            String(
                authRequest.D_id
            ),

        service_id:
            String(
                challengeRecord.service
            ),

        sid:
            String(
                authRequest.sid
            ),

        challenge:
            String(
                authRequest.challenge
            ),

        ctx:
            String(
                authRequest.ctx
            ),

        tag:
            String(
                authRequest.tag
            ),

        reference_auth:
            referenceAuth
    };


    saveJson(
        sessionInitFile,
        sessionInit
    );


    // ==================================================
    // Output
    // ==================================================

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - SessionInit"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Challenge ID  : ${challengeId}`
    );

    console.log(
        `AuthResult    : ${challengeRecord.auth_result}`
    );

    console.log(
        `Service ID    : ${challengeRecord.service}`
    );

    console.log(
        `Source domain : ${authRequest.D_id}`
    );

    console.log("");

    console.log(
        "User ephemeral DH:"
    );

    console.log(
        "a             : PRIVATE"
    );

    console.log(
        `A.x           : ${Ax}`
    );

    console.log(
        `A.y           : ${Ay}`
    );

    console.log("");

    console.log(
        `reference_auth: ${referenceAuth}`
    );

    console.log("");

    console.log(
        `Ephemeral generation: ${ephemeralGenerationMs.toFixed(3)} ms`
    );

    console.log("");

    console.log(
        "Private ephemeral state:"
    );

    console.log(
        privateFile
    );

    console.log("");

    console.log(
        "SessionInit:"
    );

    console.log(
        sessionInitFile
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
            "SessionInit generation failed:"
        );

        console.error(
            error.message
        );

        process.exit(1);
    });