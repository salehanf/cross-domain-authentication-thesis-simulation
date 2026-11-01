const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const config = require("./config");


// ======================================================
// BN254 field
// ======================================================

const BN254_FIELD =
    21888242871839275222246405745257275088548364400416034343698204186575808495617n;


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


function randomFieldElement() {

    // 248 random bits, safely inside BN254 field.
    return BigInt(
        "0x" +
        crypto
            .randomBytes(31)
            .toString("hex")
    );
}


function textToField(text) {

    const digest =
        crypto
            .createHash("sha256")
            .update(text, "utf8")
            .digest("hex");

    return BigInt(
        "0x" + digest
    ) % BN254_FIELD;
}


function getLatestSignedRoot(rootsDir) {

    if (!fs.existsSync(rootsDir)) {
        throw new Error(
            `SignedRoot directory not found: ${rootsDir}`
        );
    }


    const candidates =
        fs.readdirSync(rootsDir)
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
                    b.version - a.version
            );


    if (candidates.length === 0) {
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


// ======================================================
// Main
// ======================================================

function main() {

    const projectRoot =
        config.paths.projectRoot;


    const rootsDir =
        path.join(
            projectRoot,
            "state",
            "roots"
        );


    const {
        file:
            signedRootFile,

        data:
            signedRoot
    } =
        getLatestSignedRoot(
            rootsDir
        );


    // ==================================================
    // Destination-service generated values
    // ==================================================

    const challenge =
        randomFieldElement();


    const sid =
        randomFieldElement();


    const serviceName =
        process.argv[2] ??
        "benchmark-service";


    /*
     * ctx binds the authentication run to a particular
     * protocol/domain/service context.
     */

    const contextLabel =
        [
            "cross-domain-auth",
            `source-domain=${signedRoot.D_id}`,
            `scheme=${signedRoot.scheme_id}`,
            `service=${serviceName}`
        ].join("|");


    const ctx =
        textToField(
            contextLabel
        );


    // Local identifier for this service challenge.
    // This is NOT a protocol public input.
    const challengeId =
        crypto
            .randomBytes(8)
            .toString("hex");


    const issuedAt =
        new Date();


    // Five-minute challenge validity.
    const expiresAt =
        new Date(
            issuedAt.getTime() +
            15 * 60 * 1000
        );


    // ==================================================
    // Service-side challenge state
    // ==================================================

    const challengeRecord = {

        version:
            1,

        challenge_id:
            challengeId,

        status:
            "pending",

        service:
            serviceName,

        D_id:
            String(
                signedRoot.D_id
            ),

        scheme_id:
            String(
                signedRoot.scheme_id
            ),

        root:
            String(
                signedRoot.root
            ),

        root_version:
            Number(
                signedRoot.version
            ),

        challenge:
            challenge.toString(),

        sid:
            sid.toString(),

        ctx:
            ctx.toString(),

        context_label:
            contextLabel,

        issued_at:
            issuedAt.toISOString(),

        expires_at:
            expiresAt.toISOString(),

        signed_root_file:
            signedRootFile
    };


    const challengeDir =
        path.join(
            projectRoot,
            "state",
            "auth_challenges"
        );


    const challengeFile =
        path.join(
            challengeDir,
            `${challengeId}.json`
        );


    saveJson(
        challengeFile,
        challengeRecord
    );


    // ==================================================
    // Output
    // ==================================================

    console.log(
        "============================================"
    );

    console.log(
        " Destination Service - Auth Challenge"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Challenge ID : ${challengeId}`
    );

    console.log(
        `Service      : ${serviceName}`
    );

    console.log(
        `SignedRoot   : v${signedRoot.version}`
    );

    console.log(
        `Root         : ${signedRoot.root}`
    );

    console.log(
        `D_id         : ${signedRoot.D_id}`
    );

    console.log(
        `scheme_id    : ${signedRoot.scheme_id}`
    );

    console.log("");

    console.log(
        `Challenge    : ${challenge}`
    );

    console.log(
        `sid          : ${sid}`
    );

    console.log(
        `ctx          : ${ctx}`
    );

    console.log("");

    console.log(
        `Issued at    : ${issuedAt.toISOString()}`
    );

    console.log(
        `Expires at   : ${expiresAt.toISOString()}`
    );

    console.log("");

    console.log(
        "Challenge state:"
    );

    console.log(
        challengeFile
    );

    console.log(
        "============================================"
    );
}


try {

    main();

} catch (error) {

    console.error("");

    console.error(
        "Authentication challenge generation failed:"
    );

    console.error(
        error.message
    );

    process.exit(1);
}