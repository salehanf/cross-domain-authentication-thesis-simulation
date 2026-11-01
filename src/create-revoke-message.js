const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const config = require("./config");

const {
    signMessage,
    verifyMessage,
    defaultSigners
} = require("./frost");


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


    if (Array.isArray(value)) {

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


function verificationSucceeded(result) {

    if (result === true) {
        return true;
    }


    if (
        result &&
        typeof result === "object"
    ) {

        return (
            result.valid === true ||
            result.verified === true ||
            result.success === true
        );
    }


    return false;
}


function getLatestSignedRoot(
    rootsDir
) {

    const roots =
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
                    Number(
                        match[1]
                    ),

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
        roots.length === 0
    ) {

        throw new Error(
            "No SignedRoot found."
        );
    }


    return {

        file:
            roots[0].file,

        data:
            loadJson(
                roots[0].file
            )
    };
}


// ======================================================
// Main
// ======================================================

function main() {

    const enrollmentId =
        process.argv[2];


    const reasonCode =
        process.argv[3] ??
        "POLICY_REVOCATION";


    if (!enrollmentId) {

        throw new Error(
            "Usage: node src\\create-revoke-message.js <enrollment-id> [reason-code]"
        );
    }


    const projectRoot =
        config.paths.projectRoot;


    // ==================================================
    // Paths
    // ==================================================

    const reconstructionReportFile =
        path.join(
            projectRoot,
            "results",
            "revocation",
            enrollmentId,
            "threshold_reconstruction_report.json"
        );


    const registryFile =
        path.join(
            projectRoot,
            "state",
            "bas",
            "enrollment_registry.json"
        );


    const rootsDir =
        path.join(
            projectRoot,
            "state",
            "roots"
        );


    const artifactDir =
        path.join(
            projectRoot,
            "artifacts",
            "revocation",
            enrollmentId
        );


    const revokeMessageFile =
        path.join(
            artifactDir,
            "revoke_message.json"
        );


    const reportFile =
        path.join(
            projectRoot,
            "results",
            "revocation",
            enrollmentId,
            "revoke_message_report.json"
        );


    // ==================================================
    // Do not overwrite an existing instruction
    // ==================================================

    if (
        fs.existsSync(
            revokeMessageFile
        )
    ) {

        throw new Error(
            "Revoke_Message already exists. Refusing to overwrite."
        );
    }


    // ==================================================
    // Load reconstruction result
    // ==================================================

    const reconstruction =
        loadJson(
            reconstructionReportFile
        );


    if (
        reconstruction.threshold_reconstruction !==
        "VALID"
    ) {

        throw new Error(
            "Threshold reconstruction is not VALID."
        );
    }


    if (
        reconstruction.revocation_target !==
        "VALID_ACTIVE_RECORD"
    ) {

        throw new Error(
            "Revocation target is not a valid active BAS record."
        );
    }


    if (
        reconstruction.reconstructed_x_anchor_exposed !==
        false
    ) {

        throw new Error(
            "Unexpected reconstruction privacy state."
        );
    }


    const yHash =
        String(
            reconstruction.y_hash
        );


    const domainId =
        String(
            reconstruction.D_id
        );


    const schemeId =
        String(
            reconstruction.scheme_id
        );


    // ==================================================
    // Check BAS state again
    //
    // The state may have changed after reconstruction.
    // ==================================================

    const registry =
        loadJson(
            registryFile
        );


    const basRecord =
        registry.entries?.[
            yHash
        ];


    if (!basRecord) {

        throw new Error(
            "BAS record no longer exists for y_hash."
        );
    }


    if (
        String(
            basRecord.status
        ).toLowerCase() !==
        "active"
    ) {

        throw new Error(
            `BAS record is no longer active: ${basRecord.status}`
        );
    }


    // ==================================================
    // Current SignedRoot
    //
    // version in Revoke_Message means expected current
    // root version.
    // ==================================================

    const latest =
        getLatestSignedRoot(
            rootsDir
        );


    const signedRoot =
        latest.data;


    if (
        String(
            signedRoot.D_id
        ) !==
        domainId
    ) {

        throw new Error(
            "SignedRoot D_id mismatch."
        );
    }


    if (
        String(
            signedRoot.scheme_id
        ) !==
        schemeId
    ) {

        throw new Error(
            "SignedRoot scheme_id mismatch."
        );
    }


    if (
        Number(
            basRecord.version
        ) !==
        Number(
            signedRoot.version
        )
    ) {

        throw new Error(
            "BAS record version does not match current SignedRoot version."
        );
    }


    // ==================================================
    // Threshold key ID
    // ==================================================

    const keyId =
        String(
            signedRoot.key_id
        );


    if (!keyId) {

        throw new Error(
            "SignedRoot key_id missing."
        );
    }


    // ==================================================
    // Unsigned Revoke_Message
    //
    // Thesis:
    //
    // D_id
    // scheme_id
    // y_hash
    // reason_code
    // version
    // timestamp
    // key_id
    // ==================================================

    const timestamp =
        new Date()
            .toISOString();


    const unsignedMessage = {

        D_id:
            domainId,

        scheme_id:
            schemeId,

        y_hash:
            yHash,

        reason_code:
            String(
                reasonCode
            ),

        version:
            Number(
                signedRoot.version
            ),

        timestamp:
            timestamp,

        key_id:
            keyId
    };


    // ==================================================
    // Revocation signing statement
    //
    // Thesis relation:
    //
    // H(
    //   "REVOKE" ||
    //   D_id ||
    //   scheme_id ||
    //   y_hash ||
    //   reason_code ||
    //   version ||
    //   timestamp ||
    //   key_id
    // )
    //
    // Experimental deterministic encoding:
    // canonical JSON array -> SHA-256.
    // ==================================================

    const signingStatement = [

        "REVOKE",

        unsignedMessage.D_id,

        unsignedMessage.scheme_id,

        unsignedMessage.y_hash,

        unsignedMessage.reason_code,

        String(
            unsignedMessage.version
        ),

        unsignedMessage.timestamp,

        unsignedMessage.key_id
    ];


    const messageDigest =
        sha256Buffer(
            Buffer.from(
                canonicalJson(
                    signingStatement
                ),
                "utf8"
            )
        );


    // ==================================================
    // FROST threshold signing
    // ==================================================

    const signers =
        defaultSigners();


    if (
        signers.length <
        Number(
            config.admins.t
        )
    ) {

        throw new Error(
            "Insufficient FROST signers."
        );
    }


    const signingStart =
        process.hrtime.bigint();


    const artifactName =
        `revoke_${enrollmentId}_v${signedRoot.version}`;


    const signatureResult =
        signMessage(
            messageDigest,
            artifactName,
            signers
        );


    const signingEnd =
        process.hrtime.bigint();


    const signingMs =
        Number(
            signingEnd -
            signingStart
        ) / 1e6;


    if (
        !signatureResult ||
        !signatureResult.signatureHex
    ) {

        throw new Error(
            "FROST did not return signatureHex."
        );
    }


    const signatureHex =
        signatureResult.signatureHex;


    // ==================================================
    // Immediate threshold-signature verification
    // ==================================================

    const verifyStart =
        process.hrtime.bigint();


    const verifyResult =
        verifyMessage(
            messageDigest,
            signatureHex
        );


    const verifyEnd =
        process.hrtime.bigint();


    const verifyMs =
        Number(
            verifyEnd -
            verifyStart
        ) / 1e6;


    if (
        !verificationSucceeded(
            verifyResult
        )
    ) {

        throw new Error(
            "FROST Revoke_Message signature verification failed."
        );
    }


    // ==================================================
    // Final public Revoke_Message
    //
    // NO x
    // NO x_anchor
    // NO plaintext shares
    // NO idx
    // NO L
    // ==================================================

    const revokeMessage = {

        ...unsignedMessage,

        signature:
            signatureHex
    };


    // ==================================================
    // Privacy check
    // ==================================================

    const serialized =
        JSON.stringify(
            revokeMessage
        );


    const forbiddenFields = [

        "\"x\"",
        "\"x_anchor\"",
        "\"shares\"",
        "\"share\"",
        "\"idx\"",
        "\"L\"",
        "\"secret_key\""
    ];


    for (
        const field
        of forbiddenFields
    ) {

        if (
            serialized.includes(
                field
            )
        ) {

            throw new Error(
                `Forbidden private field detected: ${field}`
            );
        }
    }


    saveJson(
        revokeMessageFile,
        revokeMessage
    );


    // ==================================================
    // Report
    // ==================================================

    const report = {

        enrollment_id:
            enrollmentId,

        D_id:
            domainId,

        scheme_id:
            schemeId,

        y_hash:
            yHash,

        reason_code:
            reasonCode,

        expected_root_version:
            Number(
                signedRoot.version
            ),

        key_id:
            keyId,

        threshold:
            `${config.admins.t}-of-${config.admins.n}`,

        signers:
            signers,

        signing_statement:
            "SHA256(canonical([REVOKE,D_id,scheme_id,y_hash,reason_code,version,timestamp,key_id]))",

        frost_signature_valid:
            true,

        private_x_exposed:
            false,

        private_x_anchor_exposed:
            false,

        plaintext_shares_exposed:
            false,

        bas_record_active_before_revocation:
            true,

        revocation_applied:
            false,

        timings_ms: {

            frost_sign:
                signingMs,

            frost_verify:
                verifyMs
        }
    };


    saveJson(
        reportFile,
        report
    );


    // ==================================================
    // Output
    // ==================================================

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - Revoke_Message"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Enrollment ID  : ${enrollmentId}`
    );

    console.log(
        `D_id           : ${domainId}`
    );

    console.log(
        `scheme_id      : ${schemeId}`
    );

    console.log(
        `Root version   : v${signedRoot.version}`
    );

    console.log(
        `Reason code    : ${reasonCode}`
    );

    console.log(
        `Key ID         : ${keyId}`
    );

    console.log("");

    console.log(
        `Threshold      : ${config.admins.t}-of-${config.admins.n}`
    );

    console.log(
        `FROST signers  : ${signers.join(", ")}`
    );

    console.log("");

    console.log(
        "y_hash / BAS active record : MATCH"
    );

    console.log(
        "FROST signature            : VALID"
    );

    console.log("");

    console.log(
        "Private data in Revoke_Message:"
    );

    console.log(
        "x              : NO"
    );

    console.log(
        "x_anchor       : NO"
    );

    console.log(
        "plaintext share: NO"
    );

    console.log(
        "idx            : NO"
    );

    console.log(
        "L              : NO"
    );

    console.log("");

    console.log(
        `FROST signing   : ${signingMs.toFixed(3)} ms`
    );

    console.log(
        `FROST verify    : ${verifyMs.toFixed(3)} ms`
    );

    console.log("");

    console.log(
        "Revoke_Message:"
    );

    console.log(
        revokeMessageFile
    );

    console.log("");

    console.log(
        "Experiment report:"
    );

    console.log(
        reportFile
    );

    console.log("");

    console.log(
        "No BAS state has been changed yet."
    );

    console.log(
        "============================================"
    );
}


try {

    main();

    process.exit(0);

} catch (error) {

    console.log("");

    console.log(
        "============================================"
    );

    console.log(
        "REVOKE MESSAGE CREATION: REJECT"
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
}