const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const config = require("./config");

const {
    signMessage,
    verifyMessage
} = require("./frost");


const projectRoot =
    config.paths.projectRoot;


// ======================================================
// SHA-256
// ======================================================

function sha256(data) {

    return crypto
        .createHash("sha256")
        .update(data)
        .digest();
}


// ======================================================
// Canonical AAT signing payload
//
// Implements:
//
// H(
//   "AAT" ||
//   D_id ||
//   scheme_id ||
//   purpose ||
//   nonce ||
//   issued_at ||
//   expires_at ||
//   key_id
// )
// ======================================================

function createAATPayload(
    aat
) {

    /*
     * Fixed-position array avoids ambiguity caused by
     * JavaScript object formatting or field ordering.
     */

    return JSON.stringify([
        "AAT",

        String(
            aat.D_id
        ),

        String(
            aat.scheme_id
        ),

        String(
            aat.purpose
        ),

        String(
            aat.nonce
        ),

        String(
            aat.issued_at
        ),

        String(
            aat.expires_at
        ),

        String(
            aat.key_id
        )
    ]);
}


// ======================================================
// Compute AAT nullifier
//
// H(
//   "AAT-null" ||
//   D_id ||
//   scheme_id ||
//   purpose ||
//   nonce
// )
//
// NOTE:
// The thesis contains minor typographical variants
// such as AAT_null / AAT-null.
// This implementation consistently uses "AAT-null".
// ======================================================

function computeAATNullifier(
    aat
) {

    const canonical =
        JSON.stringify([
            config.aat.nullifierTag,

            String(
                aat.D_id
            ),

            String(
                aat.scheme_id
            ),

            String(
                aat.purpose
            ),

            String(
                aat.nonce
            )
        ]);


    return sha256(
        Buffer.from(
            canonical,
            "utf8"
        )
    )
    .toString(
        "hex"
    );
}


// ======================================================
// Load active FROST setup
// ======================================================

function loadFrostSetup() {

    const frostSetupFile =
        path.join(
            projectRoot,
            "results",
            "frost_setup.json"
        );


    if (
        !fs.existsSync(
            frostSetupFile
        )
    ) {

        throw new Error(
            "frost_setup.json was not found. Run admin_setup.js first."
        );
    }


    return JSON.parse(
        fs.readFileSync(
            frostSetupFile,
            "utf8"
        )
    );
}


// ======================================================
// Issue AAT
// ======================================================

function issueAAT() {

    const frostSetup =
        loadFrostSetup();


    // --------------------------------------------------
    // Consistency checks
    // --------------------------------------------------

    if (
        frostSetup.domain_id !==
        config.domain.domainId
    ) {

        throw new Error(
            "FROST domain_id does not match config.js."
        );
    }


    if (
        frostSetup.scheme_id !==
        config.protocol.schemeId
    ) {

        throw new Error(
            "FROST scheme_id does not match config.js."
        );
    }


    if (
        frostSetup.n !==
        config.admins.n ||
        frostSetup.t !==
        config.admins.t
    ) {

        throw new Error(
            "FROST threshold configuration does not match config.js."
        );
    }


    // ==================================================
    // Generate one-time nonce
    // ==================================================

    const nonce =
        crypto
            .randomBytes(32)
            .toString("hex");


    // ==================================================
    // Token validity interval
    // ==================================================

    const issuedAtDate =
        new Date();


    const expiresAtDate =
        new Date(
            issuedAtDate.getTime() +
            config.aat.validitySeconds *
            1000
        );


    const unsignedAAT = {

        D_id:
            config.domain.domainId,

        scheme_id:
            config.protocol.schemeId,

        purpose:
            config.aat.purpose,

        nonce,

        issued_at:
            issuedAtDate.toISOString(),

        expires_at:
            expiresAtDate.toISOString(),

        key_id:
            frostSetup.key_id
    };


    // ==================================================
    // Canonical signing payload
    // ==================================================

    const payload =
        createAATPayload(
            unsignedAAT
        );


    /*
     * Thesis:
     *
     * ThSig_Admin(
     *   H("AAT" || ...)
     * )
     *
     * Experimental instantiation:
     *
     * H = SHA-256
     */

    const messageDigest =
        sha256(
            Buffer.from(
                payload,
                "utf8"
            )
        );


    // ==================================================
    // FROST threshold signature
    // ==================================================

    const artifactName =
        `aat_${nonce.slice(0, 16)}`;


    const signatureResult =
        signMessage(
            messageDigest,
            artifactName
        );


    const aat = {

        ...unsignedAAT,

        signature:
            signatureResult
                .signatureHex
    };


    // ==================================================
    // Immediate signature verification
    // ==================================================

    const verification =
        verifyAAT(
            aat,
            {
                checkTime: true
            }
        );


    if (
        !verification.valid
    ) {

        throw new Error(
            `Issued AAT failed verification: ${verification.reason}`
        );
    }


    // ==================================================
    // Compute nullifier for testing/display ONLY
    //
    // IMPORTANT:
    // It is NOT inserted into the BAS consumed-token
    // registry here.
    //
    // BAS stores it only after successful enrollment.
    // ==================================================

    const nullifier =
        computeAATNullifier(
            aat
        );


    // ==================================================
    // Save issued token as an interchange artifact
    //
    // This represents delivery of the AAT to the user.
    // It is NOT the BAS persistent token database.
    // ==================================================

    const aatDir =
        path.join(
            projectRoot,
            "artifacts",
            "aat"
        );


    fs.mkdirSync(
        aatDir,
        {
            recursive: true
        }
    );


    const aatFile =
        path.join(
            aatDir,
            `${artifactName}.json`
        );


    fs.writeFileSync(
        aatFile,

        JSON.stringify(
            aat,
            null,
            2
        )
    );


    // ==================================================
    // Experimental report
    // ==================================================

    const resultsDir =
        path.join(
            projectRoot,
            "results",
            "aat"
        );


    fs.mkdirSync(
        resultsDir,
        {
            recursive: true
        }
    );


    const reportFile =
        path.join(
            resultsDir,
            `${artifactName}.report.json`
        );


    const report = {

        component:
            "Admin Approval Token issuance",

        D_id:
            aat.D_id,

        scheme_id:
            aat.scheme_id,

        purpose:
            aat.purpose,

        key_id:
            aat.key_id,

        validity_seconds:
            config.aat.validitySeconds,

        nonce_bytes:
            Buffer.from(
                nonce,
                "hex"
            ).length,

        signature_bytes:
            signatureResult
                .report
                .signature_bytes,

        threshold:
            config.admins.t,

        administrators:
            config.admins.n,

        signers:
            signatureResult
                .report
                .signers,

        signature_valid:
            verification.valid,

        frost_timing:
            signatureResult
                .report
                .timing,

        /*
         * Stored here only for experimental inspection.
         *
         * During the protocol, BAS computes this value
         * when validating enrollment.
         */
        experimental_nullifier:
            nullifier
    };


    fs.writeFileSync(
        reportFile,

        JSON.stringify(
            report,
            null,
            2
        )
    );


    // ==================================================
    // Display
    // ==================================================

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - AAT Issuance"
    );

    console.log(
        "============================================"
    );


    console.log(
        "Purpose:",
        aat.purpose
    );


    console.log(
        "Domain ID:",
        aat.D_id
    );


    console.log(
        "Scheme ID:",
        aat.scheme_id
    );


    console.log(
        "Nonce:",
        aat.nonce
    );


    console.log(
        "Issued at:",
        aat.issued_at
    );


    console.log(
        "Expires at:",
        aat.expires_at
    );


    console.log(
        "Validity:",
        `${config.aat.validitySeconds} seconds`
    );


    console.log(
        "Key ID:",
        aat.key_id
    );


    console.log(
        "Signature bytes:",
        signatureResult
            .report
            .signature_bytes
    );


    console.log(
        "FROST signature valid:",
        verification.valid
    );


    console.log(
        "AAT nullifier:"
    );

    console.log(
        nullifier
    );


    console.log(
        "FROST signing time:",
        signatureResult
            .report
            .timing
            .total_ms
            .toFixed(3),
        "ms"
    );


    console.log("");

    console.log(
        "AAT artifact:"
    );

    console.log(
        aatFile
    );


    console.log("");

    console.log(
        "Experiment report:"
    );

    console.log(
        reportFile
    );


    console.log(
        "============================================"
    );


    return {
        aat,
        nullifier,
        verification,
        aatFile,
        reportFile
    };
}


// ======================================================
// Verify AAT
// ======================================================

function verifyAAT(
    aat,
    options = {}
) {

    const {
        checkTime = true,
        now = new Date()
    } = options;


    try {

        // ------------------------------------------------
        // Basic structure
        // ------------------------------------------------

        const requiredFields = [
            "D_id",
            "scheme_id",
            "purpose",
            "nonce",
            "issued_at",
            "expires_at",
            "key_id",
            "signature"
        ];


        for (
            const field of requiredFields
        ) {

            if (
                aat[field] === undefined ||
                aat[field] === null
            ) {

                return {
                    valid: false,
                    reason:
                        `Missing AAT field: ${field}`
                };
            }
        }


        // ------------------------------------------------
        // Domain binding
        // ------------------------------------------------

        if (
            aat.D_id !==
            config.domain.domainId
        ) {

            return {
                valid: false,
                reason:
                    "AAT domain mismatch."
            };
        }


        // ------------------------------------------------
        // Scheme binding
        // ------------------------------------------------

        if (
            aat.scheme_id !==
            config.protocol.schemeId
        ) {

            return {
                valid: false,
                reason:
                    "AAT scheme_id mismatch."
            };
        }


        // ------------------------------------------------
        // Purpose binding
        // ------------------------------------------------

        if (
            aat.purpose !==
            config.aat.purpose
        ) {

            return {
                valid: false,
                reason:
                    "Invalid AAT purpose."
            };
        }


        // ------------------------------------------------
        // Active threshold key
        // ------------------------------------------------

        const frostSetup =
            loadFrostSetup();


        if (
            aat.key_id !==
            frostSetup.key_id
        ) {

            return {
                valid: false,
                reason:
                    "AAT key_id does not match the active threshold key."
            };
        }


        // ------------------------------------------------
        // Nonce format
        // ------------------------------------------------

        if (
            typeof aat.nonce !==
                "string" ||
            !/^[0-9a-f]{64}$/i.test(
                aat.nonce
            )
        ) {

            return {
                valid: false,
                reason:
                    "Invalid AAT nonce."
            };
        }


        // ------------------------------------------------
        // Time validity
        // ------------------------------------------------

        const issuedAt =
            new Date(
                aat.issued_at
            );


        const expiresAt =
            new Date(
                aat.expires_at
            );


        if (
            Number.isNaN(
                issuedAt.getTime()
            ) ||
            Number.isNaN(
                expiresAt.getTime()
            )
        ) {

            return {
                valid: false,
                reason:
                    "Invalid AAT timestamp."
            };
        }


        if (
            expiresAt <=
            issuedAt
        ) {

            return {
                valid: false,
                reason:
                    "AAT expiration must be after issuance."
            };
        }


        if (
            checkTime
        ) {

            if (
                now <
                issuedAt
            ) {

                return {
                    valid: false,
                    reason:
                        "AAT is not valid yet."
                };
            }


            if (
                now >
                expiresAt
            ) {

                return {
                    valid: false,
                    reason:
                        "AAT has expired."
                };
            }
        }


        // ------------------------------------------------
        // Reconstruct signed payload
        // ------------------------------------------------

        const payload =
            createAATPayload(
                aat
            );


        const messageDigest =
            sha256(
                Buffer.from(
                    payload,
                    "utf8"
                )
            );


        // ------------------------------------------------
        // FROST signature verification
        // ------------------------------------------------

        const signatureValid =
            verifyMessage(
                messageDigest,
                aat.signature
            );


        if (
            !signatureValid
        ) {

            return {
                valid: false,
                reason:
                    "Invalid FROST threshold signature."
            };
        }


        return {

            valid: true,

            reason:
                "AAT is valid.",

            nullifier:
                computeAATNullifier(
                    aat
                )
        };


    } catch (error) {

        return {

            valid: false,

            reason:
                error.message
        };
    }
}


// ======================================================
// CLI
// ======================================================

function main() {

    const command =
        process.argv[2] ||
        "issue";


    if (
        command === "issue"
    ) {

        issueAAT();
        return;
    }


    if (
        command === "verify"
    ) {

        const inputFile =
            process.argv[3];


        if (!inputFile) {

            throw new Error(
                "Usage: node src\\aat.js verify <aat-file>"
            );
        }


        const resolvedFile =
            path.resolve(
                inputFile
            );


        const aat =
            JSON.parse(
                fs.readFileSync(
                    resolvedFile,
                    "utf8"
                )
            );


        const result =
            verifyAAT(
                aat
            );


        console.log(
            "============================================"
        );

        console.log(
            " Thesis Protocol - AAT Verification"
        );

        console.log(
            "============================================"
        );


        console.log(
            "Valid:",
            result.valid
        );


        console.log(
            "Reason:",
            result.reason
        );


        if (
            result.nullifier
        ) {

            console.log(
                "Nullifier:"
            );

            console.log(
                result.nullifier
            );
        }


        console.log(
            "============================================"
        );


        if (
            !result.valid
        ) {

            process.exit(1);
        }

        return;
    }


    throw new Error(
        `Unknown command: ${command}`
    );
}


if (
    require.main === module
) {

    try {

        main();

    } catch (error) {

        console.error("");

        console.error(
            "AAT operation failed:"
        );

        console.error(
            error.message
        );

        process.exit(1);
    }
}


module.exports = {
    createAATPayload,
    computeAATNullifier,
    issueAAT,
    verifyAAT
};