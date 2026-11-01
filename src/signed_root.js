const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const config =
    require("./config");

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
// Canonical ROOT signing payload
//
// Implements:
//
// H(
//   "ROOT" ||
//   D_id ||
//   scheme_id ||
//   root ||
//   version ||
//   timestamp ||
//   prev_hash ||
//   key_id
// )
// ======================================================

function createRootPayload(
    signedRoot
) {

    /*
        Fixed-position JSON array is used instead of
        a JavaScript object so field ordering is
        unambiguous and reproducible.
    */

    return JSON.stringify([
        "ROOT",

        String(
            signedRoot.D_id
        ),

        String(
            signedRoot.scheme_id
        ),

        String(
            signedRoot.root
        ),

        String(
            signedRoot.version
        ),

        String(
            signedRoot.timestamp
        ),

        String(
            signedRoot.prev_hash
        ),

        String(
            signedRoot.key_id
        )
    ]);
}


// ======================================================
// Canonical complete SignedRoot
//
// Used later for:
//
// prev_hash_new = H(SignedRoot_prev)
// ======================================================

function createSignedRootCanonical(
    signedRoot
) {

    return JSON.stringify([
        String(
            signedRoot.D_id
        ),

        String(
            signedRoot.scheme_id
        ),

        String(
            signedRoot.root
        ),

        String(
            signedRoot.version
        ),

        String(
            signedRoot.timestamp
        ),

        String(
            signedRoot.prev_hash
        ),

        String(
            signedRoot.key_id
        ),

        String(
            signedRoot.signature
        )
    ]);
}


// ======================================================
// Verify SignedRoot
// ======================================================

function verifySignedRoot(
    signedRoot
) {

    const payload =
        createRootPayload(
            signedRoot
        );


    const digest =
        sha256(
            Buffer.from(
                payload,
                "utf8"
            )
        );


    return verifyMessage(
        digest,
        signedRoot.signature
    );
}


// ======================================================
// Initial SignedRoot
// ======================================================

function createInitialSignedRoot() {

    const systemSetupFile =
        path.join(
            projectRoot,
            "results",
            "system_setup.json"
        );


    const frostSetupFile =
        path.join(
            projectRoot,
            "results",
            "frost_setup.json"
        );


    if (
        !fs.existsSync(
            systemSetupFile
        )
    ) {

        throw new Error(
            "system_setup.json was not found."
        );
    }


    if (
        !fs.existsSync(
            frostSetupFile
        )
    ) {

        throw new Error(
            "frost_setup.json was not found."
        );
    }


    const systemSetup =
        JSON.parse(
            fs.readFileSync(
                systemSetupFile,
                "utf8"
            )
        );


    const frostSetup =
        JSON.parse(
            fs.readFileSync(
                frostSetupFile,
                "utf8"
            )
        );


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
            "FROST threshold parameters do not match config.js."
        );
    }


    const root =
        systemSetup
            .state
            .smt
            .root;


    /*
        Laboratory convention:

        initial root version = 0
        initial prev_hash = 256 zero bits
    */

    const version =
        0;


    const prevHash =
        "0".repeat(64);


    const timestamp =
        new Date()
            .toISOString();


    const unsignedRoot = {

        D_id:
            config.domain.domainId,

        scheme_id:
            config.protocol.schemeId,

        root,

        version,

        timestamp,

        prev_hash:
            prevHash,

        key_id:
            frostSetup.key_id
    };


    // --------------------------------------------------
    // Canonical payload
    // --------------------------------------------------

    const payload =
        createRootPayload(
            unsignedRoot
        );


    const payloadBuffer =
        Buffer.from(
            payload,
            "utf8"
        );


    /*
        Empirical instantiation of:

        H("ROOT" || ...)

        using SHA-256.
    */

    const messageDigest =
        sha256(
            payloadBuffer
        );


    // --------------------------------------------------
    // 3-of-5 FROST signature
    // --------------------------------------------------

    const signatureResult =
        signMessage(
            messageDigest,
            "signed_root_v0"
        );


    const signedRoot = {

        ...unsignedRoot,

        signature:
            signatureResult
                .signatureHex
    };


    // --------------------------------------------------
    // Verify final SignedRoot
    // --------------------------------------------------

    const signatureValid =
        verifySignedRoot(
            signedRoot
        );


    if (!signatureValid) {

        throw new Error(
            "Initial SignedRoot verification failed."
        );
    }


    // --------------------------------------------------
    // Compute hash for future version chaining
    // --------------------------------------------------

    const canonicalSignedRoot =
        createSignedRootCanonical(
            signedRoot
        );


    const signedRootHash =
        sha256(
            Buffer.from(
                canonicalSignedRoot,
                "utf8"
            )
        )
        .toString(
            "hex"
        );


    // --------------------------------------------------
    // Save
    // --------------------------------------------------

    const rootsDir =
        path.join(
            projectRoot,
            "state",
            "roots"
        );


    fs.mkdirSync(
        rootsDir,
        {
            recursive: true
        }
    );


    const rootFile =
        path.join(
            rootsDir,
            "signed_root_v0.json"
        );


    const hashFile =
        path.join(
            rootsDir,
            "signed_root_v0.hash"
        );


    const payloadFile =
        path.join(
            rootsDir,
            "signed_root_v0.payload.json"
        );


    fs.writeFileSync(
        rootFile,

        JSON.stringify(
            signedRoot,
            null,
            2
        )
    );


    fs.writeFileSync(
        hashFile,
        signedRootHash
    );


    fs.writeFileSync(
        payloadFile,
        JSON.stringify(
            JSON.parse(
                payload
            ),
            null,
            2
        )
    );


    // --------------------------------------------------
    // Display
    // --------------------------------------------------

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - Initial SignedRoot"
    );

    console.log(
        "============================================"
    );


    console.log(
        "Version:",
        signedRoot.version
    );


    console.log(
        "Root:",
        signedRoot.root
    );


    console.log(
        "Previous hash:",
        signedRoot.prev_hash
    );


    console.log(
        "Key ID:",
        signedRoot.key_id
    );


    console.log(
        "Signature bytes:",
        signatureResult
            .report
            .signature_bytes
    );


    console.log(
        "FROST signature valid:",
        signatureValid
    );


    console.log(
        "SignedRoot hash:",
        signedRootHash
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
        "Saved:",
        rootFile
    );


    console.log(
        "============================================"
    );


    return signedRoot;
}


if (
    require.main === module
) {

    try {

        createInitialSignedRoot();

    } catch (error) {

        console.error(
            "SignedRoot creation failed:"
        );

        console.error(
            error
        );

        process.exit(1);
    }
}


module.exports = {
    createRootPayload,
    createSignedRootCanonical,
    verifySignedRoot,
    createInitialSignedRoot
};