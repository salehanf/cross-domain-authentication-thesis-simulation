const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const config = require("./config");

const {
    verifyMessage,
    signMessage
} = require("./frost");

const {
    createSparseMerkleTree
} = require("./smt");

const {
    createRootPayload,
    createSignedRootCanonical,
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


function sha256Hex(data) {

    return crypto
        .createHash("sha256")
        .update(data)
        .digest("hex");
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

async function main() {

    const enrollmentId =
        process.argv[2];


    if (!enrollmentId) {

        throw new Error(
            "Usage: node src\\bas-apply-revocation.js <enrollment-id>"
        );
    }


    const totalStart =
        process.hrtime.bigint();


    const projectRoot =
        config.paths.projectRoot;


    const depth =
        config.smt?.depth ??
        config.protocol?.smt?.depth;


    if (
        !Number.isInteger(depth) ||
        depth <= 0
    ) {

        throw new Error(
            "SMT depth not found in config."
        );
    }


    // ==================================================
    // Paths
    // ==================================================

    const revokeMessageFile =
        path.join(
            projectRoot,
            "artifacts",
            "revocation",
            enrollmentId,
            "revoke_message.json"
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


    const reportFile =
        path.join(
            projectRoot,
            "results",
            "revocation",
            enrollmentId,
            "bas_revocation_report.json"
        );


    // ==================================================
    // Load state
    // ==================================================

    const revokeMessage =
        loadJson(
            revokeMessageFile
        );


    const registry =
        loadJson(
            registryFile
        );


    const latest =
        getLatestSignedRoot(
            rootsDir
        );


    const previousSignedRoot =
        latest.data;


    // ==================================================
    // 1. Verify current SignedRoot itself
    // ==================================================

    const previousRootValid =
        await verifySignedRoot(
            previousSignedRoot
        );


    if (!previousRootValid) {

        throw new Error(
            "Current SignedRoot signature INVALID."
        );
    }


    // ==================================================
    // 2. Revoke_Message structure
    // ==================================================

    const requiredFields = [

        "D_id",
        "scheme_id",
        "y_hash",
        "reason_code",
        "version",
        "timestamp",
        "key_id",
        "signature"
    ];


    for (
        const field
        of requiredFields
    ) {

        if (
            revokeMessage[field] ===
            undefined
        ) {

            throw new Error(
                `Revoke_Message missing field: ${field}`
            );
        }
    }


    // ==================================================
    // 3. Domain / scheme / key binding
    // ==================================================

    if (
        String(
            revokeMessage.D_id
        ) !==
        String(
            previousSignedRoot.D_id
        )
    ) {

        throw new Error(
            "Revoke_Message D_id mismatch."
        );
    }


    if (
        String(
            revokeMessage.scheme_id
        ) !==
        String(
            previousSignedRoot.scheme_id
        )
    ) {

        throw new Error(
            "Revoke_Message scheme_id mismatch."
        );
    }


    if (
        String(
            revokeMessage.key_id
        ) !==
        String(
            previousSignedRoot.key_id
        )
    ) {

        throw new Error(
            "Revoke_Message key_id mismatch."
        );
    }


    // ==================================================
    // 4. Expected root version
    //
    // Revoke_Message version means:
    // "apply only while this is current state".
    // ==================================================

    if (
        Number(
            revokeMessage.version
        ) !==
        Number(
            previousSignedRoot.version
        )
    ) {

        throw new Error(
            `Stale or future Revoke_Message version. Message v${revokeMessage.version}, current v${previousSignedRoot.version}.`
        );
    }


    // ==================================================
    // 5. Timestamp consistency
    //
    // Thesis specifies timestamp but does not prescribe
    // a fixed freshness window.
    //
    // Prototype policy here:
    // - syntactically valid timestamp
    // - must not predate current SignedRoot
    // - small future clock skew tolerated
    // ==================================================

    const revokeTime =
        Date.parse(
            revokeMessage.timestamp
        );


    const rootTime =
        Date.parse(
            previousSignedRoot.timestamp
        );


    const now =
        Date.now();


    if (
        !Number.isFinite(
            revokeTime
        )
    ) {

        throw new Error(
            "Invalid Revoke_Message timestamp."
        );
    }


    if (
        Number.isFinite(rootTime) &&
        revokeTime < rootTime
    ) {

        throw new Error(
            "Revoke_Message predates current SignedRoot."
        );
    }


    const allowedFutureSkewMs =
        60 * 1000;


    if (
        revokeTime >
        now + allowedFutureSkewMs
    ) {

        throw new Error(
            "Revoke_Message timestamp is too far in the future."
        );
    }


    // ==================================================
    // 6. Rebuild exact FROST signing statement
    // ==================================================

    const signingStatement = [

        "REVOKE",

        String(
            revokeMessage.D_id
        ),

        String(
            revokeMessage.scheme_id
        ),

        String(
            revokeMessage.y_hash
        ),

        String(
            revokeMessage.reason_code
        ),

        String(
            revokeMessage.version
        ),

        String(
            revokeMessage.timestamp
        ),

        String(
            revokeMessage.key_id
        )
    ];


    const revokeDigest =
        sha256Buffer(
            Buffer.from(
                canonicalJson(
                    signingStatement
                ),
                "utf8"
            )
        );


    // ==================================================
    // 7. Verify FROST threshold signature
    // ==================================================

    const revokeVerifyStart =
        process.hrtime.bigint();


    const revokeSignatureResult =
        verifyMessage(
            revokeDigest,
            revokeMessage.signature
        );


    const revokeVerifyMs =
        Number(
            process.hrtime.bigint() -
            revokeVerifyStart
        ) / 1e6;


    if (
        !verificationSucceeded(
            revokeSignatureResult
        )
    ) {

        throw new Error(
            "Revoke_Message FROST signature INVALID."
        );
    }


    // ==================================================
    // 8. BAS y_hash lookup
    // ==================================================

    if (
        !registry.entries ||
        typeof registry.entries !==
            "object"
    ) {

        throw new Error(
            "Invalid BAS registry."
        );
    }


    const yHash =
        String(
            revokeMessage.y_hash
        );


    const target =
        registry.entries[
            yHash
        ];


    if (!target) {

        throw new Error(
            "No BAS record found for y_hash."
        );
    }


    if (
        String(
            target.status
        ).toLowerCase() !==
        "active"
    ) {

        throw new Error(
            `Revocation target is not active. Current status: ${target.status}`
        );
    }


    if (
        Number(
            target.version
        ) !==
        Number(
            previousSignedRoot.version
        )
    ) {

        throw new Error(
            "Target record version does not match current root version."
        );
    }


    const targetIdx =
        Number(
            target.idx
        );


    if (
        !Number.isSafeInteger(
            targetIdx
        )
    ) {

        throw new Error(
            "Invalid target SMT index."
        );
    }


    // ==================================================
    // 9. Reconstruct current SMT from ACTIVE registry
    // ==================================================

    const treeStart =
        process.hrtime.bigint();


    const tree =
        await createSparseMerkleTree(
            depth
        );


    const activeEntries =
        Object.values(
            registry.entries
        ).filter(
            entry =>
                String(
                    entry.status
                ).toLowerCase() ===
                "active"
        );


    for (
        const entry
        of activeEntries
    ) {

        tree.insert(
            Number(
                entry.idx
            ),

            BigInt(
                entry.L
            )
        );
    }


    const reconstructedRoot =
        tree.getRootString();


    if (
        String(
            reconstructedRoot
        ) !==
        String(
            previousSignedRoot.root
        )
    ) {

        throw new Error(
            "Reconstructed SMT root does not match current SignedRoot."
        );
    }


    const leafBefore =
        tree.getLeaf(
            targetIdx
        );


    if (
        BigInt(
            leafBefore
        ) !==
        BigInt(
            target.L
        )
    ) {

        throw new Error(
            "Target leaf does not match BAS registry record."
        );
    }


    const treeReconstructionMs =
        Number(
            process.hrtime.bigint() -
            treeStart
        ) / 1e6;


    // ==================================================
    // 10. Apply revocation IN MEMORY
    //
    // Nothing persisted yet.
    // ==================================================

    const removeStart =
        process.hrtime.bigint();


    tree.remove(
        targetIdx
    );


    const newRoot =
        tree.getRootString();


    const removeMs =
        Number(
            process.hrtime.bigint() -
            removeStart
        ) / 1e6;


    if (
        String(
            newRoot
        ) ===
        String(
            previousSignedRoot.root
        )
    ) {

        throw new Error(
            "SMT root did not change after revocation."
        );
    }


    // Since this experiment currently has exactly one
    // active member, revocation should return the tree
    // to its empty root.
    let emptyRootSanity =
        null;


    if (
        activeEntries.length === 1
    ) {

        const emptyRoot =
            tree.getEmptyRoot();


        emptyRootSanity =
            String(
                newRoot
            ) ===
            String(
                emptyRoot
            );


        if (
            !emptyRootSanity
        ) {

            throw new Error(
                "Single-member revocation did not restore SMT empty root."
            );
        }
    }


    // ==================================================
    // 11. Prepare new registry IN MEMORY
    // ==================================================

    const newRegistry =
        JSON.parse(
            JSON.stringify(
                registry
            )
        );


    newRegistry
        .entries[
            yHash
        ]
        .status =
            "revoked";


    const newVersion =
        Number(
            previousSignedRoot.version
        ) + 1;


    newRegistry
        .entries[
            yHash
        ]
        .version =
            newVersion;


    // ==================================================
    // 12. prev_hash = H(SignedRoot_previous)
    // ==================================================

    const previousRootHash =
        sha256Hex(
            Buffer.from(
                createSignedRootCanonical(
                    previousSignedRoot
                ),
                "utf8"
            )
        );


    // ==================================================
    // 13. Create SignedRoot v2
    // ==================================================

    const newSignedRoot = {

        D_id:
            previousSignedRoot.D_id,

        scheme_id:
            previousSignedRoot.scheme_id,

        root:
            newRoot,

        version:
            newVersion,

        timestamp:
            new Date()
                .toISOString(),

        prev_hash:
            previousRootHash,

        key_id:
            previousSignedRoot.key_id,

        signature:
            null
    };


    const rootPayload =
        createRootPayload(
            newSignedRoot
        );


    const rootDigest =
        sha256Buffer(
            Buffer.from(
                rootPayload,
                "utf8"
            )
        );


    // ==================================================
    // 14. FROST-sign new SignedRoot
    // ==================================================

    const rootSignStart =
        process.hrtime.bigint();


    const signatureResult =
        await signMessage(
            rootDigest,
            `signed_root_v${newVersion}`
        );


    const rootSignMs =
        Number(
            process.hrtime.bigint() -
            rootSignStart
        ) / 1e6;


    if (
        !signatureResult ||
        !signatureResult.signatureHex
    ) {

        throw new Error(
            "FROST did not produce new SignedRoot signature."
        );
    }


    newSignedRoot.signature =
        signatureResult.signatureHex;


    // ==================================================
    // 15. Verify SignedRoot BEFORE persistence
    // ==================================================

    const rootVerifyStart =
        process.hrtime.bigint();


    const newRootValid =
        await verifySignedRoot(
            newSignedRoot
        );


    const rootVerifyMs =
        Number(
            process.hrtime.bigint() -
            rootVerifyStart
        ) / 1e6;


    if (!newRootValid) {

        throw new Error(
            "New SignedRoot failed verification."
        );
    }


    // ==================================================
    // 16. Final consistency checks BEFORE COMMIT
    // ==================================================

    const rootFile =
        path.join(
            rootsDir,
            `signed_root_v${newVersion}.json`
        );


    if (
        fs.existsSync(
            rootFile
        )
    ) {

        throw new Error(
            `SignedRoot v${newVersion} already exists. Refusing to overwrite.`
        );
    }


    if (
        newRegistry
            .entries[
                yHash
            ]
            .status !==
        "revoked"
    ) {

        throw new Error(
            "Internal registry transition failed."
        );
    }


    // ==================================================
    // 17. Commit state
    //
    // All protocol/security checks are finished before
    // this point.
    // ==================================================

    const commitStart =
        process.hrtime.bigint();


    const tempRegistryFile =
        registryFile +
        ".revocation.tmp";


    const tempRootFile =
        rootFile +
        ".tmp";


    saveJson(
        tempRegistryFile,
        newRegistry
    );


    saveJson(
        tempRootFile,
        newSignedRoot
    );


    // Re-read temp files before committing.
    const tempRegistryCheck =
        loadJson(
            tempRegistryFile
        );


    const tempRootCheck =
        loadJson(
            tempRootFile
        );


    if (
        tempRegistryCheck
            .entries[
                yHash
            ]
            .status !==
        "revoked"
    ) {

        throw new Error(
            "Temporary registry verification failed."
        );
    }


    if (
        Number(
            tempRootCheck.version
        ) !==
        newVersion
    ) {

        throw new Error(
            "Temporary SignedRoot verification failed."
        );
    }


    // Save backup of current BAS registry for rollback.
    const originalRegistryBytes =
        fs.readFileSync(
            registryFile
        );


    let rootCommitted =
        false;


    try {

        // SignedRoot v2 is a new file.
        fs.renameSync(
            tempRootFile,
            rootFile
        );


        rootCommitted =
            true;


        // Replace registry only after root file exists.
        fs.writeFileSync(
            registryFile,
            fs.readFileSync(
                tempRegistryFile
            )
        );


        fs.rmSync(
            tempRegistryFile,
            {
                force: true
            }
        );

    } catch (error) {

        // Best-effort rollback.
        fs.writeFileSync(
            registryFile,
            originalRegistryBytes
        );


        if (
            rootCommitted &&
            fs.existsSync(
                rootFile
            )
        ) {

            fs.rmSync(
                rootFile,
                {
                    force: true
                }
            );
        }


        fs.rmSync(
            tempRegistryFile,
            {
                force: true
            }
        );


        fs.rmSync(
            tempRootFile,
            {
                force: true
            }
        );


        throw new Error(
            `State commit failed and rollback was attempted: ${error.message}`
        );
    }


    const commitMs =
        Number(
            process.hrtime.bigint() -
            commitStart
        ) / 1e6;


    // ==================================================
    // 18. Post-commit verification
    // ==================================================

    const persistedRegistry =
        loadJson(
            registryFile
        );


    const persistedRoot =
        loadJson(
            rootFile
        );


    if (
        persistedRegistry
            .entries[
                yHash
            ]
            .status !==
        "revoked"
    ) {

        throw new Error(
            "Post-commit BAS registry verification failed."
        );
    }


    if (
        Number(
            persistedRegistry
                .entries[
                    yHash
                ]
                .version
        ) !==
        newVersion
    ) {

        throw new Error(
            "Post-commit BAS registry version verification failed."
        );
    }


    const persistedRootValid =
        await verifySignedRoot(
            persistedRoot
        );


    if (!persistedRootValid) {

        throw new Error(
            "Persisted SignedRoot verification failed."
        );
    }


    // ==================================================
    // 19. Report
    // ==================================================

    const totalMs =
        Number(
            process.hrtime.bigint() -
            totalStart
        ) / 1e6;


    const report = {

        enrollment_id:
            enrollmentId,

        y_hash:
            yHash,

        reason_code:
            revokeMessage.reason_code,

        D_id:
            String(
                revokeMessage.D_id
            ),

        scheme_id:
            String(
                revokeMessage.scheme_id
            ),

        revoke_message: {

            expected_version:
                Number(
                    revokeMessage.version
                ),

            key_id:
                revokeMessage.key_id,

            threshold_signature_valid:
                true,

            timestamp_valid:
                true
        },

        smt: {

            depth:
                depth,

            idx:
                String(
                    target.idx
                ),

            old_root:
                String(
                    previousSignedRoot.root
                ),

            new_root:
                String(
                    newRoot
                ),

            root_changed:
                true,

            single_active_leaf_before:
                activeEntries.length === 1,

            empty_root_after:
                emptyRootSanity
        },

        bas_registry: {

            old_status:
                "active",

            new_status:
                "revoked",

            old_version:
                Number(
                    previousSignedRoot.version
                ),

            new_version:
                newVersion
        },

        signed_root: {

            previous_version:
                Number(
                    previousSignedRoot.version
                ),

            new_version:
                newVersion,

            prev_hash:
                previousRootHash,

            signature_valid:
                true
        },

        revocation_result:
            "ACCEPT",

        timings_ms: {

            revoke_signature_verify:
                revokeVerifyMs,

            smt_reconstruction:
                treeReconstructionMs,

            smt_remove:
                removeMs,

            new_root_frost_sign:
                rootSignMs,

            new_root_signature_verify:
                rootVerifyMs,

            state_commit:
                commitMs,

            total:
                totalMs
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
        " Thesis Protocol - BAS Revocation"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Enrollment ID       : ${enrollmentId}`
    );

    console.log(
        `y_hash lookup       : FOUND`
    );

    console.log(
        `Target idx          : ${target.idx}`
    );

    console.log(
        `Target status       : active`
    );

    console.log("");

    console.log(
        "Current SignedRoot:"
    );

    console.log(
        `Version             : v${previousSignedRoot.version}`
    );

    console.log(
        "Signature           : VALID"
    );

    console.log("");

    console.log(
        "Revoke_Message:"
    );

    console.log(
        "Domain/scheme       : VALID"
    );

    console.log(
        "Version binding     : VALID"
    );

    console.log(
        "Timestamp           : VALID"
    );

    console.log(
        "Key ID              : VALID"
    );

    console.log(
        "FROST signature     : VALID"
    );

    console.log("");

    console.log(
        "Current SMT reconstruction : VALID"
    );

    console.log(
        "Target leaf                : MATCH"
    );

    console.log(
        "SMT remove                 : SUCCESS"
    );

    console.log("");

    console.log(
        `Old root            : ${previousSignedRoot.root}`
    );

    console.log(
        `New root            : ${newRoot}`
    );


    if (
        emptyRootSanity !== null
    ) {

        console.log(
            `Empty-root sanity   : ${emptyRootSanity ? "VALID" : "INVALID"}`
        );
    }


    console.log("");

    console.log(
        `BAS status          : active -> revoked`
    );

    console.log(
        `Root version        : v${previousSignedRoot.version} -> v${newVersion}`
    );

    console.log(
        `SignedRoot v${newVersion}       : VALID`
    );

    console.log("");

    console.log(
        "--------------------------------------------"
    );

    console.log(
        "REVOCATION RESULT: ACCEPT"
    );

    console.log(
        "--------------------------------------------"
    );

    console.log("");

    console.log(
        `Revoke signature verify : ${revokeVerifyMs.toFixed(3)} ms`
    );

    console.log(
        `SMT reconstruction      : ${treeReconstructionMs.toFixed(3)} ms`
    );

    console.log(
        `SMT remove              : ${removeMs.toFixed(3)} ms`
    );

    console.log(
        `New root FROST sign     : ${rootSignMs.toFixed(3)} ms`
    );

    console.log(
        `New root verify         : ${rootVerifyMs.toFixed(3)} ms`
    );

    console.log(
        `Total BAS revocation    : ${totalMs.toFixed(3)} ms`
    );

    console.log("");

    console.log(
        "New SignedRoot:"
    );

    console.log(
        rootFile
    );

    console.log("");

    console.log(
        "BAS registry:"
    );

    console.log(
        registryFile
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
}


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
            "BAS REVOCATION: REJECT"
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