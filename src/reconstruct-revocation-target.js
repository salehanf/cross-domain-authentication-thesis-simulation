const fs = require("fs");
const path = require("path");

const {
    buildBabyjub,
    buildPoseidon
} = require("circomlibjs");

const config = require("./config");


// ======================================================
// BabyJub prime-order subgroup order
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


function mod(value, modulus) {

    const r =
        value % modulus;

    return (
        r >= 0n
            ? r
            : r + modulus
    );
}


function modPow(
    base,
    exponent,
    modulus
) {

    let result =
        1n;

    let b =
        mod(
            base,
            modulus
        );

    let e =
        exponent;


    while (e > 0n) {

        if (e & 1n) {

            result =
                mod(
                    result * b,
                    modulus
                );
        }


        b =
            mod(
                b * b,
                modulus
            );


        e >>= 1n;
    }


    return result;
}


function modInverse(
    value,
    modulus
) {

    const v =
        mod(
            value,
            modulus
        );


    if (v === 0n) {

        throw new Error(
            "Attempted modular inverse of zero."
        );
    }


    // BABYJUB_Q is prime.
    return modPow(
        v,
        modulus - 2n,
        modulus
    );
}


function pointFromJson(
    point,
    F
) {

    return [

        F.e(
            BigInt(
                point.x
            )
        ),

        F.e(
            BigInt(
                point.y
            )
        )
    ];
}


function pointToBigints(
    point,
    F
) {

    return {

        x:
            BigInt(
                F.toString(
                    point[0]
                )
            ),

        y:
            BigInt(
                F.toString(
                    point[1]
                )
            )
    };
}


// ======================================================
// Lagrange interpolation at x = 0
//
// secret = sum(
//     y_i * product(
//         -x_j / (x_i - x_j)
//     )
// )
//
// All arithmetic is mod q.
// ======================================================

function reconstructAtZero(
    shares,
    q
) {

    let secret =
        0n;


    for (
        let i = 0;
        i < shares.length;
        i++
    ) {

        const xi =
            BigInt(
                shares[i].x
            );

        const yi =
            BigInt(
                shares[i].y
            );


        let numerator =
            1n;

        let denominator =
            1n;


        for (
            let j = 0;
            j < shares.length;
            j++
        ) {

            if (i === j) {
                continue;
            }


            const xj =
                BigInt(
                    shares[j].x
                );


            numerator =
                mod(
                    numerator *
                    (-xj),
                    q
                );


            denominator =
                mod(
                    denominator *
                    (xi - xj),
                    q
                );
        }


        const lambda =
            mod(
                numerator *
                modInverse(
                    denominator,
                    q
                ),
                q
            );


        secret =
            mod(
                secret +
                yi * lambda,
                q
            );
    }


    return secret;
}


// ======================================================
// Main
// ======================================================

async function main() {

    const enrollmentId =
        process.argv[2];


    if (!enrollmentId) {

        throw new Error(
            "Usage: node src\\reconstruct-revocation-target.js <enrollment-id> [--source pvss|current] [--admins 1,2,3]"
        );
    }


    // ==================================================
    // CLI options
    //
    // Backward-compatible:
    // node ... <id> 1 2 3
    //
    // New:
    // node ... <id> --source current --admins 1,2,3
    // ==================================================

    const cliArgs =
        process.argv.slice(3);


    let shareSource =
        "pvss";


    let requestedAdminIds =
        [];


    for (
        let i = 0;
        i < cliArgs.length;
        i++
    ) {

        const arg =
            cliArgs[i];


        if (arg === "--source") {

            if (
                i + 1 >=
                cliArgs.length
            ) {

                throw new Error(
                    "--source requires pvss or current."
                );
            }


            shareSource =
                String(
                    cliArgs[++i]
                )
                    .trim()
                    .toLowerCase();


            continue;
        }


        if (arg === "--admins") {

            if (
                i + 1 >=
                cliArgs.length
            ) {

                throw new Error(
                    "--admins requires a comma-separated list."
                );
            }


            requestedAdminIds =
                String(
                    cliArgs[++i]
                )
                    .split(",")
                    .filter(
                        value =>
                            value.trim() !==
                            ""
                    )
                    .map(
                        value =>
                            Number(
                                value.trim()
                            )
                    );


            continue;
        }


        // Backward-compatible positional admin IDs.
        if (/^\d+$/.test(arg)) {

            requestedAdminIds.push(
                Number(
                    arg
                )
            );

            continue;
        }


        throw new Error(
            `Unknown argument: ${arg}`
        );
    }


    if (
        shareSource !== "pvss" &&
        shareSource !== "current"
    ) {

        throw new Error(
            "--source must be pvss or current."
        );
    }


    const projectRoot =
        config.paths.projectRoot;


    // ==================================================
    // Tags
    // ==================================================

    const tags =
        config.protocol?.tags ??
        config.tags;


    if (!tags) {

        throw new Error(
            "Protocol tags not found in config."
        );
    }


    if (
        tags.pvssMask === undefined ||
        tags.pvssCipherTag === undefined ||
        tags.revoke === undefined
    ) {

        throw new Error(
            "Required protocol tags are missing."
        );
    }


    // ==================================================
    // Paths
    // ==================================================

    const pvssDataFile =
        path.join(
            projectRoot,
            "artifacts",
            "enrollment",
            enrollmentId,
            "pvss_data.json"
        );


    const witnessFile =
        path.join(
            projectRoot,
            "private",
            "users",
            enrollmentId,
            "pvss_witness.json"
        );


    const registryFile =
        path.join(
            projectRoot,
            "state",
            "bas",
            "enrollment_registry.json"
        );


    const currentShareDir =
        path.join(
            projectRoot,
            "private",
            "admin_shares",
            enrollmentId
        );


    const reportFile =
        path.join(
            projectRoot,
            "results",
            "revocation",
            enrollmentId,
            "threshold_reconstruction_report.json"
        );


    // ==================================================
    // Load public PVSS and BAS state
    // ==================================================

    const pvssData =
        loadJson(
            pvssDataFile
        );


    const registry =
        loadJson(
            registryFile
        );


    // Witness is used ONLY as a laboratory correctness
    // oracle. Its secrets are never written to output.
    const witness =
        loadJson(
            witnessFile
        );


    // ==================================================
    // Basic PVSS consistency
    // ==================================================

    const n =
        Number(
            pvssData.threshold.n
        );


    const t =
        Number(
            pvssData.threshold.t
        );


    if (
        !Number.isInteger(n) ||
        !Number.isInteger(t) ||
        t < 1 ||
        t > n
    ) {

        throw new Error(
            "Invalid PVSS threshold configuration."
        );
    }


    if (
        pvssData.encryption?.construction !==
        "ECDH-Poseidon-field-mask"
    ) {

        throw new Error(
            "Unexpected PVSS encryption construction."
        );
    }


    if (
        pvssData.encrypted_shares.length !==
        n
    ) {

        throw new Error(
            "Encrypted-share count does not match n."
        );
    }


    const domainId =
        BigInt(
            pvssData.D_id
        );


    const schemeId =
        BigInt(
            pvssData.scheme_id
        );


    if (
        String(witness.D_id) !==
            String(pvssData.D_id) ||
        String(witness.scheme_id) !==
            String(pvssData.scheme_id)
    ) {

        throw new Error(
            "PVSS witness domain/scheme mismatch."
        );
    }


    // ==================================================
    // Participating admins
    // ==================================================

    let adminIds =
        [...requestedAdminIds];


    if (
        adminIds.length === 0
    ) {

        if (shareSource === "current") {

            adminIds =
                Array.from(
                    { length: n },
                    (_, index) =>
                        index + 1
                )
                    .slice(
                        0,
                        t
                    );
        }
        else {

            adminIds =
                pvssData
                    .encrypted_shares
                    .slice(0, t)
                    .map(
                        item =>
                            Number(
                                item.admin_id
                            )
                    );
        }
    }


    adminIds =
        [...new Set(adminIds)];


    for (
        const adminId
        of adminIds
    ) {

        if (
            !Number.isInteger(adminId) ||
            adminId < 1 ||
            adminId > n
        ) {

            throw new Error(
                `Invalid administrator ID: ${adminId}`
            );
        }
    }


    if (
        adminIds.length < t
    ) {

        throw new Error(
            `At least ${t} distinct admins are required.`
        );
    }


    // Use exactly t admins for this reconstruction test.
    adminIds =
        adminIds.slice(
            0,
            t
        );


    // ==================================================
    // Crypto setup
    // ==================================================

    const babyJub =
        await buildBabyjub();


    const poseidon =
        await buildPoseidon();


    const F =
        poseidon.F;


    function poseidonField(
        inputs
    ) {

        return BigInt(
            F.toString(
                poseidon(
                    inputs
                )
            )
        );
    }


    function poseidonScalar(
        inputs
    ) {

        const raw =
            poseidonField(
                inputs
            );


        return {

            raw,

            scalar:
                mod(
                    raw,
                    BABYJUB_Q
                )
        };
    }


    // ==================================================
    // Acquire t shares
    //
    // source = current
    //     read current proactive-refresh shares.
    //
    // source = pvss
    //     decrypt original PVSS shares (legacy / epoch 0).
    //
    // Both branches populate recoveredShares in the same
    // { x, y } format, so reconstruction logic below is
    // unchanged.
    // ==================================================

    const shareAcquireStart =
        process.hrtime.bigint();


    let recoveredShares =
        [];


    const adminResults =
        [];


    let shareEpoch =
        null;


    // ==================================================
    // CURRENT SHARE SOURCE
    // ==================================================

    if (
        shareSource ===
        "current"
    ) {

        if (
            !fs.existsSync(
                currentShareDir
            )
        ) {

            throw new Error(
                "Current administrator-share state does not exist. Run refresh bootstrap first."
            );
        }


        const observedEpochs =
            new Set();


        for (
            const adminId
            of adminIds
        ) {

            const adminName =
                String(
                    adminId
                ).padStart(
                    2,
                    "0"
                );


            const shareFile =
                path.join(
                    currentShareDir,
                    `admin_${adminName}.json`
                );


            const currentState =
                loadJson(
                    shareFile
                );


            // ------------------------------------------
            // Admin binding
            // ------------------------------------------

            if (
                Number(
                    currentState.admin_id
                ) !==
                adminId
            ) {

                throw new Error(
                    `Current-share admin ID mismatch for admin ${adminId}.`
                );
            }


            // ------------------------------------------
            // Enrollment binding
            // ------------------------------------------

            if (
                String(
                    currentState.enrollment_id
                ) !==
                enrollmentId
            ) {

                throw new Error(
                    `Current-share enrollment mismatch for admin ${adminId}.`
                );
            }


            // ------------------------------------------
            // Domain / scheme binding
            // ------------------------------------------

            if (
                String(
                    currentState.D_id
                ) !==
                    String(
                        pvssData.D_id
                    ) ||
                String(
                    currentState.scheme_id
                ) !==
                    String(
                        pvssData.scheme_id
                    )
            ) {

                throw new Error(
                    `Current-share domain/scheme mismatch for admin ${adminId}.`
                );
            }


            // ------------------------------------------
            // Threshold binding
            // ------------------------------------------

            if (
                Number(
                    currentState.threshold?.n
                ) !==
                    n ||
                Number(
                    currentState.threshold?.t
                ) !==
                    t
            ) {

                throw new Error(
                    `Current-share threshold mismatch for admin ${adminId}.`
                );
            }


            // ------------------------------------------
            // Epoch validation
            // ------------------------------------------

            const epoch =
                Number(
                    currentState.share_epoch
                );


            if (
                !Number.isInteger(epoch) ||
                epoch < 0
            ) {

                throw new Error(
                    `Invalid share epoch for admin ${adminId}.`
                );
            }


            observedEpochs.add(
                epoch
            );


            // ------------------------------------------
            // Evaluation point alpha_i
            // ------------------------------------------

            const alpha =
                BigInt(
                    currentState.alpha
                );


            if (
                alpha !==
                BigInt(
                    adminId
                )
            ) {

                throw new Error(
                    `Current-share alpha mismatch for admin ${adminId}.`
                );
            }


            // ------------------------------------------
            // Share range
            // ------------------------------------------

            const currentShare =
                BigInt(
                    currentState.share
                );


            if (
                currentShare < 0n ||
                currentShare >=
                    BABYJUB_Q
            ) {

                throw new Error(
                    `Current share outside field range for admin ${adminId}.`
                );
            }


            recoveredShares.push({

                x:
                    alpha,

                y:
                    currentShare
            });


            adminResults.push({

                admin_id:
                    adminId,

                share_source:
                    "current",

                share_epoch:
                    epoch,

                current_share_state_valid:
                    true
            });
        }


        // ----------------------------------------------
        // Critical proactive-refresh rule:
        //
        // all selected shares must belong to the same
        // epoch.
        // ----------------------------------------------

        if (
            observedEpochs.size !==
            1
        ) {

            throw new Error(
                "Mixed share epochs are not allowed for threshold reconstruction."
            );
        }


        shareEpoch =
            [
                ...observedEpochs
            ][0];
    }


    // ==================================================
    // ORIGINAL PVSS SOURCE
    // ==================================================

    else {

        shareEpoch =
            0;


        for (
            const adminId
            of adminIds
        ) {

            const encrypted =
                pvssData
                    .encrypted_shares
                    .find(
                        item =>
                            Number(
                                item.admin_id
                            ) ===
                            adminId
                    );


            if (!encrypted) {

                throw new Error(
                    `Encrypted PVSS share not found for admin ${adminId}.`
                );
            }


            const adminFile =
                path.join(
                    projectRoot,
                    "private",
                    "pvss",
                    `admin_${String(adminId).padStart(2, "0")}.json`
                );


            const adminPrivate =
                loadJson(
                    adminFile
                );


            if (
                Number(
                    adminPrivate.admin_id
                ) !==
                adminId
            ) {

                throw new Error(
                    `Admin private-key ID mismatch for admin ${adminId}.`
                );
            }


            if (
                Number(
                    adminPrivate.key_version
                ) !==
                Number(
                    pvssData.admin_key_version
                )
            ) {

                throw new Error(
                    `Admin key-version mismatch for admin ${adminId}.`
                );
            }


            const secretKey =
                BigInt(
                    adminPrivate.secret_key
                );


            const R =
                pointFromJson(
                    encrypted.R,
                    babyJub.F
                );


            if (
                !babyJub.inCurve(R) ||
                !babyJub.inSubgroup(R)
            ) {

                throw new Error(
                    `PVSS ephemeral point R is invalid for admin ${adminId}.`
                );
            }


            // ----------------------------------------------
            // shared_i = SK_i * R_i
            // ----------------------------------------------

            const sharedPoint =
                babyJub.mulPointEscalar(
                    R,
                    secretKey
                );


            const shared =
                pointToBigints(
                    sharedPoint,
                    babyJub.F
                );


            // ----------------------------------------------
            // mask_i =
            //
            // Poseidon(
            //   TAG_PVSS_MASK,
            //   scheme_id,
            //   D_id,
            //   admin_id,
            //   shared.x,
            //   shared.y
            // ) mod q
            // ----------------------------------------------

            const mask =
                poseidonScalar([

                    BigInt(
                        tags.pvssMask
                    ),

                    schemeId,

                    domainId,

                    BigInt(
                        adminId
                    ),

                    shared.x,

                    shared.y
                ]);


            const ciphertext =
                BigInt(
                    encrypted.c
                );


            // ----------------------------------------------
            // Verify ciphertext integrity tag
            // ----------------------------------------------

            const expectedTag =
                poseidonField([

                    BigInt(
                        tags.pvssCipherTag
                    ),

                    schemeId,

                    domainId,

                    BigInt(
                        adminId
                    ),

                    BigInt(
                        encrypted.R.x
                    ),

                    BigInt(
                        encrypted.R.y
                    ),

                    ciphertext,

                    mask.raw
                ]);


            if (
                expectedTag.toString() !==
                String(
                    encrypted.tag
                )
            ) {

                throw new Error(
                    `PVSS ciphertext integrity check failed for admin ${adminId}.`
                );
            }


            // ----------------------------------------------
            // s_i = c_i - mask_i mod q
            // ----------------------------------------------

            const recoveredShare =
                mod(
                    ciphertext -
                    mask.scalar,
                    BABYJUB_Q
                );


            recoveredShares.push({

                x:
                    BigInt(
                        adminId
                    ),

                y:
                    recoveredShare
            });


            // ----------------------------------------------
            // Laboratory correctness check only.
            //
            // This comparison is valid only for original
            // epoch-0 PVSS shares.
            // ----------------------------------------------

            const witnessShare =
                witness
                    .shares
                    .find(
                        item =>
                            Number(
                                item.admin_id
                            ) ===
                            adminId
                    );


            if (!witnessShare) {

                throw new Error(
                    `Witness share not found for admin ${adminId}.`
                );
            }


            const shareMatchesWitness =
                recoveredShare ===
                BigInt(
                    witnessShare.share
                );


            if (!shareMatchesWitness) {

                throw new Error(
                    `Recovered share mismatch for admin ${adminId}.`
                );
            }


            adminResults.push({

                admin_id:
                    adminId,

                share_source:
                    "pvss",

                share_epoch:
                    0,

                ciphertext_tag_valid:
                    true,

                decrypted_share_matches_lab_witness:
                    true
            });
        }
    }


    const shareAcquireEnd =
        process.hrtime.bigint();


    const shareAcquireMs =
        Number(
            shareAcquireEnd -
            shareAcquireStart
        ) / 1e6;


    // ==================================================
    // Threshold reconstruction
    // ==================================================

    const reconstructStart =
        process.hrtime.bigint();


    let reconstructedAnchor =
        reconstructAtZero(
            recoveredShares,
            BABYJUB_Q
        );


    const reconstructEnd =
        process.hrtime.bigint();


    const reconstructionMs =
        Number(
            reconstructEnd -
            reconstructStart
        ) / 1e6;


    // ==================================================
    // Laboratory correctness check:
    //
    // reconstructed x_anchor must match enrollment
    // witness, but it is NEVER printed or stored.
    //
    // x_anchor is invariant across refresh epochs.
    // ==================================================

    const anchorMatchesWitness =
        reconstructedAnchor ===
        BigInt(
            witness.x_anchor
        );


    if (!anchorMatchesWitness) {

        throw new Error(
            "Threshold-reconstructed x_anchor does not match enrollment witness."
        );
    }


    // ==================================================
    // Derive Y = Base8 * x_anchor
    // ==================================================

    const deriveStart =
        process.hrtime.bigint();


    const Y =
        babyJub.mulPointEscalar(
            babyJub.Base8,
            reconstructedAnchor
        );


    const Yjson =
        pointToBigints(
            Y,
            babyJub.F
        );


    // ==================================================
    // y_hash =
    //
    // Poseidon(
    //   TAG_REVOKE,
    //   scheme_id,
    //   D_id,
    //   Y.x,
    //   Y.y
    // )
    // ==================================================

    const yHash =
        poseidonField([

            BigInt(
                tags.revoke
            ),

            schemeId,

            domainId,

            Yjson.x,

            Yjson.y
        ]);


    const deriveEnd =
        process.hrtime.bigint();


    const deriveRevocationIdMs =
        Number(
            deriveEnd -
            deriveStart
        ) / 1e6;


    // ==================================================
    // Cross-check y_hash with original enrollment witness
    // ==================================================

    const yHashMatchesWitness =
        yHash.toString() ===
        String(
            witness.y_hash
        );


    if (!yHashMatchesWitness) {

        throw new Error(
            "Reconstructed y_hash does not match enrollment witness."
        );
    }


    // ==================================================
    // BAS lookup
    //
    // BAS receives only y_hash in the later protocol.
    // ==================================================

    if (
        !registry.entries ||
        typeof registry.entries !==
            "object"
    ) {

        throw new Error(
            "Invalid BAS enrollment registry."
        );
    }


    const basRecord =
        registry.entries[
            yHash.toString()
        ];


    if (!basRecord) {

        throw new Error(
            "No BAS record exists for reconstructed y_hash."
        );
    }


    const basStatus =
        String(
            basRecord.status ??
            ""
        ).toLowerCase();


    if (
        basStatus !==
        "active"
    ) {

        throw new Error(
            `BAS record is not active. Current status: ${basRecord.status}`
        );
    }


    // ==================================================
    // Final safety checks
    // ==================================================

    if (
        String(
            basRecord.y_hash ??
            yHash.toString()
        ) !==
        yHash.toString()
    ) {

        throw new Error(
            "BAS record y_hash inconsistency."
        );
    }


    // ==================================================
    // Public/non-secret report
    //
    // IMPORTANT:
    // No x
    // No x_anchor
    // No plaintext shares
    // No admin secret keys
    // ==================================================

    const report = {

        version:
            2,

        enrollment_id:
            enrollmentId,

        D_id:
            String(
                pvssData.D_id
            ),

        scheme_id:
            String(
                pvssData.scheme_id
            ),

        threshold: {

            n,

            t
        },

        participating_admins:
            adminIds,

        share_source:
            shareSource,

        share_epoch:
            shareEpoch,

        epoch_consistency:
            "VALID",

        mixed_epoch_shares_used:
            false,

        pvss_encryption:
            pvssData.encryption
                .construction,

        admin_results:
            adminResults,

        recovered_share_count:
            recoveredShares.length,

        threshold_reconstruction:
            "VALID",

        reconstructed_secret:
            "x_anchor",

        reconstructed_x_anchor_exposed:
            false,

        x_reconstructed:
            false,

        anchor_matches_enrollment_witness:
            true,

        y_hash:
            yHash.toString(),

        y_hash_matches_enrollment_witness:
            true,

        bas_record_found:
            true,

        bas_record_status:
            basRecord.status,

        revocation_target:
            "VALID_ACTIVE_RECORD",

        timings_ms: {

            share_acquisition:
                shareAcquireMs,

            pvss_decrypt_t_shares:
                shareSource === "pvss"
                    ? shareAcquireMs
                    : null,

            current_share_load:
                shareSource === "current"
                    ? shareAcquireMs
                    : null,

            lagrange_reconstruction:
                reconstructionMs,

            derive_Y_and_y_hash:
                deriveRevocationIdMs
        }
    };


    saveJson(
        reportFile,
        report
    );


    // ==================================================
    // Logical discard of reconstructed secret material.
    //
    // JavaScript does NOT guarantee forensic memory erase.
    // ==================================================

    reconstructedAnchor =
        0n;


    for (
        const item
        of recoveredShares
    ) {

        item.y =
            0n;
    }


    recoveredShares =
        [];


    // ==================================================
    // Output
    // ==================================================

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - Revocation Reconstruction"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Enrollment ID        : ${enrollmentId}`
    );

    console.log(
        `Threshold            : ${t}-of-${n}`
    );

    console.log(
        `Share source         : ${shareSource.toUpperCase()}`
    );

    console.log(
        `Share epoch          : ${shareEpoch}`
    );

    console.log(
        `Participating admins : ${adminIds.join(", ")}`
    );

    console.log("");


    for (
        const result
        of adminResults
    ) {

        if (
            result.share_source ===
            "current"
        ) {

            console.log(
                `Admin ${result.admin_id} current share state : VALID / epoch ${result.share_epoch}`
            );
        }
        else {

            console.log(
                `Admin ${result.admin_id} ciphertext tag : VALID`
            );

            console.log(
                `Admin ${result.admin_id} share recovery : VALID`
            );
        }
    }


    console.log("");

    console.log(
        `Recovered shares     : ${t}/${t}`
    );

    console.log(
        "Epoch consistency    : VALID"
    );

    console.log(
        "Lagrange reconstruction: VALID"
    );

    console.log(
        "Reconstructed value   : x_anchor"
    );

    console.log(
        "x_anchor exposed      : NO"
    );

    console.log(
        "Original user x       : NOT RECONSTRUCTED"
    );

    console.log("");

    console.log(
        "x_anchor / witness     : MATCH"
    );

    console.log(
        "Derived y_hash         : MATCH"
    );

    console.log(
        "BAS active record      : MATCH"
    );

    console.log("");

    console.log(
        "--------------------------------------------"
    );

    console.log(
        "REVOCATION TARGET: VALID"
    );

    console.log(
        "--------------------------------------------"
    );

    console.log("");


    if (
        shareSource ===
        "pvss"
    ) {

        console.log(
            `PVSS decrypt (${t} shares) : ${shareAcquireMs.toFixed(3)} ms`
        );
    }
    else {

        console.log(
            `Current share load       : ${shareAcquireMs.toFixed(3)} ms`
        );
    }


    console.log(
        `Lagrange reconstruction : ${reconstructionMs.toFixed(3)} ms`
    );

    console.log(
        `Y + y_hash derivation    : ${deriveRevocationIdMs.toFixed(3)} ms`
    );

    console.log("");

    console.log(
        "No revocation has been applied yet."
    );

    console.log(
        "No x_anchor was sent to BAS."
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
            "REVOCATION RECONSTRUCTION: REJECT"
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