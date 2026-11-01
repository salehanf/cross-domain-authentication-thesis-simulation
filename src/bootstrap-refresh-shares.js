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
        {
            recursive: true
        }
    );

    const tempFile =
        filePath + ".tmp";

    fs.writeFileSync(
        tempFile,
        JSON.stringify(
            data,
            null,
            2
        )
    );

    fs.renameSync(
        tempFile,
        filePath
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

        if (
            (e & 1n) ===
            1n
        ) {
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

    const x =
        mod(
            value,
            modulus
        );

    if (x === 0n) {
        throw new Error(
            "Cannot invert zero."
        );
    }

    return modPow(
        x,
        modulus - 2n,
        modulus
    );
}


// ======================================================
// Lagrange reconstruction at x = 0
// ======================================================

function reconstructAtZero(
    shares,
    modulus
) {

    let secret =
        0n;

    for (
        let i = 0;
        i < shares.length;
        i++
    ) {

        const xi =
            shares[i].x;

        const yi =
            shares[i].y;

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
                shares[j].x;

            numerator =
                mod(
                    numerator *
                    (-xj),
                    modulus
                );

            denominator =
                mod(
                    denominator *
                    (xi - xj),
                    modulus
                );
        }

        const lambda =
            mod(
                numerator *
                modInverse(
                    denominator,
                    modulus
                ),
                modulus
            );

        secret =
            mod(
                secret +
                yi * lambda,
                modulus
            );
    }

    return secret;
}


// ======================================================
// Combinations
// ======================================================

function combinations(
    values,
    choose
) {

    const result =
        [];

    function walk(
        start,
        current
    ) {

        if (
            current.length ===
            choose
        ) {

            result.push(
                [...current]
            );

            return;
        }

        for (
            let i = start;
            i < values.length;
            i++
        ) {

            current.push(
                values[i]
            );

            walk(
                i + 1,
                current
            );

            current.pop();
        }
    }

    walk(
        0,
        []
    );

    return result;
}


// ======================================================
// Main
// ======================================================

async function main() {

    const enrollmentId =
        process.argv[2];

    if (!enrollmentId) {

        throw new Error(
            "Usage: node src\\bootstrap-refresh-shares.js <enrollment-id>"
        );
    }


    const projectRoot =
        config.paths.projectRoot;

    const tags =
        config.protocol?.tags ??
        config.tags;

    if (
        !tags ||
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

    const enrollmentDir =
        path.join(
            projectRoot,
            "artifacts",
            "enrollment",
            enrollmentId
        );

    const pvssFile =
        path.join(
            enrollmentDir,
            "pvss_data.json"
        );

    const packageFile =
        path.join(
            enrollmentDir,
            "enroll_package.json"
        );

    const registryFile =
        path.join(
            projectRoot,
            "state",
            "bas",
            "enrollment_registry.json"
        );

    const adminPrivateDir =
        path.join(
            projectRoot,
            "private",
            "pvss"
        );

    const shareStateDir =
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
            "refresh",
            enrollmentId,
            "bootstrap_report.json"
        );


    // ==================================================
    // Load public/protocol state
    // ==================================================

    const pvssData =
        loadJson(
            pvssFile
        );

    const enrollPackage =
        loadJson(
            packageFile
        );

    const registry =
        loadJson(
            registryFile
        );


    if (
        String(
            pvssData.proof_status
        ).toLowerCase() !==
        "verified"
    ) {

        throw new Error(
            "PVSS_Data is not in VERIFIED state."
        );
    }


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
        t < 2 ||
        t > n
    ) {

        throw new Error(
            "Invalid threshold parameters."
        );
    }


    // ==================================================
    // Verify that this is an ACTIVE BAS record
    // ==================================================

    const yHash =
        String(
            enrollPackage.y_hash
        );

    const registryEntry =
        registry.entries?.[
            yHash
        ];

    if (!registryEntry) {

        throw new Error(
            "Enrollment is not present in BAS registry."
        );
    }

    if (
        registryEntry.status !==
        "active"
    ) {

        throw new Error(
            `Enrollment is not active. Current status: ${registryEntry.status}`
        );
    }


    // ==================================================
    // Prevent accidental overwrite
    // ==================================================

    if (
        fs.existsSync(
            shareStateDir
        )
    ) {

        const existing =
            fs.readdirSync(
                shareStateDir
            ).filter(
                name =>
                    /^admin_\d+\.json$/i
                        .test(name)
            );

        if (
            existing.length > 0
        ) {

            throw new Error(
                "Refresh share state already exists. Refusing to overwrite epoch state."
            );
        }
    }


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


    function pointFromJson(
        point
    ) {

        return [
            babyJub.F.e(
                BigInt(
                    point.x
                )
            ),
            babyJub.F.e(
                BigInt(
                    point.y
                )
            )
        ];
    }


    function pointToBigints(
        point
    ) {

        return {
            x:
                BigInt(
                    babyJub.F.toString(
                        point[0]
                    )
                ),

            y:
                BigInt(
                    babyJub.F.toString(
                        point[1]
                    )
                )
        };
    }


    const domainId =
        BigInt(
            pvssData.D_id
        );

    const schemeId =
        BigInt(
            pvssData.scheme_id
        );


    // ==================================================
    // Recover ALL administrator shares from PVSS
    // ==================================================

    const start =
        process.hrtime.bigint();

    let recoveredShares =
        [];

    const integrityResults =
        [];


    for (
        let adminId = 1;
        adminId <= n;
        adminId++
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
                `Encrypted share not found for admin ${adminId}.`
            );
        }


        const adminName =
            String(
                adminId
            ).padStart(
                2,
                "0"
            );

        const privateKeyFile =
            path.join(
                adminPrivateDir,
                `admin_${adminName}.json`
            );

        const adminPrivate =
            loadJson(
                privateKeyFile
            );

        const secretKey =
            BigInt(
                adminPrivate.secret_key
            );


        // ----------------------------------------------
        // R_i
        // ----------------------------------------------

        const R =
            pointFromJson(
                encrypted.R
            );

        if (
            !babyJub.inCurve(R)
        ) {

            throw new Error(
                `Invalid R point for admin ${adminId}.`
            );
        }


        if (
            typeof babyJub.inSubgroup ===
            "function" &&
            !babyJub.inSubgroup(R)
        ) {

            throw new Error(
                `R point is not in BabyJub subgroup for admin ${adminId}.`
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
                sharedPoint
            );


        // ----------------------------------------------
        // mask_i
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
            admin_id:
                adminId,

            x:
                BigInt(
                    adminId
                ),

            y:
                recoveredShare,

            key_version:
                adminPrivate.key_version ??
                pvssData.admin_key_version ??
                null
        });


        integrityResults.push({
            admin_id:
                adminId,

            ciphertext_tag:
                "VALID"
        });
    }


    const decryptEnd =
        process.hrtime.bigint();


    // ==================================================
    // Threshold consistency check
    //
    // Every t-subset must reconstruct the SAME x_anchor.
    // The secret is never printed or written.
    // ==================================================

    const subsets =
        combinations(
            recoveredShares,
            t
        );

    let reconstructedAnchor =
        null;

    let validSubsetCount =
        0;


    for (
        const subset
        of subsets
    ) {

        const value =
            reconstructAtZero(
                subset,
                BABYJUB_Q
            );

        if (
            reconstructedAnchor ===
            null
        ) {

            reconstructedAnchor =
                value;
        }

        if (
            value !==
            reconstructedAnchor
        ) {

            throw new Error(
                "Threshold reconstruction mismatch between administrator subsets."
            );
        }

        validSubsetCount++;
    }


    // ==================================================
    // Derive Y and y_hash only to bind recovered shares
    // to THIS active enrollment.
    //
    // x_anchor itself is not persisted or printed.
    // ==================================================

    const YPoint =
        babyJub.mulPointEscalar(
            babyJub.Base8,
            reconstructedAnchor
        );

    const Y =
        pointToBigints(
            YPoint
        );

    const derivedYHash =
        poseidonField([
            BigInt(
                tags.revoke
            ),

            schemeId,
            domainId,

            Y.x,
            Y.y
        ]);


    if (
        derivedYHash.toString() !==
        yHash
    ) {

        throw new Error(
            "Recovered threshold secret does not bind to enrollment y_hash."
        );
    }


    // ==================================================
    // Create epoch-0 administrator share state
    // ==================================================

    const createdAt =
        new Date()
            .toISOString();


    for (
        const item
        of recoveredShares
    ) {

        const adminName =
            String(
                item.admin_id
            ).padStart(
                2,
                "0"
            );

        const outputFile =
            path.join(
                shareStateDir,
                `admin_${adminName}.json`
            );


        saveJson(
            outputFile,
            {
                version:
                    1,

                purpose:
                    "proactive-refresh-current-share",

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

                admin_id:
                    item.admin_id,

                alpha:
                    String(
                        item.admin_id
                    ),

                share_epoch:
                    0,

                share:
                    item.y.toString(),

                threshold: {
                    n,
                    t
                },

                admin_key_version:
                    item.key_version,

                source:
                    "PVSS-decrypted",

                created_at:
                    createdAt
            }
        );
    }


    // ==================================================
    // Non-secret experiment report
    // ==================================================

    const totalEnd =
        process.hrtime.bigint();

    const decryptMs =
        Number(
            decryptEnd -
            start
        ) / 1e6;

    const totalMs =
        Number(
            totalEnd -
            start
        ) / 1e6;


    const report = {

        version:
            1,

        phase:
            "proactive-refresh-bootstrap",

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

        registry_status:
            "active",

        initial_share_epoch:
            0,

        threshold: {
            n,
            t
        },

        recovered_share_count:
            recoveredShares.length,

        ciphertext_integrity:
            integrityResults,

        threshold_subsets_tested:
            subsets.length,

        threshold_subsets_valid:
            validSubsetCount,

        reconstructed_secret:
            "x_anchor",

        reconstructed_x_anchor_exposed:
            false,

        share_values_exposed:
            false,

        derived_y_hash_matches_enrollment:
            true,

        source:
            "PVSS ciphertext decryption using administrator private keys",

        timings_ms: {

            decrypt_all_shares:
                decryptMs,

            total_bootstrap:
                totalMs
        },

        note: [
            "Plain administrator shares are stored only in private/admin_shares.",
            "The user-side PVSS witness is not used as the source of administrator shares.",
            "No BAS registry entry, SMT leaf, SignedRoot, L, idx, or y_hash is modified."
        ]
    };


    saveJson(
        reportFile,
        report
    );


    // ==================================================
    // Best-effort logical cleanup
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
        " Thesis Protocol - Refresh Share Bootstrap"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Enrollment ID          : ${enrollmentId}`
    );

    console.log(
        `BAS status             : ACTIVE`
    );

    console.log(
        `Threshold              : ${t}-of-${n}`
    );

    console.log(
        `PVSS shares recovered  : ${n}/${n}`
    );

    console.log(
        `Ciphertext tags        : ${n}/${n} VALID`
    );

    console.log(
        `Threshold subsets      : ${validSubsetCount}/${subsets.length} VALID`
    );

    console.log(
        "Reconstructed secret   : x_anchor"
    );

    console.log(
        "x_anchor exposed       : NO"
    );

    console.log(
        "y_hash binding         : MATCH"
    );

    console.log(
        "Initial share epoch    : 0"
    );

    console.log("");

    console.log(
        "Private current-share state:"
    );

    console.log(
        shareStateDir
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
        `Decrypt all shares     : ${decryptMs.toFixed(3)} ms`
    );

    console.log(
        `Total bootstrap        : ${totalMs.toFixed(3)} ms`
    );

    console.log(
        "============================================"
    );
}


main()
    .catch(
        error => {

            console.error(
                ""
            );

            console.error(
                "Refresh share bootstrap failed:"
            );

            console.error(
                error.message
            );

            process.exitCode =
                1;
        }
    );