const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const circomlibjs = require("circomlibjs");

const config = require("./config");

const {
    verifyAAT,
    computeAATNullifier
} = require("./aat");


const projectRoot =
    config.paths.projectRoot;


// ======================================================
// Modular arithmetic
// ======================================================

function mod(a, m) {

    const r =
        a % m;

    return r >= 0n
        ? r
        : r + m;
}


function modInverse(a, m) {

    let t = 0n;
    let newT = 1n;

    let r = m;
    let newR =
        mod(a, m);


    while (
        newR !== 0n
    ) {

        const quotient =
            r / newR;


        [
            t,
            newT
        ] = [
            newT,
            t -
            quotient *
            newT
        ];


        [
            r,
            newR
        ] = [
            newR,
            r -
            quotient *
            newR
        ];
    }


    if (
        r !== 1n
    ) {

        throw new Error(
            "Value has no modular inverse."
        );
    }


    return mod(
        t,
        m
    );
}


// ======================================================
// Random subgroup scalar
// ======================================================

function randomScalar(order) {

    while (true) {

        const bytes =
            crypto.randomBytes(32);


        /*
         * BabyJub subgroup order is about 251 bits.
         */

        bytes[0] &= 0x07;


        const value =
            BigInt(
                "0x" +
                bytes.toString("hex")
            );


        if (
            value > 0n &&
            value < order
        ) {

            return value;
        }
    }
}

function randomScalar248() {

    while (true) {

        const bytes =
            crypto.randomBytes(31);

        const value =
            BigInt(
                "0x" +
                bytes.toString("hex")
            );

        if (value > 0n) {
            return value;
        }
    }
}

// ======================================================
// Poseidon helpers
// ======================================================

function poseidonField(
    poseidon,
    inputs
) {

    return BigInt(
        poseidon.F
            .toObject(
                poseidon(
                    inputs
                )
            )
            .toString()
    );
}


/*
 * Map a Poseidon field output into the BabyJub
 * prime-order scalar subgroup.
 *
 * We keep the quotient as private auxiliary data so
 * the future Circom circuit can enforce:
 *
 * raw = scalar + quotient * q
 *
 * with appropriate range constraints.
 */

function poseidonScalar(
    poseidon,
    inputs,
    q
) {

    const raw =
        poseidonField(
            poseidon,
            inputs
        );


    return {

        raw,

        scalar:
            raw % q,

        quotient:
            raw / q
    };
}


// ======================================================
// Polynomial evaluation
//
// f(x) = a0 + a1*x + ... mod q
// ======================================================

function evaluatePolynomial(
    coefficients,
    x,
    q
) {

    let result =
        0n;


    let power =
        1n;


    for (
        const coefficient
        of coefficients
    ) {

        result =
            mod(
                result +
                coefficient *
                power,
                q
            );


        power =
            mod(
                power * x,
                q
            );
    }


    return result;
}


// ======================================================
// Lagrange reconstruction at x = 0
// ======================================================

function reconstructSecret(
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

            if (
                i === j
            ) {

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
                yi *
                lambda,
                q
            );
    }


    return secret;
}


// ======================================================
// Generate combinations
// ======================================================

function combinations(
    array,
    choose
) {

    const result =
        [];


    function visit(
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
            i < array.length;
            i++
        ) {

            current.push(
                array[i]
            );


            visit(
                i + 1,
                current
            );


            current.pop();
        }
    }


    visit(
        0,
        []
    );


    return result;
}


// ======================================================
// BabyJub point helpers
// ======================================================

function pointToJson(
    point,
    F
) {

    return {

        x:
            F
                .toObject(
                    point[0]
                )
                .toString(),

        y:
            F
                .toObject(
                    point[1]
                )
                .toString()
    };
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


function pointsEqual(
    a,
    b,
    F
) {

    return (
        F.toObject(
            a[0]
        ) ===
        F.toObject(
            b[0]
        )
        &&
        F.toObject(
            a[1]
        ) ===
        F.toObject(
            b[1]
        )
    );
}


// ======================================================
// Load AAT
// ======================================================

function loadAAT(
    filename
) {

    const resolved =
        path.resolve(
            filename
        );


    if (
        !fs.existsSync(
            resolved
        )
    ) {

        throw new Error(
            `AAT file not found: ${resolved}`
        );
    }


    return JSON.parse(
        fs.readFileSync(
            resolved,
            "utf8"
        )
    );
}


// ======================================================
// Load PVSS public key registry
// ======================================================

function loadPVSSPublicKeys() {

    const filename =
        path.join(
            projectRoot,
            "state",
            "pvss",
            "admin_public_keys.json"
        );


    if (
        !fs.existsSync(
            filename
        )
    ) {

        throw new Error(
            "PVSS public-key registry not found. Run pvss_setup.js first."
        );
    }


    return JSON.parse(
        fs.readFileSync(
            filename,
            "utf8"
        )
    );
}


// ======================================================
// Load one admin's PVSS private key
//
// Used ONLY for laboratory self-test.
// The user-side generation code never needs these keys.
// ======================================================

function loadAdminPrivateKey(
    adminId
) {

    const filename =
        path.join(
            projectRoot,
            "private",
            "pvss",

            `admin_${String(
                adminId
            ).padStart(
                2,
                "0"
            )}.json`
        );


    if (
        !fs.existsSync(
            filename
        )
    ) {

        throw new Error(
            `PVSS private key missing for admin ${adminId}.`
        );
    }


    return JSON.parse(
        fs.readFileSync(
            filename,
            "utf8"
        )
    );
}


// ======================================================
// Main
// ======================================================

async function main() {

    const aatFile =
        process.argv[2];


    if (
        !aatFile
    ) {

        throw new Error(
            [
                "Usage:",
                "",
                "node src\\pvss_enrollment.js <aat-file>",
                "",
                "Issue a fresh AAT first if necessary."
            ].join("\n")
        );
    }


    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - Enrollment PVSS"
    );

    console.log(
        "============================================"
    );


    // ==================================================
    // Verify AAT before user enters enrollment
    // ==================================================

    const aat =
        loadAAT(
            aatFile
        );


    const aatVerification =
        verifyAAT(
            aat
        );


    if (
        !aatVerification.valid
    ) {

        throw new Error(
            `AAT rejected: ${aatVerification.reason}`
        );
    }


    console.log(
        "AAT verification:",
        "valid"
    );


    console.log(
        "AAT purpose:",
        aat.purpose
    );


    const aatNullifier =
        computeAATNullifier(
            aat
        );


    /*
     * IMPORTANT:
     *
     * The nullifier is NOT consumed here.
     * BAS will consume it only after successful
     * enrollment validation.
     */


    // ==================================================
    // Initialize cryptographic primitives
    // ==================================================

    const initializationStart =
        performance.now();


    const [
        babyJub,
        poseidon
    ] =
        await Promise.all([

            circomlibjs
                .buildBabyjub(),

            circomlibjs
                .buildPoseidon()
        ]);


    const initializationEnd =
        performance.now();


    const F =
        babyJub.F;


    const q =
        BigInt(
            babyJub
                .subOrder
                .toString()
        );


    // ==================================================
    // Configuration
    // ==================================================

    const n =
        config.admins.n;


    const t =
        config.admins.t;


    const schemeId =
        BigInt(
            config.protocol.schemeId
        );


    const domainId =
        BigInt(
            config.domain.domainId
        );


    const tags =
        config.protocol.tags ??
        config.tags;


    if (
        !tags
    ) {

        throw new Error(
            "Protocol tags were not found in config.js."
        );
    }


    const requiredTags = [
        "anchor",
        "leaf",
        "idx",
        "revoke",
        "pvssCoeffCommit",
        "pvssMask",
        "pvssCipherTag"
    ];


    for (
        const tag
        of requiredTags
    ) {

        if (
            tags[tag] ===
            undefined
        ) {

            throw new Error(
                `Missing protocol tag: ${tag}`
            );
        }
    }


    // ==================================================
    // Validate PVSS public-key registry
    // ==================================================

    const publicRegistry =
        loadPVSSPublicKeys();


    if (
        publicRegistry.domain_id !==
        config.domain.domainId
        ||
        publicRegistry.scheme_id !==
        config.protocol.schemeId
    ) {

        throw new Error(
            "PVSS public-key registry belongs to another domain/scheme."
        );
    }


    if (
        publicRegistry.threshold.n !== n
        ||
        publicRegistry.threshold.t !== t
    ) {

        throw new Error(
            "PVSS threshold configuration mismatch."
        );
    }


    if (
        publicRegistry.admins.length !==
        n
    ) {

        throw new Error(
            "PVSS public-key registry has an invalid administrator count."
        );
    }


    // ==================================================
    // 1. Generate user secret x
    //
    // x <-R Z_q
    // ==================================================

    const userStart =
        performance.now();


    let x;
    let anchorResult;


    /*
     * x_anchor = Poseidon(
     *   TAG_ANCHOR,
     *   scheme_id,
     *   D_id,
     *   x
     * ) mod q
     *
     * Re-roll x in the astronomically unlikely event
     * that x_anchor == 0.
     */

    do {

        x =
            randomScalar(
                q
            );


        anchorResult =
            poseidonScalar(
                poseidon,

                [
                    BigInt(
                        tags.anchor
                    ),

                    schemeId,

                    domainId,

                    x
                ],

                q
            );

    } while (
        anchorResult.scalar ===
        0n
    );


    const xAnchor =
        anchorResult.scalar;


    // ==================================================
    // 2. Compute Y
    //
    // Y = x_anchor * Base8
    // ==================================================

    const Y =
        babyJub
            .mulPointEscalar(
                babyJub.Base8,
                xAnchor
            );


    const Yjson =
        pointToJson(
            Y,
            F
        );


    // ==================================================
    // 3. L
    //
    // L = H(
    //   "leaf",
    //   scheme_id,
    //   D_id,
    //   Y
    // )
    // ==================================================

    const L =
        poseidonField(
            poseidon,

            [
                BigInt(
                    tags.leaf
                ),

                schemeId,

                domainId,

                BigInt(
                    Yjson.x
                ),

                BigInt(
                    Yjson.y
                )
            ]
        );


    // ==================================================
    // 4. idx
    //
    // Development instantiation:
    //
    // idxRaw = Poseidon(...)
    // idx = low d bits
    //
    // For d = 20 this is exact and circuit-friendly.
    // ==================================================

    const idxRaw =
        poseidonField(
            poseidon,

            [
                BigInt(
                    tags.idx
                ),

                schemeId,

                domainId,

                xAnchor
            ]
        );


    const smtDepth =
        config.smt?.depth ??
        config.protocol?.smt?.depth;


    if (
        !Number.isInteger(
            smtDepth
        )
        ||
        smtDepth <= 0
        ||
        smtDepth > 253
    ) {

        throw new Error(
            "This PVSS enrollment prototype currently requires 1 <= SMT depth <= 253."
        );
    }


    const idxMask =
        (1n <<
            BigInt(
                smtDepth
            )
        ) - 1n;


    const idx =
        idxRaw &
        idxMask;


    // ==================================================
    // 5. y_hash
    // ==================================================

    const yHash =
        poseidonField(
            poseidon,

            [
                BigInt(
                    tags.revoke
                ),

                schemeId,

                domainId,

                BigInt(
                    Yjson.x
                ),

                BigInt(
                    Yjson.y
                )
            ]
        );


    const userMaterialEnd =
        performance.now();


    // ==================================================
    // 6. Shamir polynomial
    //
    // f(z) =
    // x_anchor +
    // a1*z + ... + a_(t-1)*z^(t-1)
    //
    // degree = t - 1
    // ==================================================

    const pvssStart =
        performance.now();


    const coefficients = [
        xAnchor
    ];


    for (
        let k = 1;
        k < t;
        k++
    ) {

        coefficients.push(
            randomScalar(
                q
            )
        );
    }


    // ==================================================
    // Hiding commitments to polynomial coefficients
    //
    // C_k =
    // Poseidon(
    //   TAG_PVSS_COEFF_COMMIT,
    //   scheme_id,
    //   D_id,
    //   k,
    //   a_k,
    //   blind_k
    // )
    //
    // blind_k stays private.
    // ==================================================

    const commitmentBlindings =
        [];


    const commitments =
        [];


    for (
        let k = 0;
        k < t;
        k++
    ) {

        const blinding =
            randomScalar(
                q
            );


        commitmentBlindings.push(
            blinding
        );


        const commitment =
            poseidonField(
                poseidon,

                [
                    BigInt(
                        tags.pvssCoeffCommit
                    ),

                    schemeId,

                    domainId,

                    BigInt(k),

                    coefficients[k],

                    blinding
                ]
            );


        commitments.push({

            coefficient_index:
                k,

            commitment:
                commitment.toString()
        });
    }


    // ==================================================
    // 7. Generate shares and encrypt each share
    //
    // s_i = f(i)
    //
    // Encryption:
    //
    // r_i <-R Z_q
    // R_i = r_i * G
    // S_i = r_i * PK_i
    //
    // mask_i =
    // Poseidon(... S_i ...) mod q
    //
    // c_i = s_i + mask_i mod q
    //
    // E_i = (R_i, c_i, tag_i)
    // ==================================================

    const encryptedShares =
        [];


    const privateShareAux =
        [];


    const plaintextShares =
        [];


    for (
        const admin
        of publicRegistry.admins
    ) {

        const adminId =
            admin.admin_id;


        const xCoordinate =
            BigInt(
                adminId
            );


        const share =
            evaluatePolynomial(
                coefficients,
                xCoordinate,
                q
            );


        plaintextShares.push({

            x:
                xCoordinate,

            y:
                share
        });


        const adminPublicKey =
            pointFromJson(
                admin.public_key,
                F
            );


        const encryptionRandomness = randomScalar248();


        const ephemeralPublic =
            babyJub
                .mulPointEscalar(
                    babyJub.Base8,
                    encryptionRandomness
                );


        const sharedPoint =
            babyJub
                .mulPointEscalar(
                    adminPublicKey,
                    encryptionRandomness
                );


        const ephemeralJson =
            pointToJson(
                ephemeralPublic,
                F
            );


        const sharedJson =
            pointToJson(
                sharedPoint,
                F
            );


        const maskResult =
            poseidonScalar(
                poseidon,

                [
                    BigInt(
                        tags.pvssMask
                    ),

                    schemeId,

                    domainId,

                    BigInt(
                        adminId
                    ),

                    BigInt(
                        sharedJson.x
                    ),

                    BigInt(
                        sharedJson.y
                    )
                ],

                q
            );


        const ciphertext =
            mod(
                share +
                maskResult.scalar,
                q
            );


        /*
         * Authentication/integrity tag.
         *
         * The admin can recompute this after deriving
         * the ECDH shared point.
         *
         * Later the ZK/PVSS proof can also bind it.
         */

        const cipherTag =
            poseidonField(
                poseidon,

                [
                    BigInt(
                        tags.pvssCipherTag
                    ),

                    schemeId,

                    domainId,

                    BigInt(
                        adminId
                    ),

                    BigInt(
                        ephemeralJson.x
                    ),

                    BigInt(
                        ephemeralJson.y
                    ),

                    ciphertext,

                    maskResult.raw
                ]
            );


        encryptedShares.push({

            admin_id:
                adminId,

            R:
                ephemeralJson,

            c:
                ciphertext.toString(),

            tag:
                cipherTag.toString()
        });


        /*
         * Private user-side auxiliary data.
         *
         * This will become witness material for the
         * future PVSS correctness proofs.
         */

        privateShareAux.push({

            admin_id:
                adminId,

            share:
                share.toString(),

            encryption_randomness:
                encryptionRandomness
                    .toString(),

            shared_point:
                sharedJson,

            mask_raw:
                maskResult.raw
                    .toString(),

            mask_scalar:
                maskResult.scalar
                    .toString(),

            mask_reduction_quotient:
                maskResult.quotient
                    .toString()
        });
    }


    const pvssEnd =
        performance.now();


    // ==================================================
    // 8. Laboratory decryption self-test
    //
    // Each admin independently obtains ONLY its own s_i.
    //
    // This block uses admin private keys only to test
    // correctness of the prototype.
    // ==================================================

    const decryptStart =
        performance.now();


    const recoveredShares =
        [];


    for (
        const encrypted
        of encryptedShares
    ) {

        const adminId =
            encrypted.admin_id;


        const adminPrivate =
            loadAdminPrivateKey(
                adminId
            );


        const secretKey =
            BigInt(
                adminPrivate.secret_key
            );


        const R =
            pointFromJson(
                encrypted.R,
                F
            );


        /*
         * Admin side:
         *
         * shared = SK_i * R_i
         */

        const sharedPoint =
            babyJub
                .mulPointEscalar(
                    R,
                    secretKey
                );


        const sharedJson =
            pointToJson(
                sharedPoint,
                F
            );


        const maskResult =
            poseidonScalar(
                poseidon,

                [
                    BigInt(
                        tags.pvssMask
                    ),

                    schemeId,

                    domainId,

                    BigInt(
                        adminId
                    ),

                    BigInt(
                        sharedJson.x
                    ),

                    BigInt(
                        sharedJson.y
                    )
                ],

                q
            );


        const ciphertext =
            BigInt(
                encrypted.c
            );


        const expectedTag =
            poseidonField(
                poseidon,

                [
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

                    maskResult.raw
                ]
            );


        if (
            expectedTag.toString() !==
            encrypted.tag
        ) {

            throw new Error(
                `PVSS ciphertext integrity check failed for admin ${adminId}.`
            );
        }


        const recoveredShare =
            mod(
                ciphertext -
                maskResult.scalar,
                q
            );


        const expectedShare =
            plaintextShares.find(
                item =>
                    Number(
                        item.x
                    ) ===
                    adminId
            );


        if (
            !expectedShare ||
            recoveredShare !==
            expectedShare.y
        ) {

            throw new Error(
                `PVSS share decryption failed for admin ${adminId}.`
            );
        }


        recoveredShares.push({

            x:
                BigInt(
                    adminId
                ),

            y:
                recoveredShare
        });
    }


    const decryptEnd =
        performance.now();


    // ==================================================
    // 9. Threshold reconstruction self-test
    //
    // Test EVERY t-of-n combination.
    // ==================================================

    const reconstructionStart =
        performance.now();


    const allSubsets =
        combinations(
            recoveredShares,
            t
        );


    let validReconstructions =
        0;


    for (
        const subset
        of allSubsets
    ) {

        const reconstructed =
            reconstructSecret(
                subset,
                q
            );


        if (
            reconstructed !==
            xAnchor
        ) {

            throw new Error(
                "Threshold reconstruction failed for at least one t-of-n subset."
            );
        }


        validReconstructions++;
    }


    const reconstructionEnd =
        performance.now();


    // ==================================================
    // 10. Build PRE-PROOF PVSS_Data
    //
    // π_i^pvss will be generated in the next substep.
    // ==================================================

    const pvssData = {

        version:
            1,

        D_id:
            config.domain.domainId,

        scheme_id:
            config.protocol.schemeId,

        threshold: {

            n,

            t
        },

        encryption: {

            curve:
                "BabyJubJub",

            generator:
                "Base8",

            construction:
                "ECDH-Poseidon-field-mask"
        },

        commitment_scheme:
            "Poseidon hiding coefficient commitments",

        commitments,

        encrypted_shares:
            encryptedShares,

        proofs: [],

        proof_status:
            "pending-pvss-correctness-proofs",

        admin_key_version:
            publicRegistry.key_version
    };


    // ==================================================
    // 11. Private witness material
    //
    // NEVER sent to BAS.
    // ==================================================

    const privateWitness = {

        warning:
            "Laboratory private witness material. Never send this object to BAS.",

        D_id:
            config.domain.domainId,

        scheme_id:
            config.protocol.schemeId,

        aat_nullifier:
            aatNullifier,

        x:
            x.toString(),

        x_anchor:
            xAnchor.toString(),

        anchor_hash_raw:
            anchorResult.raw
                .toString(),

        anchor_reduction_quotient:
            anchorResult.quotient
                .toString(),

        Y:
            Yjson,

        L:
            L.toString(),

        idx_raw:
            idxRaw.toString(),

        idx:
            idx.toString(),

        y_hash:
            yHash.toString(),

        polynomial_coefficients:
            coefficients.map(
                value =>
                    value.toString()
            ),

        commitment_blindings:
            commitmentBlindings.map(
                value =>
                    value.toString()
            ),

        shares:
            privateShareAux
    };


    // ==================================================
    // 12. Save artifacts
    // ==================================================

    const enrollmentId =
        aat.nonce.slice(
            0,
            16
        );


    const publicDir =
        path.join(
            projectRoot,
            "artifacts",
            "enrollment",
            enrollmentId
        );


    const privateDir =
        path.join(
            projectRoot,
            "private",
            "users",
            enrollmentId
        );


    const resultsDir =
        path.join(
            projectRoot,
            "results",
            "enrollment",
            enrollmentId
        );


    fs.mkdirSync(
        publicDir,
        {
            recursive: true
        }
    );


    fs.mkdirSync(
        privateDir,
        {
            recursive: true
        }
    );


    fs.mkdirSync(
        resultsDir,
        {
            recursive: true
        }
    );


    const publicPVSSFile =
        path.join(
            publicDir,
            "pvss_data_preproof.json"
        );


    const privateWitnessFile =
        path.join(
            privateDir,
            "pvss_witness.json"
        );


    fs.writeFileSync(
        publicPVSSFile,

        JSON.stringify(
            pvssData,
            null,
            2
        )
    );


    fs.writeFileSync(
        privateWitnessFile,

        JSON.stringify(
            privateWitness,
            null,
            2
        )
    );


    // ==================================================
    // 13. Experiment report
    // ==================================================

    const report = {

        component:
            "Enrollment PVSS generation",

        enrollment_id:
            enrollmentId,

        D_id:
            config.domain.domainId,

        scheme_id:
            config.protocol.schemeId,

        n,

        t,

        polynomial_degree:
            t - 1,

        commitments:
            commitments.length,

        encrypted_shares:
            encryptedShares.length,

        decryption_self_tests:
            recoveredShares.length,

        reconstruction_subsets_tested:
            allSubsets.length,

        reconstruction_subsets_valid:
            validReconstructions,

        all_decryptions_valid:
            recoveredShares.length === n,

        all_threshold_reconstructions_valid:
            validReconstructions ===
            allSubsets.length,

        public_proof_status:
            "pending",

        timing_ms: {

            crypto_initialization:
                initializationEnd -
                initializationStart,

            user_material:
                userMaterialEnd -
                userStart,

            pvss_generation:
                pvssEnd -
                pvssStart,

            admin_decryption_self_test:
                decryptEnd -
                decryptStart,

            threshold_reconstruction_test:
                reconstructionEnd -
                reconstructionStart
        },

        note: [
            "AAT nullifier is not consumed at this stage.",
            "Plain shares and x_anchor are stored only in the laboratory private witness artifact.",
            "PVSS public correctness proofs are generated in the next substep before Enroll_Package is sent to BAS."
        ]
    };


    const reportFile =
        path.join(
            resultsDir,
            "pvss_generation_report.json"
        );


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

    console.log("");

    console.log(
        "Enrollment user material generated."
    );


    console.log(
        "Shamir threshold:",
        `${t}-of-${n}`
    );


    console.log(
        "Polynomial degree:",
        t - 1
    );


    console.log(
        "Encrypted shares:",
        encryptedShares.length
    );


    console.log(
        "Hiding commitments:",
        commitments.length
    );


    console.log(
        "Admin decryption self-tests:",
        `${recoveredShares.length}/${n} passed`
    );


    console.log(
        "Threshold subsets tested:",
        allSubsets.length
    );


    console.log(
        "Threshold reconstructions:",
        `${validReconstructions}/${allSubsets.length} passed`
    );


    console.log("");

    console.log(
        "L:"
    );

    console.log(
        L.toString()
    );


    console.log(
        "idx:"
    );

    console.log(
        idx.toString()
    );


    console.log(
        "y_hash:"
    );

    console.log(
        yHash.toString()
    );


    console.log("");

    console.log(
        "Public pre-proof PVSS_Data:"
    );

    console.log(
        publicPVSSFile
    );


    console.log("");

    console.log(
        "Private user witness:"
    );

    console.log(
        privateWitnessFile
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
        "PVSS correctness proof status:",
        "PENDING"
    );


    console.log(
        "AAT nullifier consumed:",
        "false"
    );


    console.log(
        "============================================"
    );
}


main()
    .catch(
        error => {

            console.error("");

            console.error(
                "Enrollment PVSS generation failed:"
            );

            console.error(
                error.message
            );

            process.exit(1);
        }
    );