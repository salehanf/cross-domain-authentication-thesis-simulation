const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const {
    buildBabyjub,
    buildPoseidon
} = require("circomlibjs");

const config = require("./config");


// ======================================================
// BabyJub subgroup order
// ======================================================

const BABYJUB_Q =
    2736030358979909402780800718157159386076813972158567259200215660948447373041n;


// ======================================================
// Generic helpers
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

    fs.writeFileSync(
        filePath,
        JSON.stringify(
            data,
            null,
            2
        )
    );
}


function sha256File(filePath) {

    return crypto
        .createHash("sha256")
        .update(
            fs.readFileSync(
                filePath
            )
        )
        .digest("hex");
}


function mod(
    value,
    modulus
) {

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
// Secure random scalar in [1, q-1]
// Rejection sampling avoids modulo bias.
// ======================================================

function randomScalarQ() {

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
// Verify all t-subsets reconstruct same secret
// ======================================================

function verifyThresholdConsistency(
    shares,
    t
) {

    const subsets =
        combinations(
            shares,
            t
        );

    let reference =
        null;

    for (
        const subset
        of subsets
    ) {

        const secret =
            reconstructAtZero(
                subset,
                BABYJUB_Q
            );

        if (
            reference ===
            null
        ) {

            reference =
                secret;
        }

        if (
            secret !==
            reference
        ) {

            throw new Error(
                "Threshold reconstruction mismatch."
            );
        }
    }

    return {
        secret:
            reference,

        subset_count:
            subsets.length
    };
}


// ======================================================
// Epoch policy
// ======================================================

function requireSameEpoch(
    states
) {

    const epochs =
        new Set(
            states.map(
                item =>
                    Number(
                        item.share_epoch
                    )
            )
        );

    if (
        epochs.size !==
        1
    ) {

        throw new Error(
            "Mixed share epochs are not allowed."
        );
    }

    return [
        ...epochs
    ][0];
}


// ======================================================
// Find latest SignedRoot
// ======================================================

function findLatestSignedRoot(
    rootsDir
) {

    const files =
        fs.readdirSync(
            rootsDir
        )
        .filter(
            name =>
                /^signed_root_v\d+\.json$/i
                    .test(name)
        );

    if (
        files.length ===
        0
    ) {

        throw new Error(
            "No SignedRoot files found."
        );
    }

    files.sort(
        (a, b) => {

            const av =
                Number(
                    a.match(
                        /v(\d+)/i
                    )[1]
                );

            const bv =
                Number(
                    b.match(
                        /v(\d+)/i
                    )[1]
                );

            return bv - av;
        }
    );

    return path.join(
        rootsDir,
        files[0]
    );
}


// ======================================================
// Evaluate zero-constant refresh polynomial
//
// g_j(z) = b_1*z + ... + b_(t-1)*z^(t-1)
// ======================================================

function evaluateZeroPolynomial(
    coefficients,
    alpha
) {

    let result =
        0n;

    let power =
        alpha;

    for (
        const coefficient
        of coefficients
    ) {

        result =
            mod(
                result +
                coefficient * power,
                BABYJUB_Q
            );

        power =
            mod(
                power * alpha,
                BABYJUB_Q
            );
    }

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
            "Usage: node src\\proactive-refresh.js <enrollment-id>"
        );
    }


    const projectRoot =
        config.paths.projectRoot;

    const tags =
        config.protocol?.tags ??
        config.tags;


    if (
        !tags ||
        tags.revoke === undefined
    ) {

        throw new Error(
            "Required revoke protocol tag is missing."
        );
    }


    // ==================================================
    // Paths
    // ==================================================

    const shareDir =
        path.join(
            projectRoot,
            "private",
            "admin_shares",
            enrollmentId
        );

    const enrollmentDir =
        path.join(
            projectRoot,
            "artifacts",
            "enrollment",
            enrollmentId
        );

    const enrollPackageFile =
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

    const rootsDir =
        path.join(
            projectRoot,
            "state",
            "roots"
        );

    const reportDir =
        path.join(
            projectRoot,
            "results",
            "refresh",
            enrollmentId
        );


    // ==================================================
    // Load current private share states
    // ==================================================

    if (
        !fs.existsSync(
            shareDir
        )
    ) {

        throw new Error(
            "Administrator share state does not exist. Run bootstrap first."
        );
    }


    const shareFiles =
        fs.readdirSync(
            shareDir
        )
        .filter(
            name =>
                /^admin_\d+\.json$/i
                    .test(name)
        )
        .sort();


    if (
        shareFiles.length ===
        0
    ) {

        throw new Error(
            "No administrator share files found."
        );
    }


    const states =
        shareFiles.map(
            name => {

                const filePath =
                    path.join(
                        shareDir,
                        name
                    );

                return {
                    filePath,
                    state:
                        loadJson(
                            filePath
                        )
                };
            }
        );


    const currentEpoch =
        requireSameEpoch(
            states.map(
                item =>
                    item.state
            )
        );


    const first =
        states[0].state;

    const n =
        Number(
            first.threshold.n
        );

    const t =
        Number(
            first.threshold.t
        );


    if (
        states.length !==
        n
    ) {

        throw new Error(
            `Expected ${n} administrator shares, found ${states.length}.`
        );
    }


    for (
        const item
        of states
    ) {

        const state =
            item.state;

        if (
            String(
                state.enrollment_id
            ) !==
            enrollmentId
        ) {

            throw new Error(
                "Share-state enrollment ID mismatch."
            );
        }


        if (
            String(
                state.D_id
            ) !==
            String(
                first.D_id
            ) ||
            String(
                state.scheme_id
            ) !==
            String(
                first.scheme_id
            )
        ) {

            throw new Error(
                "Share-state domain/scheme mismatch."
            );
        }


        if (
            Number(
                state.threshold.n
            ) !== n ||
            Number(
                state.threshold.t
            ) !== t
        ) {

            throw new Error(
                "Share-state threshold mismatch."
            );
        }
    }


    // ==================================================
    // Verify ACTIVE BAS record
    // ==================================================

    const enrollPackage =
        loadJson(
            enrollPackageFile
        );

    const registry =
        loadJson(
            registryFile
        );

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
            "Enrollment is absent from BAS registry."
        );
    }


    if (
        registryEntry.status !==
        "active"
    ) {

        throw new Error(
            `Refresh target is not active: ${registryEntry.status}`
        );
    }


    // ==================================================
    // Snapshot public state BEFORE refresh
    // ==================================================

    const signedRootFile =
        findLatestSignedRoot(
            rootsDir
        );

    const signedRootBefore =
        loadJson(
            signedRootFile
        );

    const signedRootHashBefore =
        sha256File(
            signedRootFile
        );

    const registryHashBefore =
        sha256File(
            registryFile
        );

    const enrollmentHashBefore =
        sha256File(
            enrollPackageFile
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


    function pointToJson(
        point
    ) {

        return {
            x:
                babyJub.F
                    .toString(
                        point[0]
                    ),

            y:
                babyJub.F
                    .toString(
                        point[1]
                    )
        };
    }


    function pointsEqual(
        left,
        right
    ) {

        return (
            babyJub.F.toString(
                left[0]
            ) ===
            babyJub.F.toString(
                right[0]
            ) &&
            babyJub.F.toString(
                left[1]
            ) ===
            babyJub.F.toString(
                right[1]
            )
        );
    }


    const domainId =
        BigInt(
            first.D_id
        );

    const schemeId =
        BigInt(
            first.scheme_id
        );


    // ==================================================
    // Load old shares
    // ==================================================

    let oldShares =
        states.map(
            item => ({
                admin_id:
                    Number(
                        item.state.admin_id
                    ),

                x:
                    BigInt(
                        item.state.alpha
                    ),

                y:
                    BigInt(
                        item.state.share
                    ),

                epoch:
                    Number(
                        item.state.share_epoch
                    )
            })
        );


    // ==================================================
    // Validate epoch-0/current shares before refresh
    // ==================================================

    const oldValidation =
        verifyThresholdConsistency(
            oldShares,
            t
        );

    let oldSecret =
        oldValidation.secret;


    // ==================================================
    // Bind current shares to active y_hash
    // ==================================================

    const oldYPoint =
        babyJub.mulPointEscalar(
            babyJub.Base8,
            oldSecret
        );

    const oldY =
        pointToJson(
            oldYPoint
        );

    const oldDerivedYHash =
        poseidonField([
            BigInt(
                tags.revoke
            ),

            schemeId,
            domainId,

            BigInt(
                oldY.x
            ),

            BigInt(
                oldY.y
            )
        ]);


    if (
        oldDerivedYHash.toString() !==
        yHash
    ) {

        throw new Error(
            "Current administrator shares do not bind to active enrollment y_hash."
        );
    }


    // ==================================================
    // Refresh starts
    // ==================================================

    const refreshStart =
        process.hrtime.bigint();

    const nextEpoch =
        currentEpoch + 1;


    // ==================================================
    // Each admin creates:
    //
    // g_j(z) =
    // b_j,1*z + ... + b_j,t-1*z^(t-1)
    //
    // constant term = 0
    // ==================================================

    const polynomialStart =
        process.hrtime.bigint();

    let refreshPolynomials =
        [];

    const publicCommitments =
        [];


    for (
        let senderId = 1;
        senderId <= n;
        senderId++
    ) {

        const coefficients =
            [];

        const commitments =
            [];


        for (
            let k = 1;
            k <= t - 1;
            k++
        ) {

            const coefficient =
                randomScalarQ();

            coefficients.push(
                coefficient
            );


            const commitmentPoint =
                babyJub.mulPointEscalar(
                    babyJub.Base8,
                    coefficient
                );


            commitments.push(
                commitmentPoint
            );
        }


        refreshPolynomials.push({
            sender_id:
                senderId,

            coefficients,

            commitments
        });


        publicCommitments.push({
            sender_id:
                senderId,

            coefficients_committed:
                commitments.map(
                    (point, index) => ({
                        degree:
                            index + 1,

                        commitment:
                            pointToJson(
                                point
                            )
                    })
                )
        });
    }


    const polynomialEnd =
        process.hrtime.bigint();


    // ==================================================
    // Delta generation + Feldman verification
    //
    // Δ_j->i = g_j(alpha_i)
    //
    // g^Δ ?=
    // product_k C_j,k ^ alpha_i^k
    //
    // Additive BabyJub notation:
    //
    // Base8*Δ ?=
    // sum_k alpha_i^k * C_j,k
    // ==================================================

    const deltaStart =
        process.hrtime.bigint();

    let deltaRecords =
        [];

    let verificationCount =
        0;


    for (
        const polynomial
        of refreshPolynomials
    ) {

        for (
            const recipient
            of oldShares
        ) {

            const alpha =
                recipient.x;


            const delta =
                evaluateZeroPolynomial(
                    polynomial.coefficients,
                    alpha
                );


            // ------------------------------------------
            // Left = Base8 * delta
            // ------------------------------------------

            const left =
                babyJub.mulPointEscalar(
                    babyJub.Base8,
                    delta
                );


            // ------------------------------------------
            // Right =
            // Σ C_j,k * alpha^k
            // ------------------------------------------

            let right =
                null;

            let alphaPower =
                alpha;


            for (
                let k = 0;
                k <
                polynomial.commitments.length;
                k++
            ) {

                const term =
                    babyJub.mulPointEscalar(
                        polynomial
                            .commitments[k],
                        alphaPower
                    );


                if (
                    right ===
                    null
                ) {

                    right =
                        term;
                }
                else {

                    right =
                        babyJub.addPoint(
                            right,
                            term
                        );
                }


                alphaPower =
                    mod(
                        alphaPower *
                        alpha,
                        BABYJUB_Q
                    );
            }


            if (
                right ===
                null ||
                !pointsEqual(
                    left,
                    right
                )
            ) {

                throw new Error(
                    `Refresh commitment verification failed: sender ${polynomial.sender_id}, recipient ${recipient.admin_id}`
                );
            }


            verificationCount++;


            deltaRecords.push({
                sender_id:
                    polynomial.sender_id,

                recipient_id:
                    recipient.admin_id,

                recipient_alpha:
                    alpha,

                delta
            });
        }
    }


    const deltaEnd =
        process.hrtime.bigint();


    // ==================================================
    // Aggregate deltas and create new shares
    //
    // Δ_i = Σ_j Δ_j->i
    //
    // s'_i = s_i + Δ_i mod q
    // ==================================================

    const updateStart =
        process.hrtime.bigint();

    let newShares =
        [];


    for (
        const oldShare
        of oldShares
    ) {

        const incoming =
            deltaRecords.filter(
                item =>
                    item.recipient_id ===
                    oldShare.admin_id
            );


        if (
            incoming.length !==
            n
        ) {

            throw new Error(
                `Expected ${n} deltas for admin ${oldShare.admin_id}.`
            );
        }


        let totalDelta =
            0n;


        for (
            const item
            of incoming
        ) {

            totalDelta =
                mod(
                    totalDelta +
                    item.delta,
                    BABYJUB_Q
                );
        }


        const newShare =
            mod(
                oldShare.y +
                totalDelta,
                BABYJUB_Q
            );


        newShares.push({
            admin_id:
                oldShare.admin_id,

            x:
                oldShare.x,

            y:
                newShare,

            epoch:
                nextEpoch
        });
    }


    const updateEnd =
        process.hrtime.bigint();


    // ==================================================
    // Validate NEW shares
    // ==================================================

    const verifyStart =
        process.hrtime.bigint();


    const newValidation =
        verifyThresholdConsistency(
            newShares,
            t
        );

    let newSecret =
        newValidation.secret;


    if (
        newSecret !==
        oldSecret
    ) {

        throw new Error(
            "Refresh changed x_anchor."
        );
    }


    // ==================================================
    // Derive y_hash again from refreshed shares
    // ==================================================

    const newYPoint =
        babyJub.mulPointEscalar(
            babyJub.Base8,
            newSecret
        );

    const newY =
        pointToJson(
            newYPoint
        );

    const newDerivedYHash =
        poseidonField([
            BigInt(
                tags.revoke
            ),

            schemeId,
            domainId,

            BigInt(
                newY.x
            ),

            BigInt(
                newY.y
            )
        ]);


    if (
        newDerivedYHash.toString() !==
        yHash
    ) {

        throw new Error(
            "Refreshed shares no longer bind to enrollment y_hash."
        );
    }


    // ==================================================
    // Check that shares actually changed
    // ==================================================

    let changedShareCount =
        0;


    for (
        let i = 0;
        i < oldShares.length;
        i++
    ) {

        if (
            oldShares[i].y !==
            newShares[i].y
        ) {

            changedShareCount++;
        }
    }


    if (
        changedShareCount ===
        0
    ) {

        throw new Error(
            "Refresh produced no changed shares."
        );
    }


    // ==================================================
    // Mixed-epoch policy test
    //
    // Reconstruction layer MUST reject shares from
    // different epochs before using them.
    // ==================================================

    let mixedEpochRejected =
        false;


    try {

        requireSameEpoch([
            {
                share_epoch:
                    currentEpoch
            },
            {
                share_epoch:
                    nextEpoch
            }
        ]);

    }
    catch {

        mixedEpochRejected =
            true;
    }


    if (
        !mixedEpochRejected
    ) {

        throw new Error(
            "Mixed-epoch policy self-test failed."
        );
    }


    const verifyEnd =
        process.hrtime.bigint();


    // ==================================================
    // Commit new private shares
    //
    // All cryptographic validation has already succeeded
    // before this point.
    //
    // Old share values are overwritten logically.
    // No epoch-0 backup is retained.
    // ==================================================

    const commitStart =
        process.hrtime.bigint();

    const refreshedAt =
        new Date()
            .toISOString();


    for (
        const newShare
        of newShares
    ) {

        const adminName =
            String(
                newShare.admin_id
            ).padStart(
                2,
                "0"
            );

        const currentState =
            states.find(
                item =>
                    Number(
                        item.state.admin_id
                    ) ===
                    newShare.admin_id
            );


        if (!currentState) {

            throw new Error(
                `Current state missing for admin ${newShare.admin_id}.`
            );
        }


        const updatedState = {

            ...currentState.state,

            share_epoch:
                nextEpoch,

            share:
                newShare.y.toString(),

            source:
                "proactive-refresh",

            refreshed_at:
                refreshedAt
        };


        fs.writeFileSync(
            currentState.filePath,
            JSON.stringify(
                updatedState,
                null,
                2
            )
        );
    }


    const commitEnd =
        process.hrtime.bigint();


    // ==================================================
    // Verify committed epoch
    // ==================================================

    const committedStates =
        shareFiles.map(
            name =>
                loadJson(
                    path.join(
                        shareDir,
                        name
                    )
                )
        );


    const committedEpoch =
        requireSameEpoch(
            committedStates
        );


    if (
        committedEpoch !==
        nextEpoch
    ) {

        throw new Error(
            "Committed refresh epoch mismatch."
        );
    }


    // ==================================================
    // Public-state invariant check
    //
    // Refresh MUST NOT change:
    // - SignedRoot
    // - BAS registry
    // - Enroll_Package
    // - L
    // - idx
    // - y_hash
    // ==================================================

    const signedRootHashAfter =
        sha256File(
            signedRootFile
        );

    const registryHashAfter =
        sha256File(
            registryFile
        );

    const enrollmentHashAfter =
        sha256File(
            enrollPackageFile
        );


    const signedRootUnchanged =
        signedRootHashBefore ===
        signedRootHashAfter;

    const registryUnchanged =
        registryHashBefore ===
        registryHashAfter;

    const enrollmentUnchanged =
        enrollmentHashBefore ===
        enrollmentHashAfter;


    if (
        !signedRootUnchanged ||
        !registryUnchanged ||
        !enrollmentUnchanged
    ) {

        throw new Error(
            "Public protocol state changed during proactive refresh."
        );
    }


    const refreshEnd =
        process.hrtime.bigint();


    // ==================================================
    // Timings
    // ==================================================

    function elapsedMs(
        start,
        end
    ) {

        return (
            Number(
                end - start
            ) / 1e6
        );
    }


    const polynomialMs =
        elapsedMs(
            polynomialStart,
            polynomialEnd
        );

    const deltaMs =
        elapsedMs(
            deltaStart,
            deltaEnd
        );

    const updateMs =
        elapsedMs(
            updateStart,
            updateEnd
        );

    const verifyMs =
        elapsedMs(
            verifyStart,
            verifyEnd
        );

    const commitMs =
        elapsedMs(
            commitStart,
            commitEnd
        );

    const totalMs =
        elapsedMs(
            refreshStart,
            refreshEnd
        );


    // ==================================================
    // Non-secret report
    // ==================================================

    const reportFile =
        path.join(
            reportDir,
            `epoch_${nextEpoch}_report.json`
        );


    const report = {

        version:
            1,

        phase:
            "proactive-share-refresh",

        enrollment_id:
            enrollmentId,

        D_id:
            String(
                first.D_id
            ),

        scheme_id:
            String(
                first.scheme_id
            ),

        threshold: {
            n,
            t
        },

        epoch: {
            from:
                currentEpoch,

            to:
                nextEpoch
        },

        active_record:
            true,

        refresh_polynomials:
            n,

        polynomial_degree:
            t - 1,

        zero_constant_term:
            true,

        public_commitment_count:
            n * (t - 1),

        public_commitments:
            publicCommitments,

        delta_evaluations:
            n * n,

        peer_delta_messages:
            n * (n - 1),

        local_self_deltas:
            n,

        delta_commitment_verifications:
            verificationCount,

        old_threshold_subsets_valid:
            oldValidation.subset_count,

        new_threshold_subsets_valid:
            newValidation.subset_count,

        shares_changed:
            changedShareCount,

        x_anchor_unchanged:
            true,

        x_anchor_exposed:
            false,

        y_hash_unchanged:
            true,

        mixed_epoch_policy:
            "REJECT",

        mixed_epoch_self_test:
            mixedEpochRejected,

        public_state_invariants: {

            signed_root_version:
                Number(
                    signedRootBefore.version
                ),

            signed_root_root:
                String(
                    signedRootBefore.root
                ),

            signed_root_unchanged:
                signedRootUnchanged,

            bas_registry_unchanged:
                registryUnchanged,

            enrollment_package_unchanged:
                enrollmentUnchanged,

            L_unchanged:
                true,

            idx_unchanged:
                true,

            y_hash_unchanged:
                true
        },

        sensitive_data_written_to_report: {
            x_anchor:
                false,

            old_shares:
                false,

            new_shares:
                false,

            deltas:
                false,

            polynomial_coefficients:
                false
        },

        cleanup: {

            old_share_files_retained:
                false,

            old_share_values_logically_replaced:
                true,

            forensic_secure_erase_claimed:
                false
        },

        timings_ms: {

            polynomial_and_commitments:
                polynomialMs,

            delta_generation_and_verification:
                deltaMs,

            share_update:
                updateMs,

            threshold_and_invariant_verification:
                verifyMs,

            private_share_commit:
                commitMs,

            total_refresh:
                totalMs
        }
    };


    saveJson(
        reportFile,
        report
    );


    // ==================================================
    // Best-effort logical cleanup
    //
    // JS BigInt objects cannot provide a forensic memory
    // wipe guarantee.
    // ==================================================

    oldSecret =
        0n;

    newSecret =
        0n;


    for (
        const polynomial
        of refreshPolynomials
    ) {

        for (
            let i = 0;
            i <
            polynomial.coefficients.length;
            i++
        ) {

            polynomial.coefficients[i] =
                0n;
        }

        polynomial.coefficients =
            [];

        polynomial.commitments =
            [];
    }


    for (
        const item
        of deltaRecords
    ) {

        item.delta =
            0n;
    }


    for (
        const item
        of oldShares
    ) {

        item.y =
            0n;
    }


    for (
        const item
        of newShares
    ) {

        item.y =
            0n;
    }


    refreshPolynomials =
        [];

    deltaRecords =
        [];

    oldShares =
        [];

    newShares =
        [];


    // ==================================================
    // Output
    // ==================================================

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - Proactive Share Refresh"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Enrollment ID              : ${enrollmentId}`
    );

    console.log(
        `BAS status                 : ACTIVE`
    );

    console.log(
        `Threshold                  : ${t}-of-${n}`
    );

    console.log(
        `Epoch                      : ${currentEpoch} -> ${nextEpoch}`
    );

    console.log("");

    console.log(
        `Zero-constant polynomials  : ${n}`
    );

    console.log(
        `Public commitments         : ${n * (t - 1)}`
    );

    console.log(
        `Delta evaluations          : ${n * n}`
    );

    console.log(
        `Peer delta messages        : ${n * (n - 1)}`
    );

    console.log(
        `Commitment verifications   : ${verificationCount}/${n * n} VALID`
    );

    console.log("");

    console.log(
        `Old threshold subsets      : ${oldValidation.subset_count}/${oldValidation.subset_count} VALID`
    );

    console.log(
        `New threshold subsets      : ${newValidation.subset_count}/${newValidation.subset_count} VALID`
    );

    console.log(
        `Shares changed             : ${changedShareCount}/${n}`
    );

    console.log(
        "x_anchor unchanged         : YES"
    );

    console.log(
        "x_anchor exposed           : NO"
    );

    console.log(
        "y_hash unchanged           : YES"
    );

    console.log(
        "Mixed epoch reconstruction : REJECTED"
    );

    console.log("");

    console.log(
        `SignedRoot v${signedRootBefore.version} unchanged     : ${signedRootUnchanged ? "YES" : "NO"}`
    );

    console.log(
        `BAS registry unchanged     : ${registryUnchanged ? "YES" : "NO"}`
    );

    console.log(
        `Enroll_Package unchanged   : ${enrollmentUnchanged ? "YES" : "NO"}`
    );

    console.log(
        "L / idx / y_hash unchanged : YES"
    );

    console.log("");

    console.log(
        `Polynomial + commitments   : ${polynomialMs.toFixed(3)} ms`
    );

    console.log(
        `Delta gen + verification   : ${deltaMs.toFixed(3)} ms`
    );

    console.log(
        `Share update               : ${updateMs.toFixed(3)} ms`
    );

    console.log(
        `Threshold verification     : ${verifyMs.toFixed(3)} ms`
    );

    console.log(
        `Private share commit       : ${commitMs.toFixed(3)} ms`
    );

    console.log(
        `Total refresh              : ${totalMs.toFixed(3)} ms`
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
    .catch(
        error => {

            console.error(
                ""
            );

            console.error(
                "Proactive refresh failed:"
            );

            console.error(
                error.message
            );

            process.exitCode =
                1;
        }
    );