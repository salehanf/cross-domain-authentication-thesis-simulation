const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const snarkjs = require("snarkjs");

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
        throw new Error(`File not found: ${filePath}`);
    }

    return JSON.parse(
        fs.readFileSync(filePath, "utf8")
    );
}


function writeJsonAtomic(filePath, data) {

    const dir =
        path.dirname(filePath);

    fs.mkdirSync(
        dir,
        { recursive: true }
    );

    const tempFile =
        `${filePath}.tmp`;

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


function sameSignals(actual, expected) {

    if (actual.length !== expected.length) {
        return false;
    }

    for (
        let i = 0;
        i < actual.length;
        i++
    ) {

        if (
            String(actual[i]) !==
            String(expected[i])
        ) {
            return false;
        }
    }

    return true;
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
                    b.version -
                    a.version
            );


    if (candidates.length === 0) {

        throw new Error(
            "No SignedRoot state found."
        );
    }


    const latest =
        candidates[0];


    return {
        file:
            latest.file,

        signedRoot:
            loadJson(latest.file)
    };
}


function getAatCanonicalPayload(AAT) {

    return JSON.stringify([
        "AAT",

        String(AAT.D_id),

        String(AAT.scheme_id),

        String(AAT.purpose),

        String(AAT.nonce),

        String(AAT.issued_at),

        String(AAT.expires_at),

        String(AAT.key_id)
    ]);
}


function computeAatNullifier(AAT) {

    const canonical =
        JSON.stringify([
            "AAT-null",

            String(AAT.D_id),

            String(AAT.scheme_id),

            String(AAT.purpose),

            String(AAT.nonce)
        ]);


    return sha256Hex(
        Buffer.from(
            canonical,
            "utf8"
        )
    );
}


// ======================================================
// Main
// ======================================================

async function main() {

    const enrollmentId =
        process.argv[2];


    if (!enrollmentId) {

        throw new Error(
            "Usage: node src\\bas-verify-enrollment.js <enrollment-id>"
        );
    }


    const projectRoot =
        config.paths.projectRoot;


    const depth =
        Number(
            config.smt?.depth ??
            config.protocol?.smt?.depth ??
            20
        );


    // ==================================================
    // Paths
    // ==================================================

    const packageFile =
        path.join(
            projectRoot,
            "artifacts",
            "enrollment",
            enrollmentId,
            "enroll_package.json"
        );


    const pvssVerificationKeyFile =
        path.join(
            projectRoot,
            "build",
            "pvss_share",
            "verification_key.json"
        );


    const linkVerificationKeyFile =
        path.join(
            projectRoot,
            "build",
            "link_proof",
            "verification_key.json"
        );


    const pvssAdminKeysFile =
        path.join(
            projectRoot,
            "state",
            "pvss",
            "admin_public_keys.json"
        );


    const rootsDir =
        path.join(
            projectRoot,
            "state",
            "roots"
        );


    const basStateDir =
        path.join(
            projectRoot,
            "state",
            "bas"
        );


    const registryFile =
        path.join(
            basStateDir,
            "enrollment_registry.json"
        );


    const consumedAatFile =
        path.join(
            basStateDir,
            "consumed_aat_nullifiers.json"
        );


    const reportDir =
        path.join(
            projectRoot,
            "results",
            "enrollment",
            enrollmentId
        );


    const reportFile =
        path.join(
            reportDir,
            "bas_verification_report.json"
        );


    fs.mkdirSync(
        basStateDir,
        { recursive: true }
    );


    fs.mkdirSync(
        reportDir,
        { recursive: true }
    );


    // ==================================================
    // Load package
    // ==================================================

    const enrollPackage =
        loadJson(packageFile);


    const AAT =
        enrollPackage.AAT;


    const pvssData =
        enrollPackage.PVSS_Data;


    const linkData =
        enrollPackage.proof_link_ZK;


    if (
        !AAT ||
        !pvssData ||
        !linkData
    ) {

        throw new Error(
            "Enroll_Package is incomplete."
        );
    }


    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - BAS Enrollment Verify"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Enrollment ID: ${enrollmentId}`
    );

    console.log("");


    // ==================================================
    // 1. Package domain/scheme consistency
    // ==================================================

    const expectedDomainId =
        String(
            config.domain.domainId
        );


    const expectedSchemeId =
        String(
            config.protocol.schemeId
        );


    if (
        String(enrollPackage.D_id) !==
        expectedDomainId
    ) {

        throw new Error(
            "Enroll_Package D_id mismatch."
        );
    }


    if (
        String(enrollPackage.scheme_id) !==
        expectedSchemeId
    ) {

        throw new Error(
            "Enroll_Package scheme_id mismatch."
        );
    }


    if (
        String(AAT.D_id) !==
        expectedDomainId
    ) {

        throw new Error(
            "AAT D_id mismatch."
        );
    }


    if (
        String(AAT.scheme_id) !==
        expectedSchemeId
    ) {

        throw new Error(
            "AAT scheme_id mismatch."
        );
    }


    if (
        String(pvssData.D_id) !==
        expectedDomainId ||
        String(pvssData.scheme_id) !==
        expectedSchemeId
    ) {

        throw new Error(
            "PVSS_Data domain/scheme mismatch."
        );
    }


    console.log(
        "Domain / scheme consistency : VALID"
    );


    // ==================================================
    // 2. AAT purpose
    // ==================================================

    if (
        AAT.purpose !==
        "enroll"
    ) {

        throw new Error(
            `Invalid AAT purpose: ${AAT.purpose}`
        );
    }


    console.log(
        "AAT purpose                 : VALID"
    );


    // ==================================================
    // 3. AAT time validity
    // ==================================================

    const now =
        Date.now();


    const issuedAt =
        Date.parse(
            AAT.issued_at
        );


    const expiresAt =
        Date.parse(
            AAT.expires_at
        );


    if (
        !Number.isFinite(issuedAt) ||
        !Number.isFinite(expiresAt)
    ) {

        throw new Error(
            "Invalid AAT timestamps."
        );
    }


    if (
        now < issuedAt
    ) {

        throw new Error(
            "AAT is not valid yet."
        );
    }


    if (
        now > expiresAt
    ) {

        throw new Error(
            `AAT expired at ${AAT.expires_at}`
        );
    }


    console.log(
        "AAT temporal validity       : VALID"
    );


    // ==================================================
    // 4. AAT FROST signature
    // ==================================================

    const aatCanonical =
        getAatCanonicalPayload(
            AAT
        );


    const aatDigest =
        sha256Buffer(
            Buffer.from(
                aatCanonical,
                "utf8"
            )
        );


    const aatSignatureValid =
        await verifyMessage(
            aatDigest,
            AAT.signature
        );


    if (!aatSignatureValid) {

        throw new Error(
            "AAT FROST signature invalid."
        );
    }


    console.log(
        "AAT FROST signature         : VALID"
    );


    // ==================================================
    // 5. Load latest SignedRoot
    // ==================================================

    const {
        signedRoot:
            previousSignedRoot,

        file:
            previousSignedRootFile
    } =
        getLatestSignedRoot(
            rootsDir
        );


    const previousRootValid =
        await verifySignedRoot(
            previousSignedRoot
        );


    if (!previousRootValid) {

        throw new Error(
            "Current SignedRoot signature invalid."
        );
    }


    if (
        String(previousSignedRoot.D_id) !==
        expectedDomainId ||
        String(previousSignedRoot.scheme_id) !==
        expectedSchemeId
    ) {

        throw new Error(
            "Current SignedRoot domain/scheme mismatch."
        );
    }


    if (
        String(AAT.key_id) !==
        String(previousSignedRoot.key_id)
    ) {

        throw new Error(
            "AAT key_id does not match current domain key."
        );
    }


    console.log(
        `Current SignedRoot           : v${previousSignedRoot.version} VALID`
    );


    // ==================================================
    // 6. AAT nullifier
    // ==================================================

    const aatNullifier =
        computeAatNullifier(
            AAT
        );


    const consumedState =
        fs.existsSync(consumedAatFile)
            ? loadJson(consumedAatFile)
            : {
                version: 1,
                nullifiers: []
            };


    if (
        consumedState.nullifiers
            .some(
                item =>
                    String(item.nullifier) ===
                    aatNullifier
            )
    ) {

        throw new Error(
            "AAT nullifier already consumed."
        );
    }


    console.log(
        "AAT nullifier               : UNUSED"
    );


    // ==================================================
    // 7. Verify PVSS proofs
    // ==================================================

    const pvssVk =
        loadJson(
            pvssVerificationKeyFile
        );


    const adminRegistry =
        loadJson(
            pvssAdminKeysFile
        );


    if (
        !Array.isArray(pvssData.proofs) ||
        pvssData.proofs.length !==
        Number(pvssData.threshold.n)
    ) {

        throw new Error(
            "PVSS proof count invalid."
        );
    }


    let verifiedPvssProofs =
        0;


    for (
        let adminId = 1;
        adminId <= Number(pvssData.threshold.n);
        adminId++
    ) {

        const proofRecord =
            pvssData.proofs.find(
                item =>
                    Number(item.admin_id) ===
                    adminId
            );


        const encryptedShare =
            pvssData.encrypted_shares.find(
                item =>
                    Number(item.admin_id) ===
                    adminId
            );


        const adminPublic =
            adminRegistry.admins.find(
                item =>
                    Number(item.admin_id) ===
                    adminId
            );


        if (
            !proofRecord ||
            !encryptedShare ||
            !adminPublic
        ) {

            throw new Error(
                `Incomplete PVSS data for admin ${adminId}.`
            );
        }


        const expectedSignals = [

            String(
                pvssData.D_id
            ),

            String(
                pvssData.scheme_id
            ),

            String(
                adminId
            ),

            String(
                adminPublic.public_key.x
            ),

            String(
                adminPublic.public_key.y
            ),

            String(
                encryptedShare.R.x
            ),

            String(
                encryptedShare.R.y
            ),

            String(
                encryptedShare.c
            ),

            String(
                encryptedShare.tag
            ),

            String(
                pvssData.commitments[0]
                    .commitment
            ),

            String(
                pvssData.commitments[1]
                    .commitment
            ),

            String(
                pvssData.commitments[2]
                    .commitment
            )
        ];


        if (
            !sameSignals(
                proofRecord.public_signals,
                expectedSignals
            )
        ) {

            throw new Error(
                `PVSS public statement mismatch for admin ${adminId}.`
            );
        }


        const valid =
            await snarkjs
                .groth16
                .verify(
                    pvssVk,
                    proofRecord.public_signals,
                    proofRecord.proof
                );


        if (!valid) {

            throw new Error(
                `PVSS Groth16 proof invalid for admin ${adminId}.`
            );
        }


        verifiedPvssProofs++;
    }


    console.log(
        `PVSS Groth16 proofs          : ${verifiedPvssProofs}/${pvssData.threshold.n} VALID`
    );


    // ==================================================
    // 8. Verify Link proof statement binding
    // ==================================================

    const expectedLinkSignals = [

        String(
            enrollPackage.D_id
        ),

        String(
            enrollPackage.scheme_id
        ),

        String(
            enrollPackage.L
        ),

        String(
            enrollPackage.idx
        ),

        String(
            enrollPackage.y_hash
        ),

        String(
            pvssData.commitments[0]
                .commitment
        ),

        String(
            pvssData.commitments[1]
                .commitment
        ),

        String(
            pvssData.commitments[2]
                .commitment
        )
    ];


    if (
        !sameSignals(
            linkData.public_signals,
            expectedLinkSignals
        )
    ) {

        throw new Error(
            "Link proof public statement mismatch."
        );
    }


    const linkVk =
        loadJson(
            linkVerificationKeyFile
        );


    const linkValid =
        await snarkjs
            .groth16
            .verify(
                linkVk,
                linkData.public_signals,
                linkData.proof
            );


    if (!linkValid) {

        throw new Error(
            "Link Groth16 proof invalid."
        );
    }


    console.log(
        "Link Groth16 proof           : VALID"
    );


    // ==================================================
    // 9. Load BAS non-identifying registry
    // ==================================================

    const registry =
        fs.existsSync(registryFile)
            ? loadJson(registryFile)
            : {
                version: 1,

                entries: {}
            };


    const yHash =
        String(
            enrollPackage.y_hash
        );


    if (
        registry.entries[yHash] &&
        registry.entries[yHash].status ===
        "active"
    ) {

        throw new Error(
            "y_hash is already registered as active."
        );
    }


    // ==================================================
    // 10. Rebuild current SMT from BAS registry
    //
    // This avoids storing internal tree nodes in BAS state.
    // ==================================================

    const tree =
        await createSparseMerkleTree(
            depth
        );


    const activeEntries =
        Object.values(
            registry.entries
        ).filter(
            entry =>
                entry.status ===
                "active"
        );


    const usedIndices =
        new Set();


    for (
        const entry
        of activeEntries
    ) {

        const idx =
            Number(
                entry.idx
            );


        if (
            usedIndices.has(idx)
        ) {

            throw new Error(
                `BAS state has duplicate active SMT index ${idx}.`
            );
        }


        usedIndices.add(idx);


        tree.insert(
            idx,
            BigInt(entry.L)
        );
    }


    const reconstructedRoot =
        tree.getRootString();


    if (
        String(reconstructedRoot) !==
        String(previousSignedRoot.root)
    ) {

        throw new Error(
            "Reconstructed SMT root does not match current SignedRoot."
        );
    }


    console.log(
        "Current SMT reconstruction   : VALID"
    );


    // ==================================================
    // 11. idx availability
    // ==================================================

    const newIdx =
        Number(
            enrollPackage.idx
        );


    if (
        !Number.isSafeInteger(newIdx) ||
        newIdx < 0 ||
        newIdx >= 2 ** depth
    ) {

        throw new Error(
            "Enrollment idx is outside current SMT range."
        );
    }


    if (
        usedIndices.has(newIdx)
    ) {

        throw new Error(
            "Enrollment idx is already occupied by an active leaf."
        );
    }


    console.log(
        "SMT idx availability         : AVAILABLE"
    );


    // ==================================================
    // 12. Insert (idx, L)
    // ==================================================

    tree.insert(
        newIdx,
        BigInt(
            enrollPackage.L
        )
    );


    const newRoot =
        tree.getRootString();


    console.log(
        "SMT insertion                : SUCCESS"
    );


    // ==================================================
    // 13. Create new SignedRoot
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


    const newVersion =
        Number(
            previousSignedRoot.version
        ) + 1;


    const newSignedRoot = {

        D_id:
            enrollPackage.D_id,

        scheme_id:
            enrollPackage.scheme_id,

        root:
            newRoot,

        version:
            newVersion,

        timestamp:
            new Date().toISOString(),

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


    const signatureResult =
        await signMessage(
            rootDigest,
            `signed_root_v${newVersion}`
        );


    newSignedRoot.signature =
        signatureResult.signatureHex;


    const newSignedRootValid =
        await verifySignedRoot(
            newSignedRoot
        );


    if (!newSignedRootValid) {

        throw new Error(
            "New SignedRoot failed verification."
        );
    }


    console.log(
        `New SignedRoot              : v${newVersion} VALID`
    );


    // ==================================================
    // 14. Prepare new BAS state
    //
    // No real-world identity is stored.
    // ==================================================

    registry.entries[yHash] = {

        idx:
            String(
                enrollPackage.idx
            ),

        L:
            String(
                enrollPackage.L
            ),

        status:
            "active",

        version:
            newVersion
    };


    consumedState.nullifiers.push({

        nullifier:
            aatNullifier,

        consumed_at:
            new Date().toISOString(),

        root_version:
            newVersion
    });


    // ==================================================
    // 15. Persist only after ALL verification succeeds
    // ==================================================

    const newSignedRootFile =
        path.join(
            rootsDir,
            `signed_root_v${newVersion}.json`
        );


    writeJsonAtomic(
        registryFile,
        registry
    );


    writeJsonAtomic(
        consumedAatFile,
        consumedState
    );


    writeJsonAtomic(
        newSignedRootFile,
        newSignedRoot
    );


    // ==================================================
    // Report
    // ==================================================

    const report = {

        enrollment_id:
            enrollmentId,

        accepted:
            true,

        D_id:
            enrollPackage.D_id,

        scheme_id:
            enrollPackage.scheme_id,

        aat: {

            signature_valid:
                true,

            temporal_valid:
                true,

            purpose_valid:
                true,

            nullifier:
                aatNullifier,

            previously_consumed:
                false,

            consumed:
                true
        },

        pvss: {

            proofs_verified:
                verifiedPvssProofs,

            proof_count:
                Number(
                    pvssData.threshold.n
                ),

            valid:
                true
        },

        link_proof: {

            statement_bound:
                true,

            valid:
                true
        },

        smt: {

            depth:
                depth,

            index:
                String(
                    enrollPackage.idx
                ),

            old_root:
                String(
                    previousSignedRoot.root
                ),

            new_root:
                String(
                    newRoot
                )
        },

        signed_root: {

            previous_version:
                Number(
                    previousSignedRoot.version
                ),

            new_version:
                newVersion,

            previous_file:
                previousSignedRootFile,

            new_file:
                newSignedRootFile,

            valid:
                true
        }
    };


    writeJsonAtomic(
        reportFile,
        report
    );


    // ==================================================
    // Output
    // ==================================================

    console.log("");

    console.log(
        "--------------------------------------------"
    );

    console.log(
        "BAS ENROLLMENT DECISION: ACCEPT"
    );

    console.log(
        "--------------------------------------------"
    );

    console.log(
        `Old root version : ${previousSignedRoot.version}`
    );

    console.log(
        `New root version : ${newVersion}`
    );

    console.log(
        `SMT index        : ${enrollPackage.idx}`
    );

    console.log(
        `New root         : ${newRoot}`
    );

    console.log(
        `AAT consumed     : true`
    );

    console.log("");

    console.log(
        "SignedRoot:"
    );

    console.log(
        newSignedRootFile
    );

    console.log("");

    console.log(
        "BAS state:"
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

        /*
         * snarkjs/ffjavascript workers may otherwise
         * keep Node alive after verification.
         */

        process.exit(0);
    })
    .catch(error => {

        console.error("");

        console.error(
            "============================================"
        );

        console.error(
            "BAS ENROLLMENT DECISION: REJECT"
        );

        console.error(
            "============================================"
        );

        console.error(
            error.message
        );

        process.exit(1);
    });