const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const config = require("./config");


function loadJson(filePath) {

    if (!fs.existsSync(filePath)) {
        throw new Error(`File not found: ${filePath}`);
    }

    return JSON.parse(
        fs.readFileSync(filePath, "utf8")
    );
}


function sameSignals(actual, expected) {

    if (actual.length !== expected.length) {
        return false;
    }

    for (let i = 0; i < actual.length; i++) {

        if (
            String(actual[i]) !==
            String(expected[i])
        ) {

            return false;
        }
    }

    return true;
}


async function main() {

    const enrollmentId =
        process.argv[2];


    if (!enrollmentId) {

        throw new Error(
            "Usage: node src\\finalize-pvss-data.js <enrollment-id>"
        );
    }


    const projectRoot =
        config.paths.projectRoot;


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


    const preProofFile =
        path.join(
            enrollmentDir,
            "pvss_data_preproof.json"
        );


    const publicKeyRegistryFile =
        path.join(
            projectRoot,
            "state",
            "pvss",
            "admin_public_keys.json"
        );


    const verificationKeyFile =
        path.join(
            projectRoot,
            "build",
            "pvss_share",
            "verification_key.json"
        );


    const proofDir =
        path.join(
            projectRoot,
            "build",
            "pvss_share"
        );


    const outputFile =
        path.join(
            enrollmentDir,
            "pvss_data.json"
        );


    // ==================================================
    // Load public protocol data
    // ==================================================

    const pvssData =
        loadJson(preProofFile);


    const registry =
        loadJson(publicKeyRegistryFile);


    const verificationKey =
        loadJson(verificationKeyFile);


    const n =
        Number(
            pvssData.threshold.n
        );


    if (n !== 5) {

        throw new Error(
            `Expected n=5, received n=${n}`
        );
    }


    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - Finalize PVSS_Data"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Enrollment ID: ${enrollmentId}`
    );

    console.log(
        `Administrators: ${pvssData.threshold.t}-of-${n}`
    );

    console.log(
        "Proof system: Groth16 / bn128"
    );

    console.log("");


    const verifiedProofs = [];


    // ==================================================
    // Verify each administrator proof
    // ==================================================

    for (
        let adminId = 1;
        adminId <= n;
        adminId++
    ) {

        const id =
            String(adminId)
                .padStart(2, "0");


        const proofFile =
            path.join(
                proofDir,
                `admin_${id}_proof.json`
            );


        const publicSignalsFile =
            path.join(
                proofDir,
                `admin_${id}_public.json`
            );


        const proof =
            loadJson(proofFile);


        const publicSignals =
            loadJson(publicSignalsFile);


        // ----------------------------------------------
        // Find corresponding PVSS ciphertext
        // ----------------------------------------------

        const encryptedShare =
            pvssData
                .encrypted_shares
                .find(
                    item =>
                        Number(item.admin_id) ===
                        adminId
                );


        if (!encryptedShare) {

            throw new Error(
                `Encrypted share not found for admin ${adminId}`
            );
        }


        // ----------------------------------------------
        // Find corresponding administrator public key
        // ----------------------------------------------

        const adminPublic =
            registry
                .admins
                .find(
                    item =>
                        Number(item.admin_id) ===
                        adminId
                );


        if (!adminPublic) {

            throw new Error(
                `Public key not found for admin ${adminId}`
            );
        }


        // ==================================================
        // Expected public statement
        //
        // Must match the public input order of:
        //
        // PVSSShareProof
        // ==================================================

        const expectedPublicSignals = [

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
                pvssData
                    .commitments[0]
                    .commitment
            ),

            String(
                pvssData
                    .commitments[1]
                    .commitment
            ),

            String(
                pvssData
                    .commitments[2]
                    .commitment
            )
        ];


        // ==================================================
        // Bind proof to THIS PVSS_Data
        // ==================================================

        const statementMatches =
            sameSignals(
                publicSignals,
                expectedPublicSignals
            );


        if (!statementMatches) {

            console.error("");

            console.error(
                `Public statement mismatch for admin ${adminId}`
            );

            console.error("");

            console.error(
                "Actual public signals:"
            );

            console.error(
                publicSignals
            );

            console.error("");

            console.error(
                "Expected public signals:"
            );

            console.error(
                expectedPublicSignals
            );


            throw new Error(
                `PVSS public statement mismatch for admin ${adminId}`
            );
        }


        // ==================================================
        // Groth16 verification
        // ==================================================

        const proofValid =
            await snarkjs
                .groth16
                .verify(
                    verificationKey,
                    publicSignals,
                    proof
                );


        if (!proofValid) {

            throw new Error(
                `Groth16 verification failed for admin ${adminId}`
            );
        }


        console.log(
            `Admin ${adminId}: statement MATCH / proof VALID`
        );


        verifiedProofs.push({

            admin_id:
                adminId,

            proof_system:
                "Groth16",

            curve:
                "bn128",

            circuit:
                "PVSSShareProof-v1",

            verification_key_id:
                "pvss-share-proof-v1",

            proof:
                proof,

            public_signals:
                publicSignals,

            verified:
                true
        });
    }


    // ==================================================
    // Final PVSS_Data
    // ==================================================

    const finalPvssData = {

        ...pvssData,

        proofs:
            verifiedProofs,

        proof_status:
            "verified",

        proof_count:
            verifiedProofs.length,

        proof_system: {

            scheme:
                "Groth16",

            curve:
                "bn128",

            circuit:
                "PVSSShareProof-v1",

            constraints_per_proof:
                16195,

            public_inputs:
                12,

            private_inputs:
                14,

            verification_key_id:
                "pvss-share-proof-v1"
        }
    };


    fs.writeFileSync(
        outputFile,

        JSON.stringify(
            finalPvssData,
            null,
            2
        )
    );


    console.log("");

    console.log(
        "--------------------------------------------"
    );

    console.log(
        `Verified proofs: ${verifiedProofs.length}/${n}`
    );

    console.log(
        "PVSS proof status: VERIFIED"
    );

    console.log("");

    console.log(
        "Final PVSS_Data:"
    );

    console.log(
        outputFile
    );

    console.log(
        "============================================"
    );
}


main()
    .then(() => {

        /*
         * snarkjs / ffjavascript may leave worker handles
         * alive after Groth16 verification.
         *
         * All verification and synchronous file writes
         * have already completed at this point.
         */

        process.exit(0);
    })
    .catch(error => {

        console.error("");

        console.error(
            "PVSS finalization failed:"
        );

        console.error(
            error.message
        );

        process.exit(1);
    });