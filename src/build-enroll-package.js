const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");

const config = require("./config");


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


function sameSignals(
    actual,
    expected
) {

    if (
        actual.length !==
        expected.length
    ) {

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


function findAatArtifact(
    aatDir,
    enrollmentId
) {

    if (!fs.existsSync(aatDir)) {

        throw new Error(
            `AAT directory not found: ${aatDir}`
        );
    }


    const files =
        fs.readdirSync(aatDir);


    const match =
        files.find(
            file =>
                file.startsWith(
                    `aat_${enrollmentId}`
                ) &&
                file.endsWith(".json") &&
                !file.endsWith(".report.json")
        );


    if (!match) {

        throw new Error(
            `AAT artifact not found for enrollment ${enrollmentId}`
        );
    }


    return path.join(
        aatDir,
        match
    );
}


// ======================================================
// Main
// ======================================================

async function main() {

    const enrollmentId =
        process.argv[2];
        
    const suppliedAatFile =
    process.argv[3];

    if (!enrollmentId) {

        throw new Error(
            "Usage: node src\\build-enroll-package.js <enrollment-id> [aat-file]"
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


    const pvssDataFile =
        path.join(
            enrollmentDir,
            "pvss_data.json"
        );


    const linkProofFile =
        path.join(
            projectRoot,
            "build",
            "link_proof",
            "link-proof.json"
        );


    const linkPublicFile =
        path.join(
            projectRoot,
            "build",
            "link_proof",
            "link-public.json"
        );


    const linkVerificationKeyFile =
        path.join(
            projectRoot,
            "build",
            "link_proof",
            "verification_key.json"
        );


    const witnessFile =
        path.join(
            projectRoot,
            "private",
            "users",
            enrollmentId,
            "pvss_witness.json"
        );


    const aatDir =
        path.join(
            projectRoot,
            "artifacts",
            "aat"
        );


    const aatFile =
    suppliedAatFile
        ? path.resolve(suppliedAatFile)
        : findAatArtifact(
            aatDir,
            enrollmentId
        );


    const outputFile =
        path.join(
            enrollmentDir,
            "enroll_package.json"
        );


    // ==================================================
    // Load data
    // ==================================================

    const pvssData =
        loadJson(
            pvssDataFile
        );


    const linkProof =
        loadJson(
            linkProofFile
        );


    const linkPublic =
        loadJson(
            linkPublicFile
        );


    const linkVerificationKey =
        loadJson(
            linkVerificationKeyFile
        );


    const privateWitness =
        loadJson(
            witnessFile
        );


    const aatArtifact =
        loadJson(
            aatFile
        );


    /*
     * aat.js may store either the token directly
     * or inside a wrapper.
     */

    const AAT =
        aatArtifact.AAT ??
        aatArtifact.aat ??
        aatArtifact.token ??
        aatArtifact;


    // ==================================================
    // PVSS must already be finalized
    // ==================================================

    if (
        pvssData.proof_status !==
        "verified"
    ) {

        throw new Error(
            "PVSS_Data is not verified."
        );
    }


    if (
        Number(
            pvssData.proof_count
        ) !==
        5
    ) {

        throw new Error(
            "Expected 5 verified PVSS proofs."
        );
    }


    // ==================================================
    // Expected Link public statement
    //
    // Public input order in link-proof.circom:
    //
    // D_id
    // scheme_id
    // L
    // idx
    // y_hash
    // C0
    // C1
    // C2
    // ==================================================

    const expectedLinkPublic = [

        String(
            pvssData.D_id
        ),

        String(
            pvssData.scheme_id
        ),

        String(
            privateWitness.L
        ),

        String(
            privateWitness.idx
        ),

        String(
            privateWitness.y_hash
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
    // Bind Link proof to THIS Enrollment
    // ==================================================

    if (
        !sameSignals(
            linkPublic,
            expectedLinkPublic
        )
    ) {

        console.error("");

        console.error(
            "Actual Link public signals:"
        );

        console.error(
            linkPublic
        );

        console.error("");

        console.error(
            "Expected Link public signals:"
        );

        console.error(
            expectedLinkPublic
        );


        throw new Error(
            "Link proof public statement does not match this Enrollment."
        );
    }


    // ==================================================
    // Cryptographically verify Link proof again
    // ==================================================

    const linkProofValid =
        await snarkjs
            .groth16
            .verify(
                linkVerificationKey,
                linkPublic,
                linkProof
            );


    if (!linkProofValid) {

        throw new Error(
            "Link Groth16 proof verification failed."
        );
    }


    // ==================================================
    // Build Enroll_Package
    //
    // IMPORTANT:
    //
    // Do NOT include:
    //
    // x
    // x_anchor
    // Y
    // polynomial coefficients
    // plaintext shares
    // commitment blindings
    // encryption randomness
    //
    // They remain private.
    // ==================================================

    const enrollPackage = {

        version:
            1,

        D_id:
            pvssData.D_id,

        scheme_id:
            pvssData.scheme_id,


        AAT:
            AAT,


        L:
            String(
                privateWitness.L
            ),


        idx:
            String(
                privateWitness.idx
            ),


        y_hash:
            String(
                privateWitness.y_hash
            ),


        PVSS_Data:
            pvssData,


        proof_link_ZK: {

            proof_system:
                "Groth16",

            curve:
                "bn128",

            circuit:
                "LinkProof-v1",

            verification_key_id:
                "link-proof-v1",

            proof:
                linkProof,

            public_signals:
                linkPublic,

            verified_before_packaging:
                true
        }
    };


    // ==================================================
    // Save
    // ==================================================

    fs.writeFileSync(
        outputFile,

        JSON.stringify(
            enrollPackage,
            null,
            2
        )
    );


    // ==================================================
    // Output
    // ==================================================

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - Enroll Package"
    );

    console.log(
        "============================================"
    );


    console.log(
        `Enrollment ID: ${enrollmentId}`
    );


    console.log(
        "PVSS status: VERIFIED"
    );


    console.log(
        "PVSS proofs: 5/5"
    );


    console.log(
        "Link public statement: MATCH"
    );


    console.log(
        "Link Groth16 proof: VALID"
    );


    console.log("");

    console.log(
        "Private values included:"
    );

    console.log(
        "x            : NO"
    );

    console.log(
        "x_anchor     : NO"
    );

    console.log(
        "Y            : NO"
    );

    console.log(
        "plain shares : NO"
    );


    console.log("");

    console.log(
        "Enroll_Package:"
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

        process.exit(0);

    })
    .catch(error => {

        console.error("");

        console.error(
            "Enroll package creation failed:"
        );

        console.error(
            error.message
        );

        process.exit(1);
    });