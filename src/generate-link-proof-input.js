const fs = require("fs");
const path = require("path");

const {
    buildPoseidon,
    buildBabyjub
} = require("circomlibjs");

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


function mod(a, m) {

    const r = a % m;

    return r >= 0n
        ? r
        : r + m;
}


function assertEqual(
    name,
    actual,
    expected
) {

    if (
        BigInt(actual) !==
        BigInt(expected)
    ) {

        throw new Error(
            `${name} mismatch\n` +
            `Actual   : ${actual}\n` +
            `Expected : ${expected}`
        );
    }
}


// ======================================================
// Main
// ======================================================

async function main() {

    const enrollmentId =
        process.argv[2];


    if (!enrollmentId) {

        throw new Error(
            "Usage: node src\\generate-link-proof-input.js <enrollment-id>"
        );
    }


    const projectRoot =
        config.paths.projectRoot;


    // ==================================================
    // Protocol configuration
    // ==================================================

    const tags =
        config.protocol?.tags ??
        config.tags ??
        {};


    const TAG_ANCHOR =
        BigInt(
            tags.anchor ?? 1
        );


    const TAG_LEAF =
        BigInt(
            tags.leaf ?? 2
        );


    const TAG_IDX =
        BigInt(
            tags.idx ?? 3
        );


    const TAG_REVOKE =
        BigInt(
            tags.revoke ?? 4
        );


    const TAG_PVSS_COEFF_COMMIT =
        BigInt(
            tags.pvssCoeffCommit ?? 7
        );


    const depth =
        Number(
            config.smt?.depth ??
            config.protocol?.smt?.depth ??
            20
        );


    if (depth !== 20) {

        throw new Error(
            `Current link-proof circuit is compiled for SMT depth 20, but config depth is ${depth}.`
        );
    }


    // BabyJub subgroup order
    const q =
        2736030358979909402780800718157159386076813972158567259200215660948447373041n;


    // ==================================================
    // Paths
    // ==================================================

    const witnessFile =
        path.join(
            projectRoot,
            "private",
            "users",
            enrollmentId,
            "pvss_witness.json"
        );


    const pvssDataFile =
        path.join(
            projectRoot,
            "artifacts",
            "enrollment",
            enrollmentId,
            "pvss_data.json"
        );


    const outputDir =
        path.join(
            projectRoot,
            "build",
            "link_proof_inputs"
        );


    const outputFile =
        path.join(
            outputDir,
            `${enrollmentId}.json`
        );


    // ==================================================
    // Load Enrollment material
    // ==================================================

    const witness =
        loadJson(witnessFile);


    const pvssData =
        loadJson(pvssDataFile);


    if (
        pvssData.proof_status !==
        "verified"
    ) {

        throw new Error(
            "PVSS_Data is not finalized/verified."
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
    // Private user material
    // ==================================================

    const x =
        BigInt(
            witness.x
        );


    const xAnchor =
        BigInt(
            witness.x_anchor
        );


    const coefficients =
        witness
            .polynomial_coefficients
            .map(BigInt);


    const blindings =
        witness
            .commitment_blindings
            .map(BigInt);


    if (
        coefficients.length !== 3
    ) {

        throw new Error(
            "Expected exactly 3 PVSS polynomial coefficients."
        );
    }


    if (
        blindings.length !== 3
    ) {

        throw new Error(
            "Expected exactly 3 commitment blindings."
        );
    }


    const a0 =
        coefficients[0];

    const a1 =
        coefficients[1];

    const a2 =
        coefficients[2];


    // ==================================================
    // Critical PVSS bridge:
    //
    // polynomial constant coefficient must be x_anchor
    // ==================================================

    assertEqual(
        "PVSS a0 / x_anchor",
        a0,
        xAnchor
    );


    // ==================================================
    // Initialize Poseidon + BabyJub
    // ==================================================

    const poseidon =
        await buildPoseidon();


    const poseidonF =
        poseidon.F;


    const babyJub =
        await buildBabyjub();


    const babyF =
        babyJub.F;


    function poseidonBigInt(inputs) {

        const result =
            poseidon(
                inputs.map(BigInt)
            );

        return BigInt(
            poseidonF.toString(
                result
            )
        );
    }


    // ==================================================
    // Recompute x_anchor
    //
    // anchorRaw =
    // Poseidon(
    //   TAG_ANCHOR,
    //   scheme,
    //   domain,
    //   x
    // )
    //
    // x_anchor = anchorRaw mod q
    // ==================================================

    const schemeId =
        BigInt(
            pvssData.scheme_id
        );


    const domainId =
        BigInt(
            pvssData.D_id
        );


    const anchorRaw =
        poseidonBigInt([
            TAG_ANCHOR,
            schemeId,
            domainId,
            x
        ]);


    const expectedXAnchor =
        mod(
            anchorRaw,
            q
        );


    assertEqual(
        "x_anchor",
        xAnchor,
        expectedXAnchor
    );


    const anchorNumerator =
        anchorRaw -
        xAnchor;


    if (
        anchorNumerator < 0n ||
        anchorNumerator % q !== 0n
    ) {

        throw new Error(
            "Invalid anchor reduction relation."
        );
    }


    const anchorQ =
        anchorNumerator /
        q;


    if (
        anchorQ < 0n ||
        anchorQ > 7n
    ) {

        throw new Error(
            `Unexpected anchor quotient: ${anchorQ}`
        );
    }


    // ==================================================
    // Recompute:
    //
    // Y = x_anchor * Base8
    // ==================================================

    const Y =
        babyJub.mulPointEscalar(
            babyJub.Base8,
            xAnchor
        );


    const Yx =
        BigInt(
            babyF.toString(
                Y[0]
            )
        );


    const Yy =
        BigInt(
            babyF.toString(
                Y[1]
            )
        );


    // ==================================================
    // Recompute L
    // ==================================================

    const expectedL =
        poseidonBigInt([
            TAG_LEAF,
            schemeId,
            domainId,
            Yx,
            Yy
        ]);


    assertEqual(
        "L",
        witness.L,
        expectedL
    );


    // ==================================================
    // Recompute idx
    //
    // Current SMT:
    //
    // idx = low 20 bits of Poseidon output
    // ==================================================

    const idxRaw =
        poseidonBigInt([
            TAG_IDX,
            schemeId,
            domainId,
            xAnchor
        ]);


    const idxMask =
        (1n << BigInt(depth)) -
        1n;


    const expectedIdx =
        idxRaw &
        idxMask;


    assertEqual(
        "idx",
        witness.idx,
        expectedIdx
    );


    // ==================================================
    // Recompute y_hash
    // ==================================================

    const expectedYHash =
        poseidonBigInt([
            TAG_REVOKE,
            schemeId,
            domainId,
            Yx,
            Yy
        ]);


    assertEqual(
        "y_hash",
        witness.y_hash,
        expectedYHash
    );


    // ==================================================
    // Recompute PVSS commitments
    //
    // C0 must commit to x_anchor.
    // ==================================================

    const expectedC0 =
        poseidonBigInt([
            TAG_PVSS_COEFF_COMMIT,
            schemeId,
            domainId,
            0n,
            xAnchor,
            blindings[0]
        ]);


    const expectedC1 =
        poseidonBigInt([
            TAG_PVSS_COEFF_COMMIT,
            schemeId,
            domainId,
            1n,
            a1,
            blindings[1]
        ]);


    const expectedC2 =
        poseidonBigInt([
            TAG_PVSS_COEFF_COMMIT,
            schemeId,
            domainId,
            2n,
            a2,
            blindings[2]
        ]);


    assertEqual(
        "C0",
        pvssData.commitments[0].commitment,
        expectedC0
    );


    assertEqual(
        "C1",
        pvssData.commitments[1].commitment,
        expectedC1
    );


    assertEqual(
        "C2",
        pvssData.commitments[2].commitment,
        expectedC2
    );


    // ==================================================
    // Build Circom input
    // ==================================================

    const input = {

        // ----------------------------------------------
        // Public statement
        // ----------------------------------------------

        D_id:
            domainId.toString(),

        scheme_id:
            schemeId.toString(),

        L:
            expectedL.toString(),

        idx:
            expectedIdx.toString(),

        y_hash:
            expectedYHash.toString(),

        C0:
            expectedC0.toString(),

        C1:
            expectedC1.toString(),

        C2:
            expectedC2.toString(),


        // ----------------------------------------------
        // Private witness
        // ----------------------------------------------

        x:
            x.toString(),

        x_anchor:
            xAnchor.toString(),

        anchor_q:
            anchorQ.toString(),

        a1:
            a1.toString(),

        a2:
            a2.toString(),

        blind0:
            blindings[0].toString(),

        blind1:
            blindings[1].toString(),

        blind2:
            blindings[2].toString()
    };


    // ==================================================
    // Save
    // ==================================================

    fs.mkdirSync(
        outputDir,
        {
            recursive: true
        }
    );


    fs.writeFileSync(
        outputFile,
        JSON.stringify(
            input,
            null,
            2
        )
    );


    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - Link Proof Input"
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

    console.log("");

    console.log(
        "Link relations checked:"
    );

    console.log(
        "x -> x_anchor            : MATCH"
    );

    console.log(
        "x_anchor -> Y            : MATCH"
    );

    console.log(
        "Y -> L                   : MATCH"
    );

    console.log(
        "x_anchor -> idx          : MATCH"
    );

    console.log(
        "Y -> y_hash              : MATCH"
    );

    console.log(
        "x_anchor -> PVSS C0       : MATCH"
    );

    console.log(
        "PVSS C1/C2 openings      : MATCH"
    );

    console.log("");

    console.log(
        `Anchor reduction quotient: ${anchorQ}`
    );

    console.log(
        `SMT depth: ${depth}`
    );

    console.log("");

    console.log(
        "Link proof input:"
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
         * Explicit exit prevents circomlibjs worker
         * handles from keeping PowerShell open.
         */

        process.exit(0);
    })
    .catch(error => {

        console.error("");

        console.error(
            "Link proof input generation failed:"
        );

        console.error(
            error.message
        );

        process.exit(1);
    });