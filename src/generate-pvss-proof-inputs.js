const fs = require("fs");
const path = require("path");

const config = require("./config");


const projectRoot =
    config.paths.projectRoot;


function mod(a, m) {

    const r =
        a % m;

    return r >= 0n
        ? r
        : r + m;
}


function main() {

    const enrollmentId =
        process.argv[2];


    if (!enrollmentId) {

        throw new Error(
            "Usage: node src\\generate_pvss_proof_inputs.js <enrollment-id>"
        );
    }


    const publicFile =
        path.join(
            projectRoot,
            "artifacts",
            "enrollment",
            enrollmentId,
            "pvss_data_preproof.json"
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
            "pvss",
            "admin_public_keys.json"
        );


    if (!fs.existsSync(publicFile)) {

        throw new Error(
            `PVSS public data not found: ${publicFile}`
        );
    }


    if (!fs.existsSync(witnessFile)) {

        throw new Error(
            `PVSS witness not found: ${witnessFile}`
        );
    }


    if (!fs.existsSync(registryFile)) {

        throw new Error(
            `PVSS public-key registry not found: ${registryFile}`
        );
    }


    const publicData =
        JSON.parse(
            fs.readFileSync(
                publicFile,
                "utf8"
            )
        );


    const witness =
        JSON.parse(
            fs.readFileSync(
                witnessFile,
                "utf8"
            )
        );


    const registry =
        JSON.parse(
            fs.readFileSync(
                registryFile,
                "utf8"
            )
        );


    if (
        publicData.threshold.n !== 5 ||
        publicData.threshold.t !== 3
    ) {

        throw new Error(
            "The current PVSS proof circuit is the baseline 3-of-5 circuit."
        );
    }


    const q =
        BigInt(
            registry.subgroup_order
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
        coefficients.length !== 3 ||
        blindings.length !== 3
    ) {

        throw new Error(
            "Expected exactly 3 coefficients/blindings for t=3."
        );
    }


    const outputDir =
        path.join(
            projectRoot,
            "build",
            "pvss_share_inputs",
            enrollmentId
        );


    fs.mkdirSync(
        outputDir,
        {
            recursive: true
        }
    );


    for (
        const encrypted
        of publicData.encrypted_shares
    ) {

        const adminId =
            encrypted.admin_id;


        const adminPublic =
            registry.admins.find(
                item =>
                    item.admin_id ===
                    adminId
            );


        const privateShare =
            witness.shares.find(
                item =>
                    item.admin_id ===
                    adminId
            );


        if (
            !adminPublic ||
            !privateShare
        ) {

            throw new Error(
                `Missing data for admin ${adminId}.`
            );
        }


        const i =
            BigInt(
                adminId
            );


        const a0 =
            coefficients[0];

        const a1 =
            coefficients[1];

        const a2 =
            coefficients[2];


        // ----------------------------------------------
        // Horner step 1:
        //
        // a2*i + a1 =
        // u1 + poly_q1*q
        // ----------------------------------------------

        const raw1 =
            a2 * i +
            a1;


        const u1 =
            mod(
                raw1,
                q
            );


        const polyQ1 =
            (
                raw1 -
                u1
            ) / q;


        // ----------------------------------------------
        // Horner step 2:
        //
        // u1*i + a0 =
        // share + poly_q2*q
        // ----------------------------------------------

        const raw2 =
            u1 * i +
            a0;


        const expectedShare =
            mod(
                raw2,
                q
            );


        const share =
            BigInt(
                privateShare.share
            );


        if (
            expectedShare !==
            share
        ) {

            throw new Error(
                `Stored share mismatch for admin ${adminId}.`
            );
        }


        const polyQ2 =
            (
                raw2 -
                share
            ) / q;


        // ----------------------------------------------
        // Cipher reduction
        // ----------------------------------------------

        const maskScalar =
            BigInt(
                privateShare.mask_scalar
            );


        const cipherC =
            BigInt(
                encrypted.c
            );


        const cipherNumerator =
            share +
            maskScalar -
            cipherC;


        if (
            cipherNumerator !== 0n &&
            cipherNumerator !== q
        ) {

            throw new Error(
                `Invalid ciphertext reduction for admin ${adminId}.`
            );
        }


        const cipherQ =
            cipherNumerator /
            q;


        // ----------------------------------------------
        // Circuit input
        // ----------------------------------------------

        const input = {

            D_id:
                String(
                    publicData.D_id
                ),

            scheme_id:
                String(
                    publicData.scheme_id
                ),

            admin_id:
                String(
                    adminId
                ),


            pk_x:
                adminPublic
                    .public_key
                    .x,

            pk_y:
                adminPublic
                    .public_key
                    .y,


            R_x:
                encrypted
                    .R
                    .x,

            R_y:
                encrypted
                    .R
                    .y,


            cipher_c:
                encrypted.c,

            cipher_tag:
                encrypted.tag,


            C0:
                publicData
                    .commitments[0]
                    .commitment,

            C1:
                publicData
                    .commitments[1]
                    .commitment,

            C2:
                publicData
                    .commitments[2]
                    .commitment,


            a0:
                a0.toString(),

            a1:
                a1.toString(),

            a2:
                a2.toString(),


            blind0:
                blindings[0]
                    .toString(),

            blind1:
                blindings[1]
                    .toString(),

            blind2:
                blindings[2]
                    .toString(),


            share:
                share.toString(),

            u1:
                u1.toString(),

            poly_q1:
                polyQ1.toString(),

            poly_q2:
                polyQ2.toString(),


            encryption_r:
                privateShare
                    .encryption_randomness,


            mask_scalar:
                privateShare
                    .mask_scalar,

            mask_q:
                privateShare
                    .mask_reduction_quotient,


            cipher_q:
                cipherQ.toString()
        };


        const outputFile =
            path.join(
                outputDir,

                `admin_${String(
                    adminId
                ).padStart(
                    2,
                    "0"
                )}.json`
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
            `Admin ${adminId} input: ${outputFile}`
        );
    }


    console.log("");

    console.log(
        "PVSS proof inputs generated successfully."
    );
}


try {

    main();

} catch (error) {

    console.error("");

    console.error(
        "PVSS proof input generation failed:"
    );

    console.error(
        error.message
    );

    process.exit(1);
}