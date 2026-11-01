const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const circomlibjs = require("circomlibjs");

const config = require("./config");


function randomScalar(order) {

    while (true) {

        const bytes =
            crypto.randomBytes(32);

        /*
         * BabyJub subgroup order is ~251 bits.
         *
         * Keep only 251 random bits and use
         * rejection sampling.
         *
         * This avoids modulo-reduction bias.
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


function pointsEqual(
    pointA,
    pointB,
    F
) {

    return (
        F.toObject(
            pointA[0]
        ) ===
        F.toObject(
            pointB[0]
        )
        &&
        F.toObject(
            pointA[1]
        ) ===
        F.toObject(
            pointB[1]
        )
    );
}


async function main() {

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - PVSS Admin Key Setup"
    );

    console.log(
        "============================================"
    );


    const projectRoot =
        config.paths.projectRoot;


    const n =
        config.admins.n;


    const t =
        config.admins.t;


    if (
        !Number.isInteger(n) ||
        !Number.isInteger(t) ||
        t < 2 ||
        t > n
    ) {

        throw new Error(
            "Invalid threshold configuration."
        );
    }


    // ==================================================
    // Initialize BabyJub
    // ==================================================

    const start =
        performance.now();


    const babyJub =
        await circomlibjs.buildBabyjub();


    const F =
        babyJub.F;


    const q =
        BigInt(
            babyJub.subOrder.toString()
        );


    // ==================================================
    // Paths
    // ==================================================

    const privateDir =
        path.join(
            projectRoot,
            "private",
            "pvss"
        );


    const stateDir =
        path.join(
            projectRoot,
            "state",
            "pvss"
        );


    const resultsDir =
        path.join(
            projectRoot,
            "results"
        );


    const publicKeysFile =
        path.join(
            stateDir,
            "admin_public_keys.json"
        );


    /*
     * We intentionally refuse accidental
     * key regeneration.
     *
     * Existing enrolled users would have
     * PVSS_Data encrypted to the old keys.
     */

    if (
        fs.existsSync(
            publicKeysFile
        )
    ) {

        throw new Error(
            [
                "PVSS admin keys already exist.",
                "Refusing to overwrite them.",
                "",
                `Existing file: ${publicKeysFile}`
            ].join("\n")
        );
    }


    fs.mkdirSync(
        privateDir,
        {
            recursive: true
        }
    );


    fs.mkdirSync(
        stateDir,
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


    // ==================================================
    // Generate independent PVSS key pair
    // for each administrator
    // ==================================================

    const admins =
        [];


    const individualTimings =
        [];


    for (
        let adminId = 1;
        adminId <= n;
        adminId++
    ) {

        const keyStart =
            performance.now();


        const secretKey =
            randomScalar(q);


        /*
         * PK_i = SK_i * Base8
         */

        const publicKey =
            babyJub.mulPointEscalar(
                babyJub.Base8,
                secretKey
            );


        // ----------------------------------------------
        // Local ECDH consistency self-test
        //
        // User side:
        //     shared1 = r * PK_i
        //
        // Admin side:
        //     shared2 = SK_i * (r * G)
        //
        // They must be equal.
        // ----------------------------------------------

        const ephemeralScalar =
            randomScalar(q);


        const ephemeralPublic =
            babyJub.mulPointEscalar(
                babyJub.Base8,
                ephemeralScalar
            );


        const sharedUser =
            babyJub.mulPointEscalar(
                publicKey,
                ephemeralScalar
            );


        const sharedAdmin =
            babyJub.mulPointEscalar(
                ephemeralPublic,
                secretKey
            );


        const selfTest =
            pointsEqual(
                sharedUser,
                sharedAdmin,
                F
            );


        if (!selfTest) {

            throw new Error(
                `PVSS key self-test failed for admin ${adminId}.`
            );
        }


        const keyEnd =
            performance.now();


        // ----------------------------------------------
        // Private admin file
        // ----------------------------------------------

        const privateRecord = {

            admin_id:
                adminId,

            purpose:
                "PVSS share decryption",

            curve:
                config.pvss.curve,

            generator:
                config.pvss.generator,

            key_version:
                config.pvss.keyVersion,

            secret_key:
                secretKey.toString(),

            public_key:
                pointToJson(
                    publicKey,
                    F
                )
        };


        const privateFilename =
            path.join(
                privateDir,

                `admin_${String(
                    adminId
                ).padStart(
                    2,
                    "0"
                )}.json`
            );


        fs.writeFileSync(
            privateFilename,

            JSON.stringify(
                privateRecord,
                null,
                2
            )
        );


        // ----------------------------------------------
        // Public record
        // ----------------------------------------------

        admins.push({

            admin_id:
                adminId,

            public_key:
                pointToJson(
                    publicKey,
                    F
                ),

            self_test:
                true
        });


        individualTimings.push({

            admin_id:
                adminId,

            key_generation_ms:
                keyEnd -
                keyStart
        });
    }


    const end =
        performance.now();


    // ==================================================
    // Public PVSS key registry
    // ==================================================

    const publicRegistry = {

        scheme_id:
            config.protocol.schemeId,

        domain_id:
            config.domain.domainId,

        purpose:
            "PVSS share encryption",

        curve:
            config.pvss.curve,

        generator:
            config.pvss.generator,

        key_version:
            config.pvss.keyVersion,

        threshold: {

            n,

            t
        },

        subgroup_order:
            q.toString(),

        admins
    };


    fs.writeFileSync(
        publicKeysFile,

        JSON.stringify(
            publicRegistry,
            null,
            2
        )
    );


    // ==================================================
    // Setup result
    // ==================================================

    const setupResult = {

        scheme_id:
            config.protocol.schemeId,

        domain_id:
            config.domain.domainId,

        component:
            "PVSS admin encryption key setup",

        curve:
            config.pvss.curve,

        generator:
            config.pvss.generator,

        key_version:
            config.pvss.keyVersion,

        n,

        t,

        generated_key_pairs:
            n,

        all_self_tests_passed:
            admins.every(
                admin =>
                    admin.self_test
            ),

        timing: {

            total_ms:
                end - start,

            per_admin:
                individualTimings
        },

        note:
            [
                "No x_anchor or user share is generated during setup.",
                "These key pairs are only for future PVSS share encryption/decryption during enrollment.",
                "Private PVSS keys are distinct from FROST signing shares."
            ]
    };


    const resultFile =
        path.join(
            resultsDir,
            "pvss_setup.json"
        );


    fs.writeFileSync(
        resultFile,

        JSON.stringify(
            setupResult,
            null,
            2
        )
    );


    // ==================================================
    // Display
    // ==================================================

    console.log("");

    console.log(
        "PVSS admin key setup completed successfully."
    );


    console.log(
        "Administrators:",
        `${t}-of-${n}`
    );


    console.log(
        "Curve:",
        config.pvss.curve
    );


    console.log(
        "Generator:",
        config.pvss.generator
    );


    console.log(
        "Key pairs generated:",
        n
    );


    console.log(
        "All ECDH self-tests:",
        "true"
    );


    console.log(
        "Total key setup:",
        `${(end - start).toFixed(3)} ms`
    );


    console.log("");

    console.log(
        "Public PVSS keys:"
    );

    console.log(
        publicKeysFile
    );


    console.log("");

    console.log(
        "Private admin keys:"
    );

    console.log(
        path.join(
            privateDir,
            "admin_01.json"
        ),
        "...",
        `admin_${String(n).padStart(
            2,
            "0"
        )}.json`
    );


    console.log("");

    console.log(
        "Setup snapshot:"
    );

    console.log(
        resultFile
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
                "PVSS admin key setup failed:"
            );

            console.error(
                error.message
            );

            process.exit(1);
        }
    );