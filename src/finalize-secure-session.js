const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const {
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


function canonicalize(value) {

    if (
        value === null ||
        typeof value !== "object"
    ) {
        return value;
    }


    if (Array.isArray(value)) {

        return value.map(
            canonicalize
        );
    }


    const result = {};

    for (
        const key
        of Object.keys(value).sort()
    ) {

        result[key] =
            canonicalize(
                value[key]
            );
    }

    return result;
}


function canonicalJson(value) {

    return JSON.stringify(
        canonicalize(value)
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


function hmacSha256(
    key,
    data
) {

    return crypto
        .createHmac(
            "sha256",
            key
        )
        .update(data)
        .digest();
}


function timingSafeEqual(
    a,
    b
) {

    return (
        a.length === b.length &&
        crypto.timingSafeEqual(
            a,
            b
        )
    );
}


function bigintTo32Bytes(value) {

    const hex =
        BigInt(value)
            .toString(16)
            .padStart(
                64,
                "0"
            );

    return Buffer.from(
        hex,
        "hex"
    );
}


// ======================================================
// Main
// ======================================================

async function main() {

    const challengeId =
        process.argv[2];


    if (!challengeId) {

        throw new Error(
            "Usage: node src\\finalize-secure-session.js <challenge-id>"
        );
    }


    const projectRoot =
        config.paths.projectRoot;


    // ==================================================
    // Paths
    // ==================================================

    const privateSessionDir =
        path.join(
            projectRoot,
            "private",
            "sessions",
            challengeId
        );


    const artifactSessionDir =
        path.join(
            projectRoot,
            "artifacts",
            "sessions",
            challengeId
        );


    const resultDir =
        path.join(
            projectRoot,
            "results",
            "secure_session",
            challengeId
        );


    const userEphemeralFile =
        path.join(
            privateSessionDir,
            "user_ephemeral.json"
        );


    const serviceEphemeralFile =
        path.join(
            privateSessionDir,
            "service_ephemeral.json"
        );


    const sessionInitFile =
        path.join(
            artifactSessionDir,
            "session_init.json"
        );


    const sessionResponseFile =
        path.join(
            artifactSessionDir,
            "session_response.json"
        );


    const publicResultFile =
        path.join(
            artifactSessionDir,
            "session_established.json"
        );


    const privateSessionStateFile =
        path.join(
            privateSessionDir,
            "session_key.json"
        );


    const reportFile =
        path.join(
            resultDir,
            "secure_session_report.json"
        );


    // ==================================================
    // Load
    // ==================================================

    const userEphemeral =
        loadJson(
            userEphemeralFile
        );


    const serviceEphemeral =
        loadJson(
            serviceEphemeralFile
        );


    const sessionInit =
        loadJson(
            sessionInitFile
        );


    const sessionResponse =
        loadJson(
            sessionResponseFile
        );


    const serviceId =
        String(
            sessionInit.service_id
        );


    const serviceIdentityFile =
        path.join(
            projectRoot,
            "state",
            "services",
            serviceId,
            "service_identity.json"
        );


    const serviceIdentity =
        loadJson(
            serviceIdentityFile
        );


    const servicePublicKeyFile =
        serviceIdentity.public_key_file;


    if (
        !fs.existsSync(
            servicePublicKeyFile
        )
    ) {

        throw new Error(
            `Service public key not found: ${servicePublicKeyFile}`
        );
    }


    const publicKey =
        crypto.createPublicKey(
            fs.readFileSync(
                servicePublicKeyFile,
                "utf8"
            )
        );


    const totalStart =
        process.hrtime.bigint();


    const timings = {};


    // ==================================================
    // 1. Basic consistency
    // ==================================================

    if (
        String(userEphemeral.challenge_id) !==
        challengeId
    ) {

        throw new Error(
            "User ephemeral challenge_id mismatch."
        );
    }


    if (
        String(serviceEphemeral.challenge_id) !==
        challengeId
    ) {

        throw new Error(
            "Service ephemeral challenge_id mismatch."
        );
    }


    if (
        serviceId !==
        serviceEphemeral.service_id
    ) {

        throw new Error(
            "Service ID mismatch."
        );
    }


    // ==================================================
    // 2. Verify registered service key_id
    // ==================================================

    const publicDer =
        publicKey.export({
            type: "spki",
            format: "der"
        });


    const derivedKeyId =
        sha256Hex(
            publicDer
        );


    if (
        derivedKeyId !==
        serviceIdentity.key_id
    ) {

        throw new Error(
            "Service public key key_id mismatch."
        );
    }


    if (
        sessionResponse.sigma_S.key_id !==
        serviceIdentity.key_id
    ) {

        throw new Error(
            "SessionResponse key_id mismatch."
        );
    }


    // ==================================================
    // 3. Rebuild KEX-S signature statement
    // ==================================================

    const signatureStatement = [

        "KEX-S",

        {
            x:
                String(
                    sessionInit.A.x
                ),

            y:
                String(
                    sessionInit.A.y
                )
        },

        {
            x:
                String(
                    sessionResponse.B.x
                ),

            y:
                String(
                    sessionResponse.B.y
                )
        },

        String(
            sessionInit.sid
        ),

        String(
            sessionInit.challenge
        ),

        String(
            sessionInit.ctx
        ),

        String(
            sessionInit.tag
        ),

        String(
            sessionInit.D_id_src
        ),

        String(
            sessionInit.service_id
        )
    ];


    const signatureDigest =
        sha256Buffer(
            Buffer.from(
                canonicalJson(
                    signatureStatement
                ),
                "utf8"
            )
        );


    if (
        signatureDigest.toString("hex") !==
        sessionResponse.sigma_S.digest
    ) {

        throw new Error(
            "KEX-S signature digest mismatch."
        );
    }


    // ==================================================
    // 4. User verifies service signature
    // ==================================================

    const verifyStart =
        process.hrtime.bigint();


    const serviceSignatureValid =
        crypto.verify(
            null,
            signatureDigest,
            publicKey,
            Buffer.from(
                sessionResponse
                    .sigma_S
                    .signature,
                "base64"
            )
        );


    timings.service_signature_verify_ms =
        Number(
            process.hrtime.bigint() -
            verifyStart
        ) / 1e6;


    if (
        !serviceSignatureValid
    ) {

        throw new Error(
            "KEX-S service signature INVALID."
        );
    }


    // ==================================================
    // 5. Initialize BabyJub
    // ==================================================

    const babyJub =
        await buildBabyjub();


    const F =
        babyJub.F;


    const A = [

        F.e(
            BigInt(
                sessionInit.A.x
            )
        ),

        F.e(
            BigInt(
                sessionInit.A.y
            )
        )
    ];


    const B = [

        F.e(
            BigInt(
                sessionResponse.B.x
            )
        ),

        F.e(
            BigInt(
                sessionResponse.B.y
            )
        )
    ];


    if (
        !babyJub.inCurve(A) ||
        !babyJub.inSubgroup(A)
    ) {

        throw new Error(
            "A is not a valid BabyJub subgroup point."
        );
    }


    if (
        !babyJub.inCurve(B) ||
        !babyJub.inSubgroup(B)
    ) {

        throw new Error(
            "B is not a valid BabyJub subgroup point."
        );
    }


    // ==================================================
    // 6. User computes:
    //
    // K_DH_user = B^a
    // ==================================================

    const a =
        BigInt(
            userEphemeral.a
        );


    const userDhStart =
        process.hrtime.bigint();


    const sharedUser =
        babyJub.mulPointEscalar(
            B,
            a
        );


    timings.user_dh_ms =
        Number(
            process.hrtime.bigint() -
            userDhStart
        ) / 1e6;


    const sharedUserX =
        BigInt(
            F.toString(
                sharedUser[0]
            )
        );


    const sharedUserY =
        BigInt(
            F.toString(
                sharedUser[1]
            )
        );


    // ==================================================
    // 7. Service computes:
    //
    // K_DH_service = A^b
    // ==================================================

    const b =
        BigInt(
            serviceEphemeral.b
        );


    const serviceDhStart =
        process.hrtime.bigint();


    const sharedService =
        babyJub.mulPointEscalar(
            A,
            b
        );


    timings.service_dh_ms =
        Number(
            process.hrtime.bigint() -
            serviceDhStart
        ) / 1e6;


    const sharedServiceX =
        BigInt(
            F.toString(
                sharedService[0]
            )
        );


    const sharedServiceY =
        BigInt(
            F.toString(
                sharedService[1]
            )
        );


    // ==================================================
    // 8. Shared-secret equality
    // ==================================================

    if (
        sharedUserX !==
            sharedServiceX ||
        sharedUserY !==
            sharedServiceY
    ) {

        throw new Error(
            "Diffie-Hellman shared secrets do not match."
        );
    }


    // ==================================================
    // 9. Transcript
    //
    // Thesis:
    //
    // H(
    //  "TRANSCRIPT" ||
    //  A || B ||
    //  sid ||
    //  challenge ||
    //  ctx ||
    //  tag ||
    //  D_id_src ||
    //  service_id ||
    //  reference_auth
    // )
    // ==================================================

    const transcriptStart =
        process.hrtime.bigint();


    const transcriptStatement = [

        "TRANSCRIPT",

        {
            x:
                String(
                    sessionInit.A.x
                ),

            y:
                String(
                    sessionInit.A.y
                )
        },

        {
            x:
                String(
                    sessionResponse.B.x
                ),

            y:
                String(
                    sessionResponse.B.y
                )
        },

        String(
            sessionInit.sid
        ),

        String(
            sessionInit.challenge
        ),

        String(
            sessionInit.ctx
        ),

        String(
            sessionInit.tag
        ),

        String(
            sessionInit.D_id_src
        ),

        String(
            sessionInit.service_id
        ),

        String(
            sessionInit.reference_auth
        )
    ];


    const transcript =
        sha256Buffer(
            Buffer.from(
                canonicalJson(
                    transcriptStatement
                ),
                "utf8"
            )
        );


    timings.transcript_ms =
        Number(
            process.hrtime.bigint() -
            transcriptStart
        ) / 1e6;


    // ==================================================
    // 10. Serialize K_DH
    //
    // Empirical encoding of BabyJub point:
    //
    // X(32 bytes) || Y(32 bytes)
    // ==================================================

    const userIKM =
        Buffer.concat([

            bigintTo32Bytes(
                sharedUserX
            ),

            bigintTo32Bytes(
                sharedUserY
            )
        ]);


    const serviceIKM =
        Buffer.concat([

            bigintTo32Bytes(
                sharedServiceX
            ),

            bigintTo32Bytes(
                sharedServiceY
            )
        ]);


    // ==================================================
    // 11. HKDF salt
    //
    // salt =
    // H("salt" || transcript)
    // ==================================================

    const salt =
        sha256Buffer(
            Buffer.concat([

                Buffer.from(
                    "salt",
                    "utf8"
                ),

                transcript
            ])
        );


    // ==================================================
    // 12. HKDF info
    //
    // Thesis:
    //
    // "session-key" ||
    // D_id_src ||
    // service_id ||
    // sid
    // ==================================================

    const info =
        Buffer.from(
            canonicalJson([

                "session-key",

                String(
                    sessionInit.D_id_src
                ),

                String(
                    sessionInit.service_id
                ),

                String(
                    sessionInit.sid
                )
            ]),
            "utf8"
        );


    // ==================================================
    // 13. User derives K_session
    // ==================================================

    const userHkdfStart =
        process.hrtime.bigint();


    const userSessionKey =
        Buffer.from(
            crypto.hkdfSync(
                "sha256",
                userIKM,
                salt,
                info,
                32
            )
        );


    timings.user_hkdf_ms =
        Number(
            process.hrtime.bigint() -
            userHkdfStart
        ) / 1e6;


    // ==================================================
    // 14. Service derives K_session
    // ==================================================

    const serviceHkdfStart =
        process.hrtime.bigint();


    const serviceSessionKey =
        Buffer.from(
            crypto.hkdfSync(
                "sha256",
                serviceIKM,
                salt,
                info,
                32
            )
        );


    timings.service_hkdf_ms =
        Number(
            process.hrtime.bigint() -
            serviceHkdfStart
        ) / 1e6;


    if (
        !timingSafeEqual(
            userSessionKey,
            serviceSessionKey
        )
    ) {

        throw new Error(
            "Derived session keys do not match."
        );
    }


    // ==================================================
    // 15. Server confirmation MAC
    //
    // MAC_S =
    //
    // HMAC(
    //   K_session,
    //   "server-confirm" || transcript
    // )
    // ==================================================

    const serverMacStart =
        process.hrtime.bigint();


    const serverMac =
        hmacSha256(
            serviceSessionKey,
            Buffer.concat([

                Buffer.from(
                    "server-confirm",
                    "utf8"
                ),

                transcript
            ])
        );


    timings.server_mac_generate_ms =
        Number(
            process.hrtime.bigint() -
            serverMacStart
        ) / 1e6;


    // ==================================================
    // 16. User verifies server MAC
    // ==================================================

    const expectedServerMac =
        hmacSha256(
            userSessionKey,
            Buffer.concat([

                Buffer.from(
                    "server-confirm",
                    "utf8"
                ),

                transcript
            ])
        );


    if (
        !timingSafeEqual(
            serverMac,
            expectedServerMac
        )
    ) {

        throw new Error(
            "Server confirmation MAC INVALID."
        );
    }


    // ==================================================
    // 17. User confirmation MAC
    //
    // MAC_U =
    //
    // HMAC(
    //   K_session,
    //   "user-confirm" || transcript
    // )
    // ==================================================

    const userMacStart =
        process.hrtime.bigint();


    const userMac =
        hmacSha256(
            userSessionKey,
            Buffer.concat([

                Buffer.from(
                    "user-confirm",
                    "utf8"
                ),

                transcript
            ])
        );


    timings.user_mac_generate_ms =
        Number(
            process.hrtime.bigint() -
            userMacStart
        ) / 1e6;


    // ==================================================
    // 18. Service verifies user MAC
    // ==================================================

    const expectedUserMac =
        hmacSha256(
            serviceSessionKey,
            Buffer.concat([

                Buffer.from(
                    "user-confirm",
                    "utf8"
                ),

                transcript
            ])
        );


    if (
        !timingSafeEqual(
            userMac,
            expectedUserMac
        )
    ) {

        throw new Error(
            "User confirmation MAC INVALID."
        );
    }


    // ==================================================
    // 19. Store ACTIVE session key privately
    //
    // Do not publish K_session.
    // ==================================================

    const privateSessionState = {

        version:
            1,

        challenge_id:
            challengeId,

        service_id:
            serviceId,

        status:
            "established",

        transcript:
            transcript.toString(
                "hex"
            ),

        session_key:
            userSessionKey.toString(
                "hex"
            ),

        established_at:
            new Date()
                .toISOString()
    };


    saveJson(
        privateSessionStateFile,
        privateSessionState
    );


    // ==================================================
    // 20. Public result
    // ==================================================

    const publicResult = {

        version:
            1,

        challenge_id:
            challengeId,

        service_id:
            serviceId,

        D_id_src:
            String(
                sessionInit.D_id_src
            ),

        sid:
            String(
                sessionInit.sid
            ),

        reference_auth:
            String(
                sessionInit.reference_auth
            ),

        service_key_id:
            serviceIdentity.key_id,

        transcript:
            transcript.toString(
                "hex"
            ),

        server_confirmation_mac:
            serverMac.toString(
                "hex"
            ),

        user_confirmation_mac:
            userMac.toString(
                "hex"
            ),

        shared_secret_match:
            true,

        session_key_match:
            true,

        service_signature_valid:
            true,

        server_mac_valid:
            true,

        user_mac_valid:
            true,

        status:
            "ESTABLISHED",

        established_at:
            new Date()
                .toISOString()
    };


    saveJson(
        publicResultFile,
        publicResult
    );


    // ==================================================
    // 21. Remove ephemeral scalars
    //
    // This is logical deletion in the experimental
    // prototype, not forensic secure erasure.
    // ==================================================

    fs.rmSync(
        userEphemeralFile
    );


    fs.rmSync(
        serviceEphemeralFile
    );


    // ==================================================
    // 22. Report
    // ==================================================

    const totalEnd =
        process.hrtime.bigint();


    timings.total_finalize_ms =
        Number(
            totalEnd -
            totalStart
        ) / 1e6;


    const report = {

        challenge_id:
            challengeId,

        service_id:
            serviceId,

        D_id_src:
            String(
                sessionInit.D_id_src
            ),

        curve:
            "BabyJubJub",

        generator:
            "Base8",

        signature_scheme:
            "Ed25519",

        kdf:
            "HKDF-SHA256",

        mac:
            "HMAC-SHA256",

        service_signature_valid:
            true,

        shared_secret_match:
            true,

        session_key_match:
            true,

        server_mac_valid:
            true,

        user_mac_valid:
            true,

        ephemeral_scalars_deleted:
            true,

        secure_session_status:
            "ESTABLISHED",

        timings_ms:
            timings
    };


    saveJson(
        reportFile,
        report
    );


    // ==================================================
    // Output
    // ==================================================

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - Secure Session"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Challenge ID          : ${challengeId}`
    );

    console.log(
        `Service ID            : ${serviceId}`
    );

    console.log("");

    console.log(
        "KEX-S service signature : VALID"
    );

    console.log(
        "User B^a                : COMPUTED"
    );

    console.log(
        "Service A^b             : COMPUTED"
    );

    console.log(
        "DH shared secret        : MATCH"
    );

    console.log("");

    console.log(
        `Transcript             : ${transcript.toString("hex")}`
    );

    console.log("");

    console.log(
        "HKDF user key           : DERIVED"
    );

    console.log(
        "HKDF service key        : DERIVED"
    );

    console.log(
        "Session keys            : MATCH"
    );

    console.log("");

    console.log(
        "Server confirmation MAC : VALID"
    );

    console.log(
        "User confirmation MAC   : VALID"
    );

    console.log("");

    console.log(
        "Ephemeral a             : DELETED"
    );

    console.log(
        "Ephemeral b             : DELETED"
    );

    console.log("");

    console.log(
        "--------------------------------------------"
    );

    console.log(
        "SECURE SESSION: ESTABLISHED"
    );

    console.log(
        "--------------------------------------------"
    );

    console.log("");

    console.log(
        `Service signature verify : ${timings.service_signature_verify_ms.toFixed(3)} ms`
    );

    console.log(
        `User DH                  : ${timings.user_dh_ms.toFixed(3)} ms`
    );

    console.log(
        `Service DH               : ${timings.service_dh_ms.toFixed(3)} ms`
    );

    console.log(
        `User HKDF                : ${timings.user_hkdf_ms.toFixed(3)} ms`
    );

    console.log(
        `Service HKDF             : ${timings.service_hkdf_ms.toFixed(3)} ms`
    );

    console.log(
        `Total finalize           : ${timings.total_finalize_ms.toFixed(3)} ms`
    );

    console.log("");

    console.log(
        "Public session result:"
    );

    console.log(
        publicResultFile
    );

    console.log("");

    console.log(
        "Private active session key:"
    );

    console.log(
        privateSessionStateFile
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
            "SECURE SESSION: REJECT"
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