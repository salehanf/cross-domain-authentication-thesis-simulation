const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const {
    buildPoseidon,
    buildBabyjub
} = require("circomlibjs");

const config = require("./config");


// ======================================================
// Constants
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


function mod(value, modulus) {

    const result =
        value % modulus;

    return result >= 0n
        ? result
        : result + modulus;
}


function assertEqual(
    label,
    actual,
    expected
) {

    if (
        BigInt(actual) !==
        BigInt(expected)
    ) {

        throw new Error(
            `${label} mismatch\n` +
            `Actual   : ${actual}\n` +
            `Expected : ${expected}`
        );
    }
}


function randomFieldElement() {

    /*
     * User-generated authentication nonce.
     *
     * 31 bytes = 248 bits, safely inside BN254.
     */

    return BigInt(
        "0x" +
        crypto
            .randomBytes(31)
            .toString("hex")
    );
}


// ======================================================
// Main
// ======================================================

async function main() {

    const enrollmentId =
        process.argv[2];

    const challengeId =
        process.argv[3];


    if (
        !enrollmentId ||
        !challengeId
    ) {

        throw new Error(
            "Usage: node src\\generate-auth-proof-input.js <enrollment-id> <challenge-id>"
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


    if (depth !== 20) {

        throw new Error(
            `Current auth-proof circuit expects SMT depth 20, config has ${depth}.`
        );
    }


    // ==================================================
    // Domain separation tags
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

    const TAG_NODE =
        BigInt(
            tags.node ?? 5
        );

    const TAG_EMPTY =
        BigInt(
            tags.empty ?? 6
        );

    const TAG_AUTH_KEY =
        BigInt(
            tags.authKey ?? 10
        );

    const TAG_AUTH_TAG =
        BigInt(
            tags.authTag ?? 11
        );


    // ==================================================
    // Paths
    // ==================================================

    const privateWitnessFile =
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
            "bas",
            "enrollment_registry.json"
        );


    const challengeFile =
        path.join(
            projectRoot,
            "state",
            "auth_challenges",
            `${challengeId}.json`
        );


    // ==================================================
    // Load state
    // ==================================================

    const privateWitness =
        loadJson(
            privateWitnessFile
        );


    const registry =
        loadJson(
            registryFile
        );


    const challengeRecord =
        loadJson(
            challengeFile
        );


    // ==================================================
    // Challenge policy checks
    // ==================================================

    if (
        challengeRecord.status !==
        "pending"
    ) {

        throw new Error(
            `Authentication challenge status is ${challengeRecord.status}, expected pending.`
        );
    }


    const now =
        Date.now();


    const issuedAt =
        Date.parse(
            challengeRecord.issued_at
        );


    const expiresAt =
        Date.parse(
            challengeRecord.expires_at
        );


    if (
        !Number.isFinite(issuedAt) ||
        !Number.isFinite(expiresAt)
    ) {

        throw new Error(
            "Invalid authentication challenge timestamps."
        );
    }


    if (
        now < issuedAt
    ) {

        throw new Error(
            "Authentication challenge is not valid yet."
        );
    }


    if (
        now > expiresAt
    ) {

        throw new Error(
            `Authentication challenge expired at ${challengeRecord.expires_at}`
        );
    }


    // ==================================================
    // Load SignedRoot selected by Destination Service
    // ==================================================

    const signedRoot =
        loadJson(
            challengeRecord.signed_root_file
        );


    assertEqual(
        "challenge root / SignedRoot",
        challengeRecord.root,
        signedRoot.root
    );


    if (
        Number(
            challengeRecord.root_version
        ) !==
        Number(
            signedRoot.version
        )
    ) {

        throw new Error(
            "Challenge root_version does not match SignedRoot."
        );
    }


    if (
        String(
            challengeRecord.D_id
        ) !==
        String(
            signedRoot.D_id
        )
    ) {

        throw new Error(
            "Challenge D_id does not match SignedRoot."
        );
    }


    if (
        String(
            challengeRecord.scheme_id
        ) !==
        String(
            signedRoot.scheme_id
        )
    ) {

        throw new Error(
            "Challenge scheme_id does not match SignedRoot."
        );
    }


    // ==================================================
    // Initialize crypto
    // ==================================================

    const poseidon =
        await buildPoseidon();


    const poseidonF =
        poseidon.F;


    function H(inputs) {

        return BigInt(
            poseidonF.toString(
                poseidon(
                    inputs.map(BigInt)
                )
            )
        );
    }


    const babyJub =
        await buildBabyjub();


    const babyF =
        babyJub.F;


    // ==================================================
    // User secret
    // ==================================================

    const x =
        BigInt(
            privateWitness.x
        );


    const xAnchor =
        BigInt(
            privateWitness.x_anchor
        );


    const D_id =
        BigInt(
            challengeRecord.D_id
        );


    const schemeId =
        BigInt(
            challengeRecord.scheme_id
        );


    // ==================================================
    // x -> x_anchor
    // ==================================================

    const anchorRaw =
        H([
            TAG_ANCHOR,
            schemeId,
            D_id,
            x
        ]);


    const expectedXAnchor =
        mod(
            anchorRaw,
            BABYJUB_Q
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
        anchorNumerator %
            BABYJUB_Q !== 0n
    ) {

        throw new Error(
            "Invalid x_anchor reduction relation."
        );
    }


    const anchorQ =
        anchorNumerator /
        BABYJUB_Q;


    if (
        anchorQ < 0n ||
        anchorQ > 7n
    ) {

        throw new Error(
            `Invalid anchor quotient: ${anchorQ}`
        );
    }


    // ==================================================
    // x_anchor -> Y -> L
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


    const L =
        H([
            TAG_LEAF,
            schemeId,
            D_id,
            Yx,
            Yy
        ]);


    assertEqual(
        "L",
        L,
        privateWitness.L
    );


    // ==================================================
    // x_anchor -> idx
    // ==================================================

    const idxRaw =
        H([
            TAG_IDX,
            schemeId,
            D_id,
            xAnchor
        ]);


    const idxMask =
        (1n << BigInt(depth)) -
        1n;


    const idx =
        idxRaw &
        idxMask;


    assertEqual(
        "idx",
        idx,
        privateWitness.idx
    );


    // ==================================================
    // Confirm active enrollment
    // ==================================================

    const matchingEntry =
        Object.values(
            registry.entries
        ).find(
            entry =>
                entry.status ===
                    "active" &&
                String(entry.idx) ===
                    idx.toString() &&
                String(entry.L) ===
                    L.toString()
        );


    if (!matchingEntry) {

        throw new Error(
            "User leaf is not active in BAS state."
        );
    }


    // ==================================================
    // Sparse Merkle default hashes
    // ==================================================

    const zero =
        new Array(
            depth + 1
        );


    zero[0] =
        H([
            TAG_EMPTY,
            schemeId,
            D_id,
            0n
        ]);


    for (
        let level = 0;
        level < depth;
        level++
    ) {

        zero[level + 1] =
            H([
                TAG_NODE,
                schemeId,
                BigInt(level),
                zero[level],
                zero[level]
            ]);
    }


    // ==================================================
    // Reconstruct current SMT
    // ==================================================

    const levelMaps =
        new Array(
            depth + 1
        );


    levelMaps[0] =
        new Map();


    for (
        const entry
        of Object.values(
            registry.entries
        )
    ) {

        if (
            entry.status !==
            "active"
        ) {
            continue;
        }


        levelMaps[0].set(
            Number(entry.idx),
            BigInt(entry.L)
        );
    }


    for (
        let level = 0;
        level < depth;
        level++
    ) {

        const current =
            levelMaps[level];


        const next =
            new Map();


        const parentIndices =
            new Set();


        for (
            const nodeIndex
            of current.keys()
        ) {

            parentIndices.add(
                Math.floor(
                    nodeIndex / 2
                )
            );
        }


        for (
            const parentIndex
            of parentIndices
        ) {

            const leftIndex =
                parentIndex * 2;


            const rightIndex =
                leftIndex + 1;


            const left =
                current.has(leftIndex)
                    ? current.get(leftIndex)
                    : zero[level];


            const right =
                current.has(rightIndex)
                    ? current.get(rightIndex)
                    : zero[level];


            const parent =
                H([
                    TAG_NODE,
                    schemeId,
                    BigInt(level),
                    left,
                    right
                ]);


            if (
                parent !==
                zero[level + 1]
            ) {

                next.set(
                    parentIndex,
                    parent
                );
            }
        }


        levelMaps[level + 1] =
            next;
    }


    const reconstructedRoot =
        levelMaps[depth].has(0)
            ? levelMaps[depth].get(0)
            : zero[depth];


    assertEqual(
        "SMT root / challenge root",
        reconstructedRoot,
        challengeRecord.root
    );


    // ==================================================
    // Generate private Merkle authentication path
    // ==================================================

    const siblings =
        [];


    let nodeIndex =
        Number(
            idx
        );


    for (
        let level = 0;
        level < depth;
        level++
    ) {

        const siblingIndex =
            nodeIndex ^ 1;


        const sibling =
            levelMaps[level]
                .has(siblingIndex)
                ? levelMaps[level]
                    .get(siblingIndex)
                : zero[level];


        siblings.push(
            sibling
        );


        nodeIndex =
            Math.floor(
                nodeIndex / 2
            );
    }


    // ==================================================
    // Verify Merkle path before handing it to Circom
    // ==================================================

    let current =
        L;


    const idxNumber =
        Number(
            idx
        );


    for (
        let level = 0;
        level < depth;
        level++
    ) {

        const direction =
            (
                idxNumber >>
                level
            ) & 1;


        const left =
            direction === 0
                ? current
                : siblings[level];


        const right =
            direction === 0
                ? siblings[level]
                : current;


        current =
            H([
                TAG_NODE,
                schemeId,
                BigInt(level),
                left,
                right
            ]);
    }


    assertEqual(
        "Merkle membership root",
        current,
        challengeRecord.root
    );


    // ==================================================
    // Destination-service supplied public session data
    // ==================================================

    const challenge =
        BigInt(
            challengeRecord.challenge
        );


    const sid =
        BigInt(
            challengeRecord.sid
        );


    const ctx =
        BigInt(
            challengeRecord.ctx
        );


    // ==================================================
    // User-generated one-time auth nonce
    // ==================================================

    const authNonce =
        randomFieldElement();


    // ==================================================
    // Circuit-friendly thesis KDF instantiation
    //
    // k_auth =
    // Poseidon(
    //   AUTH_KEY,
    //   scheme,
    //   D_id,
    //   x_anchor
    // )
    // ==================================================

    const kAuth =
        H([
            TAG_AUTH_KEY,
            schemeId,
            D_id,
            xAnchor
        ]);


    // ==================================================
    // Session tag
    //
    // tag =
    // Poseidon(
    //   AUTH_TAG,
    //   k_auth,
    //   challenge,
    //   ctx,
    //   sid,
    //   auth_nonce
    // )
    // ==================================================

    const tag =
        H([
            TAG_AUTH_TAG,
            kAuth,
            challenge,
            ctx,
            sid,
            authNonce
        ]);


    // ==================================================
    // Circom input
    // ==================================================

    const circuitInput = {

        // Public
        root:
            String(
                challengeRecord.root
            ),

        root_version:
            String(
                challengeRecord.root_version
            ),

        D_id:
            D_id.toString(),

        scheme_id:
            schemeId.toString(),

        challenge:
            challenge.toString(),

        ctx:
            ctx.toString(),

        sid:
            sid.toString(),

        auth_nonce:
            authNonce.toString(),

        tag:
            tag.toString(),


        // Private
        x:
            x.toString(),

        x_anchor:
            xAnchor.toString(),

        anchor_q:
            anchorQ.toString(),

        path_siblings:
            siblings.map(
                value =>
                    value.toString()
            )
    };


    // ==================================================
    // Save proof input
    // ==================================================

    const inputFile =
        path.join(
            projectRoot,
            "build",
            "auth_proof_inputs",
            `${challengeId}.json`
        );


    saveJson(
        inputFile,
        circuitInput
    );


    // ==================================================
    // Public authentication context
    //
    // NO x / x_anchor / L / idx / path.
    // ==================================================

    const artifactDir =
        path.join(
            projectRoot,
            "artifacts",
            "auth",
            challengeId
        );


    const contextFile =
        path.join(
            artifactDir,
            "auth_context.json"
        );


    const publicContext = {

        challenge_id:
            challengeId,

        enrollment_id:
            enrollmentId,

        service:
            challengeRecord.service,

        context_label:
            challengeRecord.context_label,

        SignedRoot:
            signedRoot,

        root_version:
            challengeRecord.root_version,

        D_id:
            challengeRecord.D_id,

        scheme_id:
            challengeRecord.scheme_id,

        challenge:
            challenge.toString(),

        ctx:
            ctx.toString(),

        sid:
            sid.toString(),

        auth_nonce:
            authNonce.toString(),

        tag:
            tag.toString()
    };


    saveJson(
        contextFile,
        publicContext
    );


    // ==================================================
    // Output
    // ==================================================

    console.log(
        "============================================"
    );

    console.log(
        " Thesis Protocol - Authentication Input"
    );

    console.log(
        "============================================"
    );

    console.log(
        `Enrollment ID : ${enrollmentId}`
    );

    console.log(
        `Challenge ID  : ${challengeId}`
    );

    console.log(
        `Service       : ${challengeRecord.service}`
    );

    console.log(
        `SignedRoot    : v${challengeRecord.root_version}`
    );

    console.log(
        `SMT depth     : ${depth}`
    );

    console.log("");

    console.log(
        "Challenge source:"
    );

    console.log(
        "challenge     : DESTINATION SERVICE"
    );

    console.log(
        "sid           : DESTINATION SERVICE"
    );

    console.log(
        "ctx           : DESTINATION SERVICE"
    );

    console.log(
        "auth_nonce    : USER"
    );

    console.log("");

    console.log(
        "Authentication relations checked:"
    );

    console.log(
        "x -> x_anchor            : MATCH"
    );

    console.log(
        "x_anchor -> Y -> L       : MATCH"
    );

    console.log(
        "x_anchor -> idx          : MATCH"
    );

    console.log(
        "Active enrollment record : MATCH"
    );

    console.log(
        "SMT reconstruction       : MATCH"
    );

    console.log(
        "Merkle membership path   : VALID"
    );

    console.log(
        "Session tag              : VALID"
    );

    console.log("");

    console.log(
        `Merkle siblings : ${siblings.length}`
    );

    console.log(
        `Anchor quotient : ${anchorQ}`
    );

    console.log("");

    console.log(
        "Private values exposed:"
    );

    console.log(
        "x            : NO"
    );

    console.log(
        "x_anchor     : NO"
    );

    console.log(
        "L            : NO"
    );

    console.log(
        "idx          : NO"
    );

    console.log(
        "Merkle path  : NO"
    );

    console.log("");

    console.log(
        "Circuit input:"
    );

    console.log(
        inputFile
    );

    console.log("");

    console.log(
        "Public auth context:"
    );

    console.log(
        contextFile
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
            "Authentication input generation failed:"
        );

        console.error(
            error.message
        );

        process.exit(1);
    });