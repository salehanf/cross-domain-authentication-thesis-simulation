pragma circom 2.2.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";


// ======================================================
// BabyJub subgroup scalar range
// ======================================================

template AssertScalarQ() {

    var Q =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;


    signal input in;


    component bits =
        Num2Bits(251);

    bits.in <==
        in;


    component lt =
        LessThan(251);

    lt.in[0] <==
        in;

    lt.in[1] <==
        Q;

    lt.out === 1;
}


// ======================================================
// Reduce BN254 field element modulo BabyJub q
// ======================================================

template ReduceFieldModQ() {

    var Q =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;


    var P_MINUS_7Q =
    2736030358979909402780800718157159386010666595306063529296694559936676884330;


    signal input raw;

    signal input scalar;

    signal input quotient;


    component scalarRange =
        AssertScalarQ();

    scalarRange.in <==
        scalar;


    component quotientBits =
        Num2Bits(3);

    quotientBits.in <==
        quotient;


    raw ===
        scalar +
        quotient * Q;


    component qIsSeven =
        IsEqual();

    qIsSeven.in[0] <==
        quotient;

    qIsSeven.in[1] <==
        7;


    component scalarBoundForSeven =
        LessThan(251);

    scalarBoundForSeven.in[0] <==
        scalar;

    scalarBoundForSeven.in[1] <==
        P_MINUS_7Q;


    qIsSeven.out *
    (
        1 -
        scalarBoundForSeven.out
    )
    === 0;
}


// ======================================================
// Authentication ZK Proof
//
// Public statement:
//
// root
// root_version
// D_id
// scheme_id
// challenge
// ctx
// sid
// auth_nonce
// tag
//
// Private witness:
//
// x
// x_anchor
// anchor_q
// Merkle siblings
//
// L, idx, Y and path direction are derived internally.
// ======================================================

template AuthProof(depth) {

    // ==================================================
    // Domain-separation tags
    // ==================================================

    var TAG_ANCHOR =
        1;

    var TAG_LEAF =
        2;

    var TAG_IDX =
        3;

    var TAG_NODE =
        5;

    var TAG_AUTH_KEY =
        10;

    var TAG_AUTH_TAG =
        11;


    // ==================================================
    // Public statement
    // ==================================================

    signal input root;

    signal input root_version;

    signal input D_id;

    signal input scheme_id;

    signal input challenge;

    signal input ctx;

    signal input sid;

    signal input auth_nonce;

    signal input tag;


    // ==================================================
    // Private witness
    // ==================================================

    signal input x;

    signal input x_anchor;

    signal input anchor_q;


    // Merkle authentication path.
    //
    // Direction bits are NOT supplied separately.
    // They are derived from idx, which itself is
    // derived from x_anchor.

    signal input path_siblings[depth];


    // ==================================================
    // 0. Root version range
    //
    // The destination service separately verifies that
    // root_version equals SignedRoot.version.
    //
    // This constraint also binds root_version as an
    // actual Groth16 public input.
    // ==================================================

    component versionBits =
        Num2Bits(32);

    versionBits.in <==
        root_version;


    // ==================================================
    // 1. x range
    // ==================================================

    component xRange =
        AssertScalarQ();

    xRange.in <==
        x;


    // ==================================================
    // 2. x_anchor range
    // ==================================================

    component anchorRange =
        AssertScalarQ();

    anchorRange.in <==
        x_anchor;


    component anchorZero =
        IsZero();

    anchorZero.in <==
        x_anchor;

    anchorZero.out === 0;


    // ==================================================
    // 3.
    //
    // x_anchor =
    //
    // H_F(
    //   "anchor",
    //   scheme_id,
    //   D_id,
    //   x
    // ) mod q
    // ==================================================

    component anchorHash =
        Poseidon(4);


    anchorHash.inputs[0] <==
        TAG_ANCHOR;

    anchorHash.inputs[1] <==
        scheme_id;

    anchorHash.inputs[2] <==
        D_id;

    anchorHash.inputs[3] <==
        x;


    component anchorReduction =
        ReduceFieldModQ();


    anchorReduction.raw <==
        anchorHash.out;

    anchorReduction.scalar <==
        x_anchor;

    anchorReduction.quotient <==
        anchor_q;


    // ==================================================
    // 4.
    //
    // Y = x_anchor * Base8
    //
    // Y remains private.
    // ==================================================

    component Y =
        BabyPbk();

    Y.in <==
        x_anchor;


    // ==================================================
    // 5.
    //
    // L =
    //
    // H(
    //   "leaf",
    //   scheme_id,
    //   D_id,
    //   Y
    // )
    //
    // L remains private.
    // ==================================================

    component leafHash =
        Poseidon(5);


    leafHash.inputs[0] <==
        TAG_LEAF;

    leafHash.inputs[1] <==
        scheme_id;

    leafHash.inputs[2] <==
        D_id;

    leafHash.inputs[3] <==
        Y.Ax;

    leafHash.inputs[4] <==
        Y.Ay;


    // ==================================================
    // 6.
    //
    // idx =
    //
    // low-depth-bits(
    //   H(
    //     "idx",
    //     scheme_id,
    //     D_id,
    //     x_anchor
    //   )
    // )
    //
    // idx itself remains private.
    //
    // The low bits are also the Merkle path directions.
    // ==================================================

    component idxHash =
        Poseidon(4);


    idxHash.inputs[0] <==
        TAG_IDX;

    idxHash.inputs[1] <==
        scheme_id;

    idxHash.inputs[2] <==
        D_id;

    idxHash.inputs[3] <==
        x_anchor;


    component idxBits =
        Num2Bits_strict();

    idxBits.in <==
        idxHash.out;


    // ==================================================
    // 7. Sparse Merkle membership
    //
    // Tree convention:
    //
    // LSB-first path
    //
    // node =
    //
    // Poseidon(
    //   TAG_NODE,
    //   scheme_id,
    //   level,
    //   left,
    //   right
    // )
    //
    // leaf value is L itself.
    // ==================================================

    signal current[depth + 1];

    signal leftChild[depth];

    signal rightChild[depth];


    component merkleHash[depth];


    current[0] <==
        leafHash.out;


    for (
        var level = 0;
        level < depth;
        level++
    ) {

        /*
         * idx bit = 0:
         *
         * left  = current
         * right = sibling
         *
         *
         * idx bit = 1:
         *
         * left  = sibling
         * right = current
         */

        leftChild[level] <==
            current[level] +
            idxBits.out[level] *
            (
                path_siblings[level] -
                current[level]
            );


        rightChild[level] <==
            path_siblings[level] +
            idxBits.out[level] *
            (
                current[level] -
                path_siblings[level]
            );


        merkleHash[level] =
            Poseidon(5);


        merkleHash[level].inputs[0] <==
            TAG_NODE;

        merkleHash[level].inputs[1] <==
            scheme_id;

        merkleHash[level].inputs[2] <==
            level;

        merkleHash[level].inputs[3] <==
            leftChild[level];

        merkleHash[level].inputs[4] <==
            rightChild[level];


        current[level + 1] <==
            merkleHash[level].out;
    }


    current[depth] ===
        root;


    // ==================================================
    // 8.
    //
    // Empirical circuit-friendly KDF:
    //
    // k_auth =
    //
    // Poseidon(
    //   TAG_AUTH_KEY,
    //   scheme_id,
    //   D_id,
    //   x_anchor
    // )
    //
    // This instantiates the thesis-level KDF.
    // ==================================================

    component authKey =
        Poseidon(4);


    authKey.inputs[0] <==
        TAG_AUTH_KEY;

    authKey.inputs[1] <==
        scheme_id;

    authKey.inputs[2] <==
        D_id;

    authKey.inputs[3] <==
        x_anchor;


    // ==================================================
    // 9.
    //
    // Empirical circuit-friendly PRF:
    //
    // tag =
    //
    // Poseidon(
    //   TAG_AUTH_TAG,
    //   k_auth,
    //   challenge,
    //   ctx,
    //   sid,
    //   auth_nonce
    // )
    //
    // Thus the proof is bound to THIS session.
    // ==================================================

    component sessionTag =
        Poseidon(6);


    sessionTag.inputs[0] <==
        TAG_AUTH_TAG;

    sessionTag.inputs[1] <==
        authKey.out;

    sessionTag.inputs[2] <==
        challenge;

    sessionTag.inputs[3] <==
        ctx;

    sessionTag.inputs[4] <==
        sid;

    sessionTag.inputs[5] <==
        auth_nonce;


    sessionTag.out ===
        tag;
}


// ======================================================
// Current experimental SMT depth = 20
// ======================================================

component main {
    public [
        root,
        root_version,
        D_id,
        scheme_id,
        challenge,
        ctx,
        sid,
        auth_nonce,
        tag
    ]
} = AuthProof(20);