pragma circom 2.2.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/babyjub.circom";


// ======================================================
// Assert:
//
//      0 <= in < BabyJub subgroup order q
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
// Reduce one BN254 field element modulo BabyJub q
//
// raw = scalar + quotient*q
//
// with:
//
//      0 <= scalar < q
//      0 <= quotient <= 7
//
// Additional q=7 bound prevents BN254 field wrap.
// ======================================================

template ReduceFieldModQ() {

    var Q =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;


    var P_MINUS_7Q =
    2736030358979909402780800718157159386010666595306063529296694559936676884330;


    signal input raw;

    signal input scalar;

    signal input quotient;


    // --------------------------------------------------
    // scalar < q
    // --------------------------------------------------

    component scalarRange =
        AssertScalarQ();

    scalarRange.in <==
        scalar;


    // --------------------------------------------------
    // quotient is 3 bits: 0 ... 7
    // --------------------------------------------------

    component quotientBits =
        Num2Bits(3);

    quotientBits.in <==
        quotient;


    // --------------------------------------------------
    // raw = scalar + quotient*q
    // --------------------------------------------------

    raw ===
        scalar +
        quotient * Q;


    // --------------------------------------------------
    // Prevent wrap when quotient == 7
    // --------------------------------------------------

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
// Link Proof
//
// Current experimental instantiation:
//
//      SMT depth = 20
//      Poseidon hashes
//      BabyJub/Base8
//      Groth16 / BN254
//
// Proves:
//
// 1) x_anchor = H_F(anchor || scheme || domain || x) mod q
//
// 2) Y = x_anchor * Base8
//
// 3) L = H(leaf || scheme || domain || Y)
//
// 4) idx = low_depth_bits(
//          H(idx || scheme || domain || x_anchor)
//        )
//
// 5) y_hash =
//      H(revoke || scheme || domain || Y)
//
// 6) PVSS polynomial commitments are consistent
//    with a0 = x_anchor.
//
// ======================================================

template LinkProof(depth) {

    // ==================================================
    // Protocol domain-separation tags
    // ==================================================

    var TAG_ANCHOR =
        1;

    var TAG_LEAF =
        2;

    var TAG_IDX =
        3;

    var TAG_REVOKE =
        4;

    var TAG_PVSS_COEFF_COMMIT =
        7;


    // ==================================================
    // Public statement
    // ==================================================

    signal input D_id;

    signal input scheme_id;


    // Merkle enrollment values
    signal input L;

    signal input idx;

    signal input y_hash;


    // PVSS public polynomial commitments
    signal input C0;

    signal input C1;

    signal input C2;


    // ==================================================
    // Private witness
    // ==================================================

    // User's original enrollment secret
    signal input x;


    // Domain-separated secret
    signal input x_anchor;


    // Quotient for:
    //
    // anchorRaw = x_anchor + anchor_q*q
    //
    signal input anchor_q;


    // Remaining Shamir polynomial coefficients:
    //
    // f(z) = x_anchor + a1*z + a2*z^2
    //
    signal input a1;

    signal input a2;


    // Hiding randomness for the three commitments
    signal input blind0;

    signal input blind1;

    signal input blind2;


    // ==================================================
    // Range checks
    // ==================================================

    component rangeX =
        AssertScalarQ();

    rangeX.in <==
        x;


    component rangeAnchor =
        AssertScalarQ();

    rangeAnchor.in <==
        x_anchor;


    component rangeA1 =
        AssertScalarQ();

    rangeA1.in <==
        a1;


    component rangeA2 =
        AssertScalarQ();

    rangeA2.in <==
        a2;


    component rangeBlind0 =
        AssertScalarQ();

    rangeBlind0.in <==
        blind0;


    component rangeBlind1 =
        AssertScalarQ();

    rangeBlind1.in <==
        blind1;


    component rangeBlind2 =
        AssertScalarQ();

    rangeBlind2.in <==
        blind2;


    // x_anchor must not be zero.
    //
    // Current enrollment implementation regenerates
    // the material if x_anchor == 0.

    component anchorZero =
        IsZero();

    anchorZero.in <==
        x_anchor;

    anchorZero.out === 0;


    // ==================================================
    // 1)
    //
    // anchorRaw =
    //
    // Poseidon(
    //      TAG_ANCHOR,
    //      scheme_id,
    //      D_id,
    //      x
    // )
    //
    // x_anchor = anchorRaw mod q
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
    // 2)
    //
    // Y = x_anchor * Base8
    //
    // Y remains PRIVATE.
    //
    // BabyPbk internally performs the fixed-base
    // BabyJub multiplication.
    // ==================================================

    component Y =
        BabyPbk();

    Y.in <==
        x_anchor;


    // ==================================================
    // 3)
    //
    // L =
    //
    // Poseidon(
    //      TAG_LEAF,
    //      scheme_id,
    //      D_id,
    //      Y.x,
    //      Y.y
    // )
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


    leafHash.out ===
        L;


    // ==================================================
    // 4)
    //
    // idxRaw =
    //
    // Poseidon(
    //      TAG_IDX,
    //      scheme_id,
    //      D_id,
    //      x_anchor
    // )
    //
    // Current development SMT depth = 20.
    //
    // idx = low "depth" bits of idxRaw.
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


    /*
     * Strict decomposition is important:
     *
     * Poseidon output is a BN254 field element.
     *
     * Num2Bits_strict enforces the canonical
     * representation before extracting the low bits.
     */

    component idxRawBits =
        Num2Bits_strict();

    idxRawBits.in <==
        idxHash.out;


    component idxLowBits =
        Bits2Num(depth);


    for (
        var i = 0;
        i < depth;
        i++
    ) {

        idxLowBits.in[i] <==
            idxRawBits.out[i];
    }


    idxLowBits.out ===
        idx;


    // ==================================================
    // 5)
    //
    // y_hash =
    //
    // Poseidon(
    //      TAG_REVOKE,
    //      scheme_id,
    //      D_id,
    //      Y.x,
    //      Y.y
    // )
    // ==================================================

    component revokeHash =
        Poseidon(5);


    revokeHash.inputs[0] <==
        TAG_REVOKE;

    revokeHash.inputs[1] <==
        scheme_id;

    revokeHash.inputs[2] <==
        D_id;

    revokeHash.inputs[3] <==
        Y.Ax;

    revokeHash.inputs[4] <==
        Y.Ay;


    revokeHash.out ===
        y_hash;


    // ==================================================
    // 6)
    //
    // PVSS consistency bridge
    //
    // The five already-verified π_i^pvss proofs
    // demonstrate that encrypted shares correspond
    // to the polynomial represented by:
    //
    //      C0, C1, C2
    //
    // Here we prove that the SAME commitments open to:
    //
    //      a0 = x_anchor
    //      a1
    //      a2
    //
    // Therefore the PVSS polynomial is rooted at
    // the same x_anchor used for L / idx / y_hash.
    // ==================================================


    // --------------------------------------------------
    // C0 commits to x_anchor
    // --------------------------------------------------

    component commit0 =
        Poseidon(6);


    commit0.inputs[0] <==
        TAG_PVSS_COEFF_COMMIT;

    commit0.inputs[1] <==
        scheme_id;

    commit0.inputs[2] <==
        D_id;

    commit0.inputs[3] <==
        0;

    commit0.inputs[4] <==
        x_anchor;

    commit0.inputs[5] <==
        blind0;


    commit0.out ===
        C0;


    // --------------------------------------------------
    // C1 commits to a1
    // --------------------------------------------------

    component commit1 =
        Poseidon(6);


    commit1.inputs[0] <==
        TAG_PVSS_COEFF_COMMIT;

    commit1.inputs[1] <==
        scheme_id;

    commit1.inputs[2] <==
        D_id;

    commit1.inputs[3] <==
        1;

    commit1.inputs[4] <==
        a1;

    commit1.inputs[5] <==
        blind1;


    commit1.out ===
        C1;


    // --------------------------------------------------
    // C2 commits to a2
    // --------------------------------------------------

    component commit2 =
        Poseidon(6);


    commit2.inputs[0] <==
        TAG_PVSS_COEFF_COMMIT;

    commit2.inputs[1] <==
        scheme_id;

    commit2.inputs[2] <==
        D_id;

    commit2.inputs[3] <==
        2;

    commit2.inputs[4] <==
        a2;

    commit2.inputs[5] <==
        blind2;


    commit2.out ===
        C2;
}


// ======================================================
// Current baseline experiment:
//
//      SMT depth = 20
//
// Public statement:
//
//      D_id
//      scheme_id
//      L
//      idx
//      y_hash
//      C0
//      C1
//      C2
//
// Everything else remains private.
// ======================================================

component main {
    public [
        D_id,
        scheme_id,

        L,
        idx,
        y_hash,

        C0,
        C1,
        C2
    ]
} = LinkProof(20);