pragma circom 2.2.0;

include "../node_modules/circomlib/circuits/poseidon.circom";
include "../node_modules/circomlib/circuits/escalarmulany.circom";


// ======================================================
// Assert:
//      0 <= in < BabyJub subgroup order q
// ======================================================

template AssertScalarQ() {

    var Q =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;

    signal input in;


    // q is a 251-bit number.
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
// Reduce a BN254 field element modulo BabyJub q
//
// We provide:
//
//      raw
//      scalar
//      quotient
//
// and prove:
//
//      raw = scalar + quotient * q
//
// with:
//
//      0 <= scalar < q
//      0 <= quotient <= 7
//
// Since BN254 field prime p < 8q.
//
// For quotient = 7 we additionally require:
//
//      scalar < p - 7q
//
// so RHS does not wrap around modulo p.
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
    // 0 <= scalar < q
    // --------------------------------------------------

    component scalarRange =
        AssertScalarQ();

    scalarRange.in <==
        scalar;


    // --------------------------------------------------
    // quotient is 3 bits:
    // 0 ... 7
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
    // If quotient == 7:
    //
    // scalar < p - 7q
    //
    // prevents field wrap-around.
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
// PVSS Share Correctness Proof
//
// Baseline configuration:
//
//      n = 5
//      t = 3
//
// Polynomial:
//
//      f(z) = a0 + a1*z + a2*z^2 mod q
//
// where:
//
//      a0 = x_anchor
//
// This circuit proves for one administrator:
//
//  1. Commitments correspond to a0,a1,a2.
//  2. share = f(admin_id) mod q.
//  3. R_i = r_i * Base8.
//  4. Shared_i = r_i * PK_i.
//  5. mask derives from Shared_i.
//  6. ciphertext encrypts the same share.
//  7. ciphertext tag is consistent.
//
// Public:
//
//      D_id
//      scheme_id
//      admin_id
//      PK_i
//      E_i = (R_i, c_i, tag_i)
//      C0,C1,C2
//
// Private:
//
//      a0,a1,a2
//      commitment blindings
//      share
//      r_i
//      reduction witnesses
// ======================================================

template PVSSShareProof() {

    // ==================================================
    // Constants
    // ==================================================

    var Q =
    2736030358979909402780800718157159386076813972158567259200215660948447373041;


    var TAG_PVSS_COEFF_COMMIT = 7;

    var TAG_PVSS_MASK = 8;

    var TAG_PVSS_CIPHER_TAG = 9;


    /*
     * BabyJub Base8.
     *
     * This is the same Base8 used by circomlib.
     */

    var BASE8[2] = [

        5299619240641551281634865583518297030282874472190772894086521144482721001553,

        16950150798460657717958625567821834550301663161624707787222815936182638968203
    ];


    // ==================================================
    // Public statement
    // ==================================================

    signal input D_id;

    signal input scheme_id;

    signal input admin_id;


    // Administrator PVSS public key
    signal input pk_x;

    signal input pk_y;


    // Ephemeral public point R_i
    signal input R_x;

    signal input R_y;


    // Encrypted share
    signal input cipher_c;

    signal input cipher_tag;


    // Polynomial coefficient commitments
    signal input C0;

    signal input C1;

    signal input C2;


    // ==================================================
    // Private witness
    // ==================================================

    // Polynomial coefficients
    signal input a0;

    signal input a1;

    signal input a2;


    // Hiding commitment randomness
    signal input blind0;

    signal input blind1;

    signal input blind2;


    // Plaintext Shamir share
    signal input share;


    /*
     * Intermediate value for Horner evaluation:
     *
     * u1 =
     * (a2 * admin_id + a1) mod q
     */

    signal input u1;


    /*
     * Quotients used for explicit mod-q
     * polynomial reduction.
     */

    signal input poly_q1;

    signal input poly_q2;


    // Per-admin encryption randomness
    signal input encryption_r;


    // Poseidon mask reduced to q
    signal input mask_scalar;

    signal input mask_q;


    /*
     * Encryption reduction quotient:
     *
     * share + mask =
     * cipher_c + cipher_q*q
     *
     * Since share, mask < q,
     * cipher_q can only be 0 or 1.
     */

    signal input cipher_q;


    // ==================================================
    // Admin ID must be 1 ... 5
    // ==================================================

    component adminBits =
        Num2Bits(3);

    adminBits.in <==
        admin_id;


    component adminUpper =
        LessThan(3);

    adminUpper.in[0] <==
        admin_id;

    adminUpper.in[1] <==
        6;

    adminUpper.out === 1;


    component adminZero =
        IsZero();

    adminZero.in <==
        admin_id;

    adminZero.out === 0;


    // ==================================================
    // Scalar range checks
    // ==================================================

    component rangeA0 =
        AssertScalarQ();

    rangeA0.in <==
        a0;


    component rangeA1 =
        AssertScalarQ();

    rangeA1.in <==
        a1;


    component rangeA2 =
        AssertScalarQ();

    rangeA2.in <==
        a2;


    component rangeB0 =
        AssertScalarQ();

    rangeB0.in <==
        blind0;


    component rangeB1 =
        AssertScalarQ();

    rangeB1.in <==
        blind1;


    component rangeB2 =
        AssertScalarQ();

    rangeB2.in <==
        blind2;


    component rangeShare =
        AssertScalarQ();

    rangeShare.in <==
        share;


    component rangeU1 =
        AssertScalarQ();

    rangeU1.in <==
        u1;


    component rangeR =
        AssertScalarQ();

    rangeR.in <==
        encryption_r;


    component rangeMask =
        AssertScalarQ();

    rangeMask.in <==
        mask_scalar;


    component rangeCipher =
        AssertScalarQ();

    rangeCipher.in <==
        cipher_c;


    // Encryption randomness must not be zero.

    component rZero =
        IsZero();

    rZero.in <==
        encryption_r;

    rZero.out === 0;


    // ==================================================
    // Coefficient commitment C0
    //
    // C0 =
    // Poseidon(
    //   TAG,
    //   scheme_id,
    //   D_id,
    //   0,
    //   a0,
    //   blind0
    // )
    // ==================================================

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
        a0;

    commit0.inputs[5] <==
        blind0;

    commit0.out ===
        C0;


    // ==================================================
    // Coefficient commitment C1
    // ==================================================

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


    // ==================================================
    // Coefficient commitment C2
    // ==================================================

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


    // ==================================================
    // Polynomial evaluation mod q
    //
    // Horner:
    //
    // raw1 =
    //      a2 * admin_id + a1
    //
    // raw1 =
    //      u1 + poly_q1*q
    //
    //
    // raw2 =
    //      u1 * admin_id + a0
    //
    // raw2 =
    //      share + poly_q2*q
    //
    //
    // admin_id <= 5
    //
    // therefore:
    //
    // raw1 < 6q
    // raw2 < 6q
    //
    // so quotient <= 5.
    // ==================================================

    component polyQ1Bits =
        Num2Bits(3);

    polyQ1Bits.in <==
        poly_q1;


    component polyQ1Upper =
        LessThan(3);

    polyQ1Upper.in[0] <==
        poly_q1;

    polyQ1Upper.in[1] <==
        6;

    polyQ1Upper.out === 1;


    component polyQ2Bits =
        Num2Bits(3);

    polyQ2Bits.in <==
        poly_q2;


    component polyQ2Upper =
        LessThan(3);

    polyQ2Upper.in[0] <==
        poly_q2;

    polyQ2Upper.in[1] <==
        6;

    polyQ2Upper.out === 1;


    a2 *
    admin_id +
    a1
    ===
    u1 +
    poly_q1 *
    Q;


    u1 *
    admin_id +
    a0
    ===
    share +
    poly_q2 *
    Q;


    // ==================================================
    // Validate administrator public key
    // ==================================================

    component pkCheck =
        BabyCheck();

    pkCheck.x <==
        pk_x;

    pkCheck.y <==
        pk_y;


    /*
     * Our registry generates:
     *
     * PK_i = SK_i * Base8
     *
     * with SK_i != 0.
     *
     * Therefore PK_i must not be the identity.
     */

    component pkXZero =
        IsZero();

    pkXZero.in <==
        pk_x;

    pkXZero.out === 0;


    // ==================================================
    // encryption_r is restricted to 248 bits.
    //
    // EscalarMulAny in circomlib supports n <= 248.
    // ==================================================

    component rBits =
        Num2Bits(248);

    rBits.in <==
        encryption_r;


    // ==================================================
    // R_i = encryption_r * Base8
    //
    // We intentionally use EscalarMulAny(248)
    // instead of EscalarMulFix because the current
    // circomlib EscalarMulFix segmentation logic
    // does not handle n = 248 correctly.
    // ==================================================

    component ephemeralMul =
        EscalarMulAny(248);


    for (
        var j = 0;
        j < 248;
        j++
    ) {

        ephemeralMul.e[j] <==
            rBits.out[j];
    }


    // Base8 is a fixed, valid,
    // non-zero BabyJub subgroup point.

    ephemeralMul.p[0] <==
        BASE8[0];

    ephemeralMul.p[1] <==
        BASE8[1];


    ephemeralMul.out[0] ===
        R_x;

    ephemeralMul.out[1] ===
        R_y;


    // ==================================================
    // Shared_i =
    // encryption_r * PK_i
    // ==================================================

    component sharedMul =
        EscalarMulAny(248);


    for (
        var k = 0;
        k < 248;
        k++
    ) {

        sharedMul.e[k] <==
            rBits.out[k];
    }


    sharedMul.p[0] <==
        pk_x;

    sharedMul.p[1] <==
        pk_y;


    // ==================================================
    // mask_raw =
    //
    // Poseidon(
    //   TAG_PVSS_MASK,
    //   scheme_id,
    //   D_id,
    //   admin_id,
    //   Shared_x,
    //   Shared_y
    // )
    // ==================================================

    component maskHash =
        Poseidon(6);


    maskHash.inputs[0] <==
        TAG_PVSS_MASK;

    maskHash.inputs[1] <==
        scheme_id;

    maskHash.inputs[2] <==
        D_id;

    maskHash.inputs[3] <==
        admin_id;

    maskHash.inputs[4] <==
        sharedMul.out[0];

    maskHash.inputs[5] <==
        sharedMul.out[1];


    // ==================================================
    // mask_scalar =
    // mask_raw mod q
    // ==================================================

    component maskReduction =
        ReduceFieldModQ();


    maskReduction.raw <==
        maskHash.out;

    maskReduction.scalar <==
        mask_scalar;

    maskReduction.quotient <==
        mask_q;


    // ==================================================
    // Ciphertext:
    //
    // cipher_c =
    // (share + mask_scalar) mod q
    //
    // Because:
    //
    // 0 <= share < q
    // 0 <= mask_scalar < q
    //
    // quotient can only be 0 or 1.
    // ==================================================

    cipher_q *
    (
        cipher_q - 1
    )
    === 0;


    share +
    mask_scalar
    ===
    cipher_c +
    cipher_q *
    Q;


    // ==================================================
    // Ciphertext integrity/binding tag
    //
    // tag =
    //
    // Poseidon(
    //   TAG_PVSS_CIPHER_TAG,
    //   scheme_id,
    //   D_id,
    //   admin_id,
    //   R_x,
    //   R_y,
    //   cipher_c,
    //   mask_raw
    // )
    // ==================================================

    component tagHash =
        Poseidon(8);


    tagHash.inputs[0] <==
        TAG_PVSS_CIPHER_TAG;

    tagHash.inputs[1] <==
        scheme_id;

    tagHash.inputs[2] <==
        D_id;

    tagHash.inputs[3] <==
        admin_id;

    tagHash.inputs[4] <==
        R_x;

    tagHash.inputs[5] <==
        R_y;

    tagHash.inputs[6] <==
        cipher_c;

    tagHash.inputs[7] <==
        maskHash.out;


    tagHash.out ===
        cipher_tag;
}


// ======================================================
// Main circuit
//
// Explicit public inputs.
// Everything else remains private witness.
// ======================================================

component main {
    public [
        D_id,
        scheme_id,
        admin_id,

        pk_x,
        pk_y,

        R_x,
        R_y,

        cipher_c,
        cipher_tag,

        C0,
        C1,
        C2
    ]
} = PVSSShareProof();