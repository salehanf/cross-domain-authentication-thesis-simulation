const { buildPoseidon } =
    require("circomlibjs");

const config =
    require("./config");

const {
    SparseMerkleTree
} = require("./smt");


function expectThrow(fn, message) {

    let threw = false;

    try {

        fn();

    } catch {

        threw = true;
    }


    if (!threw) {

        throw new Error(message);
    }
}


async function main() {

    console.log(
        "============================================"
    );

    console.log(
        " Sparse Merkle Tree Test"
    );

    console.log(
        "============================================"
    );


    const poseidon =
        await buildPoseidon();

    const F =
        poseidon.F;


    // ==================================================
    // Create empty tree
    // ==================================================

    const tree =
        new SparseMerkleTree(
            config.smt.depth,
            poseidon,
            F
        );


    const initialRoot =
        tree.getRoot();


    const emptyLeaf =
        tree.getEmptyLeaf();


    console.log("");
    console.log(
        "SMT depth:",
        config.smt.depth
    );


    console.log("");
    console.log(
        "Initial root:"
    );

    console.log(
        initialRoot.toString()
    );


    // ==================================================
    // Test synthetic leaves
    //
    // These are only SMT test values.
    // Real Enrollment leaves will be generated later.
    // ==================================================

    const leaf1 =
        BigInt(
            F.toObject(
                poseidon([
                    111n,
                    222n
                ])
            )
        );


    const leaf2 =
        BigInt(
            F.toObject(
                poseidon([
                    333n,
                    444n
                ])
            )
        );


    const idx1 =
        12345n;

    const idx2 =
        54321n;


    // ==================================================
    // TEST 1
    //
    // Empty leaf must NOT be accepted as membership
    // ==================================================

    const emptyProof =
        tree.getProof(
            idx1
        );


    const emptyMembership =
        tree.verifyMembershipProof(
            emptyProof
        );


    console.log("");
    console.log(
        "Empty position accepted as member:",
        emptyMembership
    );


    if (emptyMembership) {

        throw new Error(
            "Empty SMT position was incorrectly accepted as membership."
        );
    }


    // ==================================================
    // TEST 2
    //
    // insert(idx, Z[0]) must fail
    // ==================================================

    expectThrow(

        () => {

            tree.insert(
                idx1,
                emptyLeaf
            );
        },

        "insert(idx, Z[0]) was incorrectly accepted."
    );


    console.log(
        "Empty-leaf insertion rejected: true"
    );


    // ==================================================
    // TEST 3
    //
    // Insert first member
    // ==================================================

    console.log("");
    console.log(
        "Inserting leaf 1..."
    );


    const root1 =
        tree.insert(
            idx1,
            leaf1
        );


    console.log(
        "Root after leaf 1:"
    );

    console.log(
        root1.toString()
    );


    // ==================================================
    // TEST 4
    //
    // Duplicate position must fail
    // ==================================================

    expectThrow(

        () => {

            tree.insert(
                idx1,
                leaf2
            );
        },

        "Duplicate SMT insertion was incorrectly accepted."
    );


    console.log(
        "Duplicate insertion rejected: true"
    );


    // ==================================================
    // TEST 5
    //
    // Membership proof
    // ==================================================

    const proof1Old =
        tree.getProof(
            idx1
        );


    const proof1Valid =
        tree.verifyMembershipProof(
            proof1Old
        );


    console.log("");
    console.log(
        "Proof 1 valid:",
        proof1Valid
    );


    if (!proof1Valid) {

        throw new Error(
            "Initial membership proof failed."
        );
    }


    // ==================================================
    // TEST 6
    //
    // JSON serialization must work directly
    // ==================================================

    let jsonProof;


    try {

        jsonProof =
            JSON.stringify(
                proof1Old
            );

    } catch (error) {

        throw new Error(
            "SMT proof is not JSON serializable: " +
            error.message
        );
    }


    const parsedProof =
        JSON.parse(
            jsonProof
        );


    const parsedProofValid =
        tree.verifyMembershipProof(
            parsedProof
        );


    console.log(
        "Proof JSON serialization: true"
    );


    console.log(
        "Parsed JSON proof valid:",
        parsedProofValid
    );


    if (!parsedProofValid) {

        throw new Error(
            "Proof failed after JSON round-trip."
        );
    }


    // ==================================================
    // TEST 7
    //
    // There must be no public update()
    // ==================================================

    const publicUpdateExists =
        typeof tree.update === "function";


    console.log("");
    console.log(
        "Public update() exists:",
        publicUpdateExists
    );


    if (publicUpdateExists) {

        throw new Error(
            "Unsafe public update() method still exists."
        );
    }


    // ==================================================
    // TEST 8
    //
    // Insert second leaf
    // ==================================================

    console.log("");
    console.log(
        "Inserting leaf 2..."
    );


    const root2 =
        tree.insert(
            idx2,
            leaf2
        );


    console.log(
        "Root after leaf 2:"
    );

    console.log(
        root2.toString()
    );


    // ==================================================
    // TEST 9
    //
    // Old proof must fail against CURRENT root
    // ==================================================

    const staleProofAccepted =
        tree.verifyMembershipProof(
            proof1Old
        );


    console.log("");
    console.log(
        "Old proof accepted under new root:",
        staleProofAccepted
    );


    if (staleProofAccepted) {

        throw new Error(
            "Stale membership proof was accepted against the current root."
        );
    }


    // ==================================================
    // TEST 10
    //
    // Fresh proofs must pass
    // ==================================================

    const proof1Current =
        tree.getProof(
            idx1
        );


    const proof2Current =
        tree.getProof(
            idx2
        );


    const proof1CurrentValid =
        tree.verifyMembershipProof(
            proof1Current
        );


    const proof2CurrentValid =
        tree.verifyMembershipProof(
            proof2Current
        );


    console.log("");
    console.log(
        "Leaf 1 valid under current root:",
        proof1CurrentValid
    );


    console.log(
        "Leaf 2 valid under current root:",
        proof2CurrentValid
    );


    if (
        !proof1CurrentValid ||
        !proof2CurrentValid
    ) {

        throw new Error(
            "Fresh membership proof failed."
        );
    }


    // ==================================================
    // TEST 11
    //
    // Tampered proof must fail
    // ==================================================

    const tamperedProof = {
        ...proof1Current,

        leaf:
            (
                BigInt(
                    proof1Current.leaf
                ) + 1n
            ).toString()
    };


    const tamperedValid =
        tree.verifyMembershipProof(
            tamperedProof
        );


    console.log("");
    console.log(
        "Tampered proof accepted:",
        tamperedValid
    );


    if (tamperedValid) {

        throw new Error(
            "Tampered proof was incorrectly accepted."
        );
    }


    // ==================================================
    // TEST 12
    //
    // Revoke first member
    // ==================================================

    console.log("");
    console.log(
        "Removing leaf 1..."
    );


    tree.remove(
        idx1
    );


    /*
        After revocation, idx1 now represents
        an empty leaf.
    */

    const revokedProof =
        tree.getProof(
            idx1
        );


    const revokedMembership =
        tree.verifyMembershipProof(
            revokedProof
        );


    console.log(
        "Revoked leaf accepted as member:",
        revokedMembership
    );


    if (revokedMembership) {

        throw new Error(
            "Revoked member was still accepted."
        );
    }


    // ==================================================
    // TEST 13
    //
    // Remaining member must still be valid
    // ==================================================

    const proof2AfterRemoval =
        tree.getProof(
            idx2
        );


    const proof2AfterRemovalValid =
        tree.verifyMembershipProof(
            proof2AfterRemoval
        );


    console.log(
        "Leaf 2 valid after removing leaf 1:",
        proof2AfterRemovalValid
    );


    if (!proof2AfterRemovalValid) {

        throw new Error(
            "Remaining member failed after another leaf was removed."
        );
    }


    // ==================================================
    // TEST 14
    //
    // Removing already empty position must fail
    // ==================================================

    expectThrow(

        () => {

            tree.remove(
                idx1
            );
        },

        "Removing an already-empty position was incorrectly accepted."
    );


    console.log(
        "Repeated removal rejected: true"
    );


    // ==================================================
    // TEST 15
    //
    // Remove last active member
    // ==================================================

    console.log("");
    console.log(
        "Removing leaf 2..."
    );


    tree.remove(
        idx2
    );


    const finalRoot =
        tree.getRoot();


    const restored =
        finalRoot ===
        initialRoot;


    console.log("");
    console.log(
        "Initial root restored:",
        restored
    );


    if (!restored) {

        throw new Error(
            "SMT did not return to the original empty-tree root."
        );
    }


    // ==================================================
    // Final statistics
    // ==================================================

    console.log("");
    console.log(
        "SMT statistics:"
    );


    console.log(
        tree.getStats()
    );


    console.log("");
    console.log(
        "ALL SMT TESTS PASSED"
    );


    console.log(
        "============================================"
    );
}


main().catch(
    (error) => {

        console.error("");
        console.error(
            "SMT TEST FAILED"
        );

        console.error(
            error
        );

        process.exit(1);
    }
);