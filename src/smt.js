const { buildPoseidon } = require("circomlibjs");
const config = require("./config");


class SparseMerkleTree {

    constructor(depth, poseidon, F) {

        if (!Number.isInteger(depth) || depth < 1) {
            throw new Error(
                "SMT depth must be a positive integer."
            );
        }

        if (
            config.protocol.tags.node === undefined ||
            config.protocol.tags.empty === undefined
        ) {
            throw new Error(
                "SMT tags 'node' and 'empty' are missing from config.js."
            );
        }

        this.depth = depth;

        this.poseidon = poseidon;
        this.F = F;

        this.schemeId =
            BigInt(config.protocol.schemeId);

        this.domainId =
            BigInt(config.domain.domainId);

        this.TAG_NODE =
            BigInt(config.protocol.tags.node);

        this.TAG_EMPTY =
            BigInt(config.protocol.tags.empty);


        /*
            Sparse storage.

            Only non-default nodes are stored.

            key format:
            level:index
        */

        this.nodes = new Map();

        this.leafCount = 0;


        /*
            Default hashes:

            Z[0]
            Z[1]
            ...
            Z[d]
        */

        this.zeroHashes = [];

        this._buildZeroHashes();


        /*
            Initial empty-tree root:

            root_0 = Z[d]
        */

        this.root =
            this.zeroHashes[this.depth];
    }


    // ==================================================
    // Utility
    // ==================================================

    _toBigInt(value) {

        return BigInt(
            this.F.toObject(value)
        );
    }


    // ==================================================
    // Empty leaf
    //
    // Z[0] =
    // H(
    //   "empty" ||
    //   scheme_id ||
    //   D_id ||
    //   0
    // )
    // ==================================================

    _hashEmptyLeaf() {

        const result =
            this.poseidon([
                this.TAG_EMPTY,
                this.schemeId,
                this.domainId,
                0n
            ]);

        return this._toBigInt(result);
    }


    // ==================================================
    // Internal node
    //
    // Node =
    // H(
    //   "node" ||
    //   scheme_id ||
    //   level ||
    //   left ||
    //   right
    // )
    // ==================================================

    _hashNode(level, left, right) {

        const result =
            this.poseidon([
                this.TAG_NODE,
                this.schemeId,
                BigInt(level),
                BigInt(left),
                BigInt(right)
            ]);

        return this._toBigInt(result);
    }


    // ==================================================
    // Construct default empty hashes
    // ==================================================

    _buildZeroHashes() {

        /*
            Z[0]
        */

        this.zeroHashes[0] =
            this._hashEmptyLeaf();


        /*
            Z[i + 1] =
            H(
                "node" ||
                scheme_id ||
                i ||
                Z[i] ||
                Z[i]
            )
        */

        for (
            let level = 0;
            level < this.depth;
            level++
        ) {

            this.zeroHashes[level + 1] =
                this._hashNode(
                    level,
                    this.zeroHashes[level],
                    this.zeroHashes[level]
                );
        }
    }


    // ==================================================
    // Storage helpers
    // ==================================================

    _nodeKey(level, index) {

        return (
            level.toString() +
            ":" +
            BigInt(index).toString()
        );
    }


    _getNode(level, index) {

        const key =
            this._nodeKey(
                level,
                index
            );

        if (this.nodes.has(key)) {

            return this.nodes.get(key);
        }

        /*
            Missing sparse node means
            default empty node at this level.
        */

        return this.zeroHashes[level];
    }


    _setNode(level, index, value) {

        const key =
            this._nodeKey(
                level,
                index
            );

        const nodeValue =
            BigInt(value);


        /*
            Sparse optimization:
            default nodes are never stored.
        */

        if (
            nodeValue ===
            this.zeroHashes[level]
        ) {

            this.nodes.delete(key);

        } else {

            this.nodes.set(
                key,
                nodeValue
            );
        }
    }


    // ==================================================
    // Index validation
    // ==================================================

    _validateIndex(index) {

        const idx =
            BigInt(index);

        const capacity =
            1n << BigInt(this.depth);


        if (
            idx < 0n ||
            idx >= capacity
        ) {

            throw new Error(
                `Index ${idx} is outside the valid SMT range [0, ${capacity - 1n}].`
            );
        }

        return idx;
    }


    // ==================================================
    // PRIVATE state transition
    //
    // This method cannot be called from outside
    // the class.
    //
    // Public operations are only:
    //
    // insert()
    // remove()
    // ==================================================

    #update(index, leaf) {

        let nodeIndex =
            this._validateIndex(index);

        const newLeaf =
            BigInt(leaf);

        const oldLeaf =
            this._getNode(
                0,
                nodeIndex
            );


        // ----------------------------------------------
        // Active leaf counter
        // ----------------------------------------------

        if (
            oldLeaf === this.zeroHashes[0] &&
            newLeaf !== this.zeroHashes[0]
        ) {

            this.leafCount++;

        } else if (
            oldLeaf !== this.zeroHashes[0] &&
            newLeaf === this.zeroHashes[0]
        ) {

            this.leafCount--;
        }


        // ----------------------------------------------
        // Store leaf
        // ----------------------------------------------

        this._setNode(
            0,
            nodeIndex,
            newLeaf
        );


        let current =
            newLeaf;


        // ----------------------------------------------
        // Recompute path to root
        //
        // LSB-first convention:
        // lowest index bit corresponds to level 0.
        // ----------------------------------------------

        for (
            let level = 0;
            level < this.depth;
            level++
        ) {

            const isRight =
                (nodeIndex & 1n) === 1n;


            const siblingIndex =
                isRight
                    ? nodeIndex - 1n
                    : nodeIndex + 1n;


            const sibling =
                this._getNode(
                    level,
                    siblingIndex
                );


            let parent;


            if (isRight) {

                parent =
                    this._hashNode(
                        level,
                        sibling,
                        current
                    );

            } else {

                parent =
                    this._hashNode(
                        level,
                        current,
                        sibling
                    );
            }


            /*
                Move to parent index.
            */

            nodeIndex =
                nodeIndex >> 1n;


            this._setNode(
                level + 1,
                nodeIndex,
                parent
            );


            current =
                parent;
        }


        this.root =
            current;


        return this.root;
    }


    // ==================================================
    // Public API
    // ==================================================

    getRoot() {

        return this.root;
    }


    getRootString() {

        return this.root.toString();
    }


    getEmptyRoot() {

        return this.zeroHashes[
            this.depth
        ];
    }


    getEmptyLeaf() {

        return this.zeroHashes[0];
    }


    getLeaf(index) {

        const idx =
            this._validateIndex(index);

        return this._getNode(
            0,
            idx
        );
    }


    // ==================================================
    // Enrollment operation
    // ==================================================

    insert(index, leaf) {

        const idx =
            this._validateIndex(index);

        const newLeaf =
            BigInt(leaf);


        /*
            An empty-leaf value cannot represent
            an active user.
        */

        if (
            newLeaf ===
            this.zeroHashes[0]
        ) {

            throw new Error(
                "Cannot insert the SMT empty-leaf value as an active member."
            );
        }


        const currentLeaf =
            this._getNode(
                0,
                idx
            );


        /*
            Do not overwrite an occupied position.
        */

        if (
            currentLeaf !==
            this.zeroHashes[0]
        ) {

            throw new Error(
                `SMT position ${idx} is already occupied.`
            );
        }


        return this.#update(
            idx,
            newLeaf
        );
    }


    // ==================================================
    // Revocation operation
    // ==================================================

    remove(index) {

        const idx =
            this._validateIndex(index);


        const currentLeaf =
            this._getNode(
                0,
                idx
            );


        if (
            currentLeaf ===
            this.zeroHashes[0]
        ) {

            throw new Error(
                `SMT position ${idx} is already empty.`
            );
        }


        /*
            Revocation is represented by replacing
            the active leaf with Z[0].
        */

        return this.#update(
            idx,
            this.zeroHashes[0]
        );
    }


    // ==================================================
    // Generate Merkle path
    //
    // IMPORTANT:
    // Returned object contains strings instead of BigInt
    // so that JSON.stringify() works directly.
    // ==================================================

    getProof(index) {

        let nodeIndex =
            this._validateIndex(index);


        const originalIndex =
            nodeIndex;


        const leaf =
            this._getNode(
                0,
                nodeIndex
            );


        const siblings = [];

        const pathIndices = [];


        for (
            let level = 0;
            level < this.depth;
            level++
        ) {

            const isRight =
                (nodeIndex & 1n) === 1n;


            /*
                0 = current node is left child
                1 = current node is right child
            */

            pathIndices.push(
                isRight ? 1 : 0
            );


            const siblingIndex =
                isRight
                    ? nodeIndex - 1n
                    : nodeIndex + 1n;


            const sibling =
                this._getNode(
                    level,
                    siblingIndex
                );


            /*
                Decimal strings are directly suitable
                for JSON / snarkjs inputs.
            */

            siblings.push(
                sibling.toString()
            );


            nodeIndex =
                nodeIndex >> 1n;
        }


        return {

            index:
                originalIndex.toString(),

            leaf:
                leaf.toString(),

            siblings,

            pathIndices,

            root:
                this.root.toString()
        };
    }


    // ==================================================
    // Generic path verification
    //
    // Default expected root = CURRENT tree root.
    //
    // This prevents an old proof from automatically
    // being accepted against an outdated root.
    // ==================================================

    verifyProof(
        proof,
        expectedRoot = this.root
    ) {

        if (!proof) {
            return false;
        }


        if (
            !Array.isArray(
                proof.siblings
            )
        ) {

            return false;
        }


        if (
            proof.siblings.length !==
            this.depth
        ) {

            return false;
        }


        if (
            !Array.isArray(
                proof.pathIndices
            )
        ) {

            return false;
        }


        if (
            proof.pathIndices.length !==
            this.depth
        ) {

            return false;
        }


        let nodeIndex;


        try {

            nodeIndex =
                this._validateIndex(
                    proof.index
                );

        } catch {

            return false;
        }


        const targetRoot =
            BigInt(expectedRoot);


        /*
            If the proof explicitly carries a root,
            it must match the root requested by
            the verifier.
        */

        if (
            proof.root !== undefined &&
            BigInt(proof.root) !==
            targetRoot
        ) {

            return false;
        }


        let current;


        try {

            current =
                BigInt(proof.leaf);

        } catch {

            return false;
        }


        for (
            let level = 0;
            level < this.depth;
            level++
        ) {

            let sibling;


            try {

                sibling =
                    BigInt(
                        proof.siblings[level]
                    );

            } catch {

                return false;
            }


            const isRight =
                (nodeIndex & 1n) === 1n;


            /*
                Also validate pathIndices against idx.

                This avoids accepting an inconsistent
                path description.
            */

            const expectedDirection =
                isRight ? 1 : 0;


            if (
                proof.pathIndices[level] !==
                expectedDirection
            ) {

                return false;
            }


            if (isRight) {

                current =
                    this._hashNode(
                        level,
                        sibling,
                        current
                    );

            } else {

                current =
                    this._hashNode(
                        level,
                        current,
                        sibling
                    );
            }


            nodeIndex =
                nodeIndex >> 1n;
        }


        return (
            current ===
            targetRoot
        );
    }


    // ==================================================
    // Membership verification
    //
    // Difference from generic verifyProof:
    //
    // an EMPTY leaf must never count as membership.
    // ==================================================

    verifyMembershipProof(
        proof,
        expectedRoot = this.root
    ) {

        if (!proof) {
            return false;
        }


        let leaf;


        try {

            leaf =
                BigInt(proof.leaf);

        } catch {

            return false;
        }


        /*
            Empty leaf is non-membership,
            not valid membership.
        */

        if (
            leaf ===
            this.zeroHashes[0]
        ) {

            return false;
        }


        return this.verifyProof(
            proof,
            expectedRoot
        );
    }


    // ==================================================
    // Statistics
    // ==================================================

    getStats() {

        return {

            depth:
                this.depth,

            capacity:
                (
                    1n <<
                    BigInt(this.depth)
                ).toString(),

            activeLeaves:
                this.leafCount,

            storedNonDefaultNodes:
                this.nodes.size,

            root:
                this.root.toString()
        };
    }
}


// ======================================================
// Factory
// ======================================================

async function createSparseMerkleTree(depth) {

    const poseidon =
        await buildPoseidon();

    const F =
        poseidon.F;


    return new SparseMerkleTree(
        depth,
        poseidon,
        F
    );
}


module.exports = {
    SparseMerkleTree,
    createSparseMerkleTree
};