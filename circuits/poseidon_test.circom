pragma circom 2.2.0;

include "../node_modules/circomlib/circuits/poseidon.circom";

template PoseidonTest() {
    signal input a;
    signal input b;

    signal output hash;

    component poseidon = Poseidon(2);

    poseidon.inputs[0] <== a;
    poseidon.inputs[1] <== b;

    hash <== poseidon.out;
}

component main = PoseidonTest();