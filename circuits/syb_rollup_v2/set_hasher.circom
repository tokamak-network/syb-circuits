pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/comparators.circom";

// SetHasher: computes SetHash_G(v) = Π_i (r - paddedNbrArr[i]) for a fixed-size,
// already-padded neighbor array.
//
// Algorithm (exactly maxDeg factors):
// - prod[0] = 1
// - for i in 0..maxDeg-1: prod[i+1] = prod[i] * (r - paddedNbrArr[i])
// - product = prod[maxDeg]
//
// Parameters:
//   maxDeg               - Maximum degree (fixed at compile time)
//
// Inputs:
//   d                    - Degree (d should be less eq than maxDeg)
//   r                    - Public randomizer
//   paddedNbrArr[maxDeg] - Neighbor ids padded with zeros to maxDeg
//
// Output:
//   product              - Raw set hash Π_i (r - paddedNbrArr[i])
template SetHasher(maxDeg) {
    assert(maxDeg >= 1);

    signal input d;
    signal input r;
    signal input paddedNbrArr[maxDeg];
    signal output product;

    // check that d <= maxDeg
    component dLessEqThanMaxDeg = LessEqThan(32);
    dLessEqThanMaxDeg.in[0] <== d;
    dLessEqThanMaxDeg.in[1] <== maxDeg;
    dLessEqThanMaxDeg.out === 1;

    // accumulator for the product
    signal prod[maxDeg + 1];
    prod[0] <== 1;
    for (var i = 0; i < maxDeg; i++) {
        prod[i+1] <== prod[i] * (r - paddedNbrArr[i]);
    }

    product <== prod[maxDeg];
}