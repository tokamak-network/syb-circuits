pragma circom 2.1.0;

include "../../node_modules/circomlib/circuits/comparators.circom";
include "../../node_modules/circomlib/circuits/poseidon.circom";

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
//   d                    - Degree (not enforced; kept for API symmetry)
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

    // check that d < maxDeg
    component dLessThanMaxDeg = LessThan(32);
    dLessThanMaxDeg.in[0] <== d;
    dLessThanMaxDeg.in[1] <== maxDeg;
    dLessThanMaxDeg.out === 1;

    // accumulator for the product
    signal prod[maxDeg + 1];
    prod[0] <== 1;
    for (var i = 0; i < maxDeg; i++) {
        prod[i+1] <== prod[i] * (r - paddedNbrArr[i]);
    }

    product <== prod[maxDeg];
}