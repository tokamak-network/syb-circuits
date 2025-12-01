pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "../../node_modules/circomlib/circuits/comparators.circom";

// NbrHasher: Computes NbrHash_G(v) for a vertex in the GraphTree
//
// NbrHash Algorithm (based on NbrData_G(v) = [d, u_0, u_1, ..., u_{d-1}]):
// - First block B_0: [d, u_0, ..., u_14]  (15 neighbors)
// - acc = Poseidon_16(B_0)
// - For remaining neighbors, process in chunks of 15:
//   - B_b = [acc, u_15+(b-1)*15, ..., u_15+(b-1)*15+14]
//   - acc = Poseidon_16(B_b)
//
// Key Features:
// - Enforces that nbr_arr[i] == 0 when i >= d (proper padding verification)
// - Enforces strictly ascending order: nbr_arr[i] < nbr_arr[i+1] for i in 0..d-2
// - All blocks: 15 neighbors each
//
// Parameters:
//   maxDeg - Maximum degree a node can have (fixed at compile time)
//
// Inputs:
//   d - Degree of vertex (number of actual neighbors)
//   nbr_arr[padLen] - Neighbor array MUST be padded with zeros when i >= d
//                     where padLen = 15*numR, numR = ceil(maxDeg/15)
//
// Output:
//   hash - NbrHash_G(v)
//
template NbrHasher(maxDeg) {
    assert(maxDeg >= 1);

    var numR = (maxDeg + 14) \ 15;
    var padLen = 15 * numR;
    var sumValid = 0;

    // inputs
    signal input d;               // Degree (actual number of neighbors)
    signal input nbr_arr[padLen]; // Neighbor array (must be properly padded)

    // outputs
    signal output hash;

    signal isValid[padLen];                         // 1 if index i < d (valid), 0 otherwise
    component isStrictlyAscending[padLen - 1];      // Checks if nbr_arr[i] < nbr_arr[i+1]

    // INPUT VALIDATION CHECKS
    // 1. Zero-padding check: nbr_arr[i] == 0 when i >= d
    // 2. Strictly ascending check: nbr_arr[i] < nbr_arr[i+1] when both i and i+1 < d
    // Optimized: Uses unary encoding for d (isValid array) instead of per-index comparisons
    
    // Step 1: Generate isValid array
    // for example, if d = 3, padLen = 10
    // isValid => [1, 1, 1, 0, 0, 0, 0, 0, 0, 0]
    // sumValid => 3
    for (var i = 0; i < padLen; i++) {
        // isValid[i] should be 1 if i < d, else 0
        isValid[i] <-- (i < d) ? 1 : 0;
        isValid[i] * (1 - isValid[i]) === 0;
        sumValid += isValid[i];
    }
    
    // Ensure the number of valid entries matches d
    sumValid === d;

    // Step 2: Validation checks using isValid
    for (var i = 0; i < padLen; i++) {
        if (i > 0) {
            // Enforce monotonicity: if i-1 is 0, i must be 0 (cannot go from invalid to valid)
            (1 - isValid[i-1]) * isValid[i] === 0;
        }

        // Zero-padding check: if invalid, must be 0
        (1 - isValid[i]) * nbr_arr[i] === 0;

        // Strictly ascending check (skip last element since there's no i+1)
        if (i < padLen - 1) {
            isStrictlyAscending[i] = LessThan(252);
            isStrictlyAscending[i].in[0] <== nbr_arr[i];
            isStrictlyAscending[i].in[1] <== nbr_arr[i + 1];

            // Enforce ascending only when i+1 is valid (implies i is also valid)
            isValid[i+1] * (1 - isStrictlyAscending[i].out) === 0;
        }
    }

    // HASHING: First block B_0 = [d, nbr[0..14]] (15 neighbors)
    component firstHash = Poseidon(16);
    firstHash.inputs[0] <== d;
    for (var i = 0; i < 15; i++) {
        firstHash.inputs[1 + i] <== nbr_arr[i];
    }

    // HASHING: Continuation blocks (15 neighbors each)
    signal acc[numR];
    acc[0] <== firstHash.out;

    component contHash[numR - 1];
    for (var round = 1; round < numR; round++) {
        contHash[round - 1] = Poseidon(16);
        contHash[round - 1].inputs[0] <== acc[round - 1];

        var startIdx = 15 + (round - 1) * 15;
        for (var i = 0; i < 15; i++) {
            var idx = startIdx + i;
            contHash[round - 1].inputs[1 + i] <== nbr_arr[idx];
        }

        acc[round] <== contHash[round - 1].out;
    }
    hash <== acc[numR - 1];
}
