pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

/**
 * HashInputs - Computes SHA256 of all public inputs for SNARK verification
 *
 * Must match Solidity: sha256(abi.encodePacked(
 *     oldGraphRoot, oldScoreRoot, newGraphRoot, newScoreRoot,
 *     batchId, batchSize, n, storageHash
 * ))
 *
 * Total bytes: 32*5 + 8 + 4 + 4 = 176 bytes = 1408 bits
 *
 * IMPORTANT: bytes32 values are split into high/low 128-bit parts because
 * a full bytes32 can exceed BN128's field prime (0x30644e72...).
 * Values starting with 0x31 or higher would overflow and produce wrong results.
 */
template HashInputs() {
    var DATA_BYTES = 176;  // 32*5 + 8 + 4 + 4
    var DATA_BITS = DATA_BYTES * 8;  // 1408 bits

    // Inputs - bytes32 values split into high/low 128-bit parts
    signal input oldGraphRootHigh;
    signal input oldGraphRootLow;
    signal input oldScoreRootHigh;    
    signal input oldScoreRootLow;
    signal input newGraphRootHigh;
    signal input newGraphRootLow;
    signal input newScoreRootHigh;
    signal input newScoreRootLow;
    signal input batchId;            // uint64
    signal input batchSize;          // uint32
    signal input n;                  // uint32
    signal input storageHashHigh;
    signal input storageHashLow;

    // Output - 256 bits from SHA256
    signal output hashOut[256];

    var i, j, k;

    // Convert each 128-bit value to 16 bytes
    // 128 bits is always safe (well under field prime)
    component num2Bits128[10];
    for (i = 0; i < 10; i++) {
        num2Bits128[i] = Num2Bits(128);
    }
    num2Bits128[0].in <== oldGraphRootHigh;
    num2Bits128[1].in <== oldGraphRootLow;
    num2Bits128[2].in <== oldScoreRootHigh;
    num2Bits128[3].in <== oldScoreRootLow;
    num2Bits128[4].in <== newGraphRootHigh;
    num2Bits128[5].in <== newGraphRootLow;
    num2Bits128[6].in <== newScoreRootHigh;
    num2Bits128[7].in <== newScoreRootLow;
    num2Bits128[8].in <== storageHashHigh;
    num2Bits128[9].in <== storageHashLow;
    
    component batchIdBits = Num2Bits(64);
    batchIdBits.in <== batchId;

    component batchSizeBits = Num2Bits(32);
    batchSizeBits.in <== batchSize;

    component nBits = Num2Bits(32);
    nBits.in <== n;

    // Build input bit array for SHA256
    // Bits are packed in big-endian byte order
    signal inBits[DATA_BITS];
    var bitIdx = 0;

    // Pack 4x 32-byte values (oldGraphRoot, oldScoreRoot, newGraphRoot, newScoreRoot)
    for (k = 0; k < 8; k++) { // 8 x 128-bit parts
        for (i = 0; i < 16; i++) { // 16 bytes per part
            for (j = 7; j >= 0; j--) { // 8 bits per byte
                inBits[bitIdx] <== num2Bits128[k].out[(15-i)*8 + j];
                bitIdx++;
            }
        }
    }
    
    // batchId (8 bytes)
    for (i = 0; i < 8; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== batchIdBits.out[(7-i)*8 + j];
            bitIdx++;
        }
    }

    // batchSize (4 bytes)
    for (i = 0; i < 4; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== batchSizeBits.out[(3-i)*8 + j];
            bitIdx++;
        }
    }
    
    // n (4 bytes)
    for (i = 0; i < 4; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== nBits.out[(3-i)*8 + j];
            bitIdx++;
        }
    }
    
    // storageHash (32 bytes)
    for (k = 8; k < 10; k++) { // The last 2 128-bit parts for storageHash
        for (i = 0; i < 16; i++) {
            for (j = 7; j >= 0; j--) {
                inBits[bitIdx] <== num2Bits128[k].out[(15-i)*8 + j];
                bitIdx++;
            }
        }
    }

    // SHA256 hash
    component sha = Sha256(DATA_BITS);
    for (i = 0; i < DATA_BITS; i++) {
        sha.in[i] <== inBits[i];
    }

    // Output the 256-bit hash
    for (i = 0; i < 256; i++) {
        hashOut[i] <== sha.out[i];
    }
}
