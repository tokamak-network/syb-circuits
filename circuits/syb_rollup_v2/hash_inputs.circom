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
 * Total bytes: 32*6 + 4 + 4 = 200 bytes = 1600 bits
 *
 * IMPORTANT: bytes32 values are split into high/low 128-bit parts because
 * a full bytes32 can exceed BN128's field prime (0x30644e72...).
 * Values starting with 0x31 or higher would overflow and produce wrong results.
 */
template HashInputs() {
    var DATA_BYTES = 200;  // 32*6 + 4 + 4
    var DATA_BITS = DATA_BYTES * 8;  // 1600 bits

    // Inputs - bytes32 values split into high/low 128-bit parts
    signal input oldGraphRootHigh;
    signal input oldGraphRootLow;
    signal input oldScoreRootHigh;    
    signal input oldScoreRootLow;
    signal input newGraphRootHigh;
    signal input newGraphRootLow;
    signal input newScoreRootHigh;
    signal input newScoreRootLow;
    signal input batchIdHigh;
    signal input batchIdLow;
    signal input batchSize;          // uint32 - fits in field
    signal input n;                  // uint32 - fits in field
    signal input storageHashHigh;
    signal input storageHashLow;

    // Output - 256 bits from SHA256
    signal output hashOut[256];

    var i, j;

    // Convert each 128-bit value to 16 bytes
    // 128 bits is always safe (well under field prime)
    
    component oldGraphHighBits = Num2Bits(128);
    oldGraphHighBits.in <== oldGraphRootHigh;
    component oldGraphLowBits = Num2Bits(128);
    oldGraphLowBits.in <== oldGraphRootLow;
    
    component oldScoreHighBits = Num2Bits(128);
    oldScoreHighBits.in <== oldScoreRootHigh;
    component oldScoreLowBits = Num2Bits(128);
    oldScoreLowBits.in <== oldScoreRootLow;
    
    component newGraphHighBits = Num2Bits(128);
    newGraphHighBits.in <== newGraphRootHigh;
    component newGraphLowBits = Num2Bits(128);
    newGraphLowBits.in <== newGraphRootLow;
    
    component newScoreHighBits = Num2Bits(128);
    newScoreHighBits.in <== newScoreRootHigh;
    component newScoreLowBits = Num2Bits(128);
    newScoreLowBits.in <== newScoreRootLow;
    
    component batchIdHighBits = Num2Bits(128);
    batchIdHighBits.in <== batchIdHigh;
    component batchIdLowBits = Num2Bits(128);
    batchIdLowBits.in <== batchIdLow;
    
    component batchSizeBits = Num2Bits(32);
    batchSizeBits.in <== batchSize;
    
    component nBits = Num2Bits(32);
    nBits.in <== n;
    
    component storageHashHighBits = Num2Bits(128);
    storageHashHighBits.in <== storageHashHigh;
    component storageHashLowBits = Num2Bits(128);
    storageHashLowBits.in <== storageHashLow;

    // Build input bit array for SHA256
    // Bits are packed in big-endian byte order
    signal inBits[DATA_BITS];
    var bitIdx = 0;

    // Helper: pack 128 bits into 16 bytes (big-endian)
    // bit 127 is MSB of byte 0, bit 0 is LSB of byte 15
    
    // oldGraphRoot (32 bytes = high 16 bytes + low 16 bytes)
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== oldGraphHighBits.out[127 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== oldGraphLowBits.out[127 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    
    // oldScoreRoot (32 bytes)
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== oldScoreHighBits.out[127 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== oldScoreLowBits.out[127 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    
    // newGraphRoot (32 bytes)
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== newGraphHighBits.out[127 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== newGraphLowBits.out[127 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    
    // newScoreRoot (32 bytes)
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== newScoreHighBits.out[127 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== newScoreLowBits.out[127 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    
    // batchId (32 bytes)
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== batchIdHighBits.out[127 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== batchIdLowBits.out[127 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    
    // batchSize (4 bytes)
    for (i = 0; i < 4; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== batchSizeBits.out[31 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    
    // n (4 bytes)
    for (i = 0; i < 4; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== nBits.out[31 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    
    // storageHash (32 bytes)
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== storageHashHighBits.out[127 - i*8 - (7-j)];
            bitIdx++;
        }
    }
    for (i = 0; i < 16; i++) {
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== storageHashLowBits.out[127 - i*8 - (7-j)];
            bitIdx++;
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
