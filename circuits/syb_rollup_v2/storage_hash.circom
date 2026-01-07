pragma circom 2.1.6;

include "../../node_modules/circomlib/circuits/sha256/sha256.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

/**
 * StorageHash - Computes SHA256 of edges batch for on-chain verification
 *
 * Must match Solidity: sha256(abi.encodePacked(
 *     batchId,      // uint64 - 8 bytes
 *     start,        // uint32 - 4 bytes
 *     n,            // uint32 - 4 bytes
 *     edgesPacked   // n * 9 bytes (each edge: ilo[4] || ihi[4] || flag[1])
 * ))
 *
 * Total bytes: 8 + 4 + 4 + n*9 = 16 + n*9
 */
template StorageHash(n) {
    // Calculate byte and bit lengths
    var DATA_BYTES = 16 + n * 9;
    var DATA_BITS = DATA_BYTES * 8;

    // Inputs
    signal input batchId;           // uint64
    signal input start;             // uint32
    signal input edges[n][3];       // edges[i][0] = ilo, edges[i][1] = ihi (uint32 each), edges[i][2] = flag (uint8)

    // Output - 256 bits from SHA256
    signal output storageHashOut[256];

    var i, j, k;

    // Convert all inputs to bits
    component batchIdBits = Num2Bits(64);
    batchIdBits.in <== batchId;

    component startBits = Num2Bits(32);
    startBits.in <== start;

    component iloBits[n];
    component ihiBits[n];
    component flagBits[n];
    for (k = 0; k < n; k++) {
        iloBits[k] = Num2Bits(32);
        iloBits[k].in <== edges[k][0];

        ihiBits[k] = Num2Bits(32);
        ihiBits[k].in <== edges[k][1];

        flagBits[k] = Num2Bits(8);
        flagBits[k].in <== edges[k][2];
    }

    // Build input bit array for SHA256
    // Pack all values in big-endian byte order to match Solidity abi.encodePacked
    signal inBits[DATA_BITS];
    var bitIdx = 0;

    // batchId bits (0-63) - big-endian byte order, MSB first
    for (i = 0; i < 8; i++) {
        for (j = 7; j >= 0; j--) {
            // Byte i should come from bits (7-i)*8+j of the number
            inBits[bitIdx] <== batchIdBits.out[(7-i)*8 + j];
            bitIdx++;
        }
    }

    // start bits (64-127) - big-endian byte order, MSB first
    for (i = 0; i < 4; i++) {
        for (j = 7; j >= 0; j--) {
            // Byte i should come from bits (3-i)*8+j of the number
            inBits[bitIdx] <== startBits.out[(3-i)*8 + j];
            bitIdx++;
        }
    }

    // n bits (128-159) - compile-time constant, encode as 4 bytes big-endian
    var nByte0 = (n >> 24) & 0xFF;
    var nByte1 = (n >> 16) & 0xFF;
    var nByte2 = (n >> 8) & 0xFF;
    var nByte3 = n & 0xFF;

    for (j = 7; j >= 0; j--) {
        inBits[bitIdx] <== (nByte0 >> j) & 1;
        bitIdx++;
    }
    for (j = 7; j >= 0; j--) {
        inBits[bitIdx] <== (nByte1 >> j) & 1;
        bitIdx++;
    }
    for (j = 7; j >= 0; j--) {
        inBits[bitIdx] <== (nByte2 >> j) & 1;
        bitIdx++;
    }
    for (j = 7; j >= 0; j--) {
        inBits[bitIdx] <== (nByte3 >> j) & 1;
        bitIdx++;
    }

    // edge bits (160+): each edge is 72 bits (ilo[32] + ihi[32] + flag[8])
    for (k = 0; k < n; k++) {
        // ilo bits - big-endian byte order
        for (i = 0; i < 4; i++) {
            for (j = 7; j >= 0; j--) {
                inBits[bitIdx] <== iloBits[k].out[(3-i)*8 + j];
                bitIdx++;
            }
        }
        // ihi bits - big-endian byte order
        for (i = 0; i < 4; i++) {
            for (j = 7; j >= 0; j--) {
                inBits[bitIdx] <== ihiBits[k].out[(3-i)*8 + j];
                bitIdx++;
            }
        }
        // flag bits
        for (j = 7; j >= 0; j--) {
            inBits[bitIdx] <== flagBits[k].out[j];
            bitIdx++;
        }
    }

    // SHA256 hash using circomlib's Sha256 (it does internal padding)
    component sha = Sha256(DATA_BITS);
    for (i = 0; i < DATA_BITS; i++) {
        sha.in[i] <== inBits[i];
    }

    // Output the 256-bit hash
    for (i = 0; i < 256; i++) {
        storageHashOut[i] <== sha.out[i];
    }
}
