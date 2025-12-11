pragma circom 2.1.6;

include "../../node_modules/@zk-email/circuits/lib/sha.circom";
include "../../node_modules/circomlib/circuits/bitify.circom";

/**
 * StorageHash - Computes SHA256 of edges batch for on-chain verification
 * 
 * Must match Solidity: sha256(abi.encodePacked(
 *     batchId,      // uint64 - 8 bytes
 *     start,        // uint32 - 4 bytes
 *     n,            // uint32 - 4 bytes
 *     edgesPacked   // n * 8 bytes (each edge: ilo[4] || ihi[4])
 * ))
 *
 * Total bytes: 8 + 4 + 4 + n*8 = 16 + n*8
 */
template StorageHash(n) {
    // Calculate byte lengths
    var DATA_BYTES = 16 + n * 8;
    // SHA256 pads to multiple of 64 bytes: data + 1 byte (0x80) + zeros + 8 bytes (length)
    var PADDED_BYTES = ((DATA_BYTES + 9 + 63) \ 64) * 64;
    
    // Inputs
    signal input batchId;           // uint64
    signal input start;             // uint32
    signal input edges[n][2];       // edges[i][0] = ilo, edges[i][1] = ihi (uint32 each)

    // Output
    signal output storageHashOut;

    var i, j, k;

    // Convert all inputs to bits first
    component batchIdBits = Num2Bits(64);
    batchIdBits.in <== batchId;
    
    component startBits = Num2Bits(32);
    startBits.in <== start;
    
    component iloBits[n];
    component ihiBits[n];
    for (k = 0; k < n; k++) {
        iloBits[k] = Num2Bits(32);
        iloBits[k].in <== edges[k][0];
        
        ihiBits[k] = Num2Bits(32);
        ihiBits[k].in <== edges[k][1];
    }

    // Convert bits to bytes for SHA256
    // Big-endian: MSB of value goes to first byte
    component batchIdBytes[8];
    for (i = 0; i < 8; i++) {
        batchIdBytes[i] = Bits2Num(8);
        for (j = 0; j < 8; j++) {
            batchIdBytes[i].in[7-j] <== batchIdBits.out[63 - i*8 - j];
        }
    }
    
    component startBytes[4];
    for (i = 0; i < 4; i++) {
        startBytes[i] = Bits2Num(8);
        for (j = 0; j < 8; j++) {
            startBytes[i].in[7-j] <== startBits.out[31 - i*8 - j];
        }
    }
    
    component iloBytes[n][4];
    component ihiBytes[n][4];
    for (k = 0; k < n; k++) {
        for (i = 0; i < 4; i++) {
            iloBytes[k][i] = Bits2Num(8);
            for (j = 0; j < 8; j++) {
                iloBytes[k][i].in[7-j] <== iloBits[k].out[31 - i*8 - j];
            }
            
            ihiBytes[k][i] = Bits2Num(8);
            for (j = 0; j < 8; j++) {
                ihiBytes[k][i].in[7-j] <== ihiBits[k].out[31 - i*8 - j];
            }
        }
    }

    // Build padded byte array WITH SHA256 padding
    signal paddedIn[PADDED_BYTES];
    
    // batchId bytes (0-7)
    for (i = 0; i < 8; i++) {
        paddedIn[i] <== batchIdBytes[i].out;
    }
    
    // start bytes (8-11)
    for (i = 0; i < 4; i++) {
        paddedIn[8 + i] <== startBytes[i].out;
    }
    
    // n bytes (12-15) - compile-time constant
    paddedIn[12] <== (n >> 24) & 0xFF;
    paddedIn[13] <== (n >> 16) & 0xFF;
    paddedIn[14] <== (n >> 8) & 0xFF;
    paddedIn[15] <== n & 0xFF;
    
    // edge bytes (16+)
    for (k = 0; k < n; k++) {
        for (i = 0; i < 4; i++) {
            paddedIn[16 + k*8 + i] <== iloBytes[k][i].out;
            paddedIn[16 + k*8 + 4 + i] <== ihiBytes[k][i].out;
        }
    }
    
    // SHA256 padding: append 0x80
    paddedIn[DATA_BYTES] <== 0x80;
    
    // Pad with zeros
    for (i = DATA_BYTES + 1; i < PADDED_BYTES - 8; i++) {
        paddedIn[i] <== 0;
    }
    
    // Append length in bits as 64-bit big-endian
    var bitLength = DATA_BYTES * 8;
    paddedIn[PADDED_BYTES - 8] <== (bitLength >> 56) & 0xFF;
    paddedIn[PADDED_BYTES - 7] <== (bitLength >> 48) & 0xFF;
    paddedIn[PADDED_BYTES - 6] <== (bitLength >> 40) & 0xFF;
    paddedIn[PADDED_BYTES - 5] <== (bitLength >> 32) & 0xFF;
    paddedIn[PADDED_BYTES - 4] <== (bitLength >> 24) & 0xFF;
    paddedIn[PADDED_BYTES - 3] <== (bitLength >> 16) & 0xFF;
    paddedIn[PADDED_BYTES - 2] <== (bitLength >> 8) & 0xFF;
    paddedIn[PADDED_BYTES - 1] <== bitLength & 0xFF;
    
    // SHA256 hash - paddedInLength is PADDED length (multiple of 64)
    component sha = Sha256Bytes(PADDED_BYTES);
    for (i = 0; i < PADDED_BYTES; i++) {
        sha.paddedIn[i] <== paddedIn[i];
    }
    sha.paddedInLength <== PADDED_BYTES;
    
    // Convert 256-bit output to field element
    component b2n = Bits2Num(256);
    for (i = 0; i < 256; i++) {
        b2n.in[i] <== sha.out[255 - i];
    }
    
    storageHashOut <== b2n.out;
}
