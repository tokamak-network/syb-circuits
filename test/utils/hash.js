import { ethers as ethersV6 } from "ethers";

// For backwards compatibility with existing tests, create a v5-like interface
const ethers = {
  utils: {
    solidityPack: (types, values) => ethersV6.solidityPacked(types, values),
    sha256: (data) => ethersV6.sha256(data)
  }
};

/**
 * Convert a string to an array of bits
 * @param {string} str - The string to convert
 * @param {number} totalBits - The total number of bits to return
 * @returns {number[]} - An array of bits
 */
function stringToBits(str, totalBits) {
  const bytes = Buffer.from(str, "utf8");
  const bits = [];

  for (let i = 0; i < bytes.length; i++) {
    for (let j = 7; j >= 0; j--) {
      // Big-endian
      bits.push((bytes[i] >> j) & 1);
    }
  }
  // Pad with zeros
  while (bits.length < totalBits) {
    bits.push(0);
  }
  return bits;
}

/**
 * Convert an array of bits to a hex string
 * @param {number[]} bits - The array of bits to convert
 * @returns {string} - A hex string
 */
function bitsToHex(bits) {
  let hex = "0x";
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) {
      byte = (byte << 1) | Number(bits[i + j]);
    }
    hex += byte.toString(16).padStart(2, "0");
  }
  return hex;
}

/**
   * Build storage hash matching Solidity contract and circuit:
   * sha256(abi.encodePacked(batchId, start, n, edgesPacked))
   *
   * @param {BigInt} batchId - uint64
   * @param {number} start - uint32 (hashed as value, not used as index)
   * @param {number} n - uint32
   * @param {BigInt[]} unforged - array of uint72 values: (flag << 64) | (ilo << 32) | ihi (length = n)
   */
function buildStorageHash(batchId, start, n, unforged) {
  const edgesPacked = new Uint8Array(n * 9);

  for (let i = 0; i < n; i++) {
      const w = unforged[i];
      const ilo = Number((w >> 32n) & 0xffffffffn);
      const ihi = Number(w & 0xffffffffn);
      const flag = Number((w >> 64n) & 0xffn);
      const offset = i * 9;
      edgesPacked[offset] = (ilo >> 24) & 0xff;
      edgesPacked[offset + 1] = (ilo >> 16) & 0xff;
      edgesPacked[offset + 2] = (ilo >> 8) & 0xff;
      edgesPacked[offset + 3] = ilo & 0xff;
      edgesPacked[offset + 4] = (ihi >> 24) & 0xff;
      edgesPacked[offset + 5] = (ihi >> 16) & 0xff;
      edgesPacked[offset + 6] = (ihi >> 8) & 0xff;
      edgesPacked[offset + 7] = ihi & 0xff;
      edgesPacked[offset + 8] = flag & 0xff;
  }

  // ethers v5 syntax - uint64 for batchId
  const packed = ethers.utils.solidityPack(
      ['uint64', 'uint32', 'uint32', 'bytes'],
      [batchId.toString(), start, n, edgesPacked]
  );
  console.log(`  Packed hex: ${packed}`);
  return ethers.utils.sha256(packed);
  }

/**
 * Helper: convert edges array [[ilo, ihi, flag], ...] to unforged array [(flag<<64)|(ilo<<32)|ihi, ...]
 * If flag is not provided, defaults to 0
 */
function edgesToUnforged(edges) {
  return edges.map(edge => {
    const ilo = BigInt(edge[0]);
    const ihi = BigInt(edge[1]);
    const flag = edge[2] !== undefined ? BigInt(edge[2]) : 0n;
    return (flag << 64n) | (ilo << 32n) | ihi;
  });
}

export { buildStorageHash, edgesToUnforged, stringToBits, bitsToHex };