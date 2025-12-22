/**
 * Compute the set hash in the BN254 field to mirror the circuit.
 * @param {Object} F - Finite field from circomlibjs
 * @param {number} maxDeg - Maximum degree
 * @param {number} r - Public randomizer
 * @param {Array} neighbors - Neighbor array
 * @returns {BigInt} - Hash product
 */
export function computeSetHash(F, maxDeg, r, neighbors) {
  const padded = padNeighbors(maxDeg, neighbors);
  let product = F.one;
  const rF = F.e(BigInt(r));
  for (let i = 0; i < maxDeg; i++) {
    const nF = F.e(BigInt(padded[i]));
    product = F.mul(product, F.sub(rF, nF));
  }
  return F.toObject(product);
}

/**
 * Pad neighbor array to maxDeg length with zeros.
 * @param {number} maxDeg - Maximum degree
 * @param {Array} neighbors - Neighbor array
 * @returns {string[]} - Padded array as strings
 */
export function padNeighbors(maxDeg, neighbors) {
  const padded = [...neighbors];
  while (padded.length < maxDeg) {
    padded.push(0);
  }
  return padded.map((x) => x.toString());
}

/**
 * Ensure siblings array has exactly nLevels + 1 elements.
 * SMTProcessor needs nLevels + 1, but SmtTree.getSiblings returns nLevels.
 * @param {number} nLevels - Tree depth
 * @param {Array} siblings - Siblings array
 * @returns {string[]} - Padded array as strings
 */
export function ensureSiblingsLength(nLevels, siblings) {
  const padded = [...siblings];
  while (padded.length < nLevels + 1) {
    padded.push(0);
  }
  return padded.map((x) => x.toString());
}
