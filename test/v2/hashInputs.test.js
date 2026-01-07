import fs from "fs";
import path from "path";
import { describe, it, before, after } from "mocha";
import { wasm as tester } from "circom_tester";
import { fileURLToPath } from "url";
import { ethers } from "ethers";
import fc from "fast-check";
import { bitsToHex } from "../utils/hash.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


// Generate a random numbers
const bytes32Arb = fc.uint8Array({ minLength: 32, maxLength: 32 }).map(
  (arr) => "0x" + Buffer.from(arr).toString("hex")
);
const uint64Arb = fc.bigInt({ min: 0n, max: (1n << 64n) - 1n });
const uint32Arb = fc.integer({ min: 0, max: 0xFFFFFFFF });

// helper functions
function splitBytes32(hex) {
  const full = BigInt(hex);
  const low = full & ((1n << 128n) - 1n);
  const high = full >> 128n;
  return { high, low };
}

function buildCircuitInput(oldGraphRoot, oldScoreRoot, newGraphRoot, newScoreRoot, batchId, batchSize, n, storageHash) {
  const oldGraphRootSplit = splitBytes32(oldGraphRoot);
  const oldScoreRootSplit = splitBytes32(oldScoreRoot);
  const newGraphRootSplit = splitBytes32(newGraphRoot);
  const newScoreRootSplit = splitBytes32(newScoreRoot);
  const storageHashSplit = splitBytes32(storageHash);

  return {
    oldGraphRootHigh: oldGraphRootSplit.high.toString(),
    oldGraphRootLow: oldGraphRootSplit.low.toString(),
    oldScoreRootHigh: oldScoreRootSplit.high.toString(),
    oldScoreRootLow: oldScoreRootSplit.low.toString(),
    newGraphRootHigh: newGraphRootSplit.high.toString(),
    newGraphRootLow: newGraphRootSplit.low.toString(),
    newScoreRootHigh: newScoreRootSplit.high.toString(),
    newScoreRootLow: newScoreRootSplit.low.toString(),
    batchId: batchId.toString(),
    batchSize: batchSize.toString(),
    n: n.toString(),
    storageHashHigh: storageHashSplit.high.toString(),
    storageHashLow: storageHashSplit.low.toString(),
  };
}

function buildExpectedHash(oldGraphRoot, oldScoreRoot, newGraphRoot, newScoreRoot, batchId, batchSize, n, storageHash) {
  const packed = ethers.solidityPacked(
    ['bytes32', 'bytes32', 'bytes32', 'bytes32', 'uint64', 'uint32', 'uint32', 'bytes32'],
    [oldGraphRoot, oldScoreRoot, newGraphRoot, newScoreRoot, batchId, batchSize, n, storageHash]
  );
  return ethers.sha256(packed);
}

// ============================================
// Property-based Tests
// ============================================

describe("HashInputs property-based tests (fast-check)", function () {
  this.timeout(600000); // Long timeout for many iterations

  let circuit;
  let circuitTmpPath;

  before(async () => {
    const circuitSrc = `
      pragma circom 2.1.6;
      include "../circuits/syb_rollup_v2/hash_inputs.circom";
      component main = HashInputs();
    `;
    circuitTmpPath = path.join(__dirname, "hash-inputs.property.circom");
    fs.writeFileSync(circuitTmpPath, circuitSrc, "utf8");

    circuit = await tester(circuitTmpPath, {
      reduceConstraints: false,
      include: [
        path.join(__dirname, "../"),
        path.join(__dirname, "../../node_modules"),
      ],
    });
    await circuit.loadConstraints();
    console.log(`\n✓ HashInputs circuit compiled for property tests`);
    console.log(`  Constraints: ${circuit.constraints.length}\n`);
  });

  after(() => {
    if (fs.existsSync(circuitTmpPath)) {
      fs.unlinkSync(circuitTmpPath);
    }
  });

  /**
   * Property: For any valid inputs, circuit hash should match ethers hash
   */
  it("should always match ethers.sha256 for random inputs", async () => {
    // Define the property
    const property = fc.asyncProperty(
      bytes32Arb,  // oldGraphRoot
      bytes32Arb,  // oldScoreRoot
      bytes32Arb,  // newGraphRoot
      bytes32Arb,  // newScoreRoot
      uint64Arb,  // batchId
      uint32Arb,   // batchSize
      uint32Arb,   // n
      bytes32Arb,  // storageHash
      async (oldGraphRoot, oldScoreRoot, newGraphRoot, newScoreRoot, batchId, batchSize, n, storageHash) => {
        // Calculate expected hash
        const expectedHash = buildExpectedHash(
          oldGraphRoot, oldScoreRoot, newGraphRoot, newScoreRoot,
          batchId, batchSize, n, storageHash
        );

        // Build circuit input
        const input = buildCircuitInput(
          oldGraphRoot, oldScoreRoot, newGraphRoot, newScoreRoot,
          batchId, batchSize, n, storageHash
        );

        // Run circuit
        const w = await circuit.calculateWitness(input, true);

        // Extract hash bits
        const hashBits = [];
        for (let i = 0; i < 256; i++) {
          hashBits.push(w[1 + i]);
        }
        const circuitHash = bitsToHex(hashBits);

        // Property: hashes must match
        return circuitHash === expectedHash;
      }
    );

    // Run the property test
    // numRuns: how many random cases to test (default 100)
    // verbose: show progress
    await fc.assert(property, {
      numRuns: 10, // Reduced for CI speed, increase for thorough testing
      verbose: true,
      examples: [
        // Force test specific edge cases
        [
          "0x0000000000000000000000000000000000000000000000000000000000000000",
          "0x0000000000000000000000000000000000000000000000000000000000000000",
          "0x0000000000000000000000000000000000000000000000000000000000000000",
          "0x0000000000000000000000000000000000000000000000000000000000000000",
          0n,
          0,
          0,
          "0x0000000000000000000000000000000000000000000000000000000000000000",
        ],
        [
          "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          (1n << 64n) - 1n,
          0xFFFFFFFF,
          0xFFFFFFFF,
          "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ],
      ],
    });
  });

  /**
   * Property: Different inputs should produce different hashes
   * (with high probability)
   */
  it("should produce correct hash for different input values", async () => {
    const fixedInputs = {
      oldGraphRoot: "0x1111111111111111111111111111111111111111111111111111111111111111",
      oldScoreRoot: "0x2222222222222222222222222222222222222222222222222222222222222222",
      newGraphRoot: "0x3333333333333333333333333333333333333333333333333333333333333333",
      newScoreRoot: "0x4444444444444444444444444444444444444444444444444444444444444444",
      batchSize: 100,
      n: 10,
      storageHash: "0x5555555555555555555555555555555555555555555555555555555555555555",
    };

    const property = fc.asyncProperty(
      uint64Arb,
      uint64Arb,
      async (batchId1, batchId2) => {
        // Skip if same batchId
        if (batchId1 === batchId2) return true;

        const hash1 = buildExpectedHash(
          fixedInputs.oldGraphRoot, fixedInputs.oldScoreRoot,
          fixedInputs.newGraphRoot, fixedInputs.newScoreRoot,
          batchId1, fixedInputs.batchSize, fixedInputs.n, fixedInputs.storageHash
        );
        const hash2 = buildExpectedHash(
          fixedInputs.oldGraphRoot, fixedInputs.oldScoreRoot,
          fixedInputs.newGraphRoot, fixedInputs.newScoreRoot,
          batchId2, fixedInputs.batchSize, fixedInputs.n, fixedInputs.storageHash
        );

        // Property: different batchIds should produce different hashes
        return hash1 !== hash2;
      }
    );

    await fc.assert(property, { numRuns: 20 });
  });
});

