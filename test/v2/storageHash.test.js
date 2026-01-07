import fs from "fs";
import path from "path";
import { describe, it, before, after } from "mocha";
import assert from "assert";
import { wasm as tester } from "circom_tester";
import { fileURLToPath } from "url";
import { buildStorageHash, edgesToUnforged, bitsToHex } from "../utils/hash.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("StorageHash circuit test", function () {
  this.timeout(200000);

  const N = 3;
  let circuit;
  let circuitTmpPath;

  before(async () => {
    const circuitSrc = `
      pragma circom 2.1.6;
      include "../circuits/syb_rollup_v2/storage_hash.circom";
      component main = StorageHash(${N});
    `;
    circuitTmpPath = path.join(__dirname, "storage-hash.test.circom");
    fs.writeFileSync(circuitTmpPath, circuitSrc, "utf8");

    circuit = await tester(circuitTmpPath, {
      reduceConstraints: false,
      include: [
        path.join(__dirname, "../"),
        path.join(__dirname, "../../node_modules"),
      ],
    });
    await circuit.loadConstraints();
    console.log(`\n✓ StorageHash circuit compiled with n=${N}`);
    console.log(`✓ Constraints: ${circuit.constraints.length}`);
  });

  after(() => {
    if (fs.existsSync(circuitTmpPath)) {
      fs.unlinkSync(circuitTmpPath);
    }
  });

  it("should match ethers sha256", async () => {
    const batchId = 0n;
    const start = 0;
    const edges = [[1, 2, 0], [3, 4, 0], [5, 6, 0]];  // [ilo, ihi, flag]
    const unforged = edgesToUnforged(edges);

    const expectedHash = buildStorageHash(batchId, start, N, unforged);
    console.log(`  Expected: ${expectedHash}`);

    const input = {
      batchId: batchId.toString(),
      start: start.toString(),
      edges: edges.map(([ilo, ihi, flag]) => [ilo.toString(), ihi.toString(), flag.toString()]),
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    // Extract output bits from witness (same as sha256Circomlib.test.js)
    const hashBits = [];
    for (let i = 0; i < 256; i++) {
      hashBits.push(w[1 + i]); // +1 because witness[0] is always 1
    }

    const circuitHash = bitsToHex(hashBits);
    console.log(`  Circuit:  ${circuitHash}`);

    assert.equal(circuitHash, expectedHash);
  });

  it("should pass with different batchId", async () => {
    const batchId = 0n;
    const start = 3;
    const edges = [[1, 2, 0], [3, 4, 1], [5, 6, 2]];  // [ilo, ihi, flag]
    const unforged = edgesToUnforged(edges);

    const expectedHash = buildStorageHash(batchId, start, N, unforged);
    console.log(`  Expected: ${expectedHash}`);

    const input = {
      batchId: batchId.toString(),
      start: start.toString(),
      edges: edges.map(([ilo, ihi, flag]) => [ilo.toString(), ihi.toString(), flag.toString()]),
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    // Extract output bits from witness
    const hashBits = [];
    for (let i = 0; i < 256; i++) {
      hashBits.push(w[1 + i]);
    }

    const circuitHash = bitsToHex(hashBits);
    console.log(`  Circuit:  ${circuitHash}`);

    assert.equal(circuitHash, expectedHash);
  });
});
