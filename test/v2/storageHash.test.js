import fs from "fs";
import path from "path";
import { describe, it, before, after } from "mocha";
import assert from "assert";
import { wasm as tester } from "circom_tester";
import { fileURLToPath } from "url";
import { ethers } from "ethers";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("StorageHash circuit test", function () {
  this.timeout(200000);

  const N = 3; // Number of edges for testing
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

  /**
   * Build storage hash matching Solidity contract:
   * sha256(abi.encodePacked(batchId, start, n, edgesPacked))
   * 
   * @param {BigInt} batchId - uint64
   * @param {number} start - uint32
   * @param {number} n - uint32
   * @param {BigInt[]} unforged - array of packed edges: (ilo << 32) | ihi
   */
  function buildStorageHash(batchId, start, n, unforged) {
    const edgesPacked = new Uint8Array(n * 8);

    for (let i = 0; i < n; i++) {
      const w = unforged[start + i];
      const ilo = Number((w >> 32n) & 0xffffffffn);
      const ihi = Number(w & 0xffffffffn);
      const offset = i * 8;
      edgesPacked[offset] = (ilo >> 24) & 0xff;
      edgesPacked[offset + 1] = (ilo >> 16) & 0xff;
      edgesPacked[offset + 2] = (ilo >> 8) & 0xff;
      edgesPacked[offset + 3] = ilo & 0xff;
      edgesPacked[offset + 4] = (ihi >> 24) & 0xff;
      edgesPacked[offset + 5] = (ihi >> 16) & 0xff;
      edgesPacked[offset + 6] = (ihi >> 8) & 0xff;
      edgesPacked[offset + 7] = ihi & 0xff;
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
   * Helper: convert edges array [[ilo, ihi], ...] to unforged array [(ilo<<32)|ihi, ...]
   */
  function edgesToUnforged(edges) {
    return edges.map(([ilo, ihi]) => (BigInt(ilo) << 32n) | BigInt(ihi));
  }

  it("should match buildStorageHash output", async () => {
    const batchId = 0n;
    const start = 0;
    const edges = [[1, 2], [3, 4], [5, 6]];
    const unforged = edgesToUnforged(edges);

    const expectedHash = buildStorageHash(batchId, start, N, unforged);
    console.log(`  Expected hash: ${expectedHash}`);
    console.log(`  Expected (decimal): ${BigInt(expectedHash).toString()}`);

    const input = {
      batchId: batchId.toString(),
      start: start.toString(),
      edges: edges.map(([ilo, ihi]) => [ilo.toString(), ihi.toString()]),
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    const circuitOutput = w[1].toString();
    console.log(`  Circuit output: ${circuitOutput}`);

    assert.equal(circuitOutput, BigInt(expectedHash).toString());
  });
});
