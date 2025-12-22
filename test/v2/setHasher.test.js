import fs from "fs";
import path from "path";
import { describe, it, before, after } from "mocha";
import assert from "assert";
import { wasm as tester } from "circom_tester";
import { buildPoseidon } from "circomlibjs";
import { fileURLToPath } from "url";
import { computeSetHash, padNeighbors } from "../utils/helpers.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("SetHasher circuit test", function () {
  this.timeout(200000);

  const MAX_DEG = 15 * 4; // Maximum degree: 60
  const R = 5566; // Public randomizer
  let circuit;
  let circuitTmpPath;
  let F;

  before(async () => {
    const poseidon = await buildPoseidon();
    F = poseidon.F;

    const circuitSrc = `
            pragma circom 2.1.0;
            include "../circuits/syb_rollup_v2/set_hasher.circom";
            component main = SetHasher(${MAX_DEG});
        `;
    circuitTmpPath = path.join(__dirname, "set-hasher.test.circom");
    fs.writeFileSync(circuitTmpPath, circuitSrc, "utf8");

    circuit = await tester(circuitTmpPath, {
      reduceConstraints: false,
      include: path.join(__dirname, "../"),
    });
    await circuit.loadConstraints();
    console.log(`\n✓ SetHasher circuit compiled with maxDeg=${MAX_DEG}`);
    console.log(`✓ r=${R}`);
    console.log(`✓ Constraints: ${circuit.constraints.length}\n`);
  });

  after(() => {
    if (fs.existsSync(circuitTmpPath)) {
      fs.unlinkSync(circuitTmpPath);
    }
  });

  /**
   * TEST CASES
   *
   * VALID
   * [X] hash a vertex with degree 0 (no neighbors)
   * [X] hash a vertex with degree 1
   * [X] hash a vertex with degree 5
   * [X] hash a vertex with degree 30
   * [X] hash a vertex with degree 59 (max allowed, since d < maxDeg)
   *
   * INVALID
   * [X] fail when d >= maxDeg
   */

  it("should hash a vertex with degree 0 (no neighbors)", async () => {
    const d = 0;
    const neighbors = [];

    const expectedHash = computeSetHash(F, MAX_DEG, R, neighbors);

    const input = {
      d: d.toString(),
      r: R.toString(),
      paddedNbrArr: padNeighbors(MAX_DEG, neighbors),
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    const circuitOutput = w[1].toString();
    assert.equal(circuitOutput, expectedHash.toString());
  });

  it("should hash a vertex with degree 1", async () => {
    const d = 1;
    const neighbors = [25];

    const expectedHash = computeSetHash(F, MAX_DEG, R, neighbors);

    const input = {
      d: d.toString(),
      r: R.toString(),
      paddedNbrArr: padNeighbors(MAX_DEG, neighbors),
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    const circuitOutput = w[1].toString();
    assert.equal(circuitOutput, expectedHash.toString());
  });

  it("should hash a vertex with degree 5", async () => {
    const d = 5;
    const neighbors = [1, 3, 8, 12, 15];

    const expectedHash = computeSetHash(F, MAX_DEG, R, neighbors);

    const input = {
      d: d.toString(),
      r: R.toString(),
      paddedNbrArr: padNeighbors(MAX_DEG, neighbors),
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    const circuitOutput = w[1].toString();
    assert.equal(circuitOutput, expectedHash.toString());
  });

  it("should hash a vertex with degree 30", async () => {
    const d = 30;
    const neighbors = Array.from({ length: 30 }, (_, i) => (i + 1) * 10);

    const expectedHash = computeSetHash(F, MAX_DEG, R, neighbors);

    const input = {
      d: d.toString(),
      r: R.toString(),
      paddedNbrArr: padNeighbors(MAX_DEG, neighbors),
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    const circuitOutput = w[1].toString();
    assert.equal(circuitOutput, expectedHash.toString());
  });

  it("should hash a vertex with degree 59 (max allowed)", async () => {
    const d = MAX_DEG - 1; // 59, since d < maxDeg
    const neighbors = Array.from({ length: d }, (_, i) => i + 1);

    const expectedHash = computeSetHash(F, MAX_DEG, R, neighbors);

    const input = {
      d: d.toString(),
      r: R.toString(),
      paddedNbrArr: padNeighbors(MAX_DEG, neighbors),
    };

    const w = await circuit.calculateWitness(input, true);
    await circuit.checkConstraints(w);

    const circuitOutput = w[1].toString();
    assert.equal(circuitOutput, expectedHash.toString());
  });

  it("should fail when d > maxDeg", async () => {
    const d = MAX_DEG + 1; // 61, violates d < maxDeg
    const neighbors = Array.from({ length: MAX_DEG }, (_, i) => i + 1);

    const input = {
      d: d.toString(),
      r: R.toString(),
      paddedNbrArr: padNeighbors(MAX_DEG, neighbors),
    };

    try {
      await circuit.calculateWitness(input, true);
      assert.fail("Should have failed with d >= maxDeg");
    } catch (error) {
      assert(error.message.includes("Assert Failed"));
    }
  });
});
