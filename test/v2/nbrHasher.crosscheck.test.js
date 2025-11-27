import fs from "fs";
import path from "path";
import { describe, it, before, after } from "mocha";
import assert from "assert";
import { wasm as tester } from "circom_tester";
import { fileURLToPath } from "url";
import test from "../go/test.json" with { type: "json" };

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Cross-check test: verify circuit output matches Go implementation hash values.
 *
 * Test vectors generated from Go (node_hasher.go):
 *   go run ./cmd/gen_vectors/
 *
 * Go uses: padLen = 1 + 15 * ceil(maxDeg / 15) = 61 for maxDeg=60
 * Circuit uses: nbr_arr length = 15 * ceil(maxDeg / 15) = 60 for maxDeg=60
 *
 * The hash algorithm is the same, just input format differs:
 *   Go:      nbrData = [deg, u0, u1, ..., u59]  (length 61)
 *   Circuit: d + nbr_arr = [d] + [u0, u1, ..., u59] (d separate, nbr_arr length 60)
 */

const GO_TEST_VECTORS = test.vectors;

describe("NbrHasher circuit cross-check with Go", function () {
  this.timeout(200000);

  const MAX_DEG = 60;
  const PAD_LEN = 15 * Math.ceil(MAX_DEG / 15); // 60 for circuit nbr_arr

  let circuit;
  let circuitTmpPath;

  before(async () => {
    const circuitSrc = `
      pragma circom 2.0.0;
      include "../circuits/syb_rollup_v2/nbr_hasher.circom";
      component main = NbrHasher(${MAX_DEG});
    `;
    circuitTmpPath = path.join(__dirname, "nbr-hasher-crosscheck.test.circom");
    fs.writeFileSync(circuitTmpPath, circuitSrc, "utf8");

    circuit = await tester(circuitTmpPath, {
      reduceConstraints: false,
      include: path.join(__dirname, "../"),
    });
    await circuit.loadConstraints();

    console.log(`\n✓ NbrHasher circuit compiled with maxDeg=${MAX_DEG}`);
    console.log(`✓ Circuit nbr_arr length: ${PAD_LEN}`);
    console.log(`✓ Constraints: ${circuit.constraints.length}`);
    console.log(
      `✓ Testing against ${GO_TEST_VECTORS.length} Go test vectors\n`,
    );
  });

  after(() => {
    if (fs.existsSync(circuitTmpPath)) {
      fs.unlinkSync(circuitTmpPath);
    }
  });

  for (const vector of GO_TEST_VECTORS) {
    it(`should match Go hash for ${vector.name} (deg=${vector.deg})`, async () => {
      // Pad neighbors to PAD_LEN
      const paddedNbrs = [...vector.neighbors];
      while (paddedNbrs.length < PAD_LEN) {
        paddedNbrs.push(0);
      }

      const input = {
        d: vector.deg.toString(),
        nbr_arr: paddedNbrs.map((x) => x.toString()),
      };

      const w = await circuit.calculateWitness(input, true);
      await circuit.checkConstraints(w);

      const circuitOutput = w[1].toString();

      console.log(`  ${vector.name}:`);
      console.log(`    Go hash:      ${vector.hash}`);
      console.log(`    Circuit hash: ${circuitOutput}`);

      assert.strictEqual(
        circuitOutput,
        vector.hash,
        `Hash mismatch for ${vector.name}: circuit=${circuitOutput}, go=${vector.hash}`,
      );
    });
  }
});
