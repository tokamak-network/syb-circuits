package nbrhasher

import (
	"fmt"
	"math/big"

	poseidon "github.com/iden3/go-iden3-crypto/v2/poseidon"
)

// ----------------------------
// Padding helpers
// ----------------------------

// padLenFromMaxDegree returns padLen = 1 + 15 * ceil(maxDegree / 15).
// This is the fixed neighbour-array length used in the circuit.
func PadLenFromMaxDegree(maxDegree uint64) int {
	if maxDegree == 0 {
		// deg=0 is allowed, but we still need room for the first block:
		// [deg, 15 zeros] => length at least 16.
		return 1 + 15
	}
	groups := (maxDegree + 14) / 15 // ceil(maxDeg / 15)
	return int(1 + 15*groups)
}

// zeroArray forms an all-zero neighbour array of the correct padded length
// for a given maxDegree.
//
// Layout: [deg, u0, u1, ..., u_{padLen-2}], where all entries are 0.
// Caller will set deg and neighbours as needed.
func zeroArray(maxDegree uint64) []uint64 {
	return make([]uint64, PadLenFromMaxDegree(maxDegree))
}

// buildNbrDataCompact builds the *un-padded* neighbour data [deg, u0, ..., u_{deg-1}]
func buildNbrDataCompact(nbrs []uint64) []uint64 {
	out := make([]uint64, 1+len(nbrs))
	out[0] = uint64(len(nbrs))
	copy(out[1:], nbrs)
	return out
}

// padNbrData takes a compact neighbour array [deg, u0, ..., u_{deg-1}] and
// returns a padded array of length padLenFromMaxDegree(maxDegree), with zeros
// filling the remainder.
func padNbrData(compact []uint64, maxDegree uint64) []uint64 {
	padLen := PadLenFromMaxDegree(maxDegree)
	if len(compact) > padLen {
		// This should never happen if maxDegree is respected.
		panic(fmt.Sprintf("padNbrData: compact len %d > padLen %d", len(compact), padLen))
	}
	out := make([]uint64, padLen)
	copy(out, compact) // deg + neighbours copied; the rest stays zero
	return out
}

// ----------------------------
// Poseidon-based neighbour hashing
// ----------------------------
//
// NbrHash_G(v) algorithm (field version, using Poseidon_16):
//
// - Input: PaddedNbrData_G(v) of length padLen = 1 + 15*numR
//   where numR = ceil(maxDeg / 15).
//
//   Layout: [deg, u0, u1, ..., u_{padLen-2}] where all extra entries are 0.
//
// - B0 = [deg, u0, ..., u14]  (16 field elements)
//   acc = Poseidon_16(B0)
//
// - For b = 1..numR-1:
//     Bb = [acc, next 15 unused entries of PaddedNbrData_G(v)]
//     acc = Poseidon_16(Bb)
//
// - Output: acc

// nbrArrayHasher expects a *padded* neighbour array, i.e. the output of
// padNbrData(...) or zeroArray(...) with deg & neighbours filled in.
//
// nbrData layout:
//
//	index 0: deg
//	index 1..(padLen-1): neighbour ids (sorted), zero-padded
//
// padLen must satisfy: padLen >= 16 and (padLen-1) % 15 == 0.
func NbrArrayHasher(nbrData []uint64) *big.Int {
	padLen := len(nbrData)
	if padLen < 16 {
		panic(fmt.Sprintf("nbrArrayHasher: nbrData len %d < 16", padLen))
	}
	if (padLen-1)%15 != 0 {
		panic(fmt.Sprintf("nbrArrayHasher: invalid padLen %d (padLen-1 must be divisible by 15)", padLen))
	}

	numR := (padLen - 1) / 15 // number of 15-neighbour blocks

	// Convert uint64 -> *big.Int slice for Poseidon.
	// We'll reuse the same slice for each round.
	block := make([]*big.Int, 16)

	// ----- Round 0: B0 = [deg, u0..u14] -----
	for i := 0; i < 16; i++ {
		block[i] = new(big.Int).SetUint64(nbrData[i])
	}
	acc, err := poseidon.Hash(block) // Poseidon_16 over 16 inputs
	if err != nil {
		panic(fmt.Errorf("nbrArrayHasher: poseidon.Hash round 0: %w", err))
	}

	// ----- Subsequent rounds: Bb = [acc, next 15 neighbours] -----
	//
	// We have padLen-1 neighbour slots after deg; we already consumed
	// neighbours at indices 1..15 (15 of them), leaving:
	//
	//   remaining = (padLen-1) - 15 = 15*(numR-1)
	//
	// Those live at indices 16..padLen-1, and we take 15 at each round.
	offset := 16 // next neighbour index to consume

	for r := 1; r < numR; r++ {
		// First element is previous accumulator.
		block[0] = acc

		// Next 15 inputs are nbrData[offset .. offset+14].
		for j := 1; j < 16; j++ {
			idx := offset + (j - 1)
			if idx < padLen {
				block[j] = new(big.Int).SetUint64(nbrData[idx])
			} else {
				// Should not happen if padLen is correct, but be defensive.
				block[j] = big.NewInt(0)
			}
		}

		acc, err = poseidon.Hash(block)
		if err != nil {
			panic(fmt.Errorf("nbrArrayHasher: poseidon.Hash round %d: %w", r, err))
		}
		offset += 15
	}

	return acc
}

// bigFromUint64 is a tiny helper to build *big.Int from uint64.
func bigFromUint64(x uint64) *big.Int {
	return new(big.Int).SetUint64(x)
}

// ComputeNbrHash is a convenience function that builds padded data and computes hash.
func ComputeNbrHash(deg uint64, neighbors []uint64, maxDegree uint64) *big.Int {
	compact := buildNbrDataCompact(neighbors)
	compact[0] = deg // override with actual degree
	padded := padNbrData(compact, maxDegree)
	return NbrArrayHasher(padded)
}
