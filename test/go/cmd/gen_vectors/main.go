package main

import (
	"encoding/json"
	"fmt"

	nbrhasher "github.com/tokamak-network/syb-mvp/circuits/test/go"
)

const MAX_DEG uint64 = 60

type TestVector struct {
	Name      string   `json:"name"`
	Deg       uint64   `json:"deg"`
	Neighbors []uint64 `json:"neighbors"`
	Hash      string   `json:"hash"`
}

type TestVectorsOutput struct {
	MaxDeg  uint64       `json:"maxDeg"`
	PadLen  int          `json:"padLen"`
	Vectors []TestVector `json:"vectors"`
}

func main() {
	vectors := []TestVector{
		{Name: "degree_0", Deg: 0, Neighbors: []uint64{}},
		{Name: "degree_1", Deg: 1, Neighbors: []uint64{25}},
		{Name: "degree_5", Deg: 5, Neighbors: []uint64{1, 3, 8, 12, 15}},
		{Name: "degree_15", Deg: 15, Neighbors: []uint64{2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30}},
		{Name: "degree_20", Deg: 20, Neighbors: []uint64{1, 2, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23, 25, 27, 29, 31, 33, 35, 37, 39}},
		{Name: "degree_30", Deg: 30, Neighbors: makeSeq(30, 10)},
		{Name: "degree_60", Deg: 60, Neighbors: makeSeq(60, 1)},
	}

	for i := range vectors {
		hash := nbrhasher.ComputeNbrHash(vectors[i].Deg, vectors[i].Neighbors, MAX_DEG)
		vectors[i].Hash = hash.String()
	}

	output := TestVectorsOutput{
		MaxDeg:  MAX_DEG,
		PadLen:  nbrhasher.PadLenFromMaxDegree(MAX_DEG),
		Vectors: vectors,
	}

	jsonBytes, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(jsonBytes))
}

func makeSeq(n int, multiplier int) []uint64 {
	out := make([]uint64, n)
	for i := 0; i < n; i++ {
		out[i] = uint64((i + 1) * multiplier)
	}
	return out
}
