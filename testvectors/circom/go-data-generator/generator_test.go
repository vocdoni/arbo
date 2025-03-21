package main

import (
	"encoding/json"
	"math/big"
	"os"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
)

func TestGenerator(t *testing.T) {
	c := qt.New(t)
	tree, err := arbo.NewTree(arbo.Config{
		Database:     memdb.New(),
		MaxLevels:    4,
		HashFunction: arbo.HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	testVector := [][]int64{
		{1, 11},
		{2, 22},
		{3, 33},
		{4, 44},
	}
	for i := range testVector {
		c.Assert(tree.Add(big.NewInt(testVector[i][0]), big.NewInt(testVector[i][1])), qt.IsNil)
	}

	// proof of existence
	k := big.NewInt(int64(2))
	cvp, err := tree.GenerateCircomVerifierProof(k)
	c.Assert(err, qt.IsNil)
	jCvp, err := json.Marshal(cvp)
	c.Assert(err, qt.IsNil)
	// store the data into a file that will be used at the circom test
	err = os.WriteFile("go-smt-verifier-inputs.json", jCvp, 0600)
	c.Assert(err, qt.IsNil)

	// proof of non-existence
	k = big.NewInt(int64(5))
	cvp, err = tree.GenerateCircomVerifierProof(k)
	c.Assert(err, qt.IsNil)
	jCvp, err = json.Marshal(cvp)
	c.Assert(err, qt.IsNil)
	// store the data into a file that will be used at the circom test
	err = os.WriteFile("go-smt-verifier-non-existence-inputs.json", jCvp, 0600)
	c.Assert(err, qt.IsNil)
}
