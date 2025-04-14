package main

import (
	"crypto/rand"
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
		MaxLevels:    160,
		HashFunction: arbo.HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	testVector := [][]int64{
		{1, 11},
		{2, 22},
		{3, 33},
		{4, 44},
	}
	bLen := 1
	for i := range testVector {
		k := arbo.BigIntToBytes(bLen, big.NewInt(testVector[i][0]))
		v := arbo.BigIntToBytes(bLen, big.NewInt(testVector[i][1]))
		if err := tree.Add(k, v); err != nil {
			t.Fatal(err)
		}
	}

	// proof of existence
	k := arbo.BigIntToBytes(bLen, big.NewInt(int64(2)))
	cvp, err := tree.GenerateCircomVerifierProof(k)
	c.Assert(err, qt.IsNil)
	jCvp, err := json.Marshal(cvp)
	c.Assert(err, qt.IsNil)
	// store the data into a file that will be used at the circom test
	err = os.WriteFile("go-smt-verifier-inputs.json", jCvp, 0o600)
	c.Assert(err, qt.IsNil)

	// proof of non-existence
	k = arbo.BigIntToBytes(bLen, big.NewInt(int64(5)))
	cvp, err = tree.GenerateCircomVerifierProof(k)
	c.Assert(err, qt.IsNil)
	jCvp, err = json.Marshal(cvp)
	c.Assert(err, qt.IsNil)
	// store the data into a file that will be used at the circom test
	err = os.WriteFile("go-smt-verifier-non-existence-inputs.json", jCvp, 0o600)
	c.Assert(err, qt.IsNil)

	// create a new tree with big.Int keys
	bigtree, err := arbo.NewTree(arbo.Config{
		Database:     memdb.New(),
		MaxLevels:    160,
		HashFunction: arbo.HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)
	// add 100 elements to the tree
	var bk *big.Int
	for i := range 100 {
		k, err := rand.Int(rand.Reader, big.NewInt(100_000_000_000))
		c.Assert(err, qt.IsNil)
		v := new(big.Int).Mul(k, big.NewInt(2))
		c.Assert(bigtree.AddBigInt(k, v), qt.IsNil)

		if i == 0 {
			bk = k
		}
	}
	// generate a proof of existence for the first key
	cvp, err = tree.GenerateCircomVerifierProofBigInt(bk)
	c.Assert(err, qt.IsNil)
	jCvp, err = json.Marshal(cvp)
	c.Assert(err, qt.IsNil)
	// store the data into a file that will be used at the circom test
	err = os.WriteFile("go-smt-verifier-big-inputs.json", jCvp, 0o600)
	c.Assert(err, qt.IsNil)
}
