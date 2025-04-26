package testgnark

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	"github.com/vocdoni/gnark-crypto-primitives/hash/bn254/poseidon"
	garbo "github.com/vocdoni/gnark-crypto-primitives/tree/arbo"
	gsmt "github.com/vocdoni/gnark-crypto-primitives/tree/smt"
	"github.com/vocdoni/gnark-crypto-primitives/utils"
)

const nLevels = 160

type testCircuitArbo struct {
	Root     frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable
	Siblings [nLevels]frontend.Variable
}

func (circuit *testCircuitArbo) Define(api frontend.API) error {
	return garbo.CheckInclusionProof(api, utils.Poseidon2Hasher, circuit.Key, circuit.Value, circuit.Root, circuit.Siblings[:])
}

func TestGnarkArboVerifier(t *testing.T) {
	c := qt.New(t)
	tree, err := arbo.NewTree(arbo.Config{
		Database:     memdb.New(),
		MaxLevels:    nLevels,
		HashFunction: arbo.HashFunctionPoseidon2,
	})
	c.Assert(err, qt.IsNil)

	var (
		keys   []*big.Int
		values [][]*big.Int
	)
	max, _ := new(big.Int).SetString("10000000000000000000000000", 10)
	for range 100 {
		k, err := rand.Int(rand.Reader, max)
		qt.Assert(t, err, qt.IsNil)
		v := new(big.Int).Mul(k, big.NewInt(2))
		keys = append(keys, k)
		values = append(values, []*big.Int{v})
	}
	_, err = tree.AddBatchBigInt(keys, values)
	c.Assert(err, qt.IsNil)

	proof, err := tree.GenerateGnarkVerifierProofBigInt(keys[0])
	c.Assert(err, qt.IsNil)

	var paddedSiblings [nLevels]frontend.Variable
	for i := range paddedSiblings {
		if i < len(proof.Siblings) {
			paddedSiblings[i] = proof.Siblings[i]
			continue
		}
		paddedSiblings[i] = 0
	}

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testCircuitArbo{}, &testCircuitArbo{
		Root:     proof.Root,
		Key:      proof.Key,
		Value:    proof.Value,
		Siblings: [160]frontend.Variable(paddedSiblings),
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

type testCircuitSMT struct {
	Root     frontend.Variable
	Key      frontend.Variable
	Value    frontend.Variable
	Siblings [nLevels]frontend.Variable
}

func (circuit *testCircuitSMT) Define(api frontend.API) error {
	gsmt.InclusionVerifier(api, poseidon.MultiHash, circuit.Root, circuit.Siblings[:], circuit.Key, circuit.Value)
	return nil
}

func TestGnarkSMTVerifier(t *testing.T) {
	c := qt.New(t)
	tree, err := arbo.NewTree(arbo.Config{
		Database:     memdb.New(),
		MaxLevels:    nLevels,
		HashFunction: arbo.HashFunctionMultiPoseidon,
	})
	c.Assert(err, qt.IsNil)

	var (
		keys   []*big.Int
		values [][]*big.Int
	)
	max, _ := new(big.Int).SetString("10000000000000000000000000", 10)
	for range 100 {
		k, err := rand.Int(rand.Reader, max)
		qt.Assert(t, err, qt.IsNil)
		v := new(big.Int).Mul(k, big.NewInt(2))
		keys = append(keys, k)
		values = append(values, []*big.Int{v})
	}
	_, err = tree.AddBatchBigInt(keys, values)
	c.Assert(err, qt.IsNil)

	proof, err := tree.GenerateGnarkVerifierProofBigInt(keys[0])
	c.Assert(err, qt.IsNil)

	var paddedSiblings [nLevels]frontend.Variable
	for i := range paddedSiblings {
		if i < len(proof.Siblings) {
			paddedSiblings[i] = proof.Siblings[i]
			continue
		}
		paddedSiblings[i] = 0
	}

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&testCircuitSMT{}, &testCircuitSMT{
		Root:     proof.Root,
		Key:      proof.Key,
		Value:    proof.Value,
		Siblings: [160]frontend.Variable(paddedSiblings),
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
