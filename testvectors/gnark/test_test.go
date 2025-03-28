package testgnark

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/test"
	"github.com/vocdoni/arbo"
)

type hashTestCircuit struct {
	Values [2]frontend.Variable
	Hash   frontend.Variable
}

func (c *hashTestCircuit) Define(api frontend.API) error {
	hFn, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	hFn.Write(c.Values[:]...)
	api.AssertIsEqual(hFn.Sum(), c.Hash)
	return nil
}

func TestTest(t *testing.T) {
	veryBigValue := new(big.Int).Mul(arbo.BLS12377BaseField, big.NewInt(17))
	veryBigValue2 := new(big.Int).Mul(arbo.BLS12377BaseField, big.NewInt(6))
	t.Log(veryBigValue, arbo.BigToFF(arbo.BN254BaseField, veryBigValue))
	t.Log(veryBigValue2, arbo.BigToFF(arbo.BN254BaseField, veryBigValue2))
	expected, _ := new(big.Int).SetString("708643117794185380623831897010742343910909883113872061615868952391691465348", 10)

	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&hashTestCircuit{}, &hashTestCircuit{
		Values: [2]frontend.Variable{veryBigValue, veryBigValue2},
		Hash:   expected,
	}, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}
