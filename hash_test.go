package arbo

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	qt "github.com/frankban/quicktest"
)

func TestHashPoseidon(t *testing.T) {
	c := qt.New(t)
	// Poseidon hash
	hashFunc := &HashPoseidon{}
	h, err := hashFunc.Hash(big.NewInt(1), big.NewInt(2))
	c.Assert(err, qt.IsNil)
	// value checked with circomlib
	c.Assert(h.String(), qt.Equals, "7853200120776062878684798364095072458815029376092732009249414926327459813530")
}

func TestHashMiMC(t *testing.T) {
	c := qt.New(t)
	// MiMC hash
	HashFunction := &HashMiMC_BLS12_377{}
	// generate random big int
	b, err := rand.Int(rand.Reader, BLS12377BaseField)
	c.Assert(err, qt.IsNil)
	h, err := HashFunction.Hash(b)
	c.Assert(err, qt.IsNil)

	hfn := mimc.NewMiMC()
	_, err = hfn.Write(b.Bytes())
	c.Assert(err, qt.IsNil)
	sum := new(big.Int).SetBytes(hfn.Sum(nil))
	c.Assert(sum.String(), qt.Equals, h.String())
}
