package arbo

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestHashSha256(t *testing.T) {
	// Sha256 hash
	hashFunc := &HashSha256{}
	b := []byte("test")
	h, err := hashFunc.Hash(b)
	if err != nil {
		t.Fatal(err)
	}
	c := qt.New(t)
	c.Assert(hex.EncodeToString(h),
		qt.Equals,
		"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
}

func TestHashPoseidon(t *testing.T) {
	// Poseidon hash
	hashFunc := &HashPoseidon{}
	bLen := hashFunc.Len()
	h, err := hashFunc.Hash(
		BigIntToBytes(bLen, big.NewInt(1)),
		BigIntToBytes(bLen, big.NewInt(2)))
	if err != nil {
		t.Fatal(err)
	}
	hBI := BytesToBigInt(h)
	// value checked with circomlib
	c := qt.New(t)
	c.Assert(hBI.String(),
		qt.Equals,
		"7853200120776062878684798364095072458815029376092732009249414926327459813530")
}

func TestHashBlake2b(t *testing.T) {
	// Blake2b hash
	hashFunc := &HashBlake2b{}
	b := []byte("test")
	h, err := hashFunc.Hash(b)
	if err != nil {
		t.Fatal(err)
	}
	c := qt.New(t)
	c.Assert(hex.EncodeToString(h),
		qt.Equals,
		"928b20366943e2afd11ebc0eae2e53a93bf177a4fcf35bcc64d503704e65e202")
}

func TestHashMiMC(t *testing.T) {
	// MiMC hash
	HashFunction := &HashMiMC_BLS12_377{}
	b := []byte("test")
	h, err := HashFunction.Hash(b)
	if err != nil {
		t.Fatal(err)
	}
	c := qt.New(t)
	c.Assert(hex.EncodeToString(h),
		qt.Equals,
		"f881f34991492d823e02565c778b824bac5eacef6340b70ee90a8966a2e63900")
}

func TestHashMoreThan32BytesMiMC(t *testing.T) {
	c := qt.New(t)

	// create a random 257 bytes
	b := make([]byte, 257)
	_, err := rand.Read(b)
	c.Assert(err, qt.IsNil)

	// MiMC hash bn254
	mimcbn254 := &HashMiMC_BN254{}
	h, err := mimcbn254.Hash(b)
	c.Assert(err, qt.IsNil)
	c.Assert(len(h), qt.Equals, 32)

	// MiMC hash bls12377
	mimcbls12377 := &HashMiMC_BLS12_377{}
	h, err = mimcbls12377.Hash(b)
	c.Assert(err, qt.IsNil)
	c.Assert(len(h), qt.Equals, 32)
}
