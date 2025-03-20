package arbo

import (
	"math/big"

	mimc_bls12_377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	mimc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

var (
	// TypeHashPoseidon represents the label for the HashFunction of
	// Poseidon
	TypeHashPoseidon = []byte("poseidon")
	// TypeHashMimc7 represents the label for the HashFunction of Mimc7
	TypeHashMimc7 = []byte("mimc7")
	// TypeHashMiMC_BLS12_377 represents the label for the HashFunction of MiMC
	// over BLS12-377 curve
	TypeHashMiMC_BLS12_377 = []byte("mimc_bls12_377")
	// TypeHashMiMC_BN254 represents the label for the HashFunction of MiMC
	// over BN254 curve
	TypeHashMiMC_BN254 = []byte("mimc_bn254")

	// HashFunctionPoseidon contains the HashPoseidon struct which implements
	// the HashFunction interface
	HashFunctionPoseidon HashPoseidon
	// HashFunctionMimc7 contains the HashMiMC7 struct which implements the
	// HashFunction interface
	HashFunctionMimc7 HashMiMC7
	// HashFunctionMiMC_BLS12_377 contains the HashMiMC_BLS12_377 struct which
	// implements the HashFunction interface
	HashFunctionMiMC_BLS12_377 HashMiMC_BLS12_377
	// HashFunctionMiMC_BN254 contains the HashMiMC_BN254 struct which
	// implements the HashFunction interface
	HashFunctionMiMC_BN254 HashMiMC_BN254
)

// Once Generics are at Go, this will be updated (August 2021
// https://blog.golang.org/generics-next-step)

// HashFunction defines the interface that is expected for a hash function to be
// used in a generic way in the Tree.
type HashFunction interface {
	Type() []byte
	Len() int
	Hash(...*big.Int) (*big.Int, error)
}

// HashPoseidon implements the HashFunction interface for the Poseidon hash
type HashPoseidon struct{}

// Type returns the type of HashFunction for the HashPoseidon
func (f HashPoseidon) Type() []byte {
	return TypeHashPoseidon
}

// Len returns the length of the Hash output
func (f HashPoseidon) Len() int {
	return 32 //nolint:gomnd
}

// Hash implements the hash method for the HashFunction HashPoseidon. It
// expects the byte arrays to be little-endian representations of big.Int
// values.
func (f HashPoseidon) Hash(b ...*big.Int) (*big.Int, error) {
	return poseidon.Hash(b)
}

type HashMiMC7 struct{}

func (f HashMiMC7) Type() []byte {
	return TypeHashMimc7
}

func (f HashMiMC7) Len() int {
	return 32 //nolint:gomnd
}

func (f HashMiMC7) Hash(b ...*big.Int) (*big.Int, error) {
	var toHash []*big.Int
	for _, i := range b {
		toHash = append(toHash, BigToFF(BN254BaseField, i))
	}
	h, err := mimc7.Hash(toHash, nil)
	if err != nil {
		return nil, err
	}
	return h, nil
}

// HashMiMC_BLS12_377 implements the HashFunction interface for the MiMC hash
// over the BLS12-377 curve
type HashMiMC_BLS12_377 struct{}

// Type returns the type of HashFunction for the HashMiMC_BLS12_377
func (f HashMiMC_BLS12_377) Type() []byte {
	return TypeHashMiMC_BLS12_377
}

// Len returns the length of the Hash output for the HashMiMC_BLS12_377
func (f HashMiMC_BLS12_377) Len() int {
	return mimc_bls12_377.BlockSize
}

// Hash implements the hash method for the HashFunction HashMiMC_BLS12_377
func (f HashMiMC_BLS12_377) Hash(b ...*big.Int) (*big.Int, error) {
	h := mimc_bn254.NewMiMC()
	for _, i := range b {
		h.Write(BigToFF(BLS12377BaseField, i).Bytes())
	}
	return new(big.Int).SetBytes(h.Sum(nil)), nil
}

// HashMiMC_BN254 implements the HashFunction interface for the MiMC hash
// over the BN254 curve
type HashMiMC_BN254 struct{}

// Type returns the type of HashFunction for the HashMiMC_BN254
func (f HashMiMC_BN254) Type() []byte {
	return TypeHashMiMC_BN254
}

// Len returns the length of the Hash output for the HashMiMC_BN254
func (f HashMiMC_BN254) Len() int {
	return mimc_bn254.BlockSize
}

// Hash implements the hash method for the HashFunction HashMiMC_BN254
func (f HashMiMC_BN254) Hash(b ...*big.Int) (*big.Int, error) {
	h := mimc_bn254.NewMiMC()
	for _, i := range b {
		h.Write(BigToFF(BLS12377BaseField, i).Bytes())
	}
	return new(big.Int).SetBytes(h.Sum(nil)), nil
}
