package arbo

import (
	"crypto/sha256"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	"github.com/iden3/go-iden3-crypto/poseidon"
	multiposeidon "github.com/vocdoni/vocdoni-z-sandbox/hash/poseidon"
	"golang.org/x/crypto/blake2b"
)

var (
	// TypeHashSha256 represents the label for the HashFunction of Sha256
	TypeHashSha256 = []byte("sha256")
	// TypeHashPoseidon represents the label for the HashFunction of
	// Poseidon
	TypeHashPoseidon = []byte("poseidon")
	// TypeHashPoseidon represents the label for the HashFunction of
	// Poseidon
	TypeHashMultiPoseidon = []byte("multiposeidon")
	// TypeHashBlake2b represents the label for the HashFunction of Blake2b
	TypeHashBlake2b = []byte("blake2b")
	// TypeHashMiMC_BLS12_377 represents the label for the HashFunction of MiMC
	// over BLS12-377 curve
	TypeHashMiMC_BLS12_377 = []byte("mimc_bls12_377")

	// HashFunctionSha256 contains the HashSha256 struct which implements
	// the HashFunction interface
	HashFunctionSha256 HashSha256
	// HashFunctionPoseidon contains the HashPoseidon struct which implements
	// the HashFunction interface
	HashFunctionPoseidon HashPoseidon
	// HashFunctionMultiPoseidon contains the HashMultiPoseidon struct which implements
	// the HashFunction interface
	HashFunctionMultiPoseidon HashMultiPoseidon
	// HashFunctionBlake2b contains the HashBlake2b struct which implements
	// the HashFunction interface
	HashFunctionBlake2b HashBlake2b
	// HashFunctionMiMC_BLS12_377 contains the HashMiMC_BLS12_377 struct which
	// implements the HashFunction interface
	HashFunctionMiMC_BLS12_377 HashMiMC_BLS12_377
)

// Once Generics are at Go, this will be updated (August 2021
// https://blog.golang.org/generics-next-step)

// HashFunction defines the interface that is expected for a hash function to be
// used in a generic way in the Tree.
type HashFunction interface {
	Type() []byte
	Len() int
	Hash(...[]byte) ([]byte, error)
}

// HashSha256 implements the HashFunction interface for the Sha256 hash
type HashSha256 struct{}

// Type returns the type of HashFunction for the HashSha256
func (f HashSha256) Type() []byte {
	return TypeHashSha256
}

// Len returns the length of the Hash output
func (f HashSha256) Len() int {
	return 32 //nolint:gomnd
}

// Hash implements the hash method for the HashFunction HashSha256
func (f HashSha256) Hash(b ...[]byte) ([]byte, error) {
	var toHash []byte
	for i := 0; i < len(b); i++ {
		toHash = append(toHash, b[i]...)
	}
	h := sha256.Sum256(toHash)
	return h[:], nil
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
func (f HashPoseidon) Hash(b ...[]byte) ([]byte, error) {
	var toHash []*big.Int
	for i := 0; i < len(b); i++ {
		bi := BytesToBigInt(b[i])
		toHash = append(toHash, bi)
	}
	h, err := poseidon.Hash(toHash)
	if err != nil {
		return nil, err
	}
	hB := BigIntToBytes(f.Len(), h)
	return hB, nil
}

// HashMultiPoseidon implements the HashFunction interface for the MultiPoseidon hash
type HashMultiPoseidon struct{}

// Type returns the type of HashFunction for the HashMultiPoseidon
func (f HashMultiPoseidon) Type() []byte {
	return TypeHashMultiPoseidon
}

// Len returns the length of the Hash output
func (f HashMultiPoseidon) Len() int {
	return 32 //nolint:gomnd
}

// Hash implements the hash method for the HashFunction HashMultiPoseidon. It
// expects the byte arrays to be little-endian representations of big.Int
// values. Notably, if any input is longer than 32 bytes (f.Len()), it will split it
// into 32 bytes chunks and interpret each of them as a big.Int value.
// so Hash({[64]byte}) and Hash({[32]byte, [32]byte}) will yield the same result.
func (f HashMultiPoseidon) Hash(b ...[]byte) ([]byte, error) {
	var bigints []*big.Int
	for _, input := range b {
		// Split input into chunks of 32 bytes
		for start := 0; start < len(input); start += f.Len() {
			end := start + f.Len()
			if end > len(input) {
				end = len(input)
			}
			// Convert each chunk into a big.Int
			bigints = append(bigints, BytesToBigInt(input[start:end]))
		}
	}
	h, err := multiposeidon.MultiPoseidon(bigints...)
	if err != nil {
		return nil, err
	}
	return BigIntToBytes(f.Len(), h), nil
}

// HashBlake2b implements the HashFunction interface for the Blake2b hash
type HashBlake2b struct{}

// Type returns the type of HashFunction for the HashBlake2b
func (f HashBlake2b) Type() []byte {
	return TypeHashBlake2b
}

// Len returns the length of the Hash output
func (f HashBlake2b) Len() int {
	return 32 //nolint:gomnd
}

// Hash implements the hash method for the HashFunction HashBlake2b
func (f HashBlake2b) Hash(b ...[]byte) ([]byte, error) {
	hasher, err := blake2b.New256(nil)
	if err != nil {
		return nil, err
	}
	for i := 0; i < len(b); i++ {
		if _, err = hasher.Write(b[i]); err != nil {
			return nil, err
		}
	}
	return hasher.Sum(nil), nil
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
	return mimc.BlockSize
}

// Hash implements the hash method for the HashFunction HashMiMC_BLS12_377
func (f HashMiMC_BLS12_377) Hash(b ...[]byte) ([]byte, error) {
	h := mimc.NewMiMC()
	for i := 0; i < len(b); i++ {
		if _, err := h.Write(SwapEndianness(b[i])); err != nil {
			return nil, err
		}
	}
	return SwapEndianness(h.Sum(nil)), nil
}
