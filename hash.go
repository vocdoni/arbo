package arbo

import (
	"crypto/sha256"
	"math/big"

	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	mimc_bls12_377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/mimc"
	mimc_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/iden3/go-iden3-crypto/mimc7"
	"github.com/iden3/go-iden3-crypto/poseidon"
	multiposeidon "github.com/vocdoni/vocdoni-z-sandbox/crypto/hash/poseidon"
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
	// TypeHashMiMC_BN254 represents the label for the HashFunction of MiMC
	// over BN254 curve
	TypeHashMiMC_BN254 = []byte("mimc_bn254")
	// TypeHashMimc7 represents the label for the HashFunction of Mimc7
	TypeHashMimc7 = []byte("mimc7")

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
	// HashFunctionMiMC_BN254 contains the HashMiMC_BN254 struct which
	// implements the HashFunction interface
	HashFunctionMiMC_BN254 HashMiMC_BN254
	// HashFunctionMimc7 contains the HashMiMC7 struct which implements the
	// HashFunction interface
	HashFunctionMimc7 HashMiMC7
)

// Once Generics are at Go, this will be updated (August 2021
// https://blog.golang.org/generics-next-step)

// HashFunction defines the interface that is expected for a hash function to be
// used in a generic way in the Tree.
type HashFunction interface {
	Type() []byte
	Len() int
	Hash(...[]byte) ([]byte, error)
	SafeValue([]byte) []byte
	SafeBigInt(*big.Int) []byte
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

func (f HashSha256) SafeValue(b []byte) []byte {
	return b
}

func (f HashSha256) SafeBigInt(b *big.Int) []byte {
	return b.Bytes()
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

func (f HashPoseidon) SafeValue(b []byte) []byte {
	return f.SafeBigInt(new(big.Int).SetBytes(b))
}

func (f HashPoseidon) SafeBigInt(b *big.Int) []byte {
	return BigToFF(BN254BaseField, b).Bytes()
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

func (f HashMultiPoseidon) SafeValue(b []byte) []byte {
	return f.SafeBigInt(new(big.Int).SetBytes(b))
}

func (f HashMultiPoseidon) SafeBigInt(b *big.Int) []byte {
	return BigToFF(BN254BaseField, b).Bytes()
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

func (f HashBlake2b) SafeValue(b []byte) []byte {
	return b
}

func (f HashBlake2b) SafeBigInt(b *big.Int) []byte {
	return b.Bytes()
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
func (f HashMiMC_BLS12_377) Hash(b ...[]byte) ([]byte, error) {
	h := mimc_bls12_377.NewMiMC()
	q := fr_bls12377.Modulus()
	return hashMiMCbyChunks(h, q, b...)
}

func (f HashMiMC_BLS12_377) SafeValue(b []byte) []byte {
	return f.SafeBigInt(new(big.Int).SetBytes(b))
}

func (f HashMiMC_BLS12_377) SafeBigInt(b *big.Int) []byte {
	return BigToFF(BLS12377BaseField, b).Bytes()
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
func (f HashMiMC_BN254) Hash(b ...[]byte) ([]byte, error) {
	// q := fr_bn254.Modulus()
	// h := mimc_bn254.NewMiMC()
	// return hashMiMCbyChunks(h, q, b...)
	h := mimc_bn254.NewMiMC()
	var fullBytes []byte
	for _, input := range b {
		fullBytes = append(fullBytes, input...)
	}
	for start := 0; start < len(fullBytes); start += h.BlockSize() {
		end := min(start+h.BlockSize(), len(fullBytes))
		chunk := fullBytes[start:end]
		h.Write(chunk)
	}
	return h.Sum(nil), nil
}

func (f HashMiMC_BN254) SafeValue(b []byte) []byte {
	return f.SafeBigInt(new(big.Int).SetBytes(b))
}

func (f HashMiMC_BN254) SafeBigInt(b *big.Int) []byte {
	return BigToFF(BN254BaseField, b).Bytes()
}

// hashMiMCbyChunks is a helper function to hash by chunks using the MiMC hash.
// It applies the modulo operation to the chunks before hashing.
func hashMiMCbyChunks(h hash.StateStorer, q *big.Int, b ...[]byte) ([]byte, error) {
	for _, input := range b {
		for start := 0; start < len(input); start += h.BlockSize() {
			end := start + h.BlockSize()
			if end > len(input) {
				end = len(input)
			}
			chunk := input[start:end]

			// Convert chunk to big.Int (big-endian)
			// The chunk might be less than h.BlockSize(), so zero-pad if needed.
			buf := make([]byte, h.BlockSize())
			copy(buf, chunk)

			// Endianness: Swap to big-endian if necessary.
			// Currently, 'buf' is big-endian since we just copied directly.
			// If your input is little-endian, you'd need to SwapEndianness here.
			// But the original code calls SwapEndianness(input[start:end]),
			// so let's maintain that logic.
			// We'll handle the modulo after swapping endianness since mimc expects big-endian.
			buf = SwapEndianness(buf)

			x := new(big.Int).SetBytes(buf) // big-endian to big.Int
			x.Mod(x, q)                     // modulo q

			// Convert back to big-endian 32-byte array
			modBuf := x.Bytes()
			if len(modBuf) < h.BlockSize() {
				pad := make([]byte, h.BlockSize()-len(modBuf))
				modBuf = append(pad, modBuf...) // left-pad to get h.BlockSize() length
			}

			// Ensure big-endian format for Write:
			// The MiMC expects big-endian. After modulo we have big-endian in modBuf.
			// We do not need to SwapEndianness again since we've produced big-endian already.

			if _, err := h.Write(modBuf); err != nil {
				return nil, err
			}
		}
	}
	return SwapEndianness(h.Sum(nil)), nil
}

type HashMiMC7 struct{}

func (f HashMiMC7) Type() []byte {
	return TypeHashMimc7
}

func (f HashMiMC7) Len() int {
	return 32 //nolint:gomnd
}

func (f HashMiMC7) Hash(b ...[]byte) ([]byte, error) {
	var toHash []*big.Int
	for _, i := range b {
		toHash = append(toHash, BytesToBigInt(i))
	}
	h, err := mimc7.Hash(toHash, nil)
	if err != nil {
		return nil, err
	}
	return BigIntToBytes(f.Len(), h), nil
}

func (f HashMiMC7) SafeValue(b []byte) []byte {
	return BigToFF(BN254BaseField, BytesToBigInt(b)).Bytes()
}

func (f HashMiMC7) SafeBigInt(b *big.Int) []byte {
	return f.SafeValue(b.Bytes())
}
