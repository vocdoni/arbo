package arbo

import (
	"math/big"

	"go.vocdoni.io/dvote/tree/arbo"
)

// GnarkVerifierProof is a struct that contains all the information needed to
// verify a proof in a gnark circuit. The attributes are all big.Int, so they
// can be used as frontend.Variable's in the gnark circuit. The endianess of
// root, siblings and value has been changed to Little-Endian to match the
// gnark arbo verifier.
type GnarkVerifierProof struct {
	Root     *big.Int
	Siblings []*big.Int
	OldKey   *big.Int
	IsOld0   *big.Int
	OldValue *big.Int
	Key      *big.Int
	Value    *big.Int
	Fnc      *big.Int
}

// GenerateGnarkVerifierProofLE builds a proof whose Root, Siblings and Value
// are **little-endian**, matching the arbo Poseidon-2 circuit.
func (t *Tree) GenerateGnarkVerifierProofLE(keyBE []byte) (*GnarkVerifierProof, error) {
	return t.genVerifierProof(keyBE, arbo.BytesLEToBigInt)
}

// GenerateGnarkVerifierProofBE builds an equivalent proof but keeps the
// canonical **big-endian** encoding (handy for off-chain checks & logs).
func (t *Tree) GenerateGnarkVerifierProofBE(keyBE []byte) (*GnarkVerifierProof, error) {
	return t.genVerifierProof(keyBE, BytesToBigInt)
}

// genVerifierProof contains the full algorithm; the only difference between
// LE / BE variants is the `conv` function used to turn each byte slice into a
// *big.Int*.  No other logic diverges.
func (t *Tree) genVerifierProof(
	keyBE []byte,
	conv func([]byte) *big.Int, // endian-aware byte-slice → big.Int
) (*GnarkVerifierProof, error) {

	// 1. build the sparse-Merkle proof through arbo
	oldKey, value, sibPacked, exists, err := t.GenProof(keyBE)
	if err != nil && err != ErrKeyNotFound {
		return nil, err
	}

	// 2. current tree root
	rootBE, err := t.Root()
	if err != nil {
		return nil, err
	}

	// 3. unpack and convert each sibling
	unpacked, err := UnpackSiblings(t.hashFunction, sibPacked)
	if err != nil {
		return nil, err
	}
	siblings := make([]*big.Int, len(unpacked))
	for i := range unpacked {
		siblings[i] = conv(unpacked[i])
	}

	// 4. assemble the witness
	proof := &GnarkVerifierProof{
		Root:     conv(rootBE),
		Key:      conv(keyBE),
		Value:    conv(value),
		Siblings: siblings,

		// default for inclusion
		OldKey:   big.NewInt(0),
		OldValue: big.NewInt(0),
		IsOld0:   big.NewInt(0),
		Fnc:      big.NewInt(0),
	}

	// 5. adjust flags for exclusion proofs
	if !exists {
		proof.OldKey = conv(oldKey)
		proof.OldValue = conv(value)
		proof.Fnc = big.NewInt(1) // exclusion
	}
	if len(oldKey) == 0 {
		proof.IsOld0 = big.NewInt(1)
	}
	return proof, nil
}
