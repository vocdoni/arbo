package arbo

import "math/big"

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

// GenerateGnarkVerifierProof generates a GnarkVerifierProof for a given key
// in the Tree. Every attribute is a big.Int, so it can be used in the gnark
// circuit as frontend.Variable's. The endianess of root, siblings and value
// has been changed to Little-Endian to match the gnark arbo verifier.
func (t *Tree) GenerateGnarkVerifierProof(k []byte) (*GnarkVerifierProof, error) {
	// generate the arbo proof
	oldKey, value, siblings, existence, err := t.GenProof(k)
	if err != nil && err != ErrKeyNotFound {
		return nil, err
	}
	// get the root of the tree
	root, err := t.Root()
	if err != nil {
		return nil, err
	}
	// unpack the siblings
	unpackedSiblings, err := UnpackSiblings(t.hashFunction, siblings)
	if err != nil {
		return nil, err
	}
	// convert the siblings to big.Int swaping the endianess
	bigSiblings := make([]*big.Int, len(unpackedSiblings))
	for i := range bigSiblings {
		bigSiblings[i] = BytesToBigInt(unpackedSiblings[i])
	}
	// initialize the GnarkVerifierProof
	gp := GnarkVerifierProof{
		Root:     BytesToBigInt(root),
		Key:      BytesToBigInt(k),
		Value:    BytesToBigInt(value),
		Siblings: bigSiblings,
	}
	// if the arbo proof is for a non-existing key, set the old key and value
	// to the key and value of the proof
	if !existence {
		gp.OldKey = new(big.Int).SetBytes(oldKey)
		gp.OldValue = BytesToBigInt(value)
		gp.Fnc = big.NewInt(0)
	} else {
		// if the arbo proof is for an existing key, set the old key and value
		// to 0
		gp.Fnc = big.NewInt(1)
		gp.OldKey = big.NewInt(0)
		gp.OldValue = big.NewInt(0)
	}
	// set the IsOld0 attribute to 1 if the is no old key, 0 otherwise
	if len(oldKey) > 0 {
		gp.IsOld0 = big.NewInt(1)
	} else {
		gp.IsOld0 = big.NewInt(0)
	}
	return &gp, nil
}
