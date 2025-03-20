package arbo

import (
	"encoding/json"
	"math/big"
)

// CircomVerifierProof contains the needed data to check a Circom Verifier Proof
// inside a circom circuit.  CircomVerifierProof allow to verify through a
// zkSNARK proof the inclusion/exclusion of a leaf in a tree.
type CircomVerifierProof struct {
	Root     []byte   `json:"root"`
	Siblings [][]byte `json:"siblings"`
	OldKey   []byte   `json:"oldKey"`
	OldValue []byte   `json:"oldValue"`
	IsOld0   bool     `json:"isOld0"`
	Key      []byte   `json:"key"`
	Value    []byte   `json:"value"`
	Fnc      int      `json:"fnc"` // 0: inclusion, 1: non inclusion
}

// MarshalJSON implements the JSON marshaler
func (cvp CircomVerifierProof) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})

	m["root"] = BytesToBigInt(cvp.Root).String()
	m["siblings"] = siblingsToStringArray(cvp.Siblings)
	m["oldKey"] = BytesToBigInt(cvp.OldKey).String()
	m["oldValue"] = BytesToBigInt(cvp.OldValue).String()
	if cvp.IsOld0 {
		m["isOld0"] = "1"
	} else {
		m["isOld0"] = "0"
	}
	m["key"] = BytesToBigInt(cvp.Key).String()
	m["value"] = BytesToBigInt(cvp.Value).String()
	m["fnc"] = cvp.Fnc

	return json.Marshal(m)
}

func siblingsToStringArray(s [][]byte) []string {
	var r []string
	for i := 0; i < len(s); i++ {
		si := new(big.Int).SetBytes(s[i])
		r = append(r, si.String())
	}
	return r
}

// FillMissingEmptySiblings adds the empty values to the array of siblings for
// the Tree number of max levels
func (t *Tree) FillMissingEmptySiblings(s []*big.Int) [][]byte {
	res := [][]byte{}
	for i := 0; i < t.maxLevels; i++ {
		if i < len(s) {
			res = append(res, s[i].Bytes())
		} else {
			res = append(res, emptyValue)
		}
	}
	return res
}

// GenerateCircomVerifierProof generates a CircomVerifierProof for a given key
// in the Tree
func (t *Tree) GenerateCircomVerifierProof(k *big.Int) (*CircomVerifierProof, error) {
	kAux, v, siblings, existence, err := t.GenProof(k)
	if err != nil && err != ErrKeyNotFound {
		return nil, err
	}
	var cp CircomVerifierProof
	root, err := t.Root()
	if err != nil {
		return nil, err
	}
	cp.Root = root.Bytes()
	s, err := UnpackSiblings(t.hashFunction, siblings)
	if err != nil {
		return nil, err
	}
	cp.Siblings = t.FillMissingEmptySiblings(s)
	if !existence {
		cp.OldKey = kAux.Bytes()
		cp.OldValue, err = WriteLeafValue(kAux, v...)
		if err != nil {
			return nil, err
		}
	} else {
		cp.OldKey = emptyValue
		cp.OldValue = emptyValue
	}
	cp.Key = k.Bytes()
	cp.Value, err = WriteLeafValue(k, v...)
	if err != nil {
		return nil, err
	}
	if existence {
		cp.Fnc = 0 // inclusion
	} else {
		cp.Fnc = 1 // non inclusion
	}

	return &cp, nil
}
