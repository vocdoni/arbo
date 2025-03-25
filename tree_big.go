package arbo

import (
	"bytes"
	"fmt"
	"math/big"
	"slices"
)

func (t *Tree) AddBigInt(k *big.Int, v ...*big.Int) error {
	bk, bv, fbv, err := bigIntLeaf(t.HashFunction(), k, v)
	if err != nil {
		return err
	}

	if err := t.Add(bk, bv); err != nil {
		return err
	}

	wTx := t.valuesdb.WriteTx()
	defer wTx.Discard()

	if err := wTx.Set(bk, fbv); err != nil {
		return err
	}
	return wTx.Commit()
}

func (t *Tree) GetBigInt(k *big.Int) (*big.Int, []*big.Int, error) {
	bk, bv, err := t.Get(bigIntToKey(t.HashFunction(), k))
	if err != nil {
		return nil, nil, err
	}
	return t.leafToBigInts(bk, bv)
}

func (t *Tree) GenProofBigInts(k *big.Int) (*big.Int, []*big.Int, []byte, bool, error) {
	bk, bv, siblings, exists, err := t.GenProof(bigIntToKey(t.HashFunction(), k))
	if err != nil {
		return nil, nil, nil, false, err
	}
	k, v, err := t.leafToBigInts(bk, bv)
	if err != nil {
		return nil, nil, nil, false, err
	}
	return k, v, siblings, exists, nil
}

func CheckProofBigInts(hFn HashFunction, root, packedSiblings []byte, k *big.Int, v ...*big.Int) (bool, error) {
	bk, bv, _, err := bigIntLeaf(hFn, k, v)
	if err != nil {
		return false, err
	}
	return CheckProof(hFn, bk, bv, root, packedSiblings)
}

func bigIntToKey(hFn HashFunction, b *big.Int) []byte {
	return BigIntToBytes(hFn.Len(), b)
}

func bigIntLeaf(hFn HashFunction, key *big.Int, values []*big.Int) ([]byte, []byte, []byte, error) {
	// calculate the bytes of the key
	bKey := bigIntToKey(hFn, key)
	// calculate the bytes of the full values (should be reversible)
	bFullValue := []byte{}
	for _, v := range values {
		val := append([]byte{byte(len(v.Bytes()))}, v.Bytes()...)
		bFullValue = append(bFullValue, val...)
	}
	// calculate the value used to build the tree
	bValue, err := bigIntToLeafValue(hFn, bFullValue)
	if err != nil {
		return nil, nil, nil, err
	}
	return bKey, bValue, bFullValue, nil
}

func bigIntToLeafValue(hFn HashFunction, bFullValue []byte) ([]byte, error) {
	// split the full value in chunks of the size of the hash function output
	chunks := [][]byte{}
	chunk := []byte{}
	for i := range bFullValue {
		chunk = append(chunk, bFullValue[i])
		if len(chunk) == hFn.Len() {
			chunks = append(chunks, chunk)
			chunk = []byte{}
		}
	}
	// if there is a chunk left, add it to the chunks
	if len(chunk) > 0 {
		chunks = append(chunks, chunk)
	}
	// hash the chunks
	bValue, err := hFn.Hash(chunks...)
	if err != nil {
		return nil, err
	}
	return bValue, nil
}

func (t *Tree) leafToBigInts(key, value []byte) (*big.Int, []*big.Int, error) {
	bFullValue, err := t.valuesdb.Get(key)
	if err != nil {
		return nil, nil, err
	}
	// recalculate the value to check if it matches the stored value
	expectedFullValue, err := bigIntToLeafValue(t.HashFunction(), bFullValue)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(expectedFullValue, value) {
		return nil, nil, fmt.Errorf("LeafToBigInt: expectedFullValue != value")
	}
	// reverse the process of values encoding
	values := []*big.Int{}
	for iter := slices.Clone(bFullValue); len(iter) > 0; {
		lenV := int(bFullValue[0])
		values = append(values, new(big.Int).SetBytes(bFullValue[1:1+lenV]))
		iter = iter[1+lenV:]
	}
	return BytesToBigInt(key), values, nil
}
