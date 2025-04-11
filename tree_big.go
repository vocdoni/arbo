package arbo

import (
	"bytes"
	"fmt"
	"math/big"
	"slices"
)



// AddBatchBigInt adds a batch of key-value pairs to the tree, it converts the
// big.Int keys and the slices of big.Int values into bytes and adds them to
// the tree. It locks the tree to prevent concurrent writes to the valuesdb and
// creates a transaction to store the full values in the valuesdb. It returns
// a slice of Invalid items and an error if something fails.
func (t *Tree) AddBatchBigInt(k []*big.Int, v [][]*big.Int) ([]Invalid, error) {
	if len(k) != len(v) {
		return nil, fmt.Errorf("the number of keys and values missmatch")
	}
	// convert each key-value tuple into bytes
	var err error
	bks := make([][]byte, len(k))
	bvs := make([][]byte, len(k))
	fbvs := make([][]byte, len(k))
	for i, ki := range k {
		bks[i], bvs[i], fbvs[i], err = encodeBigIntData(t.HashFunction(), t.MaxKeyLen(), ki, v[i])
		if err != nil {
			return nil, err
		}
	}
	// add the keys and leaf values in batch
	if invalids, err := t.AddBatch(bks, bvs); err != nil {
		return invalids, err
	}
	// lock the tree to prevent concurrent writes to the valuesdb
	t.Lock()
	defer t.Unlock()
	// create a transaction for each group of keys and full values and store
	// the errors in a slice to return them
	var fullInvalids []Invalid
	wTx := t.valuesdb.WriteTx()
	defer wTx.Discard()
	for i := range bks {
		if err := wTx.Set(bks[i], fbvs[i]); err != nil {
			fullInvalids = append(fullInvalids, Invalid{i, err})
		}
	}
	return fullInvalids, wTx.Commit()
}

// AddBigInt adds a key-value pair to the tree, it converts the big.Int key
// and the slice of big.Int values into bytes and adds them to the tree. It
// locks the tree to prevent concurrent writes to the valuesdb and creates a
// transaction to store the full value in the valuesdb. It returns an error if
// something fails.
func (t *Tree) AddBigInt(k *big.Int, v ...*big.Int) error {
	if k == nil {
		return fmt.Errorf("key cannot be nil")
	}
	// convert the big ints to bytes
	bk, bv, fbv, err := encodeBigIntData(t.HashFunction(), t.MaxKeyLen(), k, v)
	if err != nil {
		return err
	}
	// add it to the tree
	if err := t.Add(bk, bv); err != nil {
		return fmt.Errorf("raw key cannot be added: %w", err)
	}
	// lock the tree to prevent concurrent writes to the valuesdb
	t.Lock()
	defer t.Unlock()
	// create a transaction to store the full value
	wTx := t.valuesdb.WriteTx()
	defer wTx.Discard()
	// store the full value in the valuesdb
	if err := wTx.Set(bk, fbv); err != nil {
		return fmt.Errorf("full value cannot be stored: %w", err)
	}
	return wTx.Commit()
}

// UpdateBigInt updates the value of a key as a big.Int and the values of the
// leaf node as a slice of big.Ints. It encodes the key as bytes and updates
// the leaf node in the tree, then it stores the full value in the valuesdb. It
// returns an error if something fails.
func (t *Tree) UpdateBigInt(k *big.Int, value ...*big.Int) error {
	if k == nil {
		return fmt.Errorf("key cannot be nil")
	}
	// convert the big ints to bytes
	bk, bv, fbv, err := encodeBigIntData(t.HashFunction(), t.MaxKeyLen(), k, value)
	if err != nil {
		return err
	}
	// update the leaf in the tree
	if err := t.Update(bk, bv); err != nil {
		return err
	}
	// lock the tree to prevent concurrent writes to the valuesdb
	t.Lock()
	defer t.Unlock()
	// create a transaction to store the full value
	wTx := t.valuesdb.WriteTx()
	defer wTx.Discard()
	// store the full value in the valuesdb
	if err := wTx.Set(bk, fbv); err != nil {
		return err
	}
	return wTx.Commit()
}

// GetBigInt gets the value of a key as a big.Int and the values of the leaf
// node as a slice of big.Ints. It encodes the key as bytes and gets the leaf
// node from the tree, then it decodes the full value of the leaf node and
// returns the key and the values or an error if something fails.
func (t *Tree) GetBigInt(k *big.Int) (*big.Int, []*big.Int, error) {
	if k == nil {
		return nil, nil, fmt.Errorf("key cannot be nil")
	}
	bk := bigIntToLeafKey(k, t.MaxKeyLen())
	_, bv, err := t.Get(bk)
	if err != nil {
		return nil, nil, err
	}
	bFullValue, err := t.valuesdb.Get(bk)
	if err != nil {
		return nil, nil, err
	}
	return t.leafToBigInts(ExplicitZero(bk), bv, bFullValue)
}

// GenProofBigInts generates a proof for a key as a big.Int. It converts the
// big.Int key into bytes and generates a proof for the key, then it returns
// the key, the value of the leaf node, the siblings and a boolean indicating
// if the key exists or an error if something fails.
func (t *Tree) GenProofBigInts(k *big.Int) ([]byte, []byte, []byte, bool, error) {
	if k == nil {
		return nil, nil, nil, false, fmt.Errorf("key cannot be nil")
	}

	bk := bigIntToLeafKey(k, t.MaxKeyLen())
	return t.GenProof(bk)
}

// GenerateCircomVerifierProofBigInt generates a CircomVerifierProof for a key
// as a big.Int. It converts the big.Int key into bytes and generates a proof
// for the key, then it returns the CircomVerifierProof or an error if
// something fails.
func (t *Tree) GenerateCircomVerifierProofBigInt(k *big.Int) (*CircomVerifierProof, error) {
	if k == nil {
		return nil, fmt.Errorf("key cannot be nil")
	}
	bk := bigIntToLeafKey(k, t.MaxKeyLen())
	return t.GenerateCircomVerifierProof(bk)
}

// GenerateGnarkVerifierProofBigInt generates a GnarkVerifierProof for a key
// as a big.Int. It converts the big.Int key into bytes and generates a proof
// for the key, then it returns the GnarkVerifierProof or an error if
// something fails.
func (t *Tree) GenerateGnarkVerifierProofBigInt(k *big.Int) (*GnarkVerifierProof, error) {
	if k == nil {
		return nil, fmt.Errorf("key cannot be nil")
	}
	bk := bigIntToLeafKey(k, t.MaxKeyLen())
	return t.GenerateGnarkVerifierProof(bk)
}

// leafToBigInts converts the bytes of the key and the value of a leaf node
// into a big.Int key and a slice of big.Int values, it gets the full value
// from the valuesdb and checks if it matches the value of the leaf node. It
// returns the original key and values or an error if the values don't match.
func (t *Tree) leafToBigInts(key, value, fullValue []byte) (*big.Int, []*big.Int, error) {
	// reverse the process of values encoding
	values := fullValueToValues(fullValue)
	// recalculate the value to check if it matches the stored value
	expectedFullValue, err := valuesToFullValue(values)
	if err != nil {
		return nil, nil, err
	}
	// check if the value of the leaf node matches the stored value
	if !bytes.Equal(expectedFullValue, fullValue) {
		return nil, nil, fmt.Errorf("LeafToBigInt: expectedFullValue != value")
	}
	// reencode the leaf value of the tree to check if it matches the value
	encodedValues, err := encodeBigIntValues(t.HashFunction(), values...)
	if err != nil {
		return nil, nil, err
	}
	// check if the value of the leaf node matches the value used to build the
	// tree
	if !bytes.Equal(encodedValues, value) {
		return nil, nil, fmt.Errorf("LeafToBigInt: encodedValues != value")
	}
	// convert the bytes of the key to a big.Int
	return leafKeyToBigInt(key), values, nil
}

// leafKeyToBigInt converts the bytes of a key into a big.Int. It returns the
// big.Int value of the key in Big-Endian format, assuming the key is encoded
// in Little-Endian format.
func leafKeyToBigInt(key []byte) *big.Int {
	return BytesToBigInt(key)
}

// bigIntToLeafKey converts a big.Int key into the bytes of the key. It
// encodes the key in Little-Endian format and pads it to the maximum length
// of the key. It returns the bytes of the key.
func bigIntToLeafKey(key *big.Int, maxLen int) []byte {
	return BigIntToBytes(maxLen, key)
}

// valuesToFullValue converts a slice of big.Int values into the bytes of the
// full value encoded in a reversible way. It concatenates the bytes of the
// values with the length of each value at the beginning of each value.
func valuesToFullValue(values []*big.Int) ([]byte, error) {
	// calculate the bytes of the full values (should be reversible)
	bFullValue := []byte{}
	for _, v := range values {
		if v == nil {
			return nil, fmt.Errorf("value cannot be nil")
		}
		vBytes := v.Bytes()
		if len(vBytes) > 255 {
			return nil, fmt.Errorf("value byte length cannot exceed 255")
		}
		val := append([]byte{byte(len(vBytes))}, vBytes...)
		bFullValue = append(bFullValue, val...)
	}
	return bFullValue, nil
}

// fullValueToValues converts the bytes of the full value encoded into a slice
// of big.Int values. It iterates over the bytes of the full value and extracts
// the length of each value and the bytes of the value to build the big.Int
// values.
func fullValueToValues(fullValue []byte) []*big.Int {
	values := []*big.Int{}
	iter := slices.Clone(fullValue)
	for len(iter) > 0 {
		lenV := int(iter[0])
		values = append(values, new(big.Int).SetBytes(iter[1:1+lenV]))
		iter = iter[1+lenV:]
	}
	return values
}

// encodeBigIntData converts a big.Int key and a slice of big.Int values into
// the bytes of the key, the bytes of the value used to build the tree and the
// bytes of the full value encoded
func encodeBigIntData(hFn HashFunction, keyLen int, key *big.Int, values []*big.Int) ([]byte, []byte, []byte, error) {
	if key == nil {
		return nil, nil, nil, fmt.Errorf("key cannot be nil")
	}
	// calculate the bytes of the key
	// bKey := hFn.SafeBigInt(key)
	bKey := bigIntToLeafKey(key, keyLen)
	// calculate the bytes of the full values (should be reversible)
	bFullValue, err := valuesToFullValue(values)
	if err != nil {
		return nil, nil, nil, err
	}
	// calculate the value used to build the tree
	bValue, err := encodeBigIntValues(hFn, values...)
	if err != nil {
		return nil, nil, nil, err
	}
	return bKey, bValue, bFullValue, nil
}

// encodeBigIntValues converts a slice of big.Int values into the bytes of the
// value used to build the tree. It hashes the bytes of the big.Int values
// using the hash function of the tree.
func encodeBigIntValues(hFn HashFunction, values ...*big.Int) ([]byte, error) {
	chunks := make([][]byte, len(values))
	for _, v := range values {
		value := hFn.SafeBigInt(v)
		if value == nil {
			return nil, fmt.Errorf("value cannot be nil")
		}
		chunks = append(chunks, value)
	}
	return hFn.Hash(chunks...)
}
