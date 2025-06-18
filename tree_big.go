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
func (t *Tree) AddBatchBigInt(keys []*big.Int, bigintsBatch [][]*big.Int) ([]Invalid, error) {
	if len(keys) != len(bigintsBatch) {
		return nil, fmt.Errorf("the number of keys and values missmatch")
	}
	// convert each key-value tuple into bytes
	var err error
	bKeys := make([][]byte, len(keys))
	bValues := make([][]byte, len(keys))
	serializedBigIntsBatch := make([][]byte, len(keys))
	for i := range keys {
		bKeys[i], bValues[i], serializedBigIntsBatch[i], err = bigIntsToLeaf(t.HashFunction(), t.MaxKeyLen(), keys[i], bigintsBatch[i])
		if err != nil {
			return nil, err
		}
	}
	// acquire lock to make an atomic update to treedb and valuesdb
	t.valuesdbMu.Lock()
	defer t.valuesdbMu.Unlock()
	// add the keys and leaf values in batch
	if invalids, err := t.AddBatch(bKeys, bValues); err != nil {
		return invalids, err
	}
	// create a transaction for each group of keys and serialized values and store
	// the errors in a slice to return them
	var invalids []Invalid
	wTx := t.valuesdb.WriteTx()
	defer wTx.Discard()
	for i := range bKeys {
		if err := wTx.Set(bValues[i], serializedBigIntsBatch[i]); err != nil {
			invalids = append(invalids, Invalid{i, err})
		}
	}
	return invalids, wTx.Commit()
}

// AddBigInt adds a key-value pair to the tree, it converts the big.Int key
// and the slice of big.Int values into bytes and adds them to the tree. It
// locks the tree to prevent concurrent writes to the valuesdb and creates a
// transaction to store the serialized bigints in the valuesdb. It returns an error if
// something fails.
func (t *Tree) AddBigInt(key *big.Int, bigints ...*big.Int) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}
	// convert the big ints to bytes
	bKey, bValue, serializedBigInts, err := bigIntsToLeaf(t.HashFunction(), t.MaxKeyLen(), key, bigints)
	if err != nil {
		return err
	}
	// acquire lock to make an atomic update to treedb and valuesdb
	t.valuesdbMu.Lock()
	defer t.valuesdbMu.Unlock()
	// add it to the tree
	if err := t.Add(bKey, bValue); err != nil {
		return fmt.Errorf("raw key cannot be added: %w", err)
	}
	// create a transaction to store the serialized bigints
	wTx := t.valuesdb.WriteTx()
	defer wTx.Discard()
	// store the serialized bigints in the valuesdb
	if err := wTx.Set(bValue, serializedBigInts); err != nil {
		return fmt.Errorf("serializedBigInts cannot be stored: %w", err)
	}
	return wTx.Commit()
}

// UpdateBigInt updates the value of a key as a big.Int and the values of the
// leaf node as a slice of big.Ints. It encodes the key as bytes and updates
// the leaf node in the tree, then it stores the full value in the valuesdb. It
// returns an error if something fails.
func (t *Tree) UpdateBigInt(key *big.Int, bigints ...*big.Int) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}
	// convert the big ints to bytes
	bKey, bValue, serializedBigInts, err := bigIntsToLeaf(t.HashFunction(), t.MaxKeyLen(), key, bigints)
	if err != nil {
		return err
	}
	// acquire lock to make an atomic update to treedb and valuesdb
	t.valuesdbMu.Lock()
	defer t.valuesdbMu.Unlock()
	// update the leaf in the tree
	if err := t.Update(bKey, bValue); err != nil {
		return err
	}
	// create a transaction to store the serialized bigints
	wTx := t.valuesdb.WriteTx()
	defer wTx.Discard()
	// store the serialized bigints value in the valuesdb
	if err := wTx.Set(bValue, serializedBigInts); err != nil {
		return err
	}
	return wTx.Commit()
}

// GetBigInt receives the value of a key as a big.Int and the values of the leaf
// node as a slice of big.Ints. It encodes the key as bytes and gets the leaf
// node from the tree, then it decodes the serialized bigints of the leaf node and
// returns the key and the values or an error if something fails.
func (t *Tree) GetBigInt(k *big.Int) (
	key *big.Int, bigints []*big.Int, err error,
) {
	// acquire lock to wait for atomic updates to treedb and valuesdb to finish
	t.valuesdbMu.RLock()
	defer t.valuesdbMu.RUnlock()
	if k == nil {
		return nil, nil, fmt.Errorf("key cannot be nil")
	}
	bk := bigIntToLeafKey(k, t.MaxKeyLen())
	_, bv, err := t.Get(bk)
	if err != nil {
		return nil, nil, err
	}
	serializedBigInts, err := t.valuesdb.Get(bv)
	if err != nil {
		return nil, nil, err
	}
	return t.leafToBigInts(ExplicitZero(bk), bv, serializedBigInts)
}

// GenProofBigInts generates a proof for a key as a big.Int. It converts the
// big.Int key into bytes and generates a proof for the key, then it returns
// the key, the value of the leaf node, the siblings and a boolean indicating
// if the key exists or an error if something fails.
func (t *Tree) GenProofBigInts(key *big.Int) (
	leafKey []byte, leafValue []byte, siblings []byte, existence bool, err error,
) {
	if key == nil {
		return nil, nil, nil, false, fmt.Errorf("key cannot be nil")
	}
	bk := bigIntToLeafKey(key, t.MaxKeyLen())
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
// into a big.Int key and a slice of big.Int values, it gets the serialized bigints
// from the valuesdb and checks if it matches the value of the leaf node. It
// returns the original key and values or an error if the values don't match.
func (t *Tree) leafToBigInts(bkey, value, serializedBigInts []byte) (
	key *big.Int, bigints []*big.Int, err error,
) {
	// reverse the process of bigints encoding
	bigints = deserializeBigInts(serializedBigInts)
	// reencode the leaf value of the tree to check if it matches the value
	bigintsHash, err := HashBigInts(t.HashFunction(), bigints...)
	if err != nil {
		return nil, nil, err
	}
	// check if the value of the leaf node matches the value used to build the
	// tree
	if !bytes.Equal(bigintsHash, value) {
		return nil, nil, fmt.Errorf("LeafToBigInt: bigintsHash != value")
	}
	// convert the bytes of the key to a big.Int
	return leafKeyToBigInt(bkey), bigints, nil
}

// leafKeyToBigInt converts the bytes of a key into a big.Int.
// It assumes the key is encoded in Little-Endian format.
func leafKeyToBigInt(key []byte) *big.Int {
	return BytesToBigInt(key)
}

// bigIntToLeafKey converts a big.Int key into the bytes of the key. It
// encodes the key in Little-Endian format and pads it to the maximum length
// of the key. It returns the bytes of the key.
func bigIntToLeafKey(key *big.Int, maxLen int) []byte {
	return BigIntToBytes(maxLen, key)
}

// serializeBigInts converts a slice of big.Int values into the bytes of the
// encoded in a reversible way. It concatenates the bytes of the
// values with the length of each value at the beginning of each value.
func serializeBigInts(bigints []*big.Int) ([]byte, error) {
	serializedBigInts := []byte{}
	for _, bi := range bigints {
		if bi == nil {
			return nil, fmt.Errorf("value cannot be nil")
		}
		biBytes := bi.Bytes()
		if len(biBytes) > 255 {
			return nil, fmt.Errorf("value byte length cannot exceed 255")
		}
		val := append([]byte{byte(len(biBytes))}, biBytes...)
		serializedBigInts = append(serializedBigInts, val...)
	}
	return serializedBigInts, nil
}

// deserializeBigInts deserializes bigints encoded in bytes into a slice
// of big.Int values. It iterates over the bytes and extracts
// the length of each value and the bytes of the value to build the big.Int
// values.
func deserializeBigInts(serializedBigInts []byte) []*big.Int {
	bigints := []*big.Int{}
	iter := slices.Clone(serializedBigInts)
	for len(iter) > 0 {
		lenV := int(iter[0])
		bigints = append(bigints, new(big.Int).SetBytes(iter[1:1+lenV]))
		iter = iter[1+lenV:]
	}
	return bigints
}

// bigIntsToLeaf converts a big.Int key and a slice of big.Int values into
// the bytes of the key, the bytes of the value used to build the tree and the
// bytes of the full value encoded
func bigIntsToLeaf(hFn HashFunction, keyLen int, key *big.Int, bigints []*big.Int) (
	bKey []byte, bValue []byte, serializedBigInts []byte, err error,
) {
	if key == nil {
		return nil, nil, nil, fmt.Errorf("key cannot be nil")
	}
	// calculate the bytes of the key
	bKey = bigIntToLeafKey(key, keyLen)
	// calculate the bytes of the full values (should be reversible)
	serializedBigInts, err = serializeBigInts(bigints)
	if err != nil {
		return nil, nil, nil, err
	}
	// calculate the value used to build the tree
	bValue, err = HashBigInts(hFn, bigints...)
	if err != nil {
		return nil, nil, nil, err
	}
	return bKey, bValue, serializedBigInts, nil
}

// HashBigInts hashes the bytes of the big.Int values
// using the hash function of the tree. The resulting hash can be used as the leaf value
func HashBigInts(hFn HashFunction, values ...*big.Int) ([]byte, error) {
	chunks := make([][]byte, len(values))
	for i, v := range values {
		value := hFn.SafeBigInt(v)
		if value == nil {
			return nil, fmt.Errorf("value cannot be nil")
		}
		chunks[i] = value
	}
	return hFn.Hash(chunks...)
}
