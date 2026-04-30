package arbo

import (
	"bytes"
	"fmt"
	"math/big"
	"slices"

	"github.com/vocdoni/davinci-node/db"
	"github.com/vocdoni/davinci-node/db/prefixeddb"
)

// AddBatchBigInt adds a batch of key-value pairs to the tree, it converts the
// big.Int keys and the slices of big.Int values into bytes and adds them to
// the tree. It locks the tree to prevent concurrent writes to the valuesdb and
// stores the full values in the same transaction as the tree. It returns a
// slice of Invalid items and an error if something fails.
func (t *Tree) AddBatchBigInt(keys []*big.Int, bigintsBatch [][]*big.Int) ([]Invalid, error) {
	wTx := t.treedb.WriteTx()
	defer wTx.Discard()

	invalids, err := t.AddBatchBigIntWithTx(wTx, keys, bigintsBatch)
	if err != nil {
		return invalids, err
	}

	return invalids, wTx.Commit()
}

// AddBatchBigIntWithTx does the same than AddBatchBigInt, but allowing to pass
// the db.WriteTx that is used for the tree. The db.WriteTx will not be
// committed inside this method.
func (t *Tree) AddBatchBigIntWithTx(wTx db.WriteTx, keys []*big.Int, bigintsBatch [][]*big.Int) ([]Invalid, error) {
	if len(keys) != len(bigintsBatch) {
		return nil, fmt.Errorf("the number of keys and values missmatch")
	}
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
	t.valuesdbMu.Lock()
	defer t.valuesdbMu.Unlock()
	invalids, err := t.AddBatchWithTx(wTx, bKeys, bValues)
	if err != nil {
		return invalids, err
	}
	var valueInvalids []Invalid
	var valueErr error
	invalidIndexes := make(map[int]struct{}, len(invalids))
	for _, invalid := range invalids {
		invalidIndexes[invalid.Index] = struct{}{}
	}
	vTx := valuesWriteTx(wTx)
	for i := range bKeys {
		if _, invalid := invalidIndexes[i]; invalid {
			continue
		}
		if err := vTx.Set(bValues[i], serializedBigIntsBatch[i]); err != nil {
			valueInvalids = append(valueInvalids, Invalid{i, err})
			if valueErr == nil {
				valueErr = err
			}
		}
	}
	if valueErr != nil {
		return append(invalids, valueInvalids...), fmt.Errorf("serializedBigInts cannot be stored: %w", valueErr)
	}
	return append(invalids, valueInvalids...), nil
}

// AddBigInt adds a key-value pair to the tree, it converts the big.Int key
// and the slice of big.Int values into bytes and adds them to the tree. It
// locks the tree to prevent concurrent writes to the valuesdb and stores the
// serialized bigints in the same transaction as the tree. It returns an error
// if something fails.
func (t *Tree) AddBigInt(key *big.Int, bigints ...*big.Int) error {
	wTx := t.treedb.WriteTx()
	defer wTx.Discard()

	if err := t.AddBigIntWithTx(wTx, key, bigints...); err != nil {
		return err
	}

	return wTx.Commit()
}

// AddBigIntWithTx does the same than AddBigInt, but allowing to pass the
// db.WriteTx that is used for the tree. The db.WriteTx will not be committed
// inside this method.
func (t *Tree) AddBigIntWithTx(wTx db.WriteTx, key *big.Int, bigints ...*big.Int) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}
	bKey, bValue, serializedBigInts, err := bigIntsToLeaf(t.HashFunction(), t.MaxKeyLen(), key, bigints)
	if err != nil {
		return err
	}
	t.valuesdbMu.Lock()
	defer t.valuesdbMu.Unlock()
	if err := t.AddWithTx(wTx, bKey, bValue); err != nil {
		return fmt.Errorf("raw key cannot be added: %w", err)
	}
	vTx := valuesWriteTx(wTx)
	if err := vTx.Set(bValue, serializedBigInts); err != nil {
		return fmt.Errorf("serializedBigInts cannot be stored: %w", err)
	}
	return nil
}

// UpdateBigInt updates the value of a key as a big.Int and the values of the
// leaf node as a slice of big.Ints. It encodes the key as bytes and updates
// the leaf node in the tree, then it stores the full value in the valuesdb. It
// returns an error if something fails.
func (t *Tree) UpdateBigInt(key *big.Int, bigints ...*big.Int) error {
	wTx := t.treedb.WriteTx()
	defer wTx.Discard()

	if err := t.UpdateBigIntWithTx(wTx, key, bigints...); err != nil {
		return err
	}

	return wTx.Commit()
}

// UpdateBigIntWithTx does the same than UpdateBigInt, but allowing to pass the
// db.WriteTx that is used for the tree. The db.WriteTx will not be committed
// inside this method.
func (t *Tree) UpdateBigIntWithTx(wTx db.WriteTx, key *big.Int, bigints ...*big.Int) error {
	if key == nil {
		return fmt.Errorf("key cannot be nil")
	}
	bKey, bValue, serializedBigInts, err := bigIntsToLeaf(t.HashFunction(), t.MaxKeyLen(), key, bigints)
	if err != nil {
		return err
	}
	t.valuesdbMu.Lock()
	defer t.valuesdbMu.Unlock()
	if err := t.UpdateWithTx(wTx, bKey, bValue); err != nil {
		return err
	}
	vTx := valuesWriteTx(wTx)
	if err := vTx.Set(bValue, serializedBigInts); err != nil {
		return err
	}
	return nil
}

// GetBigInt receives the value of a key as a big.Int and the values of the leaf
// node as a slice of big.Ints. It encodes the key as bytes and gets the leaf
// node from the tree, then it decodes the serialized bigints of the leaf node and
// returns the key and the values or an error if something fails.
func (t *Tree) GetBigInt(k *big.Int) (
	key *big.Int, bigints []*big.Int, err error,
) {
	return t.GetBigIntWithTx(t.treedb, k)
}

// GetBigIntWithTx receives the value of a key as a big.Int and the values of
// the leaf node as a slice of big.Ints. It encodes the key as bytes and gets
// the leaf node from the tree using the given db.Reader, then it decodes the
// serialized bigints of the leaf node and returns the key and the values or an
// error if something fails.
func (t *Tree) GetBigIntWithTx(rTx db.Reader, k *big.Int) (
	key *big.Int, bigints []*big.Int, err error,
) {
	t.valuesdbMu.RLock()
	defer t.valuesdbMu.RUnlock()
	if k == nil {
		return nil, nil, fmt.Errorf("key cannot be nil")
	}
	bk := bigIntToLeafKey(k, t.MaxKeyLen())
	_, bv, err := t.GetWithTx(rTx, bk)
	if err != nil {
		return nil, nil, err
	}
	serializedBigInts, err := t.valuesReader(rTx).Get(bv)
	if err != nil {
		return nil, nil, err
	}
	return t.leafToBigInts(ExplicitZero(bk), bv, serializedBigInts)
}

type writeTxUnwrapper interface {
	Unwrap() db.WriteTx
}

type prefixedWriteTx interface {
	db.WriteTx
	Prefix() []byte
	Unwrap() db.WriteTx
}

func unwrapWriteTx(wTx db.WriteTx) db.WriteTx {
	for {
		unwrapped, ok := wTx.(writeTxUnwrapper)
		if !ok {
			return wTx
		}
		next := unwrapped.Unwrap()
		if next == nil || next == wTx {
			return wTx
		}
		wTx = next
	}
}

func valuesWriteTx(wTx db.WriteTx) db.WriteTx {
	if ptx, ok := wTx.(prefixedWriteTx); ok {
		prefix := ptx.Prefix()
		if bytes.HasSuffix(prefix, dbTreePrefix) {
			parentPrefix := prefix[:len(prefix)-len(dbTreePrefix)]
			valuePrefix := make([]byte, 0, len(parentPrefix)+len(dbValuesPrefix))
			valuePrefix = append(valuePrefix, parentPrefix...)
			valuePrefix = append(valuePrefix, dbValuesPrefix...)
			return prefixeddb.NewPrefixedWriteTx(ptx.Unwrap(), valuePrefix)
		}
	}
	return prefixeddb.NewPrefixedWriteTx(unwrapWriteTx(wTx), dbValuesPrefix)
}

func (t *Tree) valuesReader(rTx db.Reader) db.Reader {
	wTx, ok := rTx.(db.WriteTx)
	if !ok {
		return t.valuesdb
	}
	return valuesWriteTx(wTx)
}

// GenProofBigInts generates a proof for a key as a big.Int. It converts the
// big.Int key into bytes and generates a proof for the key, then it returns
// the key, the value of the leaf node, the siblings and a boolean indicating
// if the key exists or an error if something fails.
func (t *Tree) GenProofBigInts(key *big.Int) (
	leafKey []byte, leafValue []byte, siblings []byte, existence bool, err error,
) {
	return t.GenProofBigIntsWithTx(t.treedb, key)
}

// GenProofBigIntsWithTx generates a proof for a key as a big.Int using the
// given db.Reader.
func (t *Tree) GenProofBigIntsWithTx(rTx db.Reader, key *big.Int) (
	leafKey []byte, leafValue []byte, siblings []byte, existence bool, err error,
) {
	if key == nil {
		return nil, nil, nil, false, fmt.Errorf("key cannot be nil")
	}
	bk := bigIntToLeafKey(key, t.MaxKeyLen())
	return t.GenProofWithTx(rTx, bk)
}

// GenerateCircomVerifierProofBigInt generates a CircomVerifierProof for a key
// as a big.Int. It converts the big.Int key into bytes and generates a proof
// for the key, then it returns the CircomVerifierProof or an error if
// something fails.
func (t *Tree) GenerateCircomVerifierProofBigInt(k *big.Int) (*CircomVerifierProof, error) {
	return t.GenerateCircomVerifierProofBigIntWithTx(t.treedb, k)
}

// GenerateCircomVerifierProofBigIntWithTx generates a CircomVerifierProof for
// a key as a big.Int using the given db.Reader.
func (t *Tree) GenerateCircomVerifierProofBigIntWithTx(rTx db.Reader, k *big.Int) (*CircomVerifierProof, error) {
	if k == nil {
		return nil, fmt.Errorf("key cannot be nil")
	}
	kAux, v, siblings, existence, err := t.GenProofBigIntsWithTx(rTx, k)
	if err != nil && err != ErrKeyNotFound {
		return nil, err
	}
	var cp CircomVerifierProof
	cp.Root, err = t.RootWithTx(rTx)
	if err != nil {
		return nil, err
	}
	s, err := UnpackSiblings(t.hashFunction, siblings)
	if err != nil {
		return nil, err
	}
	cp.Siblings = t.FillMissingEmptySiblings(s)
	if !existence {
		cp.OldKey = kAux
		cp.OldValue = v
	} else {
		cp.OldKey = emptyValue
		cp.OldValue = emptyValue
	}
	cp.Key = bigIntToLeafKey(k, t.MaxKeyLen())
	cp.Value = v
	if existence {
		cp.Fnc = 0
	} else {
		cp.Fnc = 1
	}

	return &cp, nil
}

// GenerateGnarkVerifierProofBigInt generates a GnarkVerifierProof for a key
// as a big.Int. It converts the big.Int key into bytes and generates a proof
// for the key, then it returns the GnarkVerifierProof or an error if
// something fails.
func (t *Tree) GenerateGnarkVerifierProofBigInt(k *big.Int) (*GnarkVerifierProof, error) {
	return t.GenerateGnarkVerifierProofBigIntWithTx(t.treedb, k)
}

// GenerateGnarkVerifierProofBigIntWithTx generates a GnarkVerifierProof for a
// key as a big.Int using the given db.Reader.
func (t *Tree) GenerateGnarkVerifierProofBigIntWithTx(rTx db.Reader, k *big.Int) (*GnarkVerifierProof, error) {
	if k == nil {
		return nil, fmt.Errorf("key cannot be nil")
	}
	oldKey, value, siblings, existence, err := t.GenProofBigIntsWithTx(rTx, k)
	if err != nil && err != ErrKeyNotFound {
		return nil, err
	}
	root, err := t.RootWithTx(rTx)
	if err != nil {
		return nil, err
	}
	unpackedSiblings, err := UnpackSiblings(t.hashFunction, siblings)
	if err != nil {
		return nil, err
	}
	bigSiblings := make([]*big.Int, len(unpackedSiblings))
	for i := range bigSiblings {
		bigSiblings[i] = BytesToBigInt(unpackedSiblings[i])
	}
	gp := GnarkVerifierProof{
		Root:     BytesToBigInt(root),
		Key:      BytesToBigInt(bigIntToLeafKey(k, t.MaxKeyLen())),
		Value:    BytesToBigInt(value),
		Siblings: bigSiblings,
		OldKey:   big.NewInt(0),
		OldValue: big.NewInt(0),
		IsOld0:   big.NewInt(0),
		Fnc:      big.NewInt(0),
	}
	if !existence {
		gp.OldKey = BytesToBigInt(oldKey)
		gp.OldValue = BytesToBigInt(value)
		gp.Fnc = big.NewInt(1)
	}
	if len(oldKey) == 0 {
		gp.IsOld0 = big.NewInt(1)
	}
	return &gp, nil
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
	var expectedLeafValue []byte
	if len(bigints) == 1 {
		expectedLeafValue = t.HashFunction().SafeBigInt(bigints[0])
		if expectedLeafValue == nil {
			return nil, nil, fmt.Errorf("value cannot be nil")
		}
	} else {
		expectedLeafValue, err = HashBigInts(t.HashFunction(), bigints...)
		if err != nil {
			return nil, nil, err
		}
	}
	// check if the value of the leaf node matches the value used to build the
	// tree
	if !bytes.Equal(expectedLeafValue, value) {
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
	if len(bigints) == 1 {
		bValue = hFn.SafeBigInt(bigints[0])
		if bValue == nil {
			return nil, nil, nil, fmt.Errorf("value cannot be nil")
		}
	} else {
		bValue, err = HashBigInts(hFn, bigints...)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	return bKey, bValue, serializedBigInts, nil
}

// HashBigInts hashes the bytes of the big.Int values
// using the hash function of the tree. The resulting hash can be used as the leaf value
func HashBigInts(hFn HashFunction, values ...*big.Int) ([]byte, error) {
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
