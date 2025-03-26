package arbo

import (
	"bytes"
	"fmt"
	"log"
	"math/big"
	"runtime"
	"slices"
	"sync"

	"go.vocdoni.io/dvote/db"
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
		bks[i], bvs[i], fbvs[i], err = bigIntLeaf(t.HashFunction(), t.maxKeyLen(), ki, v[i])
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

//nolint:unused
func (t *Tree) addBatchBigIntByCPU(bks, fbvs [][]byte) ([]Invalid, error) {
	// lock the tree to prevent concurrent writes to the valuesdb
	t.Lock()
	defer t.Unlock()
	// split keys and full values in groups to add them in parallel by CPU
	nCPU := flp2(runtime.NumCPU())
	groupsOfKeys := splitInGroups(bks, nCPU)
	groupOfFullValues := splitInGroups(fbvs, nCPU)
	// create a transaction for each group of keys and full values and store
	// the errors in a slice to return them
	var fullInvalids []Invalid
	wTx := t.valuesdb.WriteTx()
	// if there is only one CPU or the number of groups is less than the number
	// of CPUs, add the full values in the same goroutine and commit the
	// transaction
	if nCPU == 1 || len(groupsOfKeys) < nCPU {
		for i, bk := range bks {
			if err := wTx.Set(bk, fbvs[i]); err != nil {
				fullInvalids = append(fullInvalids, Invalid{i, err})
			}
		}
		return fullInvalids, wTx.Commit()
	}
	// add the full values in parallel
	var wg sync.WaitGroup
	wg.Add(nCPU)
	txs := make([]db.WriteTx, nCPU)
	for i := range nCPU {
		// create a transaction for each CPU
		txs[i] = t.valuesdb.WriteTx()
		if err := txs[i].Apply(wTx); err != nil {
			log.Println(err)
			return fullInvalids, err
		}
		// add each group of full values in a goroutine
		go func(cpu int) {
			for j := range len(groupsOfKeys[cpu]) {
				if err := txs[cpu].Set(groupsOfKeys[cpu][j], groupOfFullValues[cpu][j]); err != nil {
					idx := (cpu + 1) * j
					fullInvalids = append(fullInvalids, Invalid{idx, err})
				}
			}
			wg.Done()
		}(i)
	}
	// wait for all the goroutines to finish and apply the transactions
	wg.Wait()
	for i := range nCPU {
		if err := wTx.Apply(txs[i]); err != nil {
			return fullInvalids, err
		}
		txs[i].Discard()
	}
	return fullInvalids, nil
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
	bk, bv, fbv, err := bigIntLeaf(t.HashFunction(), t.maxKeyLen(), k, v)
	if err != nil {
		return err
	}
	// add it to the tree
	if err := t.Add(bk, bv); err != nil {
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

// UpdateBigInt updates the value of a key as a big.Int and the values of the
// leaf node as a slice of big.Ints. It encodes the key as bytes and updates
// the leaf node in the tree, then it stores the full value in the valuesdb. It
// returns an error if something fails.
func (t *Tree) UpdateBigInt(k *big.Int, value ...*big.Int) error {
	if k == nil {
		return fmt.Errorf("key cannot be nil")
	}
	// convert the big ints to bytes
	bk, bv, fbv, err := bigIntLeaf(t.HashFunction(), t.maxKeyLen(), k, value)
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
	bk, bv, err := t.Get(bigIntToKey(t.maxKeyLen(), k))
	if err != nil {
		return nil, nil, err
	}
	return t.leafToBigInts(bk, bv)
}

func (t *Tree) GenProofBigInts(k *big.Int) ([]byte, []byte, []byte, bool, error) {
	if k == nil {
		return nil, nil, nil, false, fmt.Errorf("key cannot be nil")
	}
	return t.GenProof(bigIntToKey(t.maxKeyLen(), k))
}

func (t *Tree) GenerateCircomVerifierProofBigInt(k *big.Int) (*CircomVerifierProof, error) {
	if k == nil {
		return nil, fmt.Errorf("key cannot be nil")
	}
	return t.GenerateCircomVerifierProof(bigIntToKey(t.maxKeyLen(), k))
}

// maxKeyLen returns the maximum length of the key in bytes for a tree
func (t *Tree) maxKeyLen() int {
	return keyLenByLevels(t.maxLevels)
}

// leafToBigInts converts the bytes of the key and the value of a leaf node
// into a big.Int key and a slice of big.Int values, it gets the full value
// from the valuesdb and checks if it matches the value of the leaf node. It
// returns the original key and values or an error if the values don't match.
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
	iter := slices.Clone(bFullValue)
	for len(iter) > 0 {
		lenV := int(iter[0])
		values = append(values, new(big.Int).SetBytes(iter[1:1+lenV]))
		iter = iter[1+lenV:]
	}
	return BytesToBigInt(key), values, nil
}

// BigIntToBytes converts a big.Int into a byte slice of length keyLen
func bigIntToKey(keyLen int, b *big.Int) []byte {
	return BigIntToBytes(keyLen, b)
}

// bigIntLeaf converts a big.Int key and a slice of big.Int values into the
// bytes of the key, the bytes of the value used to build the tree and the
// bytes of the full value encoded
func bigIntLeaf(hFn HashFunction, keyLen int, key *big.Int, values []*big.Int) ([]byte, []byte, []byte, error) {
	if key == nil {
		return nil, nil, nil, fmt.Errorf("key cannot be nil")
	}
	// calculate the bytes of the key
	bKey := bigIntToKey(keyLen, key)
	// calculate the bytes of the full values (should be reversible)
	bFullValue := []byte{}
	for _, v := range values {
		if v == nil {
			return nil, nil, nil, fmt.Errorf("value cannot be nil")
		}
		vBytes := v.Bytes()
		if len(vBytes) > 255 {
			return nil, nil, nil, fmt.Errorf("value byte length cannot exceed 255")
		}
		val := append([]byte{byte(len(vBytes))}, vBytes...)
		bFullValue = append(bFullValue, val...)
	}
	// calculate the value used to build the tree
	bValue, err := bigIntToLeafValue(hFn, bFullValue)
	if err != nil {
		return nil, nil, nil, err
	}
	return bKey, bValue, bFullValue, nil
}

// bigIntToLeafValue hashes the full value of a leaf node by splitting it in
// chunks of the size of the hash function output and hashing them
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

// splitInGroups splits the items in nGroups groups
//
//nolint:unused
func splitInGroups[T any](items []T, nGroups int) [][]T {
	groups := make([][]T, nGroups)
	for i, item := range items {
		groups[i%nGroups] = append(groups[i%nGroups], item)
	}
	return groups
}
