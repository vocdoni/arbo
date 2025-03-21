/*
Package arbo implements a Merkle Tree compatible with the circomlib
implementation of the MerkleTree, following the specification from
https://docs.iden3.io/publications/pdfs/Merkle-Tree.pdf and
https://eprint.iacr.org/2018/955.

Allows to define which hash function to use. So for example, when working with
zkSnarks the Poseidon hash function can be used, but when not, it can be used
the Blake2b hash function, which has much faster computation time.
*/
package arbo

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/big"
	"runtime"
	"sync"

	"go.vocdoni.io/dvote/db"
)

const (
	// PrefixValueLen defines the bytes-prefix length used for the Value
	// bytes representation stored in the db
	PrefixValueLen = 2

	// PrefixValueEmpty is used for the first byte of a Value to indicate
	// that is an Empty value
	PrefixValueEmpty = 0
	// PrefixValueLeaf is used for the first byte of a Value to indicate
	// that is a Leaf value
	PrefixValueLeaf = 1
	// PrefixValueIntermediate is used for the first byte of a Value to
	// indicate that is a Intermediate value
	PrefixValueIntermediate = 2

	// nChars is used to crop the Graphviz nodes labels
	nChars = 4

	// maxUint8 is the max size of key length
	maxUint8 = int(^uint8(0)) // 2**8 -1
	// maxUint16 is the max size of value length
	maxUint16 = int(^uint16(0)) // 2**16 -1
)

var (
	// DefaultThresholdNLeafs defines the threshold number of leafs in the
	// tree that determines if AddBatch will work in memory or in disk.  It
	// is defined when calling NewTree, and if set to 0 it will work always
	// in disk.
	DefaultThresholdNLeafs = 65536

	dbKeyRoot   = []byte("root")
	dbKeyNLeafs = []byte("nleafs")
	emptyValue  = []byte{0}
	zero        = big.NewInt(0)

	// ErrKeyNotFound is used when a key is not found in the db neither in
	// the current db Batch.
	ErrKeyNotFound = fmt.Errorf("key not found")
	// ErrKeyAlreadyExists is used when trying to add a key as leaf to the
	// tree that already exists.
	ErrKeyAlreadyExists = fmt.Errorf("key already exists")
	// ErrInvalidValuePrefix is used when going down into the tree, a value
	// is read from the db and has an unrecognized prefix.
	ErrInvalidValuePrefix = fmt.Errorf("invalid value prefix")
	// ErrDBNoTx is used when trying to use Tree.dbPut but Tree.dbBatch==nil
	ErrDBNoTx = fmt.Errorf("dbPut error: no db Batch")
	// ErrMaxLevel indicates when going down into the tree, the max level is
	// reached
	ErrMaxLevel = fmt.Errorf("max level reached")
	// ErrMaxVirtualLevel indicates when going down into the tree, the max
	// virtual level is reached
	ErrMaxVirtualLevel = fmt.Errorf("max virtual level reached")
	// ErrSnapshotNotEditable indicates when the tree is a non writable
	// snapshot, thus can not be modified
	ErrSnapshotNotEditable = fmt.Errorf("snapshot tree can not be edited")
	// ErrTreeNotEmpty indicates when the tree was expected to be empty and
	// it is not
	ErrTreeNotEmpty = fmt.Errorf("tree is not empty")
)

// Tree defines the struct that implements the MerkleTree functionalities
type Tree struct {
	sync.Mutex

	db        db.Database
	maxLevels int
	// thresholdNLeafs defines the threshold number of leafs in the tree
	// that determines if AddBatch will work in memory or in disk.  It is
	// defined when calling NewTree, and if set to 0 it will work always in
	// disk.
	thresholdNLeafs int
	snapshotRoot    *big.Int

	hashFunction HashFunction
	// TODO in the methods that use it, check if emptyHash param is len>0
	// (check if it has been initialized)
	emptyHash *big.Int

	dbg *dbgStats
}

// Config defines the configuration for calling NewTree & NewTreeWithTx methods
type Config struct {
	Database        db.Database
	MaxLevels       int
	ThresholdNLeafs int
	HashFunction    HashFunction
}

// NewTree returns a new Tree, if there is a Tree still in the given database, it
// will load it.
func NewTree(cfg Config) (*Tree, error) {
	wTx := cfg.Database.WriteTx()
	defer wTx.Discard()

	t, err := NewTreeWithTx(wTx, cfg)
	if err != nil {
		return nil, err
	}

	if err = wTx.Commit(); err != nil {
		return nil, err
	}
	return t, nil
}

// NewTreeWithTx returns a new Tree using the given db.WriteTx, which will not
// be ccommited inside this method, if there is a Tree still in the given
// database, it will load it.
func NewTreeWithTx(wTx db.WriteTx, cfg Config) (*Tree, error) {
	// if thresholdNLeafs is set to 0, use the DefaultThresholdNLeafs
	if cfg.ThresholdNLeafs == 0 {
		cfg.ThresholdNLeafs = DefaultThresholdNLeafs
	}
	t := Tree{
		db:              cfg.Database,
		maxLevels:       cfg.MaxLevels,
		thresholdNLeafs: cfg.ThresholdNLeafs,
		hashFunction:    cfg.HashFunction,
		emptyHash:       zero, // empty
	}
	if _, err := wTx.Get(dbKeyRoot); err == db.ErrKeyNotFound {
		// store new root 0 (empty)
		if err = wTx.Set(dbKeyRoot, t.emptyHash.Bytes()); err != nil {
			return nil, err
		}
		if err = t.setNLeafs(wTx, 0); err != nil {
			return nil, err
		}
		return &t, nil
	} else if err != nil {
		return nil, err
	}
	return &t, nil
}

// Root returns the root of the Tree
func (t *Tree) Root() (*big.Int, error) {
	return t.RootWithTx(t.db)
}

// RootWithTx returns the root of the Tree using the given db.ReadTx
func (t *Tree) RootWithTx(rTx db.Reader) (*big.Int, error) {
	// if snapshotRoot is defined, means that the tree is a snapshot, and
	// the root is not obtained from the db, but from the snapshotRoot
	// parameter
	if t.snapshotRoot != nil {
		return t.snapshotRoot, nil
	}
	// get db root
	bKey, err := rTx.Get(dbKeyRoot)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(bKey), nil
}

func (t *Tree) setRoot(wTx db.WriteTx, root *big.Int) error {
	return wTx.Set(dbKeyRoot, root.Bytes())
}

// HashFunction returns Tree.hashFunction
func (t *Tree) HashFunction() HashFunction {
	return t.hashFunction
}

// editable returns true if the tree is editable, and false when is not
// editable (because is a snapshot tree)
func (t *Tree) editable() bool {
	return t.snapshotRoot == nil
}

// Invalid is used when a key-value can not be added trough AddBatch, and
// contains the index of the key-value and the error.
type Invalid struct {
	Index int
	Error error
}

// AddBatch adds a batch of key-values to the Tree. Returns an array containing
// the indexes of the keys failed to add. Supports empty values as input
// parameters, which is equivalent to 0 valued byte array.
func (t *Tree) AddBatch(keys []*big.Int, values [][]*big.Int) ([]Invalid, error) {
	wTx := t.db.WriteTx()
	defer wTx.Discard()

	invalids, err := t.AddBatchWithTx(wTx, keys, values)
	if err != nil {
		return invalids, err
	}
	return invalids, wTx.Commit()
}

// AddBatchWithTx does the same than the AddBatch method, but allowing to pass
// the db.WriteTx that is used. The db.WriteTx will not be committed inside
// this method.
func (t *Tree) AddBatchWithTx(wTx db.WriteTx, keys []*big.Int, values [][]*big.Int) ([]Invalid, error) {
	t.Lock()
	defer t.Unlock()

	if !t.editable() {
		return nil, ErrSnapshotNotEditable
	}

	// equal the number of keys & values
	if len(keys) > len(values) {
		// add missing values
		for i := len(values); i < len(keys); i++ {
			values = append(values, []*big.Int{zero})
		}
	} else if len(keys) < len(values) {
		// crop extra values
		values = values[:len(keys)]
	}

	nLeafs, err := t.GetNLeafsWithTx(wTx)
	if err != nil {
		return nil, err
	}
	if nLeafs > t.thresholdNLeafs {
		return t.addBatchInDisk(wTx, keys, values)
	}
	return t.addBatchInMemory(wTx, keys, values)
}

func (t *Tree) addBatchInDisk(wTx db.WriteTx, keys []*big.Int, values [][]*big.Int) ([]Invalid, error) {
	nCPU := flp2(runtime.NumCPU())
	if nCPU == 1 || len(keys) < nCPU {
		var invalids []Invalid
		for i := range keys {
			if err := t.addWithTx(wTx, keys[i], values[i]...); err != nil {
				invalids = append(invalids, Invalid{i, err})
			}
		}
		return invalids, nil
	}

	kvs, invalids, err := keysValuesToKvs(t.maxLevels, keys, values)
	if err != nil {
		return nil, err
	}

	buckets := splitInBuckets(kvs, nCPU)

	root, err := t.RootWithTx(wTx)
	if err != nil {
		return nil, err
	}

	l := int(math.Log2(float64(nCPU)))
	subRoots, err := t.getSubRootsAtLevel(wTx, root, l+1)
	if err != nil {
		return nil, err
	}
	if len(subRoots) != nCPU {
		// Already populated Tree but Unbalanced.

		// add one key at each bucket, and then continue with the flow
		for i := range buckets {
			// add one leaf of the bucket, if there is an error when
			// adding the k-v, try to add the next one of the bucket
			// (until one is added)
			inserted := -1
			for j := range buckets[i] {
				if newRoot, err := t.add(wTx, root, 0,
					buckets[i][j].k, buckets[i][j].v...); err == nil {
					inserted = j
					root = newRoot
					break
				}
			}

			// remove the inserted element from buckets[i]
			if inserted != -1 {
				buckets[i] = append(buckets[i][:inserted], buckets[i][inserted+1:]...)
			}
		}
		subRoots, err = t.getSubRootsAtLevel(wTx, root, l+1)
		if err != nil {
			return nil, err
		}
	}

	if len(subRoots) != nCPU {
		return nil, fmt.Errorf("this error should not be reached."+
			" len(subRoots) != nCPU, len(subRoots)=%d, nCPU=%d."+
			" Please report it in a new issue:"+
			" https://github.com/vocdoni/arbo/issues/new", len(subRoots), nCPU)
	}

	invalidsInBucket := make([][]Invalid, nCPU)
	txs := make([]db.WriteTx, nCPU)
	for i := range nCPU {
		txs[i] = t.db.WriteTx()
		err := txs[i].Apply(wTx)
		if err != nil {
			return nil, err
		}
	}

	var wg sync.WaitGroup
	wg.Add(nCPU)
	for i := range nCPU {
		go func(cpu int) {
			// use different wTx for each cpu, after once all
			// are done, iter over the cpuWTxs and copy their
			// content into the main wTx
			for j := 0; j < len(buckets[cpu]); j++ {
				newSubRoot, err := t.add(txs[cpu], subRoots[cpu],
					l, buckets[cpu][j].k, buckets[cpu][j].v...)
				if err != nil {
					invalidsInBucket[cpu] = append(invalidsInBucket[cpu],
						Invalid{buckets[cpu][j].pos, err})
					continue
				}
				// if there has not been errors, set the new subRoots[cpu]
				subRoots[cpu] = newSubRoot
			}
			wg.Done()
		}(i)
	}
	wg.Wait()

	for i := range nCPU {
		if err := wTx.Apply(txs[i]); err != nil {
			return nil, err
		}
		txs[i].Discard()
	}

	for i := range invalidsInBucket {
		invalids = append(invalids, invalidsInBucket[i]...)
	}

	newRoot, err := t.upFromSubRoots(wTx, subRoots)
	if err != nil {
		return nil, err
	}

	// update dbKeyNLeafs
	if err := t.SetRootWithTx(wTx, newRoot); err != nil {
		return nil, err
	}

	// update nLeafs
	if err := t.incNLeafs(wTx, len(keys)-len(invalids)); err != nil {
		return nil, err
	}

	return invalids, nil
}

func (t *Tree) upFromSubRoots(wTx db.WriteTx, subRoots []*big.Int) (*big.Int, error) {
	// is a method of Tree just to get access to t.hashFunction and
	// t.emptyHash.

	// go up from subRoots to up, storing nodes in the given WriteTx
	// once up at the root, store it in the WriteTx using the dbKeyRoot
	if len(subRoots) == 1 {
		return subRoots[0], nil
	}
	// get the subRoots values to know the node types of each subRoot
	nodeTypes := make([]byte, len(subRoots))
	for i := range subRoots {
		if subRoots[i].Cmp(t.emptyHash) == 0 {
			nodeTypes[i] = PrefixValueEmpty
			continue
		}
		v, err := wTx.Get(subRoots[i].Bytes())
		if err != nil {
			return nil, err
		}
		nodeTypes[i] = v[0]
	}

	var newSubRoots []*big.Int
	for i := 0; i < len(subRoots); i += 2 {
		if (subRoots[i].Cmp(t.emptyHash) == 0 && subRoots[i+1].Cmp(t.emptyHash) == 0) ||
			(nodeTypes[i] == PrefixValueLeaf && subRoots[i+1].Cmp(t.emptyHash) == 0) {
			// when both sub nodes are empty, the parent is also empty
			// or
			// when 1st sub node is a leaf but the 2nd is empty, the
			// leaf is used as 'parent'

			newSubRoots = append(newSubRoots, subRoots[i])
			continue
		}
		if subRoots[i].Cmp(t.emptyHash) == 0 && nodeTypes[i+1] == PrefixValueLeaf {
			// when 2nd sub node is a leaf but the 1st is empty,
			// the leaf is used as 'parent'
			newSubRoots = append(newSubRoots, subRoots[i+1])
			continue
		}

		k, v, err := t.newIntermediate(subRoots[i], subRoots[i+1])
		if err != nil {
			return nil, err
		}
		// store k-v to db
		if err = wTx.Set(k.Bytes(), v); err != nil {
			return nil, err
		}
		newSubRoots = append(newSubRoots, k)
	}

	return t.upFromSubRoots(wTx, newSubRoots)
}

func (t *Tree) getSubRootsAtLevel(rTx db.Reader, root *big.Int, l int) ([]*big.Int, error) {
	// go at level l and return each node key, where each node key is the
	// subRoot of the subTree that starts there

	var subRoots []*big.Int
	err := t.iterWithStop(rTx, root, 0, func(currLvl int, k *big.Int, v []byte) bool {
		if currLvl == l && k.Cmp(t.emptyHash) != 0 {
			subRoots = append(subRoots, k)
		}
		if currLvl >= l {
			return true // to stop the iter from going down
		}
		return false
	})

	return subRoots, err
}

func (t *Tree) addBatchInMemory(wTx db.WriteTx, keys []*big.Int, values [][]*big.Int) ([]Invalid, error) {
	vt, err := t.loadVT()
	if err != nil {
		return nil, err
	}

	invalids, err := vt.addBatch(keys, values)
	if err != nil {
		return nil, err
	}

	// once the VirtualTree is build, compute the hashes
	pairs, err := vt.computeHashes()
	if err != nil {
		// currently invalids in computeHashes are not counted,
		// but should not be needed, as if there is an error there is
		// nothing stored in the db and the error is returned
		return nil, err
	}

	// store pairs in db
	for i := range pairs {
		if err := wTx.Set(pairs[i][0], pairs[i][1]); err != nil {
			return nil, err
		}
	}

	// store root (from the vt) to db
	if vt.root != nil {
		if err := wTx.Set(dbKeyRoot, vt.root.h.Bytes()); err != nil {
			return nil, err
		}
	}

	// update nLeafs
	if err := t.incNLeafs(wTx, len(keys)-len(invalids)); err != nil {
		return nil, err
	}

	return invalids, nil
}

// loadVT loads a new virtual tree (vt) from the current Tree, which contains
// the same leafs.
func (t *Tree) loadVT() (vt, error) {
	vt := newVT(t.maxLevels, t.hashFunction)
	vt.params.dbg = t.dbg
	var callbackErr error
	err := t.IterateWithStopWithTx(t.db, nil, func(_ int, k *big.Int, v []byte) bool {
		if v[0] != PrefixValueLeaf {
			return false
		}
		leafK, leafV := ReadLeafValue(v)
		if err := vt.add(0, leafK, leafV...); err != nil {
			callbackErr = err
			return true
		}
		return false
	})
	if callbackErr != nil {
		return vt, callbackErr
	}

	return vt, err
}

// Add inserts the key-value into the Tree.  If the inputs come from a
// *big.Int, is expected that are represented by a Little-Endian byte array
// (for circom compatibility).
func (t *Tree) Add(k *big.Int, v ...*big.Int) error {
	wTx := t.db.WriteTx()
	defer wTx.Discard()

	if err := t.AddWithTx(wTx, k, v...); err != nil {
		return err
	}

	return wTx.Commit()
}

// AddWithTx does the same than the Add method, but allowing to pass the
// db.WriteTx that is used. The db.WriteTx will not be committed inside this
// method.
func (t *Tree) AddWithTx(wTx db.WriteTx, k *big.Int, v ...*big.Int) error {
	t.Lock()
	defer t.Unlock()

	if !t.editable() {
		return ErrSnapshotNotEditable
	}
	return t.addWithTx(wTx, k, v...)
}

// warning: addWithTx does not use the Tree mutex, the mutex is responsibility
// of the methods calling this method, and same with t.editable().
func (t *Tree) addWithTx(wTx db.WriteTx, k *big.Int, v ...*big.Int) error {
	root, err := t.RootWithTx(wTx)
	if err != nil {
		return err
	}

	root, err = t.add(wTx, root, 0, k, v...) // add from level 0
	if err != nil {
		return err
	}
	// store root to db
	if err := t.setRoot(wTx, root); err != nil {
		return err
	}
	// update nLeafs
	if err = t.incNLeafs(wTx, 1); err != nil {
		return err
	}
	return nil
}

// keyPathFromKey returns the keyPath and checks that the key is not bigger
// than maximum key length for the tree maxLevels size.
// This is because if the key bits length is bigger than the maxLevels of the
// tree, two different keys that their difference is at the end, will collision
// in the same leaf of the tree (at the max depth).
func keyPathFromKey(maxLevels int, k *big.Int) ([]byte, error) {
	maxKeyLen := int(math.Ceil(float64(maxLevels) / float64(8))) //nolint:gomnd
	if len(k.Bytes()) > maxKeyLen {
		return nil, fmt.Errorf("len(k) can not be bigger than ceil(maxLevels/8), where"+
			" len(k): %d, maxLevels: %d, max key len=ceil(maxLevels/8): %d. Might need"+
			" a bigger tree depth (maxLevels>=%d) in order to input keys of length %d",
			len(k.Bytes()), maxLevels, maxKeyLen, len(k.Bytes())*8, len(k.Bytes())) //nolint:gomnd
	}
	keyPath := make([]byte, maxKeyLen) //nolint:gomnd
	copy(keyPath[:], k.Bytes())
	return keyPath, nil
}

// checkKeyValueLen checks the key length and value length. This method is used
// when adding single leafs and also when adding a batch. The limits of lengths
// used are derived from the encoding of tree dumps: 1 byte to define the
// length of the keys (2^8-1 bytes length)), and 2 bytes to define the length
// of the values (2^16-1 bytes length).
func checkKeyValueLen(k *big.Int, v ...*big.Int) error {
	if len(k.Bytes()) > maxUint8 {
		return fmt.Errorf("len(k)=%v, can not be bigger than %v",
			len(k.Bytes()), maxUint8)
	}
	for _, vi := range v {
		if len(vi.Bytes()) > maxUint16 {
			return fmt.Errorf("len(v)=%v, can not be bigger than %v",
				len(vi.Bytes()), maxUint16)
		}
	}
	return nil
}

func (t *Tree) add(wTx db.WriteTx, root *big.Int, fromLvl int, k *big.Int, v ...*big.Int) (*big.Int, error) {
	if err := checkKeyValueLen(k, v...); err != nil {
		log.Println("checkKeyValueLen error:", err)
		return nil, err
	}

	keyPath, err := keyPathFromKey(t.maxLevels, k)
	if err != nil {
		log.Println("keyPathFromKey error:", err)
		return nil, err
	}
	path := getPath(t.maxLevels, keyPath)

	// go down to the leaf
	var siblings []*big.Int
	log.Println("down", k.String(), root.String())
	_, _, siblings, err = t.down(wTx, k, root, siblings, path, fromLvl, false)
	if err != nil {
		log.Println("down error:", err)
		return nil, err
	}

	leafKey, leafValue, err := t.newLeafValue(k, v...)
	if err != nil {
		log.Println("newLeafValue error:", err)
		return nil, err
	}

	if err := wTx.Set(leafKey.Bytes(), leafValue); err != nil {
		log.Println("wTx.Set error:", err)
		return nil, err
	}

	// go up to the root
	if len(siblings) == 0 {
		// return the leafKey as root
		return leafKey, nil
	}
	root, err = t.up(wTx, leafKey, siblings, path, len(siblings)-1, fromLvl)
	if err != nil {
		log.Println("up error:", err)
		return nil, err
	}
	log.Println("new root", root.String())
	return root, nil
}

// down goes down to the leaf recursively
func (t *Tree) down(rTx db.Reader, newKey, currKey *big.Int, siblings []*big.Int,
	path []bool, currLvl int, getLeaf bool,
) (
	*big.Int, []byte, []*big.Int, error,
) {
	if currLvl > t.maxLevels {
		return nil, nil, nil, ErrMaxLevel
	}

	var err error
	var currValue []byte
	if currKey.Cmp(t.emptyHash) == 0 {
		// empty value
		return currKey, emptyValue, siblings, nil
	}
	currValue, err = rTx.Get(currKey.Bytes())
	if err != nil {
		log.Println("rTx.Get error:", err)
		return nil, nil, nil, err
	}

	switch currValue[0] {
	case PrefixValueEmpty: // empty
		fmt.Printf("newKey: %s, currKey: %s, currLvl: %d, currValue: %s\n",
			newKey.String(), currKey.String(),
			currLvl, hex.EncodeToString(currValue))
		panic("This point should not be reached, as the 'if currKey==t.emptyHash'" +
			" above should avoid reaching this point. This panic is temporary" +
			" for reporting purposes, will be deleted in future versions." +
			" Please paste this log (including the previous log lines) in a" +
			" new issue: https://github.com/vocdoni/arbo/issues/new") // TMP
	case PrefixValueLeaf: // leaf
		if !bytes.Equal(currValue, emptyValue) {
			if getLeaf {
				return currKey, currValue, siblings, nil
			}
			oldLeafKey, _ := ReadLeafValue(currValue)
			if newKey.Cmp(oldLeafKey) == 0 {
				return nil, nil, nil, ErrKeyAlreadyExists
			}

			oldLeafKeyFull, err := keyPathFromKey(t.maxLevels, oldLeafKey)
			if err != nil {
				log.Println("keyPathFromKey error:", err)
				return nil, nil, nil, err
			}

			// if currKey is already used, go down until paths diverge
			oldPath := getPath(t.maxLevels, oldLeafKeyFull)
			siblings, err = t.downVirtually(siblings, currKey, newKey, oldPath, path, currLvl)
			if err != nil {
				log.Println("downVirtually error:", err)
				return nil, nil, nil, err
			}
		}
		return currKey, currValue, siblings, nil
	case PrefixValueIntermediate: // intermediate
		if len(currValue) != PrefixValueLen+t.hashFunction.Len()*2 {
			return nil, nil, nil,
				fmt.Errorf("intermediate value invalid length (expected: %d, actual: %d)",
					PrefixValueLen+t.hashFunction.Len()*2, len(currValue))
		}
		// collect siblings while going down
		if path[currLvl] {
			// right
			lChild, rChild := ReadIntermediateChilds(currValue)
			siblings = append(siblings, lChild)
			return t.down(rTx, newKey, rChild, siblings, path, currLvl+1, getLeaf)
		}
		// left
		lChild, rChild := ReadIntermediateChilds(currValue)
		siblings = append(siblings, rChild)
		return t.down(rTx, newKey, lChild, siblings, path, currLvl+1, getLeaf)
	default:
		return nil, nil, nil, ErrInvalidValuePrefix
	}
}

// downVirtually is used when in a leaf already exists, and a new leaf which
// shares the path until the existing leaf is being added
func (t *Tree) downVirtually(siblings []*big.Int, oldKey, newKey *big.Int, oldPath,
	newPath []bool, currLvl int) ([]*big.Int, error) {
	var err error
	if currLvl > t.maxLevels-1 {
		return nil, ErrMaxVirtualLevel
	}

	if oldPath[currLvl] == newPath[currLvl] {
		siblings = append(siblings, t.emptyHash)

		siblings, err = t.downVirtually(siblings, oldKey, newKey, oldPath, newPath, currLvl+1)
		if err != nil {
			return nil, err
		}
		return siblings, nil
	}
	// reached the divergence
	siblings = append(siblings, oldKey)

	return siblings, nil
}

// up goes up recursively updating the intermediate nodes
func (t *Tree) up(wTx db.WriteTx, key *big.Int, siblings []*big.Int, path []bool, currLvl, toLvl int) (*big.Int, error) {
	var k *big.Int
	var v []byte
	var err error
	if path[currLvl+toLvl] {
		k, v, err = t.newIntermediate(siblings[currLvl], key)
		if err != nil {
			return nil, err
		}
	} else {
		k, v, err = t.newIntermediate(key, siblings[currLvl])
		if err != nil {
			return nil, err
		}
	}
	// store k-v to db
	if err = wTx.Set(k.Bytes(), v); err != nil {
		return nil, err
	}

	if currLvl == 0 {
		// reached the root
		return k, nil
	}

	return t.up(wTx, k, siblings, path, currLvl-1, toLvl)
}

func (t *Tree) newLeafValue(k *big.Int, v ...*big.Int) (*big.Int, []byte, error) {
	t.dbg.incHash()
	return newLeafValue(t.hashFunction, k, v...)
}

// newLeafValue takes a key & value from a leaf, and computes the leaf hash,
// which is used as the leaf key. And the value is the concatenation of the
// inputed key & value. The output of this function is used as key-value to
// store the leaf in the DB.
// [     1 byte   |     1 byte    | N bytes | M bytes ]
// [ type of node | length of key |   key   |  value  ]
func newLeafValue(hashFunc HashFunction, k *big.Int, v ...*big.Int) (*big.Int, []byte, error) {
	if len(v) == 0 {
		v = []*big.Int{big.NewInt(0)}
	}
	if err := checkKeyValueLen(k, v...); err != nil {
		return nil, nil, err
	}
	inputs := []*big.Int{k}
	inputs = append(inputs, v...)
	inputs = append(inputs, big.NewInt(1)) // leaf type
	leafKey, err := hashFunc.Hash(inputs...)
	if err != nil {
		return nil, nil, err
	}
	leafValue, err := WriteLeafValue(k, v...)
	return leafKey, leafValue, err
}

func WriteLeafValue(k *big.Int, v ...*big.Int) ([]byte, error) {
	if len(v) == 0 {
		v = []*big.Int{zero}
	}
	if err := checkKeyValueLen(k, v...); err != nil {
		return nil, err
	}
	var leafValue []byte
	leafValue = append(leafValue, byte(PrefixValueLeaf))
	leafValue = append(leafValue, byte(len(k.Bytes())))
	leafValue = append(leafValue, k.Bytes()...)
	for i := range v {
		leafValue = append(leafValue, byte(len(v[i].Bytes())))
		leafValue = append(leafValue, v[i].Bytes()...)
	}
	return leafValue, nil
}

// ReadLeafValue reads from a byte array the leaf key & value
func ReadLeafValue(b []byte) (*big.Int, []*big.Int) {
	if len(b) < PrefixValueLen {
		return big.NewInt(0), nil
	}

	kLen := b[1]
	if len(b) < PrefixValueLen+int(kLen) {
		return big.NewInt(0), nil
	}
	k := new(big.Int).SetBytes(b[PrefixValueLen : PrefixValueLen+kLen])
	values := b[PrefixValueLen+kLen:]
	vLen := values[0]
	var v []*big.Int
	for {
		if len(values) < int(vLen)+1 {
			break
		}
		v = append(v, new(big.Int).SetBytes(values[1:1+vLen]))
		values = values[1+vLen:]
		if len(values) == 0 {
			break
		}
		vLen = values[0]
	}
	return k, v
}

func (t *Tree) newIntermediate(l, r *big.Int) (*big.Int, []byte, error) {
	t.dbg.incHash()
	return newIntermediate(t.hashFunction, l, r)
}

// newIntermediate takes the left & right keys of a intermediate node, and
// computes its hash. Returns the hash of the node, which is the node key, and a
// byte array that contains the value (which contains the left & right child
// keys) to store in the DB.
// [     1 byte   |     1 byte         | N bytes  |  N bytes  ]
// [ type of node | length of left key | left key | right key ]
func newIntermediate(hashFunc HashFunction, l, r *big.Int) (*big.Int, []byte, error) {
	b := make([]byte, PrefixValueLen+hashFunc.Len()*2)
	b[0] = PrefixValueIntermediate
	if len(l.Bytes()) > maxUint8 {
		return nil, nil, fmt.Errorf("newIntermediate: len(l) > %v", maxUint8)
	}
	b[1] = byte(len(l.Bytes()))
	copy(b[PrefixValueLen:PrefixValueLen+hashFunc.Len()], l.Bytes())
	copy(b[PrefixValueLen+hashFunc.Len():], r.Bytes())

	key, err := hashFunc.Hash(l, r)
	if err != nil {
		return nil, nil, err
	}

	return key, b, nil
}

// ReadIntermediateChilds reads from a byte array the two childs keys
func ReadIntermediateChilds(b []byte) (*big.Int, *big.Int) {
	if len(b) < PrefixValueLen {
		return nil, nil
	}

	lLen := b[1]
	if len(b) < PrefixValueLen+int(lLen) {
		return nil, nil
	}
	l := b[PrefixValueLen : PrefixValueLen+lLen]
	r := b[PrefixValueLen+lLen:]
	return new(big.Int).SetBytes(l), new(big.Int).SetBytes(r)
}

func getPath(numLevels int, k []byte) []bool {
	path := make([]bool, numLevels)
	for n := range numLevels {
		path[n] = k[n/8]&(1<<(n%8)) != 0
	}
	return path
}

// Update updates the value for a given existing key. If the given key does not
// exist, returns an error.
func (t *Tree) Update(k *big.Int, v ...*big.Int) error {
	wTx := t.db.WriteTx()
	defer wTx.Discard()

	if err := t.UpdateWithTx(wTx, k, v...); err != nil {
		return err
	}
	return wTx.Commit()
}

// UpdateWithTx does the same than the Update method, but allowing to pass the
// db.WriteTx that is used. The db.WriteTx will not be committed inside this
// method.
func (t *Tree) UpdateWithTx(wTx db.WriteTx, k *big.Int, v ...*big.Int) error {
	t.Lock()
	defer t.Unlock()

	if !t.editable() {
		return ErrSnapshotNotEditable
	}

	keyPath, err := keyPathFromKey(t.maxLevels, k)
	if err != nil {
		return err
	}
	path := getPath(t.maxLevels, keyPath)

	root, err := t.RootWithTx(wTx)
	if err != nil {
		return err
	}

	var siblings []*big.Int
	_, valueAtBottom, siblings, err := t.down(wTx, k, root, siblings, path, 0, true)
	if err != nil {
		return err
	}
	oldKey, _ := ReadLeafValue(valueAtBottom)
	if oldKey.Cmp(k) != 0 {
		return ErrKeyNotFound
	}

	leafKey, leafValue, err := t.newLeafValue(k, v...)
	if err != nil {
		return err
	}

	if err := wTx.Set(leafKey.Bytes(), leafValue); err != nil {
		return err
	}

	// go up to the root
	if len(siblings) == 0 {
		return t.setRoot(wTx, leafKey)
	}
	root, err = t.up(wTx, leafKey, siblings, path, len(siblings)-1, 0)
	if err != nil {
		return err
	}

	// store root to db
	if err := t.setRoot(wTx, root); err != nil {
		return err
	}
	return nil
}

// GenProof generates a MerkleTree proof for the given key. The leaf value is
// returned, together with the packed siblings of the proof, and a boolean
// parameter that indicates if the proof is of existence (true) or not (false).
func (t *Tree) GenProof(k *big.Int) (*big.Int, []*big.Int, []byte, bool, error) {
	return t.GenProofWithTx(t.db, k)
}

// GenProofWithTx does the same than the GenProof method, but allowing to pass
// the db.ReadTx that is used.
func (t *Tree) GenProofWithTx(rTx db.Reader, k *big.Int) (*big.Int, []*big.Int, []byte, bool, error) {
	keyPath, err := keyPathFromKey(t.maxLevels, k)
	if err != nil {
		return nil, nil, nil, false, err
	}
	path := getPath(t.maxLevels, keyPath)

	root, err := t.RootWithTx(rTx)
	if err != nil {
		return nil, nil, nil, false, err
	}

	// go down to the leaf
	var siblings []*big.Int
	_, value, siblings, err := t.down(rTx, k, root, siblings, path, 0, true)
	if err != nil {
		return nil, nil, nil, false, err
	}

	s, err := PackSiblings(t.hashFunction, siblings)
	if err != nil {
		return nil, nil, nil, false, err
	}

	leafK, leafV := ReadLeafValue(value)
	if k.Cmp(leafK) != 0 {
		// key not in tree, proof of non-existence
		return leafK, leafV, s, false, nil
	}

	return leafK, leafV, s, true, nil
}

// PackSiblings packs the siblings into a byte array.
// [    2 byte   |     2 byte        | L bytes |      S * N bytes    ]
// [ full length | bitmap length (L) |  bitmap | N non-zero siblings ]
// Where the bitmap indicates if the sibling is 0 or a value from the siblings
// array. And S is the size of the output of the hash function used for the
// Tree. The 2 2-byte that define the full length and bitmap length, are
// encoded in little-endian.
func PackSiblings(hashFunc HashFunction, siblings []*big.Int) ([]byte, error) {
	var b []byte
	var bitmap []bool
	for i := range siblings {
		if siblings[i].Cmp(zero) == 0 {
			bitmap = append(bitmap, false)
		} else {
			bitmap = append(bitmap, true)
			b = append(b, siblings[i].Bytes()...)
		}
	}

	bitmapBytes := bitmapToBytes(bitmap)
	l := len(bitmapBytes)
	if l > maxUint16 {
		return nil, fmt.Errorf("PackSiblings: bitmapBytes length > %v", maxUint16)
	}

	fullLen := 4 + l + len(b) //nolint:gomnd
	if fullLen > maxUint16 {
		return nil, fmt.Errorf("PackSiblings: fullLen > %v", maxUint16)
	}
	res := make([]byte, fullLen)
	binary.LittleEndian.PutUint16(res[0:2], uint16(fullLen)) // set full length
	binary.LittleEndian.PutUint16(res[2:4], uint16(l))       // set the bitmapBytes length
	copy(res[4:4+l], bitmapBytes)
	copy(res[4+l:], b)
	return res, nil
}

// UnpackSiblings unpacks the siblings from a byte array.
func UnpackSiblings(hashFunc HashFunction, b []byte) ([]*big.Int, error) {
	fullLen := binary.LittleEndian.Uint16(b[0:2])
	l := binary.LittleEndian.Uint16(b[2:4]) // bitmap bytes length
	if len(b) != int(fullLen) {
		return nil,
			fmt.Errorf("expected len: %d, current len: %d",
				fullLen, len(b))
	}

	bitmapBytes := b[4 : 4+l]
	bitmap := bytesToBitmap(bitmapBytes)
	siblingsBytes := b[4+l:]
	iSibl := 0
	emptySibl := big.NewInt(0)
	var siblings []*big.Int
	for i := range bitmap {
		if iSibl >= len(siblingsBytes) {
			break
		}
		if bitmap[i] {
			sibling := new(big.Int).SetBytes(siblingsBytes[iSibl : iSibl+hashFunc.Len()])
			siblings = append(siblings, sibling)
			iSibl += hashFunc.Len()
		} else {
			siblings = append(siblings, emptySibl)
		}
	}
	return siblings, nil
}

func bitmapToBytes(bitmap []bool) []byte {
	bitmapBytesLen := int(math.Ceil(float64(len(bitmap)) / 8)) //nolint:gomnd
	b := make([]byte, bitmapBytesLen)
	for i := range bitmap {
		if bitmap[i] {
			b[i/8] |= 1 << (i % 8)
		}
	}
	return b
}

func bytesToBitmap(b []byte) []bool {
	var bitmap []bool
	for i := range b {
		for j := range 8 {
			bitmap = append(bitmap, b[i]&(1<<j) > 0)
		}
	}
	return bitmap
}

// Get returns the value in the Tree for a given key. If the key is not found,
// will return the error ErrKeyNotFound, and in the leafK & leafV parameters
// will be placed the data found in the tree in the leaf that was on the path
// going to the input key.
func (t *Tree) Get(k *big.Int) (*big.Int, []*big.Int, error) {
	return t.GetWithTx(t.db, k)
}

// GetWithTx does the same than the Get method, but allowing to pass the
// db.ReadTx that is used. If the key is not found, will return the error
// ErrKeyNotFound, and in the leafK & leafV parameters will be placed the data
// found in the tree in the leaf that was on the path going to the input key.
func (t *Tree) GetWithTx(rTx db.Reader, k *big.Int) (*big.Int, []*big.Int, error) {
	keyPath, err := keyPathFromKey(t.maxLevels, k)
	if err != nil {
		return nil, nil, err
	}
	path := getPath(t.maxLevels, keyPath)

	root, err := t.RootWithTx(rTx)
	if err != nil {
		return nil, nil, err
	}

	// go down to the leaf
	var siblings []*big.Int
	_, value, _, err := t.down(rTx, k, root, siblings, path, 0, true)
	if err != nil {
		return nil, nil, err
	}
	leafK, leafV := ReadLeafValue(value)
	if k.Cmp(leafK) != 0 {
		return leafK, leafV, ErrKeyNotFound
	}

	return leafK, leafV, nil
}

// CheckProof verifies the given proof. The proof verification depends on the
// HashFunction passed as parameter.
func CheckProof(hashFunc HashFunction, root *big.Int, packedSiblings []byte, k *big.Int, v ...*big.Int) (bool, error) {
	siblings, err := UnpackSiblings(hashFunc, packedSiblings)
	if err != nil {
		return false, err
	}

	keyPath := make([]byte, int(math.Ceil(float64(len(siblings))/float64(8)))) //nolint:gomnd
	copy(keyPath[:], k.Bytes())

	key, _, err := newLeafValue(hashFunc, k, v...)
	if err != nil {
		return false, err
	}

	path := getPath(len(siblings), keyPath)
	for i := len(siblings) - 1; i >= 0; i-- {
		if path[i] {
			key, _, err = newIntermediate(hashFunc, siblings[i], key)
			if err != nil {
				return false, err
			}
		} else {
			key, _, err = newIntermediate(hashFunc, key, siblings[i])
			if err != nil {
				return false, err
			}
		}
	}
	return key.Cmp(root) == 0, nil
}

func (t *Tree) incNLeafs(wTx db.WriteTx, nLeafs int) error {
	oldNLeafs, err := t.GetNLeafsWithTx(wTx)
	if err != nil {
		return err
	}
	newNLeafs := oldNLeafs + nLeafs
	return t.setNLeafs(wTx, newNLeafs)
}

func (t *Tree) setNLeafs(wTx db.WriteTx, nLeafs int) error {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(nLeafs))
	if err := wTx.Set(dbKeyNLeafs, b); err != nil {
		return err
	}
	return nil
}

// GetNLeafs returns the number of Leafs of the Tree.
func (t *Tree) GetNLeafs() (int, error) {
	return t.GetNLeafsWithTx(t.db)
}

// GetNLeafsWithTx does the same than the GetNLeafs method, but allowing to
// pass the db.ReadTx that is used.
func (t *Tree) GetNLeafsWithTx(rTx db.Reader) (int, error) {
	b, err := rTx.Get(dbKeyNLeafs)
	if err != nil {
		return 0, err
	}
	nLeafs := binary.LittleEndian.Uint64(b)
	return int(nLeafs), nil
}

// SetRoot sets the root to the given root
func (t *Tree) SetRoot(root *big.Int) error {
	wTx := t.db.WriteTx()
	defer wTx.Discard()

	if err := t.SetRootWithTx(wTx, root); err != nil {
		return err
	}
	return wTx.Commit()
}

// SetRootWithTx sets the root to the given root using the given db.WriteTx
func (t *Tree) SetRootWithTx(wTx db.WriteTx, root *big.Int) error {
	if !t.editable() {
		return ErrSnapshotNotEditable
	}

	if root == nil {
		return fmt.Errorf("can not SetRoot with nil root")
	}

	// check that the root exists in the db
	if root.Cmp(t.emptyHash) != 0 {
		if _, err := wTx.Get(root.Bytes()); err == ErrKeyNotFound {
			return fmt.Errorf("can not SetRoot with root %x, as it"+
				" does not exist in the db", root)
		} else if err != nil {
			return err
		}
	}

	return wTx.Set(dbKeyRoot, root.Bytes())
}

// Snapshot returns a read-only copy of the Tree from the given root
func (t *Tree) Snapshot(fromRoot *big.Int) (*Tree, error) {
	// allow to define which root to use
	if fromRoot == nil {
		var err error
		fromRoot, err = t.Root()
		if err != nil {
			return nil, err
		}
	}
	rTx := t.db
	// check that the root exists in the db
	if fromRoot.Cmp(t.emptyHash) != 0 {
		if _, err := rTx.Get(fromRoot.Bytes()); err == ErrKeyNotFound {
			return nil,
				fmt.Errorf("can not do a Snapshot with root %x,"+
					" as it does not exist in the db", fromRoot)
		} else if err != nil {
			return nil, err
		}
	}

	return &Tree{
		db:           t.db,
		maxLevels:    t.maxLevels,
		snapshotRoot: fromRoot,
		emptyHash:    t.emptyHash,
		hashFunction: t.hashFunction,
		dbg:          t.dbg,
	}, nil
}

// Iterate iterates through the full Tree, executing the given function on each
// node of the Tree.
func (t *Tree) Iterate(fromRoot *big.Int, f func(*big.Int, []byte)) error {
	return t.IterateWithTx(t.db, fromRoot, f)
}

// IterateWithTx does the same than the Iterate method, but allowing to pass
// the db.ReadTx that is used.
func (t *Tree) IterateWithTx(rTx db.Reader, fromRoot *big.Int, f func(*big.Int, []byte)) error {
	// allow to define which root to use
	if fromRoot == nil {
		var err error
		fromRoot, err = t.RootWithTx(rTx)
		if err != nil {
			return err
		}
	}
	return t.iter(rTx, fromRoot, f)
}

// IterateWithStop does the same than Iterate, but with int for the current
// level, and a boolean parameter used by the passed function, is to indicate to
// stop iterating on the branch when the method returns 'true'.
func (t *Tree) IterateWithStop(fromRoot *big.Int, f func(int, *big.Int, []byte) bool) error {
	// allow to define which root to use
	if fromRoot == nil {
		var err error
		fromRoot, err = t.RootWithTx(t.db)
		if err != nil {
			return err
		}
	}
	return t.iterWithStop(t.db, fromRoot, 0, f)
}

// IterateWithStopWithTx does the same than the IterateWithStop method, but
// allowing to pass the db.ReadTx that is used.
func (t *Tree) IterateWithStopWithTx(rTx db.Reader, fromRoot *big.Int,
	f func(int, *big.Int, []byte) bool) error {
	// allow to define which root to use
	if fromRoot == nil {
		var err error
		fromRoot, err = t.RootWithTx(rTx)
		if err != nil {
			return err
		}
	}
	return t.iterWithStop(rTx, fromRoot, 0, f)
}

func (t *Tree) iterWithStop(rTx db.Reader, k *big.Int, currLevel int, f func(int, *big.Int, []byte) bool) error {
	var v []byte
	var err error
	if k.Cmp(t.emptyHash) == 0 {
		v = t.emptyHash.Bytes()
	} else {
		v, err = rTx.Get(k.Bytes())
		if err != nil {
			return err
		}
	}
	currLevel++

	switch v[0] {
	case PrefixValueEmpty:
		f(currLevel, k, v)
	case PrefixValueLeaf:
		f(currLevel, k, v)
	case PrefixValueIntermediate:
		stop := f(currLevel, k, v)
		if stop {
			return nil
		}
		l, r := ReadIntermediateChilds(v)
		if err = t.iterWithStop(rTx, l, currLevel, f); err != nil {
			return err
		}
		if err = t.iterWithStop(rTx, r, currLevel, f); err != nil {
			return err
		}
	default:
		return ErrInvalidValuePrefix
	}
	return nil
}

func (t *Tree) iter(rTx db.Reader, k *big.Int, f func(*big.Int, []byte)) error {
	f2 := func(currLvl int, k *big.Int, v []byte) bool {
		f(k, v)
		return false
	}
	return t.iterWithStop(rTx, k, 0, f2)
}
