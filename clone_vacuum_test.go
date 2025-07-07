package arbo

import (
	"bytes"
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/arbo/memdb"
	"github.com/vocdoni/davinci-node/db"
	"github.com/vocdoni/davinci-node/db/pebbledb"
)

func TestCloneAndVacuum(t *testing.T) {
	c := qt.New(t)

	// Create source database and tree
	sourceDB, err := pebbledb.New(db.Options{Path: c.TempDir()})
	c.Assert(err, qt.IsNil)
	defer func() { _ = sourceDB.Close() }()

	sourceTree, err := NewTree(Config{
		Database:     sourceDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Add some initial data
	bLen := 32
	for i := 0; i < 10; i++ {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))
		v := BigIntToBytes(bLen, big.NewInt(int64(i*2)))
		err := sourceTree.Add(k, v)
		c.Assert(err, qt.IsNil)
	}

	// Update some values to create orphaned nodes
	for i := 0; i < 5; i++ {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))
		v := BigIntToBytes(bLen, big.NewInt(int64(i*3))) // different value
		err := sourceTree.Update(k, v)
		c.Assert(err, qt.IsNil)
	}

	// Get the final root
	finalRoot, err := sourceTree.Root()
	c.Assert(err, qt.IsNil)

	// Create target database
	targetDB := memdb.New()

	// Test CloneAndVacuum with current root
	err = sourceTree.CloneAndVacuum(targetDB, nil)
	c.Assert(err, qt.IsNil)

	// Create a new tree from the target database
	targetTree, err := NewTree(Config{
		Database:     targetDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Verify the target tree has the same root
	targetRoot, err := targetTree.Root()
	c.Assert(err, qt.IsNil)
	c.Assert(bytes.Equal(targetRoot, finalRoot), qt.IsTrue)

	// Verify the target tree has the same leaf count
	sourceNLeafs, err := sourceTree.GetNLeafs()
	c.Assert(err, qt.IsNil)
	targetNLeafs, err := targetTree.GetNLeafs()
	c.Assert(err, qt.IsNil)
	c.Assert(targetNLeafs, qt.Equals, sourceNLeafs)

	// Verify all current key-value pairs are accessible in target tree
	for i := 0; i < 10; i++ {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))

		// Get from source
		sourceK, sourceV, err := sourceTree.Get(k)
		c.Assert(err, qt.IsNil)

		// Get from target
		targetK, targetV, err := targetTree.Get(k)
		c.Assert(err, qt.IsNil)

		// They should be identical
		c.Assert(bytes.Equal(sourceK, targetK), qt.IsTrue)
		c.Assert(bytes.Equal(sourceV, targetV), qt.IsTrue)
	}
}

func TestCloneAndVacuumWithSpecificRoot(t *testing.T) {
	c := qt.New(t)

	// Create source database and tree
	sourceDB, err := pebbledb.New(db.Options{Path: c.TempDir()})
	c.Assert(err, qt.IsNil)
	defer func() { _ = sourceDB.Close() }()

	sourceTree, err := NewTree(Config{
		Database:     sourceDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Add some initial data
	bLen := 32
	for i := 0; i < 5; i++ {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))
		v := BigIntToBytes(bLen, big.NewInt(int64(i*2)))
		err := sourceTree.Add(k, v)
		c.Assert(err, qt.IsNil)
	}

	// Get the root after initial additions
	initialRoot, err := sourceTree.Root()
	c.Assert(err, qt.IsNil)

	// Add more data
	for i := 5; i < 10; i++ {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))
		v := BigIntToBytes(bLen, big.NewInt(int64(i*2)))
		err := sourceTree.Add(k, v)
		c.Assert(err, qt.IsNil)
	}

	// Create target database
	targetDB := memdb.New()

	// Test CloneAndVacuum with the initial root (before adding more data)
	err = sourceTree.CloneAndVacuum(targetDB, initialRoot)
	c.Assert(err, qt.IsNil)

	// Create a new tree from the target database
	targetTree, err := NewTree(Config{
		Database:     targetDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Verify the target tree has the initial root
	targetRoot, err := targetTree.Root()
	c.Assert(err, qt.IsNil)
	c.Assert(bytes.Equal(targetRoot, initialRoot), qt.IsTrue)

	// Verify only the first 5 keys are accessible in target tree
	for i := 0; i < 5; i++ {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))
		_, _, err := targetTree.Get(k)
		c.Assert(err, qt.IsNil) // Should exist
	}

	// Verify the last 5 keys are NOT accessible in target tree
	for i := 5; i < 10; i++ {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))
		_, _, err := targetTree.Get(k)
		c.Assert(err, qt.Equals, ErrKeyNotFound) // Should not exist
	}
}

func TestCloneAndVacuumEmptyTree(t *testing.T) {
	c := qt.New(t)

	// Create source database and empty tree
	sourceDB := memdb.New()
	sourceTree, err := NewTree(Config{
		Database:     sourceDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Create target database
	targetDB := memdb.New()

	// Test CloneAndVacuum with empty tree
	err = sourceTree.CloneAndVacuum(targetDB, nil)
	c.Assert(err, qt.IsNil)

	// Create a new tree from the target database
	targetTree, err := NewTree(Config{
		Database:     targetDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Verify both trees have empty hash as root
	sourceRoot, err := sourceTree.Root()
	c.Assert(err, qt.IsNil)
	targetRoot, err := targetTree.Root()
	c.Assert(err, qt.IsNil)
	c.Assert(bytes.Equal(sourceRoot, targetRoot), qt.IsTrue)
	c.Assert(bytes.Equal(targetRoot, sourceTree.emptyHash), qt.IsTrue)

	// Verify both trees have 0 leafs
	sourceNLeafs, err := sourceTree.GetNLeafs()
	c.Assert(err, qt.IsNil)
	targetNLeafs, err := targetTree.GetNLeafs()
	c.Assert(err, qt.IsNil)
	c.Assert(sourceNLeafs, qt.Equals, 0)
	c.Assert(targetNLeafs, qt.Equals, 0)
}

func TestCloneAndVacuumSingleNode(t *testing.T) {
	c := qt.New(t)

	// Create source database and tree
	sourceDB := memdb.New()
	sourceTree, err := NewTree(Config{
		Database:     sourceDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Add single key-value pair
	bLen := 32
	k := BigIntToBytes(bLen, big.NewInt(42))
	v := BigIntToBytes(bLen, big.NewInt(84))
	err = sourceTree.Add(k, v)
	c.Assert(err, qt.IsNil)

	// Create target database
	targetDB := memdb.New()

	// Test CloneAndVacuum
	err = sourceTree.CloneAndVacuum(targetDB, nil)
	c.Assert(err, qt.IsNil)

	// Create a new tree from the target database
	targetTree, err := NewTree(Config{
		Database:     targetDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Verify the target tree has the same root
	sourceRoot, err := sourceTree.Root()
	c.Assert(err, qt.IsNil)
	targetRoot, err := targetTree.Root()
	c.Assert(err, qt.IsNil)
	c.Assert(bytes.Equal(sourceRoot, targetRoot), qt.IsTrue)

	// Verify the key-value pair is accessible
	targetK, targetV, err := targetTree.Get(k)
	c.Assert(err, qt.IsNil)
	c.Assert(bytes.Equal(targetK, k), qt.IsTrue)
	c.Assert(bytes.Equal(targetV, v), qt.IsTrue)
}

func TestCloneAndVacuumInvalidRoot(t *testing.T) {
	c := qt.New(t)

	// Create source database and tree
	sourceDB := memdb.New()
	sourceTree, err := NewTree(Config{
		Database:     sourceDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Create target database
	targetDB := memdb.New()

	// Test CloneAndVacuum with invalid root
	invalidRoot := []byte("invalid_root_that_does_not_exist")
	err = sourceTree.CloneAndVacuum(targetDB, invalidRoot)
	c.Assert(err, qt.Not(qt.IsNil))
	c.Assert(err.Error(), qt.Contains, "source root")
	c.Assert(err.Error(), qt.Contains, "does not exist")
}

func TestCloneAndVacuumProofVerification(t *testing.T) {
	c := qt.New(t)

	// Create source database and tree
	sourceDB, err := pebbledb.New(db.Options{Path: c.TempDir()})
	c.Assert(err, qt.IsNil)
	defer func() { _ = sourceDB.Close() }()

	sourceTree, err := NewTree(Config{
		Database:     sourceDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Add test data
	bLen := 32
	testKeys := []int64{1, 33, 1234, 5678, 9999}
	for _, i := range testKeys {
		k := BigIntToBytes(bLen, big.NewInt(i))
		v := BigIntToBytes(bLen, big.NewInt(i*2))
		err := sourceTree.Add(k, v)
		c.Assert(err, qt.IsNil)
	}

	// Create target database and clone
	targetDB := memdb.New()
	err = sourceTree.CloneAndVacuum(targetDB, nil)
	c.Assert(err, qt.IsNil)

	// Create target tree
	targetTree, err := NewTree(Config{
		Database:     targetDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Verify proofs work correctly in both trees
	for _, i := range testKeys {
		k := BigIntToBytes(bLen, big.NewInt(i))
		v := BigIntToBytes(bLen, big.NewInt(i*2))

		// Generate proof from source tree
		sourceLeafK, sourceLeafV, sourceSiblings, sourceExistence, err := sourceTree.GenProof(k)
		c.Assert(err, qt.IsNil)
		c.Assert(sourceExistence, qt.IsTrue)

		// Generate proof from target tree
		targetLeafK, targetLeafV, targetSiblings, targetExistence, err := targetTree.GenProof(k)
		c.Assert(err, qt.IsNil)
		c.Assert(targetExistence, qt.IsTrue)

		// Proofs should be identical
		c.Assert(bytes.Equal(sourceLeafK, targetLeafK), qt.IsTrue)
		c.Assert(bytes.Equal(sourceLeafV, targetLeafV), qt.IsTrue)
		c.Assert(bytes.Equal(sourceSiblings, targetSiblings), qt.IsTrue)

		// Verify proof against both roots
		sourceRoot, err := sourceTree.Root()
		c.Assert(err, qt.IsNil)
		targetRoot, err := targetTree.Root()
		c.Assert(err, qt.IsNil)

		sourceValid, err := CheckProof(sourceTree.HashFunction(), k, v, sourceRoot, sourceSiblings)
		c.Assert(err, qt.IsNil)
		c.Assert(sourceValid, qt.IsTrue)

		targetValid, err := CheckProof(targetTree.HashFunction(), k, v, targetRoot, targetSiblings)
		c.Assert(err, qt.IsNil)
		c.Assert(targetValid, qt.IsTrue)
	}
}

func TestCloneAndVacuumLargeTree(t *testing.T) {
	c := qt.New(t)

	// Create source database and tree
	sourceDB, err := pebbledb.New(db.Options{Path: c.TempDir()})
	c.Assert(err, qt.IsNil)
	defer func() { _ = sourceDB.Close() }()

	sourceTree, err := NewTree(Config{
		Database:     sourceDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Add a larger dataset
	bLen := 32
	numKeys := 1000
	for i := 0; i < numKeys; i++ {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))
		v := BigIntToBytes(bLen, big.NewInt(int64(i*2)))
		err := sourceTree.Add(k, v)
		c.Assert(err, qt.IsNil)
	}

	// Update half of the keys to create orphaned nodes
	for i := 0; i < numKeys/2; i++ {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))
		v := BigIntToBytes(bLen, big.NewInt(int64(i*3))) // different value
		err := sourceTree.Update(k, v)
		c.Assert(err, qt.IsNil)
	}

	// Create target database and clone
	targetDB, err := pebbledb.New(db.Options{Path: c.TempDir()})
	c.Assert(err, qt.IsNil)
	defer func() { _ = targetDB.Close() }()

	err = sourceTree.CloneAndVacuum(targetDB, nil)
	c.Assert(err, qt.IsNil)

	// Create target tree
	targetTree, err := NewTree(Config{
		Database:     targetDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Verify roots match
	sourceRoot, err := sourceTree.Root()
	c.Assert(err, qt.IsNil)
	targetRoot, err := targetTree.Root()
	c.Assert(err, qt.IsNil)
	c.Assert(bytes.Equal(sourceRoot, targetRoot), qt.IsTrue)

	// Verify leaf counts match
	sourceNLeafs, err := sourceTree.GetNLeafs()
	c.Assert(err, qt.IsNil)
	targetNLeafs, err := targetTree.GetNLeafs()
	c.Assert(err, qt.IsNil)
	c.Assert(targetNLeafs, qt.Equals, sourceNLeafs)

	// Spot check some keys
	testIndices := []int{0, 100, 250, 500, 750, 999}
	for _, i := range testIndices {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))

		sourceK, sourceV, err := sourceTree.Get(k)
		c.Assert(err, qt.IsNil)

		targetK, targetV, err := targetTree.Get(k)
		c.Assert(err, qt.IsNil)

		c.Assert(bytes.Equal(sourceK, targetK), qt.IsTrue)
		c.Assert(bytes.Equal(sourceV, targetV), qt.IsTrue)
	}
}

func TestCloneAndVacuumDifferentHashFunctions(t *testing.T) {
	hashFunctions := []HashFunction{
		HashFunctionPoseidon,
		HashFunctionSha256,
		HashFunctionBlake2b,
	}

	for _, hashFunc := range hashFunctions {
		t.Run(string(hashFunc.Type()), func(t *testing.T) {
			c := qt.New(t)

			// Create source database and tree
			sourceDB := memdb.New()
			sourceTree, err := NewTree(Config{
				Database:     sourceDB,
				MaxLevels:    256,
				HashFunction: hashFunc,
			})
			c.Assert(err, qt.IsNil)

			// Add test data
			bLen := 32
			for i := 0; i < 10; i++ {
				k := BigIntToBytes(bLen, big.NewInt(int64(i)))
				v := BigIntToBytes(bLen, big.NewInt(int64(i*2)))
				err := sourceTree.Add(k, v)
				c.Assert(err, qt.IsNil)
			}

			// Create target database and clone
			targetDB := memdb.New()
			err = sourceTree.CloneAndVacuum(targetDB, nil)
			c.Assert(err, qt.IsNil)

			// Create target tree
			targetTree, err := NewTree(Config{
				Database:     targetDB,
				MaxLevels:    256,
				HashFunction: hashFunc,
			})
			c.Assert(err, qt.IsNil)

			// Verify roots match
			sourceRoot, err := sourceTree.Root()
			c.Assert(err, qt.IsNil)
			targetRoot, err := targetTree.Root()
			c.Assert(err, qt.IsNil)
			c.Assert(bytes.Equal(sourceRoot, targetRoot), qt.IsTrue)

			// Verify a few key-value pairs
			for i := 0; i < 3; i++ {
				k := BigIntToBytes(bLen, big.NewInt(int64(i)))

				sourceK, sourceV, err := sourceTree.Get(k)
				c.Assert(err, qt.IsNil)

				targetK, targetV, err := targetTree.Get(k)
				c.Assert(err, qt.IsNil)

				c.Assert(bytes.Equal(sourceK, targetK), qt.IsTrue)
				c.Assert(bytes.Equal(sourceV, targetV), qt.IsTrue)
			}
		})
	}
}

func TestCloneAndVacuumBatching(t *testing.T) {
	c := qt.New(t)

	// Create source database and tree
	sourceDB, err := pebbledb.New(db.Options{Path: c.TempDir()})
	c.Assert(err, qt.IsNil)
	defer func() { _ = sourceDB.Close() }()

	sourceTree, err := NewTree(Config{
		Database:     sourceDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Add a large number of entries to test batching (more than 100,000)
	// We'll add 150,000 entries to ensure we cross the batch boundary
	bLen := 32
	numKeys := 150000

	// Add entries in batches to avoid memory issues
	batchSize := 10000
	for batch := 0; batch < numKeys/batchSize; batch++ {
		var keys, values [][]byte
		for i := 0; i < batchSize; i++ {
			keyIndex := batch*batchSize + i
			k := BigIntToBytes(bLen, big.NewInt(int64(keyIndex)))
			v := BigIntToBytes(bLen, big.NewInt(int64(keyIndex*2)))
			keys = append(keys, k)
			values = append(values, v)
		}

		invalids, err := sourceTree.AddBatch(keys, values)
		c.Assert(err, qt.IsNil)
		c.Assert(len(invalids), qt.Equals, 0)
	}

	// Update some entries to create orphaned nodes
	updateBatchSize := 1000
	for batch := 0; batch < 5; batch++ { // Update 5000 entries
		var keys, values [][]byte
		for i := 0; i < updateBatchSize; i++ {
			keyIndex := batch*updateBatchSize + i
			k := BigIntToBytes(bLen, big.NewInt(int64(keyIndex)))
			v := BigIntToBytes(bLen, big.NewInt(int64(keyIndex*3))) // different value
			keys = append(keys, k)
			values = append(values, v)
		}

		for j := range keys {
			err := sourceTree.Update(keys[j], values[j])
			c.Assert(err, qt.IsNil)
		}
	}

	// Get the final root and leaf count
	finalRoot, err := sourceTree.Root()
	c.Assert(err, qt.IsNil)

	sourceNLeafs, err := sourceTree.GetNLeafs()
	c.Assert(err, qt.IsNil)
	c.Assert(sourceNLeafs, qt.Equals, numKeys)

	// Create target database
	targetDB := memdb.New()

	// Test CloneAndVacuum with the large tree
	err = sourceTree.CloneAndVacuum(targetDB, nil)
	c.Assert(err, qt.IsNil)

	// Create a new tree from the target database
	targetTree, err := NewTree(Config{
		Database:     targetDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Verify the target tree has the same root
	targetRoot, err := targetTree.Root()
	c.Assert(err, qt.IsNil)
	c.Assert(bytes.Equal(targetRoot, finalRoot), qt.IsTrue)

	// Verify the target tree has the same leaf count
	targetNLeafs, err := targetTree.GetNLeafs()
	c.Assert(err, qt.IsNil)
	c.Assert(targetNLeafs, qt.Equals, sourceNLeafs)

	// Spot check some keys to ensure they were copied correctly
	testIndices := []int{0, 1000, 50000, 100000, 149999}
	for _, i := range testIndices {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))

		sourceK, sourceV, err := sourceTree.Get(k)
		c.Assert(err, qt.IsNil)

		targetK, targetV, err := targetTree.Get(k)
		c.Assert(err, qt.IsNil)

		c.Assert(bytes.Equal(sourceK, targetK), qt.IsTrue)
		c.Assert(bytes.Equal(sourceV, targetV), qt.IsTrue)
	}

	// Verify that updated values are correct (should be keyIndex*3 for first 5000)
	for i := 0; i < 5000; i++ {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))
		expectedV := BigIntToBytes(bLen, big.NewInt(int64(i*3)))

		_, sourceV, err := sourceTree.Get(k)
		c.Assert(err, qt.IsNil)
		c.Assert(bytes.Equal(sourceV, expectedV), qt.IsTrue)

		_, targetV, err := targetTree.Get(k)
		c.Assert(err, qt.IsNil)
		c.Assert(bytes.Equal(targetV, expectedV), qt.IsTrue)
	}

	// Verify that non-updated values are correct (should be keyIndex*2 for remaining)
	for i := 5000; i < 5010; i++ { // Just check a few to avoid long test times
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))
		expectedV := BigIntToBytes(bLen, big.NewInt(int64(i*2)))

		_, sourceV, err := sourceTree.Get(k)
		c.Assert(err, qt.IsNil)
		c.Assert(bytes.Equal(sourceV, expectedV), qt.IsTrue)

		_, targetV, err := targetTree.Get(k)
		c.Assert(err, qt.IsNil)
		c.Assert(bytes.Equal(targetV, expectedV), qt.IsTrue)
	}
}

func TestCloneAndVacuumBatchingEdgeCases(t *testing.T) {
	c := qt.New(t)

	// Test with exactly 100,000 entries (batch boundary)
	sourceDB := memdb.New()
	sourceTree, err := NewTree(Config{
		Database:     sourceDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Add exactly 100,000 entries
	bLen := 32
	numKeys := 100000

	var keys, values [][]byte
	for i := 0; i < numKeys; i++ {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))
		v := BigIntToBytes(bLen, big.NewInt(int64(i*2)))
		keys = append(keys, k)
		values = append(values, v)
	}

	invalids, err := sourceTree.AddBatch(keys, values)
	c.Assert(err, qt.IsNil)
	c.Assert(len(invalids), qt.Equals, 0)

	// Create target database and clone
	targetDB := memdb.New()
	err = sourceTree.CloneAndVacuum(targetDB, nil)
	c.Assert(err, qt.IsNil)

	// Verify the clone worked correctly
	targetTree, err := NewTree(Config{
		Database:     targetDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	sourceRoot, err := sourceTree.Root()
	c.Assert(err, qt.IsNil)
	targetRoot, err := targetTree.Root()
	c.Assert(err, qt.IsNil)
	c.Assert(bytes.Equal(sourceRoot, targetRoot), qt.IsTrue)

	sourceNLeafs, err := sourceTree.GetNLeafs()
	c.Assert(err, qt.IsNil)
	targetNLeafs, err := targetTree.GetNLeafs()
	c.Assert(err, qt.IsNil)
	c.Assert(targetNLeafs, qt.Equals, sourceNLeafs)
	c.Assert(targetNLeafs, qt.Equals, numKeys)
}

func TestCloneAndVacuumBatchingWithMetadata(t *testing.T) {
	c := qt.New(t)

	// Test that metadata is correctly handled across batch boundaries
	sourceDB := memdb.New()
	sourceTree, err := NewTree(Config{
		Database:     sourceDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Add entries that will result in exactly 100,001 total database entries
	// (100,000 nodes + 1 metadata entry, then root and nleafs metadata)
	bLen := 32
	numKeys := 99998 // This should create close to 100,000 nodes

	var keys, values [][]byte
	for i := 0; i < numKeys; i++ {
		k := BigIntToBytes(bLen, big.NewInt(int64(i)))
		v := BigIntToBytes(bLen, big.NewInt(int64(i*2)))
		keys = append(keys, k)
		values = append(values, v)
	}

	invalids, err := sourceTree.AddBatch(keys, values)
	c.Assert(err, qt.IsNil)
	c.Assert(len(invalids), qt.Equals, 0)

	// Create target database and clone
	targetDB := memdb.New()
	err = sourceTree.CloneAndVacuum(targetDB, nil)
	c.Assert(err, qt.IsNil)

	// Verify metadata was copied correctly
	targetTree, err := NewTree(Config{
		Database:     targetDB,
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)

	// Check root
	sourceRoot, err := sourceTree.Root()
	c.Assert(err, qt.IsNil)
	targetRoot, err := targetTree.Root()
	c.Assert(err, qt.IsNil)
	c.Assert(bytes.Equal(sourceRoot, targetRoot), qt.IsTrue)

	// Check leaf count
	sourceNLeafs, err := sourceTree.GetNLeafs()
	c.Assert(err, qt.IsNil)
	targetNLeafs, err := targetTree.GetNLeafs()
	c.Assert(err, qt.IsNil)
	c.Assert(targetNLeafs, qt.Equals, sourceNLeafs)
	c.Assert(targetNLeafs, qt.Equals, numKeys)
}
