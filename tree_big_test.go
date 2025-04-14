package arbo

import (
	"crypto/rand"
	"math/big"
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/arbo/memdb"
)

func TestGenCheckProofBigInt(t *testing.T) {
	c := qt.New(t)
	tree, err := NewTree(Config{
		Database:     memdb.New(),
		MaxLevels:    160,
		HashFunction: HashFunctionMimc7,
	})
	c.Assert(err, qt.IsNil)
	defer tree.treedb.Close()   //nolint:errcheck
	defer tree.valuesdb.Close() //nolint:errcheck

	keys := []*big.Int{}
	values := [][]*big.Int{}
	for range 1000 {
		k, err := rand.Int(rand.Reader, big.NewInt(100_000_000_000))
		c.Assert(err, qt.IsNil)
		v := new(big.Int).Mul(k, big.NewInt(2))
		values = append(values, []*big.Int{v})
		c.Assert(tree.AddBigInt(k, v), qt.IsNil)
		keys = append(keys, k)
	}
	_, err = tree.AddBatchBigInt(keys, values)
	c.Assert(err, qt.IsNil)

	// validate 20 random keys
	for range 20 {
		i, err := rand.Int(rand.Reader, big.NewInt(int64(len(keys))))
		c.Assert(err, qt.IsNil)
		k := keys[i.Int64()]
		kAux, vAux, siblings, existence, err := tree.GenProofBigInts(k)
		c.Assert(err, qt.IsNil)
		c.Assert(existence, qt.IsTrue)

		root, err := tree.Root()
		c.Assert(err, qt.IsNil)
		verif, err := CheckProof(tree.hashFunction, kAux, vAux, root, siblings)
		c.Assert(err, qt.IsNil)
		c.Check(verif, qt.IsTrue)
	}
}

func TestAddGetBigInt(t *testing.T) {
	c := qt.New(t)
	tree, err := NewTree(Config{
		Database:     memdb.New(),
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)
	defer tree.treedb.Close()   //nolint:errcheck
	defer tree.valuesdb.Close() //nolint:errcheck

	// Add multiple key-value pairs with large random big ints
	keys := make([]*big.Int, 100)
	values := make([][]*big.Int, 100)

	for i := range 100 {
		k, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		c.Assert(err, qt.IsNil)
		keys[i] = k

		// Create multiple random values for each key
		v1, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		c.Assert(err, qt.IsNil)
		v2, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		c.Assert(err, qt.IsNil)
		values[i] = []*big.Int{v1, v2}

		c.Assert(tree.AddBigInt(k, v1, v2), qt.IsNil)

		// Verify retrieval
		retrievedK, retrievedVs, err := tree.GetBigInt(k)
		c.Assert(err, qt.IsNil)
		c.Check(retrievedK.Cmp(k), qt.Equals, 0)
		c.Assert(len(retrievedVs), qt.Equals, 2)
		c.Check(retrievedVs[0].Cmp(v1), qt.Equals, 0)
		c.Check(retrievedVs[1].Cmp(v2), qt.Equals, 0)
	}

	// Test non-existent key
	nonExistentKey, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
	c.Assert(err, qt.IsNil)
	_, _, err = tree.GetBigInt(nonExistentKey)
	c.Check(err, qt.IsNotNil)

	// Test nil key
	_, _, err = tree.GetBigInt(nil)
	c.Check(err, qt.IsNotNil)

	// Test adding duplicate key
	err = tree.AddBigInt(keys[0], values[0]...)
	c.Check(err, qt.IsNotNil)
}

func TestUpdateBigInt(t *testing.T) {
	c := qt.New(t)
	tree, err := NewTree(Config{
		Database:     memdb.New(),
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)
	defer tree.treedb.Close()   //nolint:errcheck
	defer tree.valuesdb.Close() //nolint:errcheck

	// Store keys for later updates
	keys := make([]*big.Int, 50)
	values := make([][]*big.Int, 50)

	// Add entries with large random big ints
	for i := range 50 {
		k, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		c.Assert(err, qt.IsNil)
		keys[i] = k

		v1, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		c.Assert(err, qt.IsNil)
		v2, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		c.Assert(err, qt.IsNil)
		values[i] = []*big.Int{v1, v2}

		c.Assert(tree.AddBigInt(k, v1, v2), qt.IsNil)
	}

	// Update entries with new random values
	for i := range 25 {
		k := keys[i]

		newV1, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		c.Assert(err, qt.IsNil)
		newV2, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		c.Assert(err, qt.IsNil)

		c.Assert(tree.UpdateBigInt(k, newV1, newV2), qt.IsNil)
		// Verify update
		_, retrievedVs, err := tree.GetBigInt(k)
		c.Assert(err, qt.IsNil)
		c.Assert(len(retrievedVs), qt.Equals, 2)
		c.Check(retrievedVs[0].Cmp(newV1), qt.Equals, 0)
		c.Check(retrievedVs[1].Cmp(newV2), qt.Equals, 0)
	}

	// Test updating non-existent key
	nonExistentKey, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
	c.Assert(err, qt.IsNil)
	err = tree.UpdateBigInt(nonExistentKey, big.NewInt(1))
	c.Check(err, qt.IsNotNil)

	// Test updating with nil key
	err = tree.UpdateBigInt(nil, big.NewInt(1))
	c.Check(err, qt.IsNotNil)
}

func TestAddBatchBigInt(t *testing.T) {
	c := qt.New(t)
	tree, err := NewTree(Config{
		Database:     memdb.New(),
		MaxLevels:    256,
		HashFunction: HashFunctionPoseidon,
	})
	c.Assert(err, qt.IsNil)
	defer tree.treedb.Close()   //nolint:errcheck
	defer tree.valuesdb.Close() //nolint:errcheck

	// Prepare batch data with large random big ints
	batchSize := 1000
	keys := make([]*big.Int, batchSize)
	values := make([][]*big.Int, batchSize)

	for i := range batchSize {
		k, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		c.Assert(err, qt.IsNil)
		keys[i] = k

		// Create multiple random values for each key
		v1, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		c.Assert(err, qt.IsNil)
		v2, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		c.Assert(err, qt.IsNil)

		values[i] = []*big.Int{v1, v2}
	}

	// Add batch
	invalids, err := tree.AddBatchBigInt(keys, values)
	c.Assert(err, qt.IsNil)
	c.Check(len(invalids), qt.Equals, 0)

	// Verify random sample of entries
	for i := range 50 {
		idx := i % batchSize
		_, retrievedVs, err := tree.GetBigInt(keys[idx])
		c.Assert(err, qt.IsNil)
		c.Assert(len(retrievedVs), qt.Equals, 2)
		c.Check(retrievedVs[0].Cmp(values[idx][0]), qt.Equals, 0)
		c.Check(retrievedVs[1].Cmp(values[idx][1]), qt.Equals, 0)
	}

	// Test mismatched lengths
	_, err = tree.AddBatchBigInt(keys[:10], values[:5])
	c.Check(err, qt.IsNotNil)

	// Test empty batch
	invalids, err = tree.AddBatchBigInt([]*big.Int{}, [][]*big.Int{})
	c.Assert(err, qt.IsNil)
	c.Check(len(invalids), qt.Equals, 0)

	// Test nil values
	invalids, err = tree.AddBatchBigInt(nil, nil)
	c.Assert(err, qt.IsNil)
	c.Check(len(invalids), qt.Equals, 0)
}

func BenchmarkAddBatchBigInt(b *testing.B) {
	// Prepare batch data with large random big ints
	batchSize := 1000
	keys := make([]*big.Int, batchSize)
	values := make([][]*big.Int, batchSize)

	for i := range batchSize {
		keys[i], _ = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))

		v1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		v2, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 25))
		values[i] = []*big.Int{v1, v2}
	}

	b.Run("Poseidon", func(b *testing.B) {
		benchmarkAddBatchBigInt(b, HashFunctionPoseidon, keys, values)
	})
	b.Run("Sha256", func(b *testing.B) {
		benchmarkAddBatchBigInt(b, HashFunctionSha256, keys, values)
	})
}

func benchmarkAddBatchBigInt(b *testing.B, hashFunc HashFunction, keys []*big.Int, values [][]*big.Int) {
	c := qt.New(b)

	b.ResetTimer()
	for range b.N {
		tree, err := NewTree(Config{
			Database:     memdb.New(),
			MaxLevels:    140,
			HashFunction: hashFunc,
		})
		c.Assert(err, qt.IsNil)

		_, err = tree.AddBatchBigInt(keys, values)
		if err != nil {
			b.Fatal(err)
		}

		tree.treedb.Close()   //nolint:errcheck
		tree.valuesdb.Close() //nolint:errcheck
	}
}
