package memdb

import (
	"bytes"
	"errors"
	"sort"
	"sync"

	"github.com/vocdoni/davinci-node/db"
)

// MemoryDB is an in-memory implementation of the db.Database interface.
type MemoryDB struct {
	mu    sync.RWMutex
	store map[string][]byte
}

// New creates a new MemoryDB instance.
func New() *MemoryDB {
	return &MemoryDB{
		store: make(map[string][]byte),
	}
}

// Close closes the database. For in-memory DB, it's a no-op.
func (m *MemoryDB) Close() error {
	// No resources to release for in-memory DB
	return nil
}

// Get retrieves the value for the given key. If the key does not exist, returns ErrKeyNotFound.
func (m *MemoryDB) Get(key []byte) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	val, exists := m.store[string(key)]
	if !exists {
		return nil, db.ErrKeyNotFound
	}
	// Return a copy to prevent external modification
	return append([]byte(nil), val...), nil
}

// Iterate calls the callback with all key-value pairs in the database whose key starts with prefix.
// The iteration is ordered lexicographically by key.
func (m *MemoryDB) Iterate(prefix []byte, callback func(key, value []byte) bool) error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var keys []string
	for k := range m.store {
		if bytes.HasPrefix([]byte(k), prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys) // Lexicographical order

	for _, k := range keys {
		v := m.store[k]
		// Make copies to prevent external modification
		keyCopy := []byte(k)
		valCopy := append([]byte(nil), v...)
		cont := callback(keyCopy, valCopy)
		if !cont {
			break
		}
	}
	return nil
}

// WriteTx creates a new write transaction.
func (m *MemoryDB) WriteTx() db.WriteTx {
	return &memoryWriteTx{
		db:      m,
		sets:    make(map[string][]byte),
		deletes: make(map[string]struct{}),
		active:  true,
	}
}

// Compact is a no-op for in-memory DB.
func (m *MemoryDB) Compact() error {
	// No compaction needed for in-memory DB
	return nil
}

// memoryWriteTx implements the db.WriteTx interface.
type memoryWriteTx struct {
	db      *MemoryDB
	sets    map[string][]byte
	deletes map[string]struct{}
	mu      sync.Mutex
	active  bool
}

// ensureActive checks if the transaction is still active.
func (tx *memoryWriteTx) ensureActive() error {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if !tx.active {
		return errors.New("transaction is no longer active")
	}
	return nil
}

// Get retrieves the value for the given key within the transaction context.
func (tx *memoryWriteTx) Get(key []byte) ([]byte, error) {
	if err := tx.ensureActive(); err != nil {
		return nil, err
	}

	// Check pending deletes first
	if _, deleted := tx.deletes[string(key)]; deleted {
		return nil, db.ErrKeyNotFound
	}

	// Check pending sets
	if val, exists := tx.sets[string(key)]; exists {
		return append([]byte(nil), val...), nil
	}

	// Fallback to the main DB
	return tx.db.Get(key)
}

// Iterate iterates over the key-value pairs within the transaction context.
func (tx *memoryWriteTx) Iterate(prefix []byte, callback func(key, value []byte) bool) error {
	if err := tx.ensureActive(); err != nil {
		return err
	}

	tx.db.mu.RLock()
	defer tx.db.mu.RUnlock()

	var keys []string
	for k := range tx.db.store {
		if bytes.HasPrefix([]byte(k), prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys) // Lexicographical order

	for _, k := range keys {
		if _, deleted := tx.deletes[k]; deleted {
			continue
		}
		if val, exists := tx.sets[k]; exists {
			// Use the value from the transaction's pending sets
			keyCopy := []byte(k)
			valCopy := append([]byte(nil), val...)
			cont := callback(keyCopy, valCopy)
			if !cont {
				break
			}
		} else {
			// Use the value from the main DB
			v := tx.db.store[k]
			keyCopy := []byte(k)
			valCopy := append([]byte(nil), v...)
			cont := callback(keyCopy, valCopy)
			if !cont {
				break
			}
		}
	}

	// Also include any new keys set in the transaction that weren't in the main DB
	var newKeys []string
	for k := range tx.sets {
		if !bytes.HasPrefix([]byte(k), prefix) {
			continue
		}
		if _, exists := tx.db.store[k]; !exists {
			newKeys = append(newKeys, k)
		}
	}
	sort.Strings(newKeys)
	for _, k := range newKeys {
		val := tx.sets[k]
		keyCopy := []byte(k)
		valCopy := append([]byte(nil), val...)
		cont := callback(keyCopy, valCopy)
		if !cont {
			break
		}
	}

	return nil
}

// Set adds or updates a key-value pair in the transaction.
func (tx *memoryWriteTx) Set(key, value []byte) error {
	if err := tx.ensureActive(); err != nil {
		return err
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()

	// Optional: Check for transaction size limits here
	// For simplicity, we assume no size limits

	tx.sets[string(key)] = append([]byte(nil), value...)
	delete(tx.deletes, string(key))
	return nil
}

// Delete removes a key from the transaction.
func (tx *memoryWriteTx) Delete(key []byte) error {
	if err := tx.ensureActive(); err != nil {
		return err
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()

	delete(tx.sets, string(key))
	tx.deletes[string(key)] = struct{}{}
	return nil
}

// Apply copies the key-values from the source WriteTx into this transaction.
func (tx *memoryWriteTx) Apply(source db.WriteTx) error {
	if err := tx.ensureActive(); err != nil {
		return err
	}

	sourceTx, ok := source.(*memoryWriteTx)
	if !ok {
		return errors.New("unsupported WriteTx type")
	}

	sourceTx.mu.Lock()
	defer sourceTx.mu.Unlock()

	tx.mu.Lock()
	defer tx.mu.Unlock()

	for k, v := range sourceTx.sets {
		tx.sets[k] = append([]byte(nil), v...)
		delete(tx.deletes, k)
	}

	for k := range sourceTx.deletes {
		delete(tx.sets, k)
		tx.deletes[k] = struct{}{}
	}

	return nil
}

// Commit applies all pending changes to the main DB.
func (tx *memoryWriteTx) Commit() error {
	if err := tx.ensureActive(); err != nil {
		return err
	}

	tx.db.mu.Lock()
	defer tx.db.mu.Unlock()

	tx.mu.Lock()
	defer tx.mu.Unlock()

	// Apply sets
	for k, v := range tx.sets {
		tx.db.store[k] = append([]byte(nil), v...)
	}

	// Apply deletes
	for k := range tx.deletes {
		delete(tx.db.store, k)
	}

	tx.active = false
	return nil
}

// Discard aborts the transaction, discarding all pending changes.
func (tx *memoryWriteTx) Discard() {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.active = false
	// Clear pending changes
	tx.sets = nil
	tx.deletes = nil
}

// Unwrap allows unwrapping the WriteTx if needed.
func (tx *memoryWriteTx) Unwrap() db.WriteTx {
	return tx
}

// Ensure that MemoryDB implements db.Database and memoryWriteTx implements db.WriteTx.
var (
	_ db.Database = (*MemoryDB)(nil)
	_ db.WriteTx  = (*memoryWriteTx)(nil)
)
