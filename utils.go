package arbo

import (
	"math"
	"math/big"
)

// SwapEndianness swaps the order of the bytes in the byte slice.
func SwapEndianness(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[len(b)-1-i] = b[i]
	}
	return o
}

// BigIntToBytes converts a *big.Int into a byte array in Little-Endian
func BigIntToBytes(blen int, bi *big.Int) []byte {
	// TODO make the length depending on the tree.hashFunction.Len()
	b := make([]byte, blen)
	copy(b[:], ExplicitZero(SwapEndianness(bi.Bytes())))
	return b[:]
}

// BytesToBigInt converts a byte array in Little-Endian representation into
// *big.Int
func BytesToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(ExplicitZero(SwapEndianness(b)))
}

// ExplicitZero returns a byte slice with a single zero byte if the input slice
// is empty. This is useful for ensuring that a zero value is always returned
// instead of a nil slice, for example for big.Int zero values.
func ExplicitZero(b []byte) []byte {
	if len(b) == 0 {
		return []byte{0}
	}
	return b
}

// MaxKeyLen returns the maximum length of the key in bytes. It is calculated
// as the minimum between the length of the hash function provided and the
// number of levels in a tree provided divided by 8. This is used to limit the
// size of the keys in a tree.
func MaxKeyLen(levels, hashLen int) int {
	return min(int(math.Ceil(float64(levels)/float64(8))), hashLen)
}
