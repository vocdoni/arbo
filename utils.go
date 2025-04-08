package arbo

import "math/big"

// SwapEndianness swaps the order of the bytes in the byte slice.
func SwapEndianness(b []byte) []byte {
	o := make([]byte, len(b))
	for i := range b {
		o[len(b)-1-i] = b[i]
	}
	return ExplicitZero(o)
}

// BigIntToBytes converts a *big.Int into a byte array in Little-Endian
func BigIntToBytes(blen int, bi *big.Int) []byte {
	// TODO make the length depending on the tree.hashFunction.Len()
	b := make([]byte, blen)
	copy(b[:], SwapEndianness(bi.Bytes()))
	return b[:]
}

// BytesToBigInt converts a byte array in Little-Endian representation into
// *big.Int
func BytesToBigInt(b []byte) *big.Int {
	return new(big.Int).SetBytes(SwapEndianness(b))
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
