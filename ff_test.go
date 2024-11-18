package arbo

import (
	"math/big"
	"testing"
)

func TestBigToFF(t *testing.T) {
	baseField := BN254BaseField
	iv := new(big.Int).Sub(baseField, big.NewInt(1))
	// test with iv < baseField (the result should be iv)
	z := BigToFF(baseField, iv)
	if z.Cmp(iv) != 0 {
		t.Fatalf("BigToFF failed: %v != %v", z, iv)
	}
	// test with iv > baseField (the result should be iv % baseField)
	iv = new(big.Int).Add(baseField, big.NewInt(1))
	z = BigToFF(baseField, iv)
	if z.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("BigToFF failed: %v != 0", z)
	}
	// test with iv == baseField (the result should be 0)
	iv = baseField
	z = BigToFF(baseField, iv)
	if z.Cmp(big.NewInt(0)) != 0 {
		t.Fatalf("BigToFF failed: %v != 0", z)
	}
}
