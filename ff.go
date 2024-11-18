package arbo

import "math/big"

var (
	// BN254BaseField is the base field for the BN254 curve.
	BN254BaseField, _ = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	// BLS12377BaseField is the base field for the BLS12377 curve.
	BLS12377BaseField, _ = new(big.Int).SetString("25825498262808887005865186224201665565126143020923472090132963926938185026661", 10)
)

// BigToFF function returns the finite field representation of the big.Int
// provided. It uses the curve scalar field to represent the provided number.
func BigToFF(baseField, iv *big.Int) *big.Int {
	z := big.NewInt(0)
	if c := iv.Cmp(baseField); c == 0 {
		return z
	} else if c != 1 && iv.Cmp(z) != -1 {
		return iv
	}
	return z.Mod(iv, baseField)
}
