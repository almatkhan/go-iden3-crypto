package babyjub

import (
	"crypto/rand"
	"math/big"

	"github.com/almatkhan/go-iden3-crypto/poseidon"
)

type SchnorrSignature struct {
	R8 *Point
	S  *big.Int
}

func (sk *PrivateKey) SchnorrSign(msg *big.Int) *SchnorrSignature {
	// Choose random nonce (r)
	k, _ := rand.Int(rand.Reader, SubOrder)
	R8 := NewPoint().Mul(k, B8)

	// Compute challenge (e)
	hmInput := []*big.Int{msg, R8.X, R8.Y}
	e, err := poseidon.Hash(hmInput)
	if err != nil {
		panic(err)
	}
	e.Mod(e, SubOrder)

	// Compute s = k + e * sk (mod SubOrder)
	S := new(big.Int).Lsh(sk.RawScalar(), 3)
	S = S.Mul(S, e)
	S.Add(S, k)
	S.Mod(S, SubOrder)

	return &SchnorrSignature{R8: R8, S: S}
}

func (pk *PublicKey) SchnorrVerify(msg *big.Int, sig *SchnorrSignature) (*Point, bool) {
	// Compute challenge (e)
	hmInput := []*big.Int{msg, sig.R8.X, sig.R8.Y}
	e, err := poseidon.Hash(hmInput)
	if err != nil {
		panic(err)
	}

	e.Mul(big.NewInt(8), e)
	e.Mod(e, SubOrder)

	// Compute S * 8 * B (left side of the equation)
	R8s := NewPoint().Mul(sig.S, B8)

	// Compute e * P (right side of the equation)
	eP := NewPoint().Mul(e, pk.Point())

	// Recompute R' = S * G - e * P
	RPrime := NewPoint().Sub(R8s, eP)

	// Check if RPrime equals R8 from the signature
	return RPrime, RPrime.X.Cmp(sig.R8.X) == 0 && RPrime.Y.Cmp(sig.R8.Y) == 0
}

// RawScalar returns the private key as a big integer.
func (sk *PrivateKey) RawScalar() *big.Int {
	return new(big.Int).SetBytes(sk[:])
}

func (sk *PrivateKey) SchnorrPublicKey() *PublicKey {
	s := sk.RawScalar()
	p := new(Point).Mul(s, B8)
	return &PublicKey{X: p.X, Y: p.Y}
}
