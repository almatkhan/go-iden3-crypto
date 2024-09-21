// Package babyjub eddsa implements the EdDSA over the BabyJubJub curve
//
//nolint:gomnd
package babyjub

import (
	"crypto/rand"
	"database/sql/driver"
	"fmt"
	"log"
	"math/big"

	"github.com/almatkhan/go-iden3-crypto/mimc7"
	"github.com/almatkhan/go-iden3-crypto/poseidon"
	"github.com/almatkhan/go-iden3-crypto/utils"
)

const MaxAltBn128ValueString = "21888242871839275222246405745257275088548364400416034343698204186575808495617"

// pruneBuffer prunes the buffer during key generation according to RFC 8032.
// https://tools.ietf.org/html/rfc8032#page-13
func pruneBuffer(buf *[32]byte) *[32]byte {
	buf[0] &= 0xF8
	buf[31] &= 0x7F
	buf[31] |= 0x40
	return buf
}

// PrivateKey is an EdDSA private key, which is a 32byte buffer.
type PrivateKey [32]byte

// NewFromBytes creates a new PrivateKey from a big-endian byte slice.
func NewFromBytes(buf []byte) *PrivateKey {
	var k PrivateKey
	input := PadTruncateTo32Bytes(buf)
	copy(k[:], input)
	return &k
}

// NewRandPrivKey generates a new random private key (using cryptographically
// secure randomness).
func NewRandPrivKey() PrivateKey {
	var k PrivateKey
	_, err := rand.Read(k[:])
	if err != nil {
		panic(err)
	}
	return k
}

// Scalar converts a private key into the scalar value s following the EdDSA
// standard, and using blake-512 hash.
func (sk *PrivateKey) Scalar() *PrivKeyScalar {
	s := SkToRawBigInt(sk)
	return NewPrivKeyScalar(s)
}

// SkToRawBigInt converts a private key into the *big.Int value.
func SkToRawBigInt(sk *PrivateKey) *big.Int {
	return big.NewInt(0).SetBytes(sk[:])
}

// SkToPoseidonHash converts a private key into the *big.Int value hashing it
// with Poseidon. This is not secure, but this way we make sure that the
// key is compatible with ZoKrates.
func SkToPoseidonHash(sk *PrivateKey) *big.Int {
	s := new(big.Int).SetBytes(sk[:])
	h, _ := poseidon.Hash([]*big.Int{s})
	return h
}

// SkToBigInt converts a private key into the *big.Int value following the
// EdDSA standard, and using blake-512 hash
func SkToBigInt(sk *PrivateKey) *big.Int {
	sBuf := Blake512(sk[:])
	sBuf32 := [32]byte{}
	copy(sBuf32[:], sBuf[:32])
	pruneBuffer(&sBuf32)
	s := new(big.Int)
	utils.SetBigIntFromLEBytes(s, sBuf32[:])
	s.Rsh(s, 3)
	return s
}

// Public returns the public key corresponding to a private key.
func (sk *PrivateKey) Public() *PublicKey {
	return sk.Scalar().Public()
}

// PrivKeyScalar represents the scalar s output of a private key
type PrivKeyScalar big.Int

// NewPrivKeyScalar creates a new PrivKeyScalar from a big.Int
func NewPrivKeyScalar(s *big.Int) *PrivKeyScalar {
	sk := PrivKeyScalar(*s)
	return &sk
}

// Public returns the public key corresponding to the scalar value s of a
// private key.
func (s *PrivKeyScalar) Public() *PublicKey {
	p := NewPoint().Mul(s.BigInt(), B8)
	pk := PublicKey(*p)
	return &pk
}

// BigInt returns the big.Int corresponding to a PrivKeyScalar.
func (s *PrivKeyScalar) BigInt() *big.Int {
	return (*big.Int)(s)
}

// PublicKey represents an EdDSA public key, which is a curve point.
type PublicKey Point

// MarshalText implements the marshaler for PublicKey
func (pk PublicKey) MarshalText() ([]byte, error) {
	pkc := pk.Compress()
	return utils.Hex(pkc[:]).MarshalText()
}

// String returns the string representation of the PublicKey
func (pk PublicKey) String() string {
	pkc := pk.Compress()
	return utils.Hex(pkc[:]).String()
}

// UnmarshalText implements the unmarshaler for the PublicKey
func (pk *PublicKey) UnmarshalText(h []byte) error {
	var pkc PublicKeyComp
	if err := utils.HexDecodeInto(pkc[:], h); err != nil {
		return err
	}
	pkd, err := pkc.Decompress()
	if err != nil {
		return err
	}
	*pk = *pkd
	return nil
}

// Point returns the Point corresponding to a PublicKey.
func (pk *PublicKey) Point() *Point {
	return (*Point)(pk)
}

// PublicKeyComp represents a compressed EdDSA Public key; it's a compressed curve
// point.
type PublicKeyComp [32]byte

// MarshalText implements the marshaler for the PublicKeyComp
func (pkComp PublicKeyComp) MarshalText() ([]byte, error) {
	return utils.Hex(pkComp[:]).MarshalText()
}

// String returns the string representation of the PublicKeyComp
func (pkComp PublicKeyComp) String() string { return utils.Hex(pkComp[:]).String() }

// UnmarshalText implements the unmarshaler for the PublicKeyComp
func (pkComp *PublicKeyComp) UnmarshalText(h []byte) error {
	return utils.HexDecodeInto(pkComp[:], h)
}

// Compress returns the PublicKeyCompr for the given PublicKey
func (pk *PublicKey) Compress() PublicKeyComp {
	return PublicKeyComp((*Point)(pk).Compress())
}

// Decompress returns the PublicKey for the given PublicKeyComp
func (pkComp *PublicKeyComp) Decompress() (*PublicKey, error) {
	point, err := NewPoint().Decompress(*pkComp)
	if err != nil {
		return nil, err
	}
	pk := PublicKey(*point)
	return &pk, nil
}

// Signature represents an EdDSA uncompressed signature.
type Signature struct {
	R8 *Point
	S  *big.Int
}

// SignatureComp represents a compressed EdDSA signature.
type SignatureComp [64]byte

// MarshalText implements the marshaler for the SignatureComp
func (sComp SignatureComp) MarshalText() ([]byte, error) {
	return utils.Hex(sComp[:]).MarshalText()
}

// String returns the string representation of the SignatureComp
func (sComp SignatureComp) String() string { return utils.Hex(sComp[:]).String() }

// UnmarshalText implements the unmarshaler for the SignatureComp
func (sComp *SignatureComp) UnmarshalText(h []byte) error {
	return utils.HexDecodeInto(sComp[:], h)
}

// Compress an EdDSA signature by concatenating the compression of
// the point R8 and the Little-Endian encoding of S.
func (s *Signature) Compress() SignatureComp {
	R8p := s.R8.Compress()
	Sp := utils.BigIntLEBytes(s.S)
	buf := [64]byte{}
	copy(buf[:32], R8p[:])
	copy(buf[32:], Sp[:])
	return SignatureComp(buf)
}

// Decompress a compressed signature into s, and also returns the decompressed
// signature.  Returns error if the Point decompression fails.
func (s *Signature) Decompress(buf [64]byte) (*Signature, error) {
	R8p := [32]byte{}
	copy(R8p[:], buf[:32])
	var err error
	if s.R8, err = NewPoint().Decompress(R8p); err != nil {
		return nil, err
	}
	s.S = utils.SetBigIntFromLEBytes(new(big.Int), buf[32:])
	return s, nil
}

// Decompress a compressed signature.  Returns error if the Point decompression
// fails.
func (sComp *SignatureComp) Decompress() (*Signature, error) {
	return new(Signature).Decompress(*sComp)
}

// Scan implements Scanner for database/sql.
func (sComp *SignatureComp) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into Signature", src)
	}
	if len(srcB) != 64 {
		return fmt.Errorf("can't scan []byte of len %d into Signature, want %d", len(srcB), 64)
	}
	copy(sComp[:], srcB)
	return nil
}

// Value implements valuer for database/sql.
func (sComp SignatureComp) Value() (driver.Value, error) {
	return sComp[:], nil
}

// Scan implements Scanner for database/sql.
func (s *Signature) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into Signature", src)
	}
	if len(srcB) != 64 {
		return fmt.Errorf("can't scan []byte of len %d into Signature, want %d", len(srcB), 64)
	}
	buf := [64]byte{}
	copy(buf[:], srcB)
	_, err := s.Decompress(buf)
	return err
}

// Value implements valuer for database/sql.
func (s Signature) Value() (driver.Value, error) {
	comp := s.Compress()
	return comp[:], nil
}

// SignMimc7 signs a message encoded as a big.Int in Zq using blake-512 hash
// for buffer hashing and mimc7 for big.Int hashing.
func (sk *PrivateKey) SignMimc7(msg *big.Int) *Signature {
	h1 := Blake512(sk[:])
	msgBuf := utils.BigIntLEBytes(msg)
	msgBuf32 := [32]byte{}
	copy(msgBuf32[:], msgBuf[:])
	rBuf := Blake512(append(h1[32:], msgBuf32[:]...))
	r := utils.SetBigIntFromLEBytes(new(big.Int), rBuf) // r = H(H_{32..63}(k), msg)
	r.Mod(r, SubOrder)
	R8 := NewPoint().Mul(r, B8) // R8 = r * 8 * B
	A := sk.Public().Point()
	hmInput := []*big.Int{R8.X, R8.Y, A.X, A.Y, msg}
	hm, err := mimc7.Hash(hmInput, nil) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)
	if err != nil {
		panic(err)
	}
	S := new(big.Int).Lsh(sk.Scalar().BigInt(), 3)
	S = S.Mul(hm, S)
	S.Add(r, S)
	S.Mod(S, SubOrder) // S = r + hm * 8 * s

	return &Signature{R8: R8, S: S}
}

// VerifyMimc7 verifies the signature of a message encoded as a big.Int in Zq
// using blake-512 hash for buffer hashing and mimc7 for big.Int hashing.
func (pk *PublicKey) VerifyMimc7(msg *big.Int, sig *Signature) bool {
	hmInput := []*big.Int{sig.R8.X, sig.R8.Y, pk.X, pk.Y, msg}
	hm, err := mimc7.Hash(hmInput, nil) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)
	if err != nil {
		return false
	}

	left := NewPoint().Mul(sig.S, B8) // left = s * 8 * B
	r1 := big.NewInt(8)
	r1.Mul(r1, hm)
	right := NewPoint().Mul(r1, pk.Point())
	rightProj := right.Projective()
	rightProj.Add(sig.R8.Projective(), rightProj) // right = 8 * R + 8 * hm * A
	right = rightProj.Affine()
	return (left.X.Cmp(right.X) == 0) && (left.Y.Cmp(right.Y) == 0)
}

// SignPoseidon signs a message encoded as a big.Int in Zq using blake-512 hash
// for buffer hashing and Poseidon for big.Int hashing.
func (sk *PrivateKey) SignPoseidon(msg *big.Int) *Signature {
	h1 := Blake512(sk[:])
	msgBuf := utils.BigIntLEBytes(msg)
	msgBuf32 := [32]byte{}
	copy(msgBuf32[:], msgBuf[:])
	rBuf := Blake512(append(h1[32:], msgBuf32[:]...))
	r := utils.SetBigIntFromLEBytes(new(big.Int), rBuf) // r = H(H_{32..63}(k), msg)
	r.Mod(r, SubOrder)

	R8 := NewPoint().Mul(r, B8) // R8 = r * 8 * B

	A := sk.Public().Point()

	hmInput := []*big.Int{R8.X, R8.Y, A.X, A.Y, msg}
	hm, err := poseidon.Hash(hmInput) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)
	if err != nil {
		panic(err)
	}

	S := sk.Scalar().BigInt()
	S = S.Mul(hm, S)
	S.Add(r, S)
	S.Mod(S, SubOrder) // S = r + hm * s

	return &Signature{R8: R8, S: S}
}

// VerifyPoseidon verifies the signature of a message encoded as a big.Int in Zq
// using blake-512 hash for buffer hashing and Poseidon for big.Int hashing.
func (pk *PublicKey) VerifyPoseidon(msg *big.Int, sig *Signature) bool {
	hmInput := []*big.Int{sig.R8.X, sig.R8.Y, pk.X, pk.Y, msg}
	hm, err := poseidon.Hash(hmInput) // hm = H1(8*R.x, 8*R.y, A.x, A.y, msg)
	if err != nil {
		return false
	}

	left := NewPoint().Mul(sig.S, B8) // left = s * 8 * B

	right := NewPoint().Mul(hm, pk.Point())
	rightProj := right.Projective()
	rightProj.Add(sig.R8.Projective(), rightProj) // right = 8 * R + 8 * hm * A
	right = rightProj.Affine()

	return (left.X.Cmp(right.X) == 0) && (left.Y.Cmp(right.Y) == 0)
}

// Scan implements Scanner for database/sql.
func (pk *PublicKey) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into PublicKey", src)
	}
	if len(srcB) != 32 {
		return fmt.Errorf("can't scan []byte of len %d into PublicKey, want %d", len(srcB), 32)
	}
	var comp PublicKeyComp
	copy(comp[:], srcB)
	decomp, err := comp.Decompress()
	if err != nil {
		return err
	}
	*pk = *decomp
	return nil
}

// Value implements valuer for database/sql.
func (pk PublicKey) Value() (driver.Value, error) {
	comp := pk.Compress()
	return comp[:], nil
}

// Scan implements Scanner for database/sql.
func (pkComp *PublicKeyComp) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into PublicKeyComp", src)
	}
	if len(srcB) != 32 {
		return fmt.Errorf("can't scan []byte of len %d into PublicKeyComp, want %d", len(srcB), 32)
	}
	copy(pkComp[:], srcB)
	return nil
}

// Value implements valuer for database/sql.
func (pkComp PublicKeyComp) Value() (driver.Value, error) {
	return pkComp[:], nil
}

func (sk *PrivateKey) BlindSign(msg *big.Int) (*Signature, error) {
	// Get Bob's public Key derived from the private key
	bobPublicKey := sk.Public().Point()

	// Step 1: Bob generates random nonce bobK and computes R = bobK*G (mod P)
	bobK, _ := rand.Int(rand.Reader, SubOrder)
	bobR8 := NewPoint().Mul(bobK, B8)

	fmt.Println("bobK:", bobK)

	// Send R8 to Alice

	// Step 2.1: Alice picks random a, b and computes
	a, _ := rand.Int(rand.Reader, SubOrder)
	b, _ := rand.Int(rand.Reader, SubOrder)

	fmt.Println("a:", a)
	fmt.Println("b:", b)

	fmt.Println("total nonce:", new(big.Int).Add(a, b))

	// Step 2.2: Alice computes R' = 8*R + a*G + b*P
	// 		Compute a*G and b*P
	aG := NewPoint().Mul(a, B8)
	// bP := NewPoint().Mul(b, bobPublicKey)

	// R' = R8 + a*G + b*P
	RPrime := NewPoint().Set(bobR8)
	RPrimeProj := RPrime.Projective()
	RPrimeProj.Add(aG.Projective(), RPrimeProj)
	RPrime = RPrimeProj.Affine()

	// Step 2.3: Alice computes e' = H(R' || P || M) using the modulo Poseidon Hash
	hmInput := []*big.Int{RPrime.X, RPrime.Y, bobPublicKey.X, bobPublicKey.Y, msg}
	ePrime, err := poseidon.Hash(hmInput)
	if err != nil {
		return nil, fmt.Errorf("error hashing message: %v", err)
	}

	// log.Printf("hmInput: %v", hmInput)
	log.Printf("ePrime: %v", ePrime)

	// Compute e = e' + b mod q
	// e := new(big.Int).Add(ePrime, b)
	// e.Mod(e, SubOrder)
	e := new(big.Int).Set(ePrime)

	// Alice sends e to Bob

	// Step 3: Bob computes s = e*x + k mod q
	S := new(big.Int).Lsh(sk.Scalar().BigInt(), 3)
	S = S.Mul(e, S)
	S.Add(bobK, S)
	S.Mod(S, SubOrder)

	// Bob sends s to Alice

	// Step 4: Alice computes s' = s + a mod q
	sprime := new(big.Int).Add(S, a)
	sprime.Mod(sprime, SubOrder)

	// The pair (R', s') is a valid signature
	fmt.Println("Signature Rx':", RPrime.X)
	fmt.Println("Signature Ry':", RPrime.Y)
	// fmt.Println("Signature s':", sprime)

	fmt.Println("Signature s':", S)

	return &Signature{R8: RPrime, S: S}, nil
}

// PadTruncateTo32Bytes pads any byte slice shorter than 32 bytes with leading zeros
// or truncates any byte slice longer than 32 bytes by keeping the last 32 bytes.
// If the input is exactly 32 bytes, it returns the input unchanged.
func PadTruncateTo32Bytes(input []byte) []byte {
	const targetLength = 32
	inputLen := len(input)

	if inputLen == targetLength {
		// Input is already 32 bytes; return as is.
		return input
	} else if inputLen < targetLength {
		// Input is shorter than 32 bytes; pad with leading zeros.
		padded := make([]byte, targetLength)
		leadingZeros := targetLength - inputLen
		copy(padded[leadingZeros:], input)
		return padded
	} else {
		// Input is longer than 32 bytes; truncate by keeping the last 32 bytes.
		return input[inputLen-targetLength:]
	}
}
