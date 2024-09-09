package babyjub

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/almatkhan/go-iden3-crypto/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScnhorrSignVerify(t *testing.T) {
	skString := "a78c9f2658379b856e171187218d39be75124a1d7f1b49cf2474e355a682e9e9"
	b, err := hex.DecodeString(skString)
	require.Nil(t, err)
	sk := new(PrivateKey) // Private key
	copy(sk[:], b)

	msg := "0123456789012345678901234567890123456789"
	msgBuf, err := hex.DecodeString(msg)
	require.Nil(t, err)
	msgInt := utils.SetBigIntFromLEBytes(new(big.Int), msgBuf) // Message

	sig := sk.SchnorrSign(msgInt)

	// Print the signature
	fmt.Printf("\n+++Signature+++\nRx: %s\nRy: %s\nS: %s\n+++", sig.R8.X.String(), sig.R8.Y.String(), sig.S.String())

	// Print public key
	fmt.Printf("\n---Public Key---\nX: %s\nY: %s\n---", sk.Public().X.String(), sk.Public().Y.String())

	// Print private key
	fmt.Printf("\nxxxPrivateKeyxxx\n %s\nxxx\n", sk.Scalar().BigInt().Text(10))

	// Verify the signature
	point, ok := sk.SchnorrPublicKey().SchnorrVerify(msgInt, sig)
	assert.Equal(t, true, ok)

	// Print the point
	fmt.Printf("\n+++Point+++\nX: %s\nY: %s\n+++", point.X.String(), point.Y.String())

}
