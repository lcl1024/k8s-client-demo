package crypto

import (
	"crypto/elliptic"
	"math/big"
)

// PublicKey represents an elliptic curve public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// PrivateKey represents an elliptic curve private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}
