package gmsm

import (
	"unsafe"

	"github.com/hyperledger/fabric/crypto"
	"github.com/tjfoc/gmsm/sm2"
)

func toSm2PrivateKey(priv *crypto.PrivateKey) *sm2.PrivateKey {
	return (*sm2.PrivateKey)(unsafe.Pointer(priv))
}

func toCryptoPrivateKey(priv *sm2.PrivateKey) *crypto.PrivateKey {
	return (*crypto.PrivateKey)(unsafe.Pointer(priv))

}

func toSm2PublicKey(pub *crypto.PublicKey) *sm2.PublicKey {
	return (*sm2.PublicKey)(unsafe.Pointer(pub))
}

func toCryptoPublicKey(pub *sm2.PublicKey) *crypto.PublicKey {
	return (*crypto.PublicKey)(unsafe.Pointer(pub))

}
