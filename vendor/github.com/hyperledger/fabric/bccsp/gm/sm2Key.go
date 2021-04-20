package gm

import (
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/gm"
	"github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric/x509"
)

type sm2PrivateKey struct {
	privKey *crypto.PrivateKey
}

func (k *sm2PrivateKey) Bytes() ([]byte, error) {
	return nil, errors.New("Not supported.")
}

func (k *sm2PrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}

	raw := elliptic.Marshal(k.privKey.Curve, k.privKey.X, k.privKey.Y)

	// Hash it
	hash := gm.NewSm3().New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (k *sm2PrivateKey) Symmetric() bool {
	return false
}

func (k *sm2PrivateKey) Private() bool {
	return true
}

func (k *sm2PrivateKey) PublicKey() (bccsp.Key, error) {
	return &sm2PublicKey{&k.privKey.PublicKey}, nil
}

type sm2PublicKey struct {
	pubKey *crypto.PublicKey
}

func (k *sm2PublicKey) Bytes() ([]byte, error) {
	raw, err := x509.MarshalPKIXPublicKey(k.pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed marshalling key [%s]", err)
	}
	return raw, nil
}

func (k *sm2PublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}
	raw := elliptic.Marshal(k.pubKey.Curve, k.pubKey.X, k.pubKey.Y)

	// Hash it
	hash := gm.NewSm3().New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (k *sm2PublicKey) Symmetric() bool {
	return false
}

func (k *sm2PublicKey) Private() bool {
	return false
}

func (k *sm2PublicKey) PublicKey() (bccsp.Key, error) {
	return k, nil
}
