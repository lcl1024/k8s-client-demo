package gm

import (
	"errors"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/gm"
)

type sm4PrivateKey struct {
	key []byte
}

func (k *sm4PrivateKey) Bytes() (raw []byte, err error) {
	return k.key, nil
}

func (k *sm4PrivateKey) SKI() (ski []byte) {
	// Hash it
	hash := gm.NewSm3().New()
	hash.Write(k.key)
	return hash.Sum(nil)
}

func (k *sm4PrivateKey) Symmetric() bool {
	return true
}

func (k *sm4PrivateKey) Private() bool {
	return true
}

func (k *sm4PrivateKey) PublicKey() (bccsp.Key, error) {
	return nil, errors.New("Cannot call this method on a symmetric key.")
}
