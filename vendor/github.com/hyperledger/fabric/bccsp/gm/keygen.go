package gm

import (
	"crypto/rand"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/gm"
)

func getRandomBytes(len int) ([]byte, error) {
	key := make([]byte, len)

	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}

	return key, nil
}

type sm4KeyGenerator struct{}

func (kg *sm4KeyGenerator) KeyGen(_ bccsp.KeyGenOpts) (bccsp.Key, error) {
	key, err := getRandomBytes(16)
	if err != nil {
		return nil, fmt.Errorf("Failed generating sm4 %d key [%s]", 16, err)
	}

	return &sm4PrivateKey{key}, nil
}

type sm2KeyGenerator struct{}

func (kg *sm2KeyGenerator) KeyGen(_ bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	key, err := gm.NewSm2().GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("Failed generating sm2 key [%s]", err)
	}
	if key == nil {
		return nil, fmt.Errorf("Failed generating sm2 key")
	}
	return &sm2PrivateKey{key}, nil
}
