package gm

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSM2PrivateKey(t *testing.T) {
	generator := sm2KeyGenerator{}
	k, err := generator.KeyGen(nil)

	if !k.Private() {
		t.Fatal("Failed generating SM2 key. Key should be private")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating SM2 key. Key should be asymmetric")
	}

	if len(k.SKI()) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}

	_, err = k.Bytes()
	assert.Error(t, err, "Not supported.")

	pk, err := k.PublicKey()
	assert.NoError(t, err)

	if _, ok := pk.(*sm2PublicKey); !ok {
		t.Fatal("PublicKey of sm2PrivateKey must be sm2PublicKey instance")
	}
}

func TestSm2PublicKey(t *testing.T) {
	var pk *sm2PublicKey
	var ok bool

	generator := sm2KeyGenerator{}
	sk, err := generator.KeyGen(nil)
	k, err := sk.PublicKey()
	assert.NoError(t, err)

	if pk, ok = k.(*sm2PublicKey); !ok {
		t.Fatal("PublicKey of sm2PrivateKey must be sm2PublicKey instance")
	}

	pkBytes, err := pk.Bytes()
	assert.NoError(t, err)

	if len(pkBytes) == 0 {
		t.Fatal("the length of PublicKey's Byte() should not be zero")
	}

	if k.Private() {
		t.Fatal("Failed generating SM2 key. Key should be public")
	}
	if k.Symmetric() {
		t.Fatal("Failed generating SM2 key. Key should be asymmetric")
	}

	if len(k.SKI()) == 0 {
		t.Fatal("SKI not valid. Zero length.")
	}
	assert.Equal(t, sk.SKI(), k.SKI())
}
