package gm

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSM2KeyGenerator(t *testing.T) {
	t.Parallel()

	kg := &sm2KeyGenerator{}

	k, err := kg.KeyGen(nil)
	assert.NoError(t, err)

	sk, ok := k.(*sm2PrivateKey)
	assert.True(t, ok)
	assert.NotNil(t, sk.privKey)
}

func TestSM4KeyGenerator(t *testing.T) {
	t.Parallel()

	kg := &sm4KeyGenerator{}

	k, err := kg.KeyGen(nil)
	assert.NoError(t, err)

	sk, ok := k.(*sm4PrivateKey)
	assert.True(t, ok)
	assert.NotNil(t, sk.key)
	assert.Equal(t, len(sk.key), 16)
}
