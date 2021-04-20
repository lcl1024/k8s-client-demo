package gm

import (
	"bytes"
	"testing"
)

func TestSM4Key(t *testing.T) {
	generator := sm4KeyGenerator{}
	k, err := generator.KeyGen(nil)
	if err != nil {
		t.Fatal("Error should be nil")
	}
	sm4key := k.(*sm4PrivateKey).key
	if len(sm4key) != 16 {
		t.Fatal("AES Key generated key in invalid. The key must have length 16.")
	}

	keyBytes, err := k.Bytes()
	if err != nil {
		t.Fatal("Error should be nil")
	}
	if !bytes.Equal(sm4key, keyBytes) {
		t.Fatal("SM4PrivateKey Bytes should equal to its key")
	}

	if !k.Private() {
		t.Fatal("Failed generating SM4 key. Key should be private")
	}
	if !k.Symmetric() {
		t.Fatal("Failed generating SM4 key. Key should be symmetric")
	}

	pk, err := k.PublicKey()
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if pk != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}
