package gm

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/hyperledger/fabric/common/gm"
	"github.com/stretchr/testify/assert"
)

func TestInvalidStoreKey(t *testing.T) {
	t.Parallel()

	tempDir, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(tempDir)

	ks, err := NewFileBasedKeyStore(nil, filepath.Join(tempDir, "bccspks"), false)
	if err != nil {
		fmt.Printf("Failed initiliazing KeyStore [%s]", err)
		os.Exit(-1)
	}

	err = ks.StoreKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm2PrivateKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm2PublicKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}

	err = ks.StoreKey(&sm4PrivateKey{nil})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
}

func TestSm2KeyFile(t *testing.T) {
	ksPath, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedKeyStore(nil, ksPath, false)
	assert.NoError(t, err)

	// Generate a key for keystore to find
	privKey, err := gm.NewSm2().GenerateKey()
	assert.NoError(t, err)

	cspKey := &sm2PrivateKey{privKey}
	ski := cspKey.SKI()

	err = ks.StoreKey(cspKey)
	assert.NoError(t, err)

	k, err := ks.GetKey(ski)
	assert.NoError(t, err)
	if sk, ok := k.(*sm2PrivateKey); !ok {
		t.Fatal("It should be sm2PrivateKey instance!")
	} else if sk.privKey.D.Cmp(privKey.D) != 0 {
		t.Fatal("It shouble be equal to the origin private key!")
	}

}

func TestSm4KeyFile(t *testing.T) {
	ksPath, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedKeyStore(nil, ksPath, false)
	assert.NoError(t, err)

	// Generate a key for keystore to find
	privKey, err := getRandomBytes(16)
	assert.NoError(t, err)

	cspKey := &sm4PrivateKey{privKey}
	ski := cspKey.SKI()

	err = ks.StoreKey(cspKey)
	assert.NoError(t, err)

	k, err := ks.GetKey(ski)
	assert.NoError(t, err)
	if sk, ok := k.(*sm4PrivateKey); !ok {
		t.Fatal("It should be sm2PrivateKey instance!")
	} else {
		assert.Equal(t, sk.key, privKey)
	}
}

func TestReInitKeyStore(t *testing.T) {
	ksPath, err := ioutil.TempDir("", "bccspks")
	assert.NoError(t, err)
	defer os.RemoveAll(ksPath)

	ks, err := NewFileBasedKeyStore(nil, ksPath, false)
	assert.NoError(t, err)
	fbKs, isFileBased := ks.(*fileBasedKeyStore)
	assert.True(t, isFileBased)
	err = fbKs.Init(nil, ksPath, false)
	assert.EqualError(t, err, "KeyStore already initilized.")
}
