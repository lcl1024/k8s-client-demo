package gm

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/common/gm"
	initX509 "github.com/hyperledger/fabric/common/x509"
	"github.com/stretchr/testify/assert"
)

var (
	tempDir string
)

func Provider(t *testing.T) (bccsp.BCCSP, bccsp.KeyStore, func()) {
	gm.InitGMPlugin("gmsm")
	td, err := ioutil.TempDir(tempDir, "test")
	assert.NoError(t, err)
	ks, err := NewFileBasedKeyStore(nil, td, false)
	assert.NoError(t, err)
	p, err := New(ks)
	assert.NoError(t, err)
	return p, ks, func() { os.RemoveAll(td) }
}

func TestMain(m *testing.M) {
	gm.InitGMPlugin("gmsm")
	initX509.InitX509("gmsm")
	var err error
	tempDir, err = ioutil.TempDir("", "bccsp-gm")
	if err != nil {
		fmt.Printf("Failed to create temporary directory: %s\n\n", err)
		os.Exit(-1)
	}
	defer os.RemoveAll(tempDir)
	m.Run()
	os.Exit(0)
}

func TestInvalidNewParameter(t *testing.T) {
	t.Parallel()
	_, ks, cleanup := Provider(t)
	defer cleanup()
	gm.InitGMPlugin("gmsm")
	r, err := New(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if r != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	_, err = New(ks)
	assert.NoError(t, err)
}

func TestInvalidSKI(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()

	k, err := provider.GetKey(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	k, err = provider.GetKey([]byte{0, 1, 2, 3, 4, 5, 6})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

func TestKeyGenNoOpts(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()

	// nil opts
	k, err := provider.KeyGen(nil)
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}

	// not gm opts
	k, err = provider.KeyGen(&bccsp.ECDSAKeyGenOpts{})
	if err == nil {
		t.Fatal("Error should be different from nil in this case")
	}
	if k != nil {
		t.Fatal("Return value should be equal to nil in this case")
	}
}

func TestKeyGenSM4Opts(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM4KeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("Failed generating SM4 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM4 key. Key must be different from nil")
	}

	sm4key := k.(*sm4PrivateKey).key
	if len(sm4key) != 16 {
		t.Fatal("AES Key generated key in invalid. The key must have length 16.")
	}
}

func TestKeyGenSM2Opts(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()

	k, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: true})
	if err != nil {
		t.Fatalf("Failed generating SM2 key [%s]", err)
	}
	if k == nil {
		t.Fatal("Failed generating SM2 key. Key must be different from nil")
	}
}

func TestGetHash(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()

	hasher, err := provider.GetHash(nil)
	assert.NoError(t, err)
	assert.NotNil(t, hasher)
}

func TestHash(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()

	msg := []byte("abc")
	digest, err := provider.Hash(msg, nil)
	assert.NoError(t, err)
	assert.NotNil(t, digest)

	//expectDigest,err := hex.DecodeString("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
	//assert.NoError(t, err)
	//assert.Equal(t, expectDigest, digest)
}

func TestSign(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()

	_, err := provider.Sign(nil, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid Key. It must not be nil.")

	_, err = provider.Sign(&sm2PrivateKey{}, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid digest. Cannot be empty.")

	digest, err := provider.Hash([]byte("abc"), nil)
	assert.NoError(t, err)
	assert.NotNil(t, digest)

	_, err = provider.Sign(&sm4PrivateKey{}, digest, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid private Key. PrivateKey must be sm2PrivateKey")

	_, err = provider.Sign(&sm2PrivateKey{}, digest, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid sm2PrivateKey Key. It's privKey must not be nil.")
}

func TestVerify(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()

	_, err := provider.Verify(nil, nil, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid Key. It must not be nil.")

	_, err = provider.Verify(&sm2PublicKey{}, nil, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid signature. Cannot be empty.")

	_, err = provider.Verify(&sm2PublicKey{}, []byte("abc"), nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid digest. Cannot be empty.")

	digest, err := provider.Hash([]byte("abc"), nil)
	assert.NoError(t, err)
	assert.NotNil(t, digest)

	_, err = provider.Verify(&sm2PrivateKey{}, digest, digest, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid public Key. PublicKey must be sm2PublicKey")

	_, err = provider.Verify(&sm2PublicKey{}, digest, digest, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid sm2PublicKey Key. It's pubKey must not be nil.")
}
func TestSignAndVerify(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()

	msg := []byte("abc")
	digest, err := provider.Hash(msg, nil)
	assert.NoError(t, err)
	assert.NotNil(t, digest)

	sk, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{Temporary: false})
	assert.NoError(t, err)
	//sign
	signature, err := provider.Sign(sk, digest, nil)
	assert.NoError(t, err)
	assert.NotNil(t, signature)
	//verify
	pk, err := sk.PublicKey()
	assert.NoError(t, err)
	valid, err := provider.Verify(pk, signature, digest, nil)
	assert.NoError(t, err)
	assert.Equal(t, true, valid)

	// another digest
	msg1 := []byte("abc1")
	digest1, err := provider.Hash(msg1, nil)
	assert.NoError(t, err)
	assert.NotNil(t, digest)
	valid, err = provider.Verify(pk, signature, digest1, nil)
	assert.NoError(t, err)
	assert.Equal(t, false, valid)
}

func TestEncrypt(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()
	msg := make([]byte, 16)
	copy(msg, []byte("abc"))

	_, err := provider.Encrypt(nil, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid Key. It must not be nil.")

	_, err = provider.Encrypt(&sm2PrivateKey{}, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid Key. It must be sm2PublicKey or sm4PrivateKey")

	_, err = provider.Encrypt(&sm4PrivateKey{}, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid sm4PrivateKey Key. It's key must not be nil.")

	_, err = provider.Encrypt(&sm2PublicKey{}, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid sm2PublicKey Key. It's pubKey must not be nil.")

}

func TestDecrypt(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()
	msg := make([]byte, 16)
	copy(msg, []byte("abc"))

	_, err := provider.Decrypt(nil, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid Key. It must not be nil.")

	_, err = provider.Decrypt(&sm2PublicKey{}, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid Key. It must be sm2PrivateKey or sm4PrivateKey")

	_, err = provider.Decrypt(&sm4PrivateKey{}, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid sm4PrivateKey Key. It's key must not be nil.")

	_, err = provider.Decrypt(&sm2PrivateKey{}, msg, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid sm2PrivateKey Key. It's privKey must not be nil.")

}

func TestSm4EncryptAndDecrypt(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()

	msg := make([]byte, 16)
	copy(msg, []byte("abc"))

	key, err := provider.KeyGen(&bccsp.SM4KeyGenOpts{})
	assert.NoError(t, err)
	ciphertext, err := provider.Encrypt(key, msg, nil)
	assert.NoError(t, err)

	msg1, err := provider.Decrypt(key, ciphertext, nil)
	assert.NoError(t, err)
	assert.Equal(t, msg1, msg)
}

func TestSm2EncryptAndDecrypt(t *testing.T) {
	t.Parallel()
	provider, _, cleanup := Provider(t)
	defer cleanup()

	msg := make([]byte, 16)
	copy(msg, []byte("abc"))

	key, err := provider.KeyGen(&bccsp.SM2KeyGenOpts{})
	assert.NoError(t, err)

	pubKey, err := key.PublicKey()
	assert.NoError(t, err)
	ciphertext, err := provider.Encrypt(pubKey, msg, nil)
	assert.NoError(t, err)

	msg1, err := provider.Decrypt(key, ciphertext, nil)
	assert.NoError(t, err)
	assert.Equal(t, msg1, msg)
}
