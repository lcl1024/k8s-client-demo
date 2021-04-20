package gm

import (
	"testing"

	mocks2 "github.com/hyperledger/fabric/bccsp/mocks"
	"github.com/hyperledger/fabric/x509"
	"github.com/stretchr/testify/assert"
)

func TestSm4ImportKeyOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := sm4KeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid Key Length [")

	sm4Bytes := make([]byte, 16)
	sm4Key, err := ki.KeyImport(sm4Bytes, &mocks2.KeyImportOpts{})
	assert.NoError(t, err)
	assert.NotNil(t, sm4Key)

	if sk, ok := sm4Key.(*sm4PrivateKey); !ok {
		t.Fatal("It should be *sm4PrivateKey type")
	} else {
		assert.Equal(t, sm4Bytes, sk.key)
	}
}

func TestSm2PrivateKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := sm2PrivateKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected byte array.")

	_, err = ki.KeyImport([]byte(nil), &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw. It must not be nil.")

	_, err = ki.KeyImport([]byte{0}, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Failed converting PKIX to sm2 private key")
}

func TestSm2PublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := sm2PublicKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Certificate's public key type not recognized. Supported keys: sm")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Certificate's public key type not recognized. Supported keys: sm")
}

func TestX509PublicKeyImportOptsKeyImporter(t *testing.T) {
	t.Parallel()

	ki := x509PublicKeyImporter{}

	_, err := ki.KeyImport("Hello World", &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected *x509.Certificate.")

	_, err = ki.KeyImport(nil, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Invalid raw material. Expected *x509.Certificate.")

	cert := &x509.Certificate{}
	cert.PublicKey = "Hello world"
	_, err = ki.KeyImport(cert, &mocks2.KeyImportOpts{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "Certificate's public key type not recognized. Supported keys: sm2")
}
