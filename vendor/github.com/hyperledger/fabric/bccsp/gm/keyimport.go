package gm

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"unsafe"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/utils"
	"github.com/hyperledger/fabric/crypto"
	"github.com/hyperledger/fabric/x509"
)

type sm4KeyImporter struct{}

func (*sm4KeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	sm4Raw, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected byte array.")
	}

	if sm4Raw == nil {
		return nil, errors.New("Invalid raw material. It must not be nil.")
	}

	if len(sm4Raw) != 16 {
		return nil, fmt.Errorf("Invalid Key Length [%d]. Must be 16 bytes", len(sm4Raw))
	}

	return &sm4PrivateKey{utils.Clone(sm4Raw)}, nil
}

type sm2PrivateKeyImporter struct{}

func (*sm2PrivateKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	der, ok := raw.([]byte)
	if !ok {
		return nil, errors.New("[sm2PrivateKeyImporter] Invalid raw material. Expected byte array.")
	}

	if len(der) == 0 {
		return nil, errors.New("[sm2PrivateKeyImporter] Invalid raw. It must not be nil.")
	}

	privKey, err := utils.DERToPrivateKey(der)
	if err != nil || privKey == nil {
		return nil, fmt.Errorf("Failed converting PKIX to sm2 private key [%s]", err)
	}

	sk, ok := privKey.(*crypto.PrivateKey)
	if !ok {
		return nil, errors.New("Failed casting to sm2 private key. Invalid raw material.")
	}

	return &sm2PrivateKey{privKey: sk}, nil

}

type sm2PublicKeyImporter struct{}

func (*sm2PublicKeyImporter) KeyImport(pk interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	switch pk.(type) {
	case *crypto.PublicKey:
		pkk := pk.(*crypto.PublicKey)
		return &sm2PublicKey{pkk}, nil
	case *ecdsa.PublicKey:
		ecdsaPk := pk.(*ecdsa.PublicKey)
		pkk := (*crypto.PublicKey)(unsafe.Pointer(ecdsaPk))
		return &sm2PublicKey{pkk}, nil
	default:
		return nil, errors.New("Certificate's public key type not recognized. Supported keys: sm2")
	}
}

type x509PublicKeyImporter struct{}

func (ki *x509PublicKeyImporter) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (bccsp.Key, error) {
	x509Cert, ok := raw.(*x509.Certificate)
	if !ok {
		return nil, errors.New("Invalid raw material. Expected *x509.Certificate.")
	}

	pk := x509Cert.PublicKey
	importer := sm2PublicKeyImporter{}
	return importer.KeyImport(pk, opts)
}
