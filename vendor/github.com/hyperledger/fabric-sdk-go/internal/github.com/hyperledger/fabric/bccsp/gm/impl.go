/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package gm

import (
	"crypto/rand"
	"hash"
	"reflect"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
	"github.com/pkg/errors"
)

var (
	logger = flogging.MustGetLogger("bccsp_gm")
)

type impl struct {
	ks            bccsp.KeyStore
	keyImporters  map[reflect.Type]KeyImporter
	keyGenerators map[reflect.Type]KeyGenerator
}

func New(keyStore bccsp.KeyStore) (bccsp.BCCSP, error) {
	if keyStore == nil {
		return nil, errors.Errorf("Invalid bccsp.KeyStore instance. It must be different from nil.")
	}

	impl := &impl{ks: keyStore}
	keyImporters := make(map[reflect.Type]KeyImporter)
	keyImporters[reflect.TypeOf(&bccsp.ECDSAPrivateKeyImportOpts{})] = &sm2PrivateKeyImporter{}
	keyImporters[reflect.TypeOf(&bccsp.ECDSAGoPublicKeyImportOpts{})] = &sm2PublicKeyImporter{}
	keyImporters[reflect.TypeOf(&bccsp.SM2PublicKeyImportOpts{})] = &sm2PublicKeyImporter{}
	keyImporters[reflect.TypeOf(&bccsp.X509PublicKeyImportOpts{})] = &x509PublicKeyImporter{}
	keyImporters[reflect.TypeOf(&bccsp.SM4KeyImportOpts{})] = &sm4KeyImporter{}

	keyGenerators := make(map[reflect.Type]KeyGenerator)
	keyGenerators[reflect.TypeOf(&bccsp.SM4KeyGenOpts{})] = &sm4KeyGenerator{}
	keyGenerators[reflect.TypeOf(&bccsp.SM2KeyGenOpts{})] = &sm2KeyGenerator{}
	keyGenerators[reflect.TypeOf(&bccsp.ECDSAP256KeyGenOpts{})] = &sm2KeyGenerator{}

	impl.keyGenerators = keyGenerators
	impl.keyImporters = keyImporters

	return impl, nil
}

// KeyGen generates a key using opts.
func (gmcsp *impl) KeyGen(opts bccsp.KeyGenOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if opts == nil {
		return nil, errors.New("Invalid Opts parameter. It must not be nil.")
	}

	keyGenerator, found := gmcsp.keyGenerators[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'KeyGenOpts' provided [%v]", opts)
	}

	k, err = keyGenerator.KeyGen(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed generating key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = gmcsp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing key [%s]", opts.Algorithm())
		}
	}
	return k, nil
}

// KeyDeriv derives a key from k using opts.
// The opts argument should be appropriate for the primitive used.
func (gmcsp *impl) KeyDeriv(k bccsp.Key, opts bccsp.KeyDerivOpts) (dk bccsp.Key, err error) {
	return nil, nil
}

// KeyImport imports a key from its raw representation using opts.
// The opts argument should be appropriate for the primitive used.
func (gmcsp *impl) KeyImport(raw interface{}, opts bccsp.KeyImportOpts) (k bccsp.Key, err error) {
	// Validate arguments
	if raw == nil {
		return nil, errors.New("Invalid raw. It must not be nil.")
	}
	if opts == nil {
		return nil, errors.New("Invalid opts. It must not be nil.")
	}

	keyImporter, found := gmcsp.keyImporters[reflect.TypeOf(opts)]
	if !found {
		return nil, errors.Errorf("Unsupported 'KeyImportOpts' provided [%v]", opts)
	}

	k, err = keyImporter.KeyImport(raw, opts)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed importing key with opts [%v]", opts)
	}

	// If the key is not Ephemeral, store it.
	if !opts.Ephemeral() {
		// Store the key
		err = gmcsp.ks.StoreKey(k)
		if err != nil {
			return nil, errors.Wrapf(err, "Failed storing imported key with opts [%v]", opts)
		}
	}

	return
}

// GetKey returns the key this CSP associates to
// the Subject Key Identifier ski.
func (gmcsp *impl) GetKey(ski []byte) (k bccsp.Key, err error) {
	k, err = gmcsp.ks.GetKey(ski)
	if err != nil {
		return nil, errors.Wrapf(err, "Failed getting key for SKI [%v]", ski)
	}

	return
}

// Hash hashes messages msg using options opts.
func (gmcsp *impl) Hash(msg []byte, opts bccsp.HashOpts) ([]byte, error) {
	hasher := gm.NewSm3().New()
	if hasher == nil {
		return nil, errors.New("the hasher gm.NewSm3() return is nil")
	}

	hasher.Write(msg)
	digest := hasher.Sum(nil)

	return digest, nil
}

// GetHash returns and instance of hash.Hash using options opts.
// If opts is nil then the default hash function is returned.
func (gmcsp *impl) GetHash(opts bccsp.HashOpts) (h hash.Hash, err error) {
	hasher := gm.NewSm3().New()
	if hasher == nil {
		return nil, errors.New("the hasher that gm.NewSm3() return is nil")
	}
	return hasher, nil
}

// Sign signs digest using key k.
// The opts argument should be appropriate for the primitive used.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest).
func (gmcsp *impl) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	if len(digest) == 0 {
		return nil, errors.New("Invalid digest. Cannot be empty.")
	}

	if sk, ok := k.(*sm2PrivateKey); ok {
		if sk.privKey == nil {
			return nil, errors.New("Invalid sm2PrivateKey Key. It's privKey must not be nil.")
		}
		signature, err = gm.NewSm2().Sign(sk.privKey, rand.Reader, digest, opts)
	} else {
		return nil, errors.New("Invalid private Key. PrivateKey must be sm2PrivateKey")
	}
	return
}

// Verify verifies signature against key k and digest
func (gmcsp *impl) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	// Validate arguments
	if k == nil {
		return false, errors.New("Invalid Key. It must not be nil.")
	}
	if len(signature) == 0 {
		return false, errors.New("Invalid signature. Cannot be empty.")
	}
	if len(digest) == 0 {
		return false, errors.New("Invalid digest. Cannot be empty.")
	}

	if pk, ok := k.(*sm2PublicKey); ok {
		if pk.pubKey == nil {
			return false, errors.New("Invalid sm2PublicKey Key. It's pubKey must not be nil.")
		}
		valid = gm.NewSm2().Verify(pk.pubKey, digest, signature)
	} else {
		return false, errors.New("Invalid public Key. PublicKey must be sm2PublicKey")
	}
	return
}

// Encrypt encrypts plaintext using key k.
// The opts argument should be appropriate for the primitive used.
func (gmcsp *impl) Encrypt(k bccsp.Key, plaintext []byte, opts bccsp.EncrypterOpts) ([]byte, error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}
	switch k.(type) {
	case *sm2PublicKey:
		kk := k.(*sm2PublicKey)
		if kk.pubKey == nil {
			return nil, errors.New("Invalid sm2PublicKey Key. It's pubKey must not be nil.")
		}
		return gm.NewSm2().Encrypt(kk.pubKey, plaintext)
	case *sm4PrivateKey:
		kk := k.(*sm4PrivateKey)
		if kk.key == nil {
			return nil, errors.New("Invalid sm4PrivateKey Key. It's key must not be nil.")
		}
		dstLen := (len(plaintext) + 15) / 16
		ciphertext := make([]byte, dstLen*16)
		gm.NewSm4().Encrypt(kk.key, ciphertext, plaintext)
		return ciphertext, nil
	}
	return nil, errors.New("Invalid Key. It must be sm2PublicKey or sm4PrivateKey")
}

// Decrypt decrypts ciphertext using key k.
// The opts argument should be appropriate for the primitive used.
func (gmcsp *impl) Decrypt(k bccsp.Key, ciphertext []byte, opts bccsp.DecrypterOpts) ([]byte, error) {
	// Validate arguments
	if k == nil {
		return nil, errors.New("Invalid Key. It must not be nil.")
	}

	switch k.(type) {
	case *sm2PrivateKey:
		kk := k.(*sm2PrivateKey)
		if kk.privKey == nil {
			return nil, errors.New("Invalid sm2PrivateKey Key. It's privKey must not be nil.")
		}
		return gm.NewSm2().Decrypt(kk.privKey, ciphertext)
	case *sm4PrivateKey:
		kk := k.(*sm4PrivateKey)
		if kk.key == nil {
			return nil, errors.New("Invalid sm4PrivateKey Key. It's key must not be nil.")
		}
		plaintext := make([]byte, len(ciphertext))
		gm.NewSm4().Decrypt(kk.key, plaintext, ciphertext)
		return plaintext, nil
	}
	return nil, errors.New("Invalid Key. It must be sm2PrivateKey or sm4PrivateKey")
}
