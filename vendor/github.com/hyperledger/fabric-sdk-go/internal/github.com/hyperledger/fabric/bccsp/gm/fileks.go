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
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"sync"

	"errors"
	"strings"

	"encoding/hex"
	"fmt"
	"path/filepath"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
)

// NewFileBasedKeyStore instantiated a file-based key store at a given position.
// The key store can be encrypted if a non-empty password is specifiec.
// It can be also be set as read only. In this case, any store operation
// will be forbidden
func NewFileBasedKeyStore(pwd []byte, path string, readOnly bool) (bccsp.KeyStore, error) {
	ks := &fileBasedKeyStore{}
	return ks, ks.Init(pwd, path, readOnly)
}

// fileBasedKeyStore is a folder-based KeyStore.
// Each key is stored in a separated file whose name contains the key's SKI
// and flags to identity the key's type. All the keys are stored in
// a folder whose path is provided at initialization time.
// The KeyStore can be initialized with a password, this password
// is used to encrypt and decrypt the files storing the keys.
// A KeyStore can be read only to avoid the overwriting of keys.
type fileBasedKeyStore struct {
	path string

	readOnly bool
	isOpen   bool

	pwd []byte

	// Sync
	m sync.Mutex
}

// Init initializes this KeyStore with a password, a path to a folder
// where the keys are stored and a read only flag.
// Each key is stored in a separated file whose name contains the key's SKI
// and flags to identity the key's type.
// If the KeyStore is initialized with a password, this password
// is used to encrypt and decrypt the files storing the keys.
// The pwd can be nil for non-encrypted KeyStores. If an encrypted
// key-store is initialized without a password, then retrieving keys from the
// KeyStore will fail.
// A KeyStore can be read only to avoid the overwriting of keys.
func (ks *fileBasedKeyStore) Init(pwd []byte, path string, readOnly bool) error {
	// Validate inputs
	// pwd can be nil

	if len(path) == 0 {
		return errors.New("an invalid KeyStore path provided. Path cannot be an empty string")
	}

	ks.m.Lock()
	defer ks.m.Unlock()

	if ks.isOpen {
		return errors.New("keystore is already initialized")
	}

	ks.path = path

	clone := make([]byte, len(pwd))
	copy(ks.pwd, pwd)
	ks.pwd = clone
	ks.readOnly = readOnly

	exists, err := dirExists(path)
	if err != nil {
		return err
	}
	if !exists {
		err = ks.createKeyStore()
		if err != nil {
			return err
		}
		return ks.openKeyStore()
	}

	empty, err := dirEmpty(path)
	if err != nil {
		return err
	}
	if empty {
		err = ks.createKeyStore()
		if err != nil {
			return err
		}
	}

	return ks.openKeyStore()
}

// ReadOnly returns true if this KeyStore is read only, false otherwise.
// If ReadOnly is true then StoreKey will fail.
func (ks *fileBasedKeyStore) ReadOnly() bool {
	return ks.readOnly
}

// GetKey returns a key object whose SKI is the one passed.
func (ks *fileBasedKeyStore) GetKey(ski []byte) (bccsp.Key, error) {
	// Validate arguments
	if len(ski) == 0 {
		return nil, errors.New("invalid SKI. Cannot be of zero length")
	}

	suffix := ks.getSuffix(hex.EncodeToString(ski))

	switch suffix {
	case "key":
		// Load the key
		path := ks.getPathForAlias(hex.EncodeToString(ski), "key")
		key, err := gm.NewSm4().LoadKeyFromPem(path, nil)
		if err != nil || key == nil {
			return nil, fmt.Errorf("failed loading key [%x] [%s]", ski, err)
		}
		return &sm4PrivateKey{key}, nil
	case "sk":
		// Load the private key

		path := ks.getPathForAlias(hex.EncodeToString(ski), "sk")
		key, err := gm.NewSm2().LoadPrivateKeyFromPem(path, nil)
		if err != nil || key == nil {
			return nil, fmt.Errorf("failed loading secret key [%x] [%s]", ski, err)
		}
		return &sm2PrivateKey{key}, nil

	case "pk":
		// Load the public key
		path := ks.getPathForAlias(hex.EncodeToString(ski), "pk")
		key, err := gm.NewSm2().LoadPublicKeyFromPem(path, nil)
		if err != nil || key == nil {
			return nil, fmt.Errorf("failed loading public key [%x] [%s]", ski, err)
		}
		return &sm2PublicKey{key}, nil

	default:
		return ks.searchKeystoreForSKI(ski)
	}
}

// StoreKey stores the key k in this KeyStore.
// If this KeyStore is read only then the method will fail.
func (ks *fileBasedKeyStore) StoreKey(k bccsp.Key) (err error) {
	if ks.readOnly {
		return errors.New("read only KeyStore")
	}

	if k == nil {
		return errors.New("invalid key. It must be different from nil")
	}
	switch k.(type) {
	case *sm2PrivateKey:
		kk := k.(*sm2PrivateKey)
		if kk.privKey == nil {
			return errors.New("invalid key. It's privkey must be different from nil")
		}
		path := ks.getPathForAlias(hex.EncodeToString(k.SKI()), "sk")
		_, err = gm.NewSm2().SavePrivateKeytoPem(path, kk.privKey, nil)
		if err != nil {
			return fmt.Errorf("failed storing sm2 private key [%s]", err)
		}

	case *sm2PublicKey:
		kk := k.(*sm2PublicKey)
		if kk.pubKey == nil {
			return errors.New("invalid key. It's pubKey must be different from nil")
		}
		path := ks.getPathForAlias(hex.EncodeToString(k.SKI()), "pk")
		_, err = gm.NewSm2().SavePublicKeytoPem(path, kk.pubKey, nil)
		if err != nil {
			return fmt.Errorf("failed storing sm2 public key [%s]", err)
		}

	case *sm4PrivateKey:
		kk := k.(*sm4PrivateKey)
		if kk.key == nil {
			return errors.New("invalid key. It's key must be different from nil")
		}
		path := ks.getPathForAlias(hex.EncodeToString(k.SKI()), "key")
		_, err = gm.NewSm4().SaveKeyToPem(path, kk.key, nil)
		if err != nil {
			return fmt.Errorf("failed storing sm4 private key [%s]", err)
		}
	default:
		return fmt.Errorf("key type not reconigned [%s]", k)
	}

	return
}

func (ks *fileBasedKeyStore) searchKeystoreForSKI(ski []byte) (k bccsp.Key, err error) {

	files, _ := ioutil.ReadDir(ks.path)
	for _, f := range files {
		if f.IsDir() {
			continue
		}

		if f.Size() > (1 << 16) { //64k, somewhat arbitrary limit, considering even large RSA keys
			continue
		}

		sk, err := gm.NewSm2().LoadPrivateKeyFromPem(filepath.Join(ks.path, f.Name()), nil)
		if err != nil {
			continue
		}
		k = &sm2PrivateKey{sk}
		if !bytes.Equal(k.SKI(), ski) {
			continue
		}

		return k, nil
	}

	return nil, fmt.Errorf("key with SKI %s not found in %s", hex.EncodeToString(ski), ks.path)
}

func (ks *fileBasedKeyStore) getSuffix(alias string) string {
	files, _ := ioutil.ReadDir(ks.path)
	for _, f := range files {
		if strings.HasPrefix(f.Name(), alias) {
			if strings.HasSuffix(f.Name(), "sk") {
				return "sk"
			}
			if strings.HasSuffix(f.Name(), "pk") {
				return "pk"
			}
			if strings.HasSuffix(f.Name(), "key") {
				return "key"
			}
			break
		}
	}
	return ""
}

func (ks *fileBasedKeyStore) createKeyStore() error {
	// Create keystore directory root if it doesn't exist yet
	ksPath := ks.path
	logger.Debugf("Creating KeyStore at [%s]...", ksPath)

	err := os.MkdirAll(ksPath, 0755)
	if err != nil {
		return err
	}

	logger.Debugf("KeyStore created at [%s].", ksPath)
	return nil
}

func (ks *fileBasedKeyStore) openKeyStore() error {
	if ks.isOpen {
		return nil
	}
	ks.isOpen = true

	return nil
}

func (ks *fileBasedKeyStore) getPathForAlias(alias, suffix string) string {
	return filepath.Join(ks.path, alias+"_"+suffix)
}

func dirExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func dirEmpty(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	_, err = f.Readdir(1)
	if err == io.EOF {
		return true, nil
	}
	return false, err
}
