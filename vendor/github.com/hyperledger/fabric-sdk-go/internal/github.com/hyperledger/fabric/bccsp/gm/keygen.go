/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
	"fmt"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
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
