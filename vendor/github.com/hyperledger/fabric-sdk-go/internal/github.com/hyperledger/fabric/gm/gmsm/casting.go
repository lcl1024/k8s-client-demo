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
package gmsm

import (
	"unsafe"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/crypto"
	"github.com/tjfoc/gmsm/sm2"
)

func toSm2PrivateKey(priv *crypto.PrivateKey) *sm2.PrivateKey {
	return (*sm2.PrivateKey)(unsafe.Pointer(priv))
}

func toCryptoPrivateKey(priv *sm2.PrivateKey) *crypto.PrivateKey {
	return (*crypto.PrivateKey)(unsafe.Pointer(priv))

}

func toSm2PublicKey(pub *crypto.PublicKey) *sm2.PublicKey {
	return (*sm2.PublicKey)(unsafe.Pointer(pub))
}

func toCryptoPublicKey(pub *sm2.PublicKey) *crypto.PublicKey {
	return (*crypto.PublicKey)(unsafe.Pointer(pub))

}
