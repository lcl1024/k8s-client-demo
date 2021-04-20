// +build !pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

import "github.com/hyperledger/fabric-ca/api"

// GetKeyRequest constructs and returns api.BasicKeyRequest object based on the bccsp
// configuration options
func GetKeyRequest(cfg *CAConfig) *api.BasicKeyRequest {
	if cfg.IsGMConfig() {
		return &api.BasicKeyRequest{Algo: "gmsm2", Size: 256}
	}
	if cfg.CSP.SwOpts != nil {
		return &api.BasicKeyRequest{Algo: "ecdsa", Size: cfg.CSP.SwOpts.SecLevel}
	}
	return api.NewBasicKeyRequest()
}
