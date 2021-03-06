// +build pkcs11

/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"github.com/cloudflare/cfssl/log"
	"github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric/common/x509"
	"github.com/hyperledger/fabric/common/gm"
	"github.com/pkg/errors"
	"path"
	"strings"
)

// ConfigureBCCSP configures BCCSP, using
func ConfigureBCCSP(optsPtr **factory.FactoryOpts, mspDir, homeDir string) error {
	var err error
	if optsPtr == nil {
		return errors.New("nil argument not allowed")
	}
	opts := *optsPtr
	if opts == nil {
		opts = &factory.FactoryOpts{}
	}
	if opts.ProviderName == "" {
		opts.ProviderName = "SW"
	}
	if strings.ToUpper(opts.ProviderName) == "SW" {
		if opts.SwOpts == nil {
			opts.SwOpts = &factory.SwOpts{}
		}
		if opts.SwOpts.HashFamily == "" {
			opts.SwOpts.HashFamily = "SHA2"
		}
		if opts.SwOpts.SecLevel == 0 {
			opts.SwOpts.SecLevel = 256
		}
		if opts.SwOpts.FileKeystore == nil {
			opts.SwOpts.FileKeystore = &factory.FileKeystoreOpts{}
		}
		// The mspDir overrides the KeyStorePath; otherwise, if not set, set default
		if mspDir != "" {
			opts.SwOpts.FileKeystore.KeyStorePath = path.Join(mspDir, "keystore")
		} else if opts.SwOpts.FileKeystore.KeyStorePath == "" {
			opts.SwOpts.FileKeystore.KeyStorePath = path.Join("msp", "keystore")
		}
	} else if strings.ToUpper(opts.ProviderName) == "GM" {
		if opts.SwOpts == nil {
			opts.SwOpts = &factory.SwOpts{}
		}
		if opts.SwOpts.FileKeystore == nil {
			opts.SwOpts.FileKeystore = &factory.FileKeystoreOpts{}
		}
		if mspDir != "" {
			opts.SwOpts.FileKeystore.KeyStorePath = path.Join(mspDir, "keystore")
		} else if opts.SwOpts.FileKeystore.KeyStorePath == "" {
			opts.SwOpts.FileKeystore.KeyStorePath = path.Join("msp", "keystore")
		}
		x509.InitX509("gmsm")
		gm.InitGMPlugin("gmsm")
	}
	err = makeFileNamesAbsolute(opts, homeDir)
	if err != nil {
		return errors.WithMessage(err, "Failed to make BCCSP files absolute")
	}
	log.Debugf("Initializing BCCSP: %+v", opts)
	if opts.SwOpts != nil {
		log.Debugf("Initializing BCCSP with software options %+v", opts.SwOpts)
	}
	if opts.Pkcs11Opts != nil {
		log.Debugf("Initializing BCCSP with PKCS11 options %+v", opts.Pkcs11Opts)
	}
	*optsPtr = opts
	return nil
}
