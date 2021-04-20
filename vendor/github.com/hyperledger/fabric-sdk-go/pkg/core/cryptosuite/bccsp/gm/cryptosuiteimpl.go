/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package gm

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/sw"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/common/gm"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/logging"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/cryptosuite/bccsp/wrapper"
	"github.com/pkg/errors"
)

var logger = logging.NewLogger("fabsdk/core")

//GetSuiteByConfig returns cryptosuite adaptor for bccsp loaded according to given config
func GetSuiteByConfig(config core.CryptoSuiteConfig) (core.CryptoSuite, error) {
	// TODO: delete this check?
	if config.SecurityProvider() != "gm" {
		return nil, errors.Errorf("Unsupported BCCSP Provider: %s", config.SecurityProvider())
	}

	opts := getOptsByConfig(config)
	bccsp, err := getBCCSPFromOpts(opts)
	if err != nil {
		return nil, err
	}
	return wrapper.NewCryptoSuite(bccsp), nil
}

//GetSuiteWithDefaultEphemeral returns cryptosuite adaptor for bccsp with default ephemeral options (intended to aid testing)
func GetSuiteWithDefaultEphemeral() (core.CryptoSuite, error) {
	opts := getEphemeralOpts()

	bccsp, err := getBCCSPFromOpts(opts)
	if err != nil {
		return nil, err
	}
	return wrapper.NewCryptoSuite(bccsp), nil
}

func getBCCSPFromOpts(config *factory.FactoryOpts) (bccsp.BCCSP, error) {
	f := &factory.GMFactory{}

	//如果是国密，需要针对参数加载对应plugin
	err := gm.InitGMPlugin(config.SwOpts.Library)
	if err != nil {
		return nil, errors.Wrapf(errors.Errorf("unrecognized gm plugin type: %s", config.SwOpts.Library), "Failed initializing BCCSP.")
	}

	csp, err := f.Get(config)
	if err != nil {
		return nil, errors.Wrapf(err, "Could not initialize BCCSP %s", f.Name())
	}
	return csp, nil
}

// GetSuite returns a new instance of the software-based BCCSP
// set at the passed security level, hash family and KeyStore.
func GetSuite(securityLevel int, hashFamily string, keyStore bccsp.KeyStore) (core.CryptoSuite, error) {
	bccsp, err := sw.NewWithParams(securityLevel, hashFamily, keyStore)
	if err != nil {
		return nil, err
	}
	return wrapper.NewCryptoSuite(bccsp), nil
}

//GetOptsByConfig Returns Factory opts for given SDK config
func getOptsByConfig(c core.CryptoSuiteConfig) *factory.FactoryOpts {
	opts := &factory.FactoryOpts{
		ProviderName: "GM",
		SwOpts: &factory.SwOpts{
			HashFamily: c.SecurityAlgorithm(),
			SecLevel:   c.SecurityLevel(),
			Library:    c.SecurityProviderLibPath(),
			FileKeystore: &factory.FileKeystoreOpts{
				KeyStorePath: c.KeyStorePath(),
			},
		},
	}
	logger.Debug("Initialized GM cryptosuite")

	return opts
}

func getEphemeralOpts() *factory.FactoryOpts {
	opts := &factory.FactoryOpts{
		ProviderName: "GM",
		SwOpts: &factory.SwOpts{
			HashFamily: "SHA2",
			SecLevel:   256,
			Ephemeral:  true,
		},
	}
	logger.Debug("Initialized ephemeral SW cryptosuite with default opts")

	return opts
}
