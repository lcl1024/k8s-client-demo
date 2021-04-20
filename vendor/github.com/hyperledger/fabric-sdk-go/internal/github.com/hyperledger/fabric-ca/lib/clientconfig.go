/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package lib

import (
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/lib/tls"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric-ca/sdkinternal/pkg/api"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/bccsp/factory"
	"github.com/hyperledger/fabric-sdk-go/pkg/common/providers/core"
)

// ClientConfig is the fabric-ca client's config
type ClientConfig struct {
	URL        string `def:"http://localhost:7054" opt:"u" help:"URL of fabric-ca-server"`
	MSPDir     string `def:"msp" opt:"M" help:"Membership Service Provider directory"`
	TLS        tls.ClientTLSConfig
	Enrollment api.EnrollmentRequest
	CSR        api.CSRInfo
	ID         api.RegistrationRequest
	Revoke     api.RevocationRequest
	CAInfo     api.GetCAInfoRequest
	CAName     string               `help:"Name of CA"`
	CSP        core.CryptoSuite     `mapstructure:"bccsp" hide:"true"`
	Opts       *factory.FactoryOpts `mapstructure:"bccsp" hide:"true"`
	ServerName string               `help:"CA server name to be used in case of host name override"`

	Debug    bool   `opt:"d" help:"Enable debug level logging" hide:"true"`
	LogLevel string `help:"Set logging level (info, warning, debug, error, fatal, critical)"`
}
