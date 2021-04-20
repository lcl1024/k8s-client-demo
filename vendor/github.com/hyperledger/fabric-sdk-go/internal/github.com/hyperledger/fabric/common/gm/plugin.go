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
	"fmt"
	"strings"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm/gmsm"
	flogging "github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/sdkpatch/logbridge"
)

/**
 * @Author: eggsy
 * @Description:
 * @File:  plugin
 * @Version: 1.0.0
 * @Date: 4/29/20 11:08 上午
 */

var NewSm2 func() gm.Sm2
var NewSm3 func() gm.Sm3
var NewSm4 func() gm.Sm4
var logger = flogging.MustGetLogger("GM-Plugin")

func InitGMPlugin(pluginType string) error {
	logger.Infof("InitGMPlugin: Plugin Name [%s]", pluginType)
	switch strings.ToLower(pluginType) {
	case "", "gmsm":
		NewSm2 = gmsm.NewSm2
		NewSm3 = gmsm.NewSm3
		NewSm4 = gmsm.NewSm4
	default:
		return fmt.Errorf("unrecognized gm plugin type: %s", pluginType)
	}
	return nil
}
