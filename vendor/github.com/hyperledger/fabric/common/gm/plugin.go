package gm

import (
	"fmt"
	"strings"

	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/gm"
	"github.com/hyperledger/fabric/gm/gmsm"
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
