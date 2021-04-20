package gm

import (
	"testing"

	gm2 "github.com/hyperledger/fabric/gm"
	"github.com/stretchr/testify/assert"
)

/**
 * @Author: eggsy
 * @Description:
 * @File:  plugin_test
 * @Version: 1.0.0
 * @Date: 4/29/20 12:45 下午
 */
func Test_Plugin(t *testing.T) {
	var gmsm2 gm2.Sm2
	InitGMPlugin("gmsm")
	gmsm2 = NewSm2().(gm2.Sm2)
	key, err := gmsm2.GenerateKey()
	assert.NoError(t, err)
	assert.NotNil(t, key)
}
