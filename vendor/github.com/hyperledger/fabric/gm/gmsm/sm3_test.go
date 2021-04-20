package gmsm

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

/**
 * @Author: eggsy
 * @Description:
 * @File:  sm3_test
 * @Version: 1.0.0
 * @Date: 4/20/20 3:37 下午
 */

func TestSM3_New(t *testing.T) {
	sm3 := NewSm3()
	hash := sm3.New()
	assert.NotNil(t, hash)
}

func TestNewSm3(t *testing.T) {
	sm3 := NewSm3()
	hash := sm3.New()
	var text = "hello world"
	hash.Write([]byte(text))
	hashStr := base64.StdEncoding.EncodeToString(hash.Sum(nil))
	assert.True(t, hashStr == "RPAGHmn6b9/CkMSUZUoF3AwFPaflxSuE75Op1n0//4g=")
}
