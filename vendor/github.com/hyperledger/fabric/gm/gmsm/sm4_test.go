package gmsm

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
)

/**
 * @Author: eggsy
 * @Description:
 * @File:  sm4_test
 * @Version: 1.0.0
 * @Date: 4/20/20 3:49 下午
 */

func TestNewSM4(t *testing.T) {
	sm4 := NewSm4()
	assert.NotNil(t, sm4)
}

func TestSM4_NewCipher(t *testing.T) {
	sm4 := NewSm4()
	var key = []byte("1234567890abcdef")
	block, err := sm4.NewCipher(key)
	assert.NoError(t, err)
	assert.NotNil(t, block)
}

func TestSM4_Encrypt(t *testing.T) {
	sm4 := NewSm4()
	// 期望密文base64结果
	var ciphertext = "NauavGfy6+o+hH7ihy6vrw=="
	// 密文[]byte
	var dst = make([]byte, 16)
	// 加密src
	// 需要加密的明文
	var src = []byte("hi, hello world!")
	// key
	var key = []byte("1234567890abcdef")
	sm4.Encrypt(key, dst, src)
	assert.True(t, base64.StdEncoding.EncodeToString(dst) == ciphertext)
}

func TestSM4_Decrypt(t *testing.T) {
	sm4 := NewSm4()
	// 加密的密文
	var in = "NauavGfy6+o+hH7ihy6vrw=="
	// 解密后的明文[]byte
	var out = make([]byte, 16)
	// 期望的明文 string类型
	var plaintext = "hi, hello world!"
	var key = []byte("1234567890abcdef")
	inByte, err := base64.StdEncoding.DecodeString(in)
	assert.NoError(t, err)
	sm4.Decrypt(key, out, inByte)
	assert.True(t, string(out) == plaintext)
}

func TestSM4_SaveKeyToPem(t *testing.T) {
	var filename = "./key.pem"
	var key = []byte("1234567890abcdef")
	var pwd = []byte("123")
	sm4 := NewSm4()
	flag, err := sm4.SaveKeyToPem(filename, key, pwd)
	assert.NoError(t, err)
	assert.True(t, flag)
}

func TestSM4_LoadKeyFromPem(t *testing.T) {
	var filename = "./key.pem"
	var key = []byte("1234567890abcdef")
	var pwd = []byte("123")
	sm4 := NewSm4()
	keyByte, err := sm4.LoadKeyFromPem(filename, pwd)
	assert.NoError(t, err)
	assert.True(t, string(keyByte) == string(key))
}
