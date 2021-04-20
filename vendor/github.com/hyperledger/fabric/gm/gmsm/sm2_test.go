package gmsm

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

/**
 * @Author: eggsy
 * @Description:
 * @File:  sm2_test
 * @Version: 1.0.0
 * @Date: 4/20/20 5:52 下午
 */
func TestNewSm2(t *testing.T) {
	sm2 := NewSm2()
	assert.NotNil(t, sm2)
}

func TestSM2_GenerateKey(t *testing.T) {
	sm2 := NewSm2()
	key, err := sm2.GenerateKey()
	assert.NoError(t, err)
	assert.NotNil(t, key)
	// 验证是否为sm2的曲线
	flag := key.Curve.IsOnCurve(key.X, key.Y)
	assert.True(t, flag)
}

// 保存公钥私钥
func TestSM2_SaveKeytoPem(t *testing.T) {
	sm2 := NewSm2()
	privKey, err := sm2.GenerateKey()
	assert.NoError(t, err)
	// 测试保存私钥
	flag, err := sm2.SavePrivateKeytoPem("priv.pem", privKey, nil)
	assert.NoError(t, err)
	assert.True(t, flag)
	pubKey := &privKey.PublicKey
	// 测试保存公钥
	flag, err = sm2.SavePublicKeytoPem("pub.pem", pubKey, nil)
	assert.NoError(t, err)
	assert.True(t, flag)
}

// 加载公钥私钥
func TestSM2_LoadKeyFromPem(t *testing.T) {
	sm2 := NewSm2()
	privkey, err := sm2.LoadPrivateKeyFromPem("priv.pem", nil)
	assert.NoError(t, err)
	assert.NotNil(t, privkey)
	pubkey, err := sm2.LoadPublicKeyFromPem("pub.pem", nil)
	assert.NoError(t, err)
	assert.NotNil(t, pubkey)
}

// 利用保存的私钥签名
func TestSM2_Sign(t *testing.T) {
	sm2 := NewSm2()
	privkey, err := sm2.LoadPrivateKeyFromPem("priv.pem", nil)
	assert.NoError(t, err)
	assert.NotNil(t, privkey)
	// 签名
	msg := "this is input text"
	out, err := sm2.Sign(privkey, rand.Reader, []byte(msg), nil)
	assert.NoError(t, err)
	// 保存签名数据
	err = ioutil.WriteFile("outfile", out, os.FileMode(0644))
	assert.NoError(t, err)
}

// 基于公钥验证
func TestSM2_Verify(t *testing.T) {
	sm2 := NewSm2()
	pubkey, err := sm2.LoadPublicKeyFromPem("pub.pem", nil)
	assert.NoError(t, err)
	assert.NotNil(t, pubkey)
	signdata, _ := ioutil.ReadFile("outfile")
	msg := "this is input text"
	ok := sm2.Verify(pubkey, []byte(msg), signdata)
	assert.True(t, ok)
}

// 利用保存的公钥加密
func TestSM2_Encrypt(t *testing.T) {
	sm2 := NewSm2()
	pubkey, err := sm2.LoadPublicKeyFromPem("pub.pem", nil)
	assert.NoError(t, err)
	assert.NotNil(t, pubkey)
	plaintext := []byte("this is plaintext")
	cipertext, err := sm2.Encrypt(pubkey, plaintext)
	assert.NoError(t, err)
	err = ioutil.WriteFile("cipertext", cipertext, os.FileMode(0644))
	assert.NoError(t, err)
}

// 利用保存的私钥解密
func TestSM2_Decrypt(t *testing.T) {
	sm2 := NewSm2()
	privkey, err := sm2.LoadPrivateKeyFromPem("priv.pem", nil)
	assert.NoError(t, err)
	assert.NotNil(t, privkey)
	cipertext, _ := ioutil.ReadFile("cipertext")
	plaintext, err := sm2.Decrypt(privkey, cipertext)
	assert.NoError(t, err)
	text := []byte("this is plaintext")
	assert.True(t, string(plaintext) == string(text))
}
