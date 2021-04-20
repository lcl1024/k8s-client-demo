package gmsm

import (
	"hash"

	"github.com/hyperledger/fabric/gm"
	"github.com/tjfoc/gmsm/sm3"
)

/**
 * @Author: eggsy
 * @Description:
 * @File:  sm3
 * @Version: 1.0.0
 * @Date: 4/20/20 3:32 下午
 */

type SM3 struct {
	hash.Hash
}

func NewSm3() gm.Sm3 {
	return &SM3{sm3.New()}
}

func (s *SM3) New() hash.Hash {
	return sm3.New()
}
