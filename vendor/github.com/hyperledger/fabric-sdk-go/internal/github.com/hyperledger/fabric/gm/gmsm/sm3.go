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
package gmsm

import (
	"hash"

	"github.com/hyperledger/fabric-sdk-go/internal/github.com/hyperledger/fabric/gm"
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
