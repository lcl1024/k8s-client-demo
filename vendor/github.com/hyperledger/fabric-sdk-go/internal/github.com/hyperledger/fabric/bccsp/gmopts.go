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
package bccsp

const (
	SM2 = "SM2"
	SM3 = "SM3"
	SM4 = "SM4"
)

type SM2KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM2KeyGenOpts) Algorithm() string {
	return SM2
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM2KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM2PublicKeyImportOpts struct {
	Temporary bool
}

func (opts *SM2PublicKeyImportOpts) Algorithm() string {
	return SM2
}

func (opts *SM2PublicKeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4KeyGenOpts struct {
	Temporary bool
}

// Algorithm returns the key generation algorithm identifier (to be used).
func (opts *SM4KeyGenOpts) Algorithm() string {
	return SM4
}

// Ephemeral returns true if the key to generate has to be ephemeral,
// false otherwise.
func (opts *SM4KeyGenOpts) Ephemeral() bool {
	return opts.Temporary
}

type SM4KeyImportOpts struct {
	Temporary bool
}

func (opts *SM4KeyImportOpts) Algorithm() string {
	return SM4
}

func (opts *SM4KeyImportOpts) Ephemeral() bool {
	return opts.Temporary
}
