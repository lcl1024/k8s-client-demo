/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package lib

// The response to the POST /gencrl request
type genCRLResponseNet struct {
	// Base64 encoding of PEM-encoded CRL
	CRL string
}
