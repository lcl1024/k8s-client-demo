/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/
/*
Notice: This file has been modified for Hyperledger Fabric SDK Go usage.
Please review third_party pinning scripts and patches for more details.
*/

package api

import (
	"github.com/cloudflare/cfssl/signer"
)

/*
 * This file contains the structure definitions for the request
 * and responses which flow over the network between a fabric-ca client
 * and the fabric-ca server.
 */

// RegistrationRequestNet is the registration request for a new identity
type RegistrationRequestNet struct {
	RegistrationRequest
}

// RegistrationResponseNet is a registration response
type RegistrationResponseNet struct {
	RegistrationResponse
}

// EnrollmentRequestNet is a request to enroll an identity
type EnrollmentRequestNet struct {
	signer.SignRequest
	CAName   string
	AttrReqs []*AttributeRequest `json:"attr_reqs,omitempty"`
}

// ReenrollmentRequestNet is a request to reenroll an identity.
// This is useful to renew a certificate before it has expired.
type ReenrollmentRequestNet struct {
	signer.SignRequest
	CAName   string
	AttrReqs []*AttributeRequest `json:"attr_reqs,omitempty"`
}

// RevocationRequestNet is a revocation request which flows over the network
// to the fabric-ca server.
// To revoke a single certificate, both the Serial and AKI fields must be set;
// otherwise, to revoke all certificates and the identity associated with an enrollment ID,
// the Name field must be set to an existing enrollment ID.
// A RevocationRequest can only be performed by a user with the "hf.Revoker" attribute.
type RevocationRequestNet struct {
	RevocationRequest
}

// AddIdentityRequestNet is a network request for adding a new identity
type AddIdentityRequestNet struct {
	AddIdentityRequest
}

// ModifyIdentityRequestNet is a network request for modifying an existing identity
type ModifyIdentityRequestNet struct {
	ModifyIdentityRequest
}

// AddAffiliationRequestNet is a network request for adding a new affiliation
type AddAffiliationRequestNet struct {
	AddAffiliationRequest
}

// ModifyAffiliationRequestNet is a network request for modifying an existing affiliation
type ModifyAffiliationRequestNet struct {
	ModifyAffiliationRequest
}

// GetCertificatesRequestNet is a network request for getting certificates
type GetCertificatesRequestNet struct {
	GetCertificatesRequest
}

// KeySig is a public key, signature, and signature algorithm tuple
type KeySig struct {
	// Key is a public key
	Key []byte `json:"key"`
	// Sig is a signature over the PublicKey
	Sig []byte `json:"sig"`
	// Alg is the signature algorithm
	Alg string `json:"alg"`
}
