// Copyright 2015 CoreOS, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tspi

// #include <trousers/tss.h>
import "C"
import (
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"math/big"
	"unsafe"
)

// ModulusFromBlob provides the modulus of a provided TSS key blob
func ModulusFromBlob(blob []byte) []byte {
	return blob[28:]
}

// Key is a TSS key
type Key struct {
	handle  C.TSS_HKEY
	context C.TSS_HCONTEXT
}

// GetPolicy returns the policy associated with the key
func (key *Key) GetPolicy(poltype int) (*Policy, error) {
	var policyHandle C.TSS_HPOLICY
	err := tspiError(C.Tspi_GetPolicyObject((C.TSS_HOBJECT)(key.handle), (C.TSS_FLAG)(poltype), &policyHandle))
	return &Policy{handle: policyHandle, context: key.context}, err
}

// SetModulus sets the modulus of a public key to the provided value
func (key *Key) SetModulus(n []byte) error {
	err := tspiError(C.Tspi_SetAttribData((C.TSS_HOBJECT)(key.handle), C.TSS_TSPATTRIB_RSAKEY_INFO, C.TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, (C.UINT32)(len(n)), (*C.BYTE)(unsafe.Pointer(&n[0]))))
	return err
}

// GetExponent returns the exponent of the public key
func (key *Key) GetExponent() (uint32, error) {
	var dataLen C.UINT32
	var cData *C.BYTE
	err := tspiError(C.Tspi_GetAttribData((C.TSS_HOBJECT)(key.handle), C.TSS_TSPATTRIB_RSAKEY_INFO, C.TSS_TSPATTRIB_KEYINFO_RSA_EXPONENT, &dataLen, &cData))
	data := C.GoBytes(unsafe.Pointer(cData), (C.int)(dataLen))
	C.Tspi_Context_FreeMemory(key.context, cData)
	if err != nil {
		return 0, err
	}
	if len(data) > 4 {
		return 0, errors.New("Exponent doesn't fit in int")
	}
	var exponent uint32
	for _, b := range data {
		exponent = (exponent << 8) + uint32(b)
	}
	return exponent, nil
}

// GetPublicKey returns a go-native *rsa.PublicKey instance of this key's public key
func (key *Key) GetPublicKey() (*rsa.PublicKey, error) {
	modulus, err := key.GetModulus()
	if err != nil {
		return nil, err
	}
	exponent, err := key.GetExponent()
	if err != nil {
		return nil, err
	}
	pk := &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulus),
		E: int(exponent),
	}
	return pk, nil
}

// GetModulus returns the modulus of the public key
func (key *Key) GetModulus() (modulus []byte, err error) {
	var dataLen C.UINT32
	var cData *C.BYTE
	err = tspiError(C.Tspi_GetAttribData((C.TSS_HOBJECT)(key.handle), C.TSS_TSPATTRIB_RSAKEY_INFO, C.TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, &dataLen, &cData))
	data := C.GoBytes(unsafe.Pointer(cData), (C.int)(dataLen))
	C.Tspi_Context_FreeMemory(key.context, cData)
	return data, err
}

// GetPubKeyBlob returns the public half of the key in TPM blob format
func (key *Key) GetPubKeyBlob() (pubkey []byte, err error) {
	var dataLen C.UINT32
	var cData *C.BYTE
	err = tspiError(C.Tspi_GetAttribData((C.TSS_HOBJECT)(key.handle), C.TSS_TSPATTRIB_KEY_BLOB, C.TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &dataLen, &cData))
	data := C.GoBytes(unsafe.Pointer(cData), (C.int)(dataLen))
	C.Tspi_Context_FreeMemory(key.context, cData)
	return data, err
}

// GetKeyBlob returns an encrypted blob containing the public and private
// halves of the key
func (key *Key) GetKeyBlob() ([]byte, error) {
	var dataLen C.UINT32
	var cData *C.BYTE
	err := tspiError(C.Tspi_GetAttribData((C.TSS_HOBJECT)(key.handle), C.TSS_TSPATTRIB_KEY_BLOB, C.TSS_TSPATTRIB_KEYBLOB_BLOB, &dataLen, &cData))
	data := C.GoBytes(unsafe.Pointer(cData), (C.int)(dataLen))
	C.Tspi_Context_FreeMemory(key.context, cData)
	return data, err
}

// Bind encrypts some data using the TPM and returns it.
func (key *Key) Bind(data []byte) ([]byte, error) {
	var encdata C.TSS_HENCDATA
	var dataLen C.UINT32
	var cData *C.BYTE

	err := tspiError(C.Tspi_Context_CreateObject(key.context, C.TSS_OBJECT_TYPE_ENCDATA, C.TSS_ENCDATA_BIND, (*C.TSS_HOBJECT)(&encdata)))
	if err != nil {
		return nil, err
	}

	err = tspiError(C.Tspi_Data_Bind(encdata, key.handle, (C.UINT32)(len(data)), (*C.BYTE)(&data[0])))
	if err != nil {
		return nil, err
	}

	err = tspiError(C.Tspi_GetAttribData((C.TSS_HOBJECT)(encdata), C.TSS_TSPATTRIB_ENCDATA_BLOB, C.TSS_TSPATTRIB_ENCDATABLOB_BLOB, &dataLen, &cData))
	if err != nil {
		return nil, err
	}

	blob := C.GoBytes(unsafe.Pointer(cData), (C.int(dataLen)))
	C.Tspi_Context_FreeMemory(key.context, cData)
	return blob, nil
}

// Unbind decrypts data previously encrypted with this key
func (key *Key) Unbind(data []byte) ([]byte, error) {
	var encdata C.TSS_HENCDATA
	var dataLen C.UINT32
	var cData *C.BYTE

	err := tspiError(C.Tspi_Context_CreateObject(key.context, C.TSS_OBJECT_TYPE_ENCDATA, C.TSS_ENCDATA_BIND, (*C.TSS_HOBJECT)(&encdata)))
	if err != nil {
		return nil, err
	}

	err = tspiError(C.Tspi_SetAttribData((C.TSS_HOBJECT)(encdata), C.TSS_TSPATTRIB_ENCDATA_BLOB, C.TSS_TSPATTRIB_ENCDATABLOB_BLOB, (C.UINT32)(len(data)), (*C.BYTE)(unsafe.Pointer(&data[0]))))
	if err != nil {
		return nil, err
	}

	err = tspiError(C.Tspi_Data_Unbind(encdata, key.handle, &dataLen, &cData))
	if err != nil {
		return nil, err
	}

	blob := C.GoBytes(unsafe.Pointer(cData), (C.int(dataLen)))
	C.Tspi_Context_FreeMemory(key.context, cData)
	return blob, nil
}

// Seal encrypts the data using the TPM such that it can only be decrypted
// when the TPM's PCR values match the values set on the provided PCRs
// object. If pcrs is nil, the data will be sealed to the TPM but may be
// decrypted regardless of platform state.
func (key *Key) Seal(data []byte, pcrs *PCRs) ([]byte, error) {
	var encdata C.TSS_HENCDATA
	var dataLen C.UINT32
	var cData *C.BYTE
	var pcrhandle C.TSS_HPCRS

	if pcrs != nil {
		pcrhandle = pcrs.handle
	}

	err := tspiError(C.Tspi_Context_CreateObject(key.context, C.TSS_OBJECT_TYPE_ENCDATA, C.TSS_ENCDATA_SEAL, (*C.TSS_HOBJECT)(&encdata)))
	if err != nil {
		return nil, err
	}

	err = tspiError(C.Tspi_Data_Seal(encdata, key.handle, (C.UINT32)(len(data)), (*C.BYTE)(&data[0]), pcrhandle))
	if err != nil {
		return nil, err
	}

	err = tspiError(C.Tspi_GetAttribData((C.TSS_HOBJECT)(encdata), C.TSS_TSPATTRIB_ENCDATA_BLOB, C.TSS_TSPATTRIB_ENCDATABLOB_BLOB, &dataLen, &cData))
	if err != nil {
		return nil, err
	}

	blob := C.GoBytes(unsafe.Pointer(cData), (C.int(dataLen)))
	C.Tspi_Context_FreeMemory(key.context, cData)
	return blob, nil
}

// Unseal decrypts data previously encrypted with this key as long as the
// PCR values match those the data was sealed against
func (key *Key) Unseal(data []byte) ([]byte, error) {
	var encdata C.TSS_HENCDATA
	var dataLen C.UINT32
	var cData *C.BYTE

	err := tspiError(C.Tspi_Context_CreateObject(key.context, C.TSS_OBJECT_TYPE_ENCDATA, C.TSS_ENCDATA_SEAL, (*C.TSS_HOBJECT)(&encdata)))
	if err != nil {
		return nil, err
	}

	err = tspiError(C.Tspi_SetAttribData((C.TSS_HOBJECT)(encdata), C.TSS_TSPATTRIB_ENCDATA_BLOB, C.TSS_TSPATTRIB_ENCDATABLOB_BLOB, (C.UINT32)(len(data)), (*C.BYTE)(unsafe.Pointer(&data[0]))))
	if err != nil {
		return nil, err
	}

	err = tspiError(C.Tspi_Data_Unseal(encdata, key.handle, &dataLen, &cData))
	if err != nil {
		return nil, err
	}

	blob := C.GoBytes(unsafe.Pointer(cData), (C.int(dataLen)))
	C.Tspi_Context_FreeMemory(key.context, cData)
	return blob, nil
}

// SetSignatureScheme sets the signature scheme on a newly created key. The scheme parameter should be one of tspiconst.TSS_SS_RSASSAPKCS1V15_SHA1
// or tspiconst.TSS_SS_RSASSAPKCS1V15_DER
func (key *Key) SetSignatureScheme(scheme int) error {
	return tspiError(C.Tspi_SetAttribUint32((C.TSS_HOBJECT)(key.handle), C.TSS_TSPATTRIB_KEY_INFO, C.TSS_TSPATTRIB_KEYINFO_SIGSCHEME, (C.UINT32)(scheme)))
}

// GenerateKey generates a key pair on the TPM, wrapping it with the provided
// key
func (key *Key) GenerateKey(wrapkey *Key) (err error) {
	err = tspiError(C.Tspi_Key_CreateKey((C.TSS_HKEY)(key.handle), (C.TSS_HKEY)(wrapkey.handle), 0))
	return err
}

// Certify signs the public key with another key held by the TPM
func (key *Key) Certify(certifykey *Key, challenge []byte) ([]byte, []byte, error) {
	var validation C.TSS_VALIDATION

	challengeHash := sha1.Sum(challenge[:])
	validation.ulExternalDataLength = sha1.Size
	validation.rgbExternalData = (*C.BYTE)(&challengeHash[0])

	err := tspiError(C.Tspi_Key_CertifyKey((C.TSS_HKEY)(key.handle), (C.TSS_HKEY)(certifykey.handle), &validation))
	if err != nil {
		return nil, nil, err
	}

	data := C.GoBytes(unsafe.Pointer(validation.rgbData), (C.int)(validation.ulDataLength))
	validationdata := C.GoBytes(unsafe.Pointer(validation.rgbValidationData), (C.int)(validation.ulValidationDataLength))

	C.Tspi_Context_FreeMemory(key.context, validation.rgbData)
	C.Tspi_Context_FreeMemory(key.context, validation.rgbValidationData)

	return data, validationdata, nil
}

// AssignPolicy assigns a TSS policy to the key.
func (key *Key) AssignPolicy(policy *Policy) error {
	err := tspiError(C.Tspi_Policy_AssignToObject(policy.handle, (C.TSS_HOBJECT)(key.handle)))
	return err
}

// Close closes the Key object.
func (key *Key) Close() error {
	err := tspiError(C.Tspi_Context_CloseObject(key.context, key.handle))
	return err
}
