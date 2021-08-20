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
	"crypto"
	"errors"
	"unsafe"
)

// Hash is a TSS hash
type Hash struct {
	handle  C.TSS_HHASH
	context C.TSS_HCONTEXT
	hashAlg crypto.Hash
}

// Update updates a TSS hash with the data provided. It returns an error on
// failure.
func (hash *Hash) Update(data []byte) error {
	err := tspiError(C.Tspi_Hash_UpdateHashValue(hash.handle, (C.UINT32)(len(data)), (*C.BYTE)(&data[0])))
	return err
}

// Verify checks whether a hash matches the signature signed with the
// provided key. It returns an error on failure.
func (hash *Hash) Verify(key *Key, signature []byte) error {
	err := tspiError(C.Tspi_Hash_VerifySignature(hash.handle, key.handle, (C.UINT32)(len(signature)), (*C.BYTE)(&signature[0])))
	return err
}

// https://golang.org/src/crypto/rsa/pkcs1v15.go#L204
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

// SetValue sets the value of the hash to the given bytes
func (hash *Hash) SetValue(hashed []byte) error {
	var data []byte
	if hash.hashAlg == crypto.SHA1 {
		data = hashed
	} else {
		prefix, ok := hashPrefixes[hash.hashAlg]
		if !ok {
			return errors.New("unsupported hash algorithm")
		}
		data = append(prefix, hashed...)
	}

	return tspiError(C.Tspi_Hash_SetHashValue(hash.handle, (C.UINT32)(len(data)), (*C.BYTE)(&data[0])))
}

// Sign uses the provided key to create a signature.
func (hash *Hash) Sign(key *Key) ([]byte, error) {
	var dataLen C.UINT32
	var cData *C.BYTE
	err := tspiError(C.Tspi_Hash_Sign(hash.handle, key.handle, &dataLen, &cData))
	data := C.GoBytes(unsafe.Pointer(cData), (C.int)(dataLen))
	C.Tspi_Context_FreeMemory(hash.context, cData)

	if err != nil {
		return nil, err
	}

	return data, nil
}

// Close closes the Hash object.
func (hash *Hash) Close() error {
	err := tspiError(C.Tspi_Context_CloseObject(hash.context, hash.handle))
	return err
}
