// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcutil

import (
	"golang.org/x/crypto/sha3"
	"hash"

	"github.com/nbcorg/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

// Calculate the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// keccak256Hash160 calculates the hash ripemd160(sha3-256(b)).
func Keccak256Hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha3.New256()), ripemd160.New())
}

// CksumHashGen computes the hash from the passed script based on
// the passed hasher.
func CksumHashGen(cksumHasher base58.CksumHasher, script []byte) []byte {
	return Keccak256Hash160(script)
}
