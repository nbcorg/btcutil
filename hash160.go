// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcutil

import (
	"crypto/sha256"
	"crypto/sha3"
	"hash"

	"github.com/dchest/blake256"
	"github.com/nbcorg/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

// Calculate the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// Hash160 calculates the hash ripemd160(sha256(b)).
func Hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}

// BlakeHash160 calculates the hash ripemd160(blake256(b)).
func BlakeHash160(buf []byte) []byte {
	return calcHash(calcHash(buf, blake256.New()), ripemd160.New())
}

// keccak256Hash160 calculates the hash ripemd160(sha3-256(b)).
func Keccak256Hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha3.New256()), ripemd160.New())
}

// CksumHashGen computes the hash from the passed script based on
// the passed hasher.
func CksumHashGen(cksumHasher base58.CksumHasher, script []byte) []byte {
	switch cksumHasher {
	case base58.Blake256D:
		return BlakeHash160(script)
	case base58.Keccak256OrSha256D:
		return Keccak256Hash160(script)
	default:
		return Hash160(script)
	}
}
