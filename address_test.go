// Copyright (c) 2013-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package btcutil_test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/nbcorg/btcd/wire"

	"github.com/nbcorg/btcutil"
	"github.com/nbcorg/btcutil/chaincfg"
	"golang.org/x/crypto/ripemd160"
)

type CustomParamStruct struct {
	Net              wire.BitcoinNet
	PubKeyHashAddrID byte
	ScriptHashAddrID byte
	Bech32HRPSegwit  string
}

var LitecoinParams = CustomParamStruct{
	Net:              wire.BitcoinNet(01),
	PubKeyHashAddrID: 0x30, // starts with L
	ScriptHashAddrID: 0x32, // starts with M
	Bech32HRPSegwit:  "ltc",
}

// We use this function to be able to test functionality in DecodeAddress for
// defaultNet addresses
func applyCustomParams(params chaincfg.Params, newParams CustomParamStruct) chaincfg.Params {
	params.Net = newParams.Net
	params.PubKeyHashAddrID = []byte{newParams.PubKeyHashAddrID}
	params.ScriptHashAddrID = []byte{newParams.ScriptHashAddrID}
	params.Bech32HRPSegwit = newParams.Bech32HRPSegwit
	chaincfg.Register(&params)
	return params
}

var customParams = applyCustomParams(chaincfg.MainNetParams, LitecoinParams)

func TestAddresses(t *testing.T) {
	chaincfg.RegisterBitcoinParams()
	defer chaincfg.ResetParams()

	tests := []struct {
		name    string
		addr    string
		encoded string
		valid   bool
		result  btcutil.Address
		f       func() (btcutil.Address, error)
		net     *chaincfg.Params
	}{
		// Positive P2PKH tests.
		{
			name:    "mainnet p2pkh",
			addr:    "1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX",
			encoded: "1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gX",
			valid:   true,
			result: btcutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{
					0xe3, 0x4c, 0xce, 0x70, 0xc8, 0x63, 0x73, 0x27, 0x3e, 0xfc,
					0xc5, 0x4c, 0xe7, 0xd2, 0xa4, 0x91, 0xbb, 0x4a, 0x0e, 0x84},
				chaincfg.MainNetParams.PubKeyHashAddrID),
			f: func() (btcutil.Address, error) {
				pkHash := []byte{
					0xe3, 0x4c, 0xce, 0x70, 0xc8, 0x63, 0x73, 0x27, 0x3e, 0xfc,
					0xc5, 0x4c, 0xe7, 0xd2, 0xa4, 0x91, 0xbb, 0x4a, 0x0e, 0x84}
				return btcutil.NewAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "mainnet p2pkh 2",
			addr:    "12MzCDwodF9G1e7jfwLXfR164RNtx4BRVG",
			encoded: "12MzCDwodF9G1e7jfwLXfR164RNtx4BRVG",
			valid:   true,
			result: btcutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{
					0x0e, 0xf0, 0x30, 0x10, 0x7f, 0xd2, 0x6e, 0x0b, 0x6b, 0xf4,
					0x05, 0x12, 0xbc, 0xa2, 0xce, 0xb1, 0xdd, 0x80, 0xad, 0xaa},
				chaincfg.MainNetParams.PubKeyHashAddrID),
			f: func() (btcutil.Address, error) {
				pkHash := []byte{
					0x0e, 0xf0, 0x30, 0x10, 0x7f, 0xd2, 0x6e, 0x0b, 0x6b, 0xf4,
					0x05, 0x12, 0xbc, 0xa2, 0xce, 0xb1, 0xdd, 0x80, 0xad, 0xaa}
				return btcutil.NewAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "testnet p2pkh",
			addr:    "mrX9vMRYLfVy1BnZbc5gZjuyaqH3ZW2ZHz",
			encoded: "mrX9vMRYLfVy1BnZbc5gZjuyaqH3ZW2ZHz",
			valid:   true,
			result: btcutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{
					0x78, 0xb3, 0x16, 0xa0, 0x86, 0x47, 0xd5, 0xb7, 0x72, 0x83,
					0xe5, 0x12, 0xd3, 0x60, 0x3f, 0x1f, 0x1c, 0x8d, 0xe6, 0x8f},
				chaincfg.TestNet3Params.PubKeyHashAddrID),
			f: func() (btcutil.Address, error) {
				pkHash := []byte{
					0x78, 0xb3, 0x16, 0xa0, 0x86, 0x47, 0xd5, 0xb7, 0x72, 0x83,
					0xe5, 0x12, 0xd3, 0x60, 0x3f, 0x1f, 0x1c, 0x8d, 0xe6, 0x8f}
				return btcutil.NewAddressPubKeyHash(pkHash, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
		{
			name:    "litecoin mainnet p2pkh",
			addr:    "LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1",
			encoded: "LM2WMpR1Rp6j3Sa59cMXMs1SPzj9eXpGc1",
			valid:   true,
			result: btcutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{
					0x13, 0xc6, 0x0d, 0x8e, 0x68, 0xd7, 0x34, 0x9f, 0x5b, 0x4c,
					0xa3, 0x62, 0xc3, 0x95, 0x4b, 0x15, 0x04, 0x50, 0x61, 0xb1},
				[]byte{LitecoinParams.PubKeyHashAddrID}),
			f: func() (btcutil.Address, error) {
				pkHash := []byte{
					0x13, 0xc6, 0x0d, 0x8e, 0x68, 0xd7, 0x34, 0x9f, 0x5b, 0x4c,
					0xa3, 0x62, 0xc3, 0x95, 0x4b, 0x15, 0x04, 0x50, 0x61, 0xb1}
				return btcutil.NewAddressPubKeyHash(pkHash, &customParams)
			},
			net: &customParams,
		},
		{
			name:    "litecoin p2pkh with ltc1 prefix",
			addr:    "LTC1eqUzePT9uvpvb413Ejd6P8Cx1Ei8Di",
			encoded: "LTC1eqUzePT9uvpvb413Ejd6P8Cx1Ei8Di",
			valid:   true,
			result: btcutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{
					0x57, 0x63, 0x01, 0x15, 0x30, 0x0a, 0x62, 0x5f, 0x5d, 0xea,
					0xab, 0x64, 0x10, 0x0f, 0xaa, 0x55, 0x06, 0xc1, 0x42, 0x2f},
				[]byte{LitecoinParams.PubKeyHashAddrID}),
			f: func() (btcutil.Address, error) {
				pkHash := []byte{
					0x57, 0x63, 0x01, 0x15, 0x30, 0x0a, 0x62, 0x5f, 0x5d, 0xea,
					0xab, 0x64, 0x10, 0x0f, 0xaa, 0x55, 0x06, 0xc1, 0x42, 0x2f}
				return btcutil.NewAddressPubKeyHash(pkHash, &customParams)
			},
			net: &customParams,
		},
		{
			name:    "litecoin p2pkh with ltc1 prefix not containing any other character 1",
			addr:    "LTC1f9gtb7bU6B4VjHXvPGDi8ACNZhkKPo",
			encoded: "LTC1f9gtb7bU6B4VjHXvPGDi8ACNZhkKPo",
			valid:   true,
			result: btcutil.TstAddressPubKeyHash(
				[ripemd160.Size]byte{
					0x57, 0x63, 0x02, 0x3d, 0x3f, 0x02, 0x50, 0x96, 0x44, 0xda,
					0xcb, 0xfc, 0x45, 0xf2, 0xc9, 0x10, 0x21, 0x29, 0x74, 0x97},
				[]byte{LitecoinParams.PubKeyHashAddrID}),
			f: func() (btcutil.Address, error) {
				pkHash := []byte{
					0x57, 0x63, 0x02, 0x3d, 0x3f, 0x02, 0x50, 0x96, 0x44, 0xda,
					0xcb, 0xfc, 0x45, 0xf2, 0xc9, 0x10, 0x21, 0x29, 0x74, 0x97}
				return btcutil.NewAddressPubKeyHash(pkHash, &customParams)
			},
			net: &customParams,
		},

		// Negative P2PKH tests.
		{
			name:  "p2pkh wrong hash length",
			addr:  "",
			valid: false,
			f: func() (btcutil.Address, error) {
				pkHash := []byte{
					0x00, 0x0e, 0xf0, 0x30, 0x10, 0x7f, 0xd2, 0x6e, 0x0b, 0x6b,
					0xf4, 0x05, 0x12, 0xbc, 0xa2, 0xce, 0xb1, 0xdd, 0x80, 0xad,
					0xaa}
				return btcutil.NewAddressPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:  "p2pkh bad checksum",
			addr:  "1MirQ9bwyQcGVJPwKUgapu5ouK2E2Ey4gY",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},

		// Positive P2SH tests.
		{
			// Taken from transactions:
			// output: 3c9018e8d5615c306d72397f8f5eef44308c98fb576a88e030c25456b4f3a7ac
			// input:  837dea37ddc8b1e3ce646f1a656e79bbd8cc7f558ac56a169626d649ebe2a3ba.
			name:    "mainnet p2sh",
			addr:    "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
			encoded: "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC",
			valid:   true,
			result: btcutil.TstAddressScriptHash(
				[ripemd160.Size]byte{
					0xf8, 0x15, 0xb0, 0x36, 0xd9, 0xbb, 0xbc, 0xe5, 0xe9, 0xf2,
					0xa0, 0x0a, 0xbd, 0x1b, 0xf3, 0xdc, 0x91, 0xe9, 0x55, 0x10},
				chaincfg.MainNetParams.ScriptHashAddrID),
			f: func() (btcutil.Address, error) {
				script := []byte{
					0x52, 0x41, 0x04, 0x91, 0xbb, 0xa2, 0x51, 0x09, 0x12, 0xa5,
					0xbd, 0x37, 0xda, 0x1f, 0xb5, 0xb1, 0x67, 0x30, 0x10, 0xe4,
					0x3d, 0x2c, 0x6d, 0x81, 0x2c, 0x51, 0x4e, 0x91, 0xbf, 0xa9,
					0xf2, 0xeb, 0x12, 0x9e, 0x1c, 0x18, 0x33, 0x29, 0xdb, 0x55,
					0xbd, 0x86, 0x8e, 0x20, 0x9a, 0xac, 0x2f, 0xbc, 0x02, 0xcb,
					0x33, 0xd9, 0x8f, 0xe7, 0x4b, 0xf2, 0x3f, 0x0c, 0x23, 0x5d,
					0x61, 0x26, 0xb1, 0xd8, 0x33, 0x4f, 0x86, 0x41, 0x04, 0x86,
					0x5c, 0x40, 0x29, 0x3a, 0x68, 0x0c, 0xb9, 0xc0, 0x20, 0xe7,
					0xb1, 0xe1, 0x06, 0xd8, 0xc1, 0x91, 0x6d, 0x3c, 0xef, 0x99,
					0xaa, 0x43, 0x1a, 0x56, 0xd2, 0x53, 0xe6, 0x92, 0x56, 0xda,
					0xc0, 0x9e, 0xf1, 0x22, 0xb1, 0xa9, 0x86, 0x81, 0x8a, 0x7c,
					0xb6, 0x24, 0x53, 0x2f, 0x06, 0x2c, 0x1d, 0x1f, 0x87, 0x22,
					0x08, 0x48, 0x61, 0xc5, 0xc3, 0x29, 0x1c, 0xcf, 0xfe, 0xf4,
					0xec, 0x68, 0x74, 0x41, 0x04, 0x8d, 0x24, 0x55, 0xd2, 0x40,
					0x3e, 0x08, 0x70, 0x8f, 0xc1, 0xf5, 0x56, 0x00, 0x2f, 0x1b,
					0x6c, 0xd8, 0x3f, 0x99, 0x2d, 0x08, 0x50, 0x97, 0xf9, 0x97,
					0x4a, 0xb0, 0x8a, 0x28, 0x83, 0x8f, 0x07, 0x89, 0x6f, 0xba,
					0xb0, 0x8f, 0x39, 0x49, 0x5e, 0x15, 0xfa, 0x6f, 0xad, 0x6e,
					0xdb, 0xfb, 0x1e, 0x75, 0x4e, 0x35, 0xfa, 0x1c, 0x78, 0x44,
					0xc4, 0x1f, 0x32, 0x2a, 0x18, 0x63, 0xd4, 0x62, 0x13, 0x53,
					0xae}
				return btcutil.NewAddressScriptHash(script, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			// Taken from transactions:
			// output: b0539a45de13b3e0403909b8bd1a555b8cbe45fd4e3f3fda76f3a5f52835c29d
			// input: (not yet redeemed at time test was written)
			name:    "mainnet p2sh 2",
			addr:    "3NukJ6fYZJ5Kk8bPjycAnruZkE5Q7UW7i8",
			encoded: "3NukJ6fYZJ5Kk8bPjycAnruZkE5Q7UW7i8",
			valid:   true,
			result: btcutil.TstAddressScriptHash(
				[ripemd160.Size]byte{
					0xe8, 0xc3, 0x00, 0xc8, 0x79, 0x86, 0xef, 0xa8, 0x4c, 0x37,
					0xc0, 0x51, 0x99, 0x29, 0x01, 0x9e, 0xf8, 0x6e, 0xb5, 0xb4},
				chaincfg.MainNetParams.ScriptHashAddrID),
			f: func() (btcutil.Address, error) {
				hash := []byte{
					0xe8, 0xc3, 0x00, 0xc8, 0x79, 0x86, 0xef, 0xa8, 0x4c, 0x37,
					0xc0, 0x51, 0x99, 0x29, 0x01, 0x9e, 0xf8, 0x6e, 0xb5, 0xb4}
				return btcutil.NewAddressScriptHashFromHash(hash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			// Taken from bitcoind base58_keys_valid.
			name:    "testnet p2sh",
			addr:    "2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n",
			encoded: "2NBFNJTktNa7GZusGbDbGKRZTxdK9VVez3n",
			valid:   true,
			result: btcutil.TstAddressScriptHash(
				[ripemd160.Size]byte{
					0xc5, 0x79, 0x34, 0x2c, 0x2c, 0x4c, 0x92, 0x20, 0x20, 0x5e,
					0x2c, 0xdc, 0x28, 0x56, 0x17, 0x04, 0x0c, 0x92, 0x4a, 0x0a},
				chaincfg.TestNet3Params.ScriptHashAddrID),
			f: func() (btcutil.Address, error) {
				hash := []byte{
					0xc5, 0x79, 0x34, 0x2c, 0x2c, 0x4c, 0x92, 0x20, 0x20, 0x5e,
					0x2c, 0xdc, 0x28, 0x56, 0x17, 0x04, 0x0c, 0x92, 0x4a, 0x0a}
				return btcutil.NewAddressScriptHashFromHash(hash, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},

		// Negative P2SH tests.
		{
			name:  "p2sh wrong hash length",
			addr:  "",
			valid: false,
			f: func() (btcutil.Address, error) {
				hash := []byte{
					0x00, 0xf8, 0x15, 0xb0, 0x36, 0xd9, 0xbb, 0xbc, 0xe5, 0xe9,
					0xf2, 0xa0, 0x0a, 0xbd, 0x1b, 0xf3, 0xdc, 0x91, 0xe9, 0x55,
					0x10}
				return btcutil.NewAddressScriptHashFromHash(hash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},

		// Segwit address tests.
		{
			name:    "segwit mainnet p2wpkh v0",
			addr:    "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
			encoded: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
			valid:   true,
			result: btcutil.TstAddressWitnessPubKeyHash(
				0,
				[20]byte{
					0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
					0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6},
				chaincfg.MainNetParams.Bech32HRPSegwit),
			f: func() (btcutil.Address, error) {
				pkHash := []byte{
					0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
					0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6}
				return btcutil.NewAddressWitnessPubKeyHash(pkHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "segwit mainnet p2wsh v0",
			addr:    "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
			encoded: "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3",
			valid:   true,
			result: btcutil.TstAddressWitnessScriptHash(
				0,
				[32]byte{
					0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68,
					0x04, 0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13,
					0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1,
					0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62},
				chaincfg.MainNetParams.Bech32HRPSegwit),
			f: func() (btcutil.Address, error) {
				scriptHash := []byte{
					0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68,
					0x04, 0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13,
					0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1,
					0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62}
				return btcutil.NewAddressWitnessScriptHash(scriptHash, &chaincfg.MainNetParams)
			},
			net: &chaincfg.MainNetParams,
		},
		{
			name:    "segwit testnet p2wpkh v0",
			addr:    "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
			encoded: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
			valid:   true,
			result: btcutil.TstAddressWitnessPubKeyHash(
				0,
				[20]byte{
					0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
					0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6},
				chaincfg.TestNet3Params.Bech32HRPSegwit),
			f: func() (btcutil.Address, error) {
				pkHash := []byte{
					0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
					0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6}
				return btcutil.NewAddressWitnessPubKeyHash(pkHash, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
		{
			name:    "segwit testnet p2wsh v0",
			addr:    "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
			encoded: "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
			valid:   true,
			result: btcutil.TstAddressWitnessScriptHash(
				0,
				[32]byte{
					0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68,
					0x04, 0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13,
					0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1,
					0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62},
				chaincfg.TestNet3Params.Bech32HRPSegwit),
			f: func() (btcutil.Address, error) {
				scriptHash := []byte{
					0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68,
					0x04, 0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13,
					0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1,
					0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62}
				return btcutil.NewAddressWitnessScriptHash(scriptHash, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
		{
			name:    "segwit testnet p2wsh witness v0",
			addr:    "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
			encoded: "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
			valid:   true,
			result: btcutil.TstAddressWitnessScriptHash(
				0,
				[32]byte{
					0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62,
					0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66,
					0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2,
					0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33},
				chaincfg.TestNet3Params.Bech32HRPSegwit),
			f: func() (btcutil.Address, error) {
				scriptHash := []byte{
					0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62,
					0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66,
					0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2,
					0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33}
				return btcutil.NewAddressWitnessScriptHash(scriptHash, &chaincfg.TestNet3Params)
			},
			net: &chaincfg.TestNet3Params,
		},
		{
			name:    "litecoin p2wpkh v0",
			addr:    "ltc1qt6nzjwaqp3nknu5h6xmh58679cjsyqj4gzf8w2",
			encoded: "ltc1qt6nzjwaqp3nknu5h6xmh58679cjsyqj4gzf8w2",
			valid:   true,
			result: btcutil.TstAddressWitnessPubKeyHash(
				0,
				[20]byte{
					0x5e, 0xa6, 0x29, 0x3b, 0xa0, 0x0c, 0x67, 0x69, 0xf2, 0x97,
					0xd1, 0xb7, 0x7a, 0x1f, 0x5e, 0x2e, 0x25, 0x02, 0x02, 0x55},
				customParams.Bech32HRPSegwit),
			f: func() (btcutil.Address, error) {
				pkHash := []byte{
					0x5e, 0xa6, 0x29, 0x3b, 0xa0, 0x0c, 0x67, 0x69, 0xf2, 0x97,
					0xd1, 0xb7, 0x7a, 0x1f, 0x5e, 0x2e, 0x25, 0x02, 0x02, 0x55}
				return btcutil.NewAddressWitnessPubKeyHash(pkHash, &customParams)
			},
			net: &customParams,
		},
		// Unsupported witness versions (version 0 only supported at this point)
		{
			name:  "segwit mainnet witness v1",
			addr:  "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit mainnet witness v16",
			addr:  "BC1SW50QA3JX3S",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit mainnet witness v2",
			addr:  "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		// Invalid segwit addresses
		{
			name:  "segwit invalid hrp",
			addr:  "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
			valid: false,
			net:   &chaincfg.TestNet3Params,
		},
		{
			name:  "segwit invalid checksum",
			addr:  "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit invalid witness version",
			addr:  "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit invalid program length",
			addr:  "bc1rw5uspcuh",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit invalid program length",
			addr:  "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit invalid program length for witness version 0 (per BIP141)",
			addr:  "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
			valid: false,
			net:   &chaincfg.MainNetParams,
		},
		{
			name:  "segwit mixed case",
			addr:  "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
			valid: false,
			net:   &chaincfg.TestNet3Params,
		},
		{
			name:  "segwit zero padding of more than 4 bits",
			addr:  "tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
			valid: false,
			net:   &chaincfg.TestNet3Params,
		},
		{
			name:  "segwit non-zero padding in 8-to-5 conversion",
			addr:  "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
			valid: false,
			net:   &chaincfg.TestNet3Params,
		},
	}

	for _, test := range tests {
		// Decode addr and compare error against valid.
		decoded, err := btcutil.DecodeAddress(test.addr, test.net)
		if (err == nil) != test.valid {
			t.Errorf("%v: decoding test failed: %v", test.name, err)
			return
		}

		if err == nil {
			// Ensure the stringer returns the same address as the
			// original.
			if decodedStringer, ok := decoded.(fmt.Stringer); ok {
				addr := test.addr

				// For Segwit addresses the string representation
				// will always be lower case, so in that case we
				// convert the original to lower case first.
				if strings.Contains(test.name, "segwit") {
					addr = strings.ToLower(addr)
				}

				if addr != decodedStringer.String() {
					t.Errorf("%v: String on decoded value does not match expected value: %v != %v",
						test.name, test.addr, decodedStringer.String())
					return
				}
			}

			// Encode again and compare against the original.
			encoded := decoded.EncodeAddress()
			if test.encoded != encoded {
				t.Errorf("%v: decoding and encoding produced different addressess: %v != %v",
					test.name, test.encoded, encoded)
				return
			}

			// Perform type-specific calculations.
			var saddr []byte
			switch d := decoded.(type) {
			case *btcutil.AddressPubKeyHash:
				saddr = btcutil.TstAddressSAddr(encoded)

			case *btcutil.AddressScriptHash:
				saddr = btcutil.TstAddressSAddr(encoded)

			case *btcutil.AddressWitnessPubKeyHash:
				saddr = btcutil.TstAddressSegwitSAddr(encoded)
			case *btcutil.AddressWitnessScriptHash:
				saddr = btcutil.TstAddressSegwitSAddr(encoded)
			}

			// Check script address, as well as the Hash160 method for P2PKH and
			// P2SH addresses.
			if !bytes.Equal(saddr, decoded.ScriptAddress()) {
				t.Errorf("%v: script addresses do not match:\n%x != \n%x",
					test.name, saddr, decoded.ScriptAddress())
				return
			}
			switch a := decoded.(type) {
			case *btcutil.AddressPubKeyHash:
				if h := a.Hash160()[:]; !bytes.Equal(saddr, h) {
					t.Errorf("%v: hashes do not match:\n%x != \n%x",
						test.name, saddr, h)
					return
				}

			case *btcutil.AddressScriptHash:
				if h := a.Hash160()[:]; !bytes.Equal(saddr, h) {
					t.Errorf("%v: hashes do not match:\n%x != \n%x",
						test.name, saddr, h)
					return
				}

			case *btcutil.AddressWitnessPubKeyHash:
				if hrp := a.Hrp(); test.net.Bech32HRPSegwit != hrp {
					t.Errorf("%v: hrps do not match:\n%x != \n%x",
						test.name, test.net.Bech32HRPSegwit, hrp)
					return
				}

				expVer := test.result.(*btcutil.AddressWitnessPubKeyHash).WitnessVersion()
				if v := a.WitnessVersion(); v != expVer {
					t.Errorf("%v: witness versions do not match:\n%x != \n%x",
						test.name, expVer, v)
					return
				}

				if p := a.WitnessProgram(); !bytes.Equal(saddr, p) {
					t.Errorf("%v: witness programs do not match:\n%x != \n%x",
						test.name, saddr, p)
					return
				}

			case *btcutil.AddressWitnessScriptHash:
				if hrp := a.Hrp(); test.net.Bech32HRPSegwit != hrp {
					t.Errorf("%v: hrps do not match:\n%x != \n%x",
						test.name, test.net.Bech32HRPSegwit, hrp)
					return
				}

				expVer := test.result.(*btcutil.AddressWitnessScriptHash).WitnessVersion()
				if v := a.WitnessVersion(); v != expVer {
					t.Errorf("%v: witness versions do not match:\n%x != \n%x",
						test.name, expVer, v)
					return
				}

				if p := a.WitnessProgram(); !bytes.Equal(saddr, p) {
					t.Errorf("%v: witness programs do not match:\n%x != \n%x",
						test.name, saddr, p)
					return
				}
			}

			// Ensure the address is for the expected network.
			if !decoded.IsForNet(test.net) {
				t.Errorf("%v: calculated network does not match expected",
					test.name)
				return
			}
		}

		if !test.valid {
			// If address is invalid, but a creation function exists,
			// verify that it returns a nil addr and non-nil error.
			if test.f != nil {
				_, err := test.f()
				if err == nil {
					t.Errorf("%v: address is invalid but creating new address succeeded",
						test.name)
					return
				}
			}
			continue
		}

		// Valid test, compare address created with f against expected result.
		addr, err := test.f()
		if err != nil {
			t.Errorf("%v: address is valid but creating new address failed with error %v",
				test.name, err)
			return
		}

		if !reflect.DeepEqual(addr, test.result) {
			t.Errorf("%v: created address does not match expected result",
				test.name)
			return
		}
	}
}
