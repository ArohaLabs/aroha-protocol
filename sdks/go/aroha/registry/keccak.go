// Copyright (c) 2026 Aroha Labs
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"encoding/binary"
	"math/bits"
)

// keccak256 is the original (pre-FIPS-202, "legacy") Keccak-256 with 0x01
// padding — the hash @noble/hashes keccak_256 computes and the registry keys
// agents by. It is NOT SHA3-256, which pads with 0x06. Implemented here so
// the module keeps its single dependency.
func keccak256(data []byte) [32]byte {
	const rate = 136 // (1600 - 2*256) / 8
	var st [25]uint64
	for len(data) >= rate {
		absorb(&st, data[:rate])
		keccakF1600(&st)
		data = data[rate:]
	}
	var block [rate]byte
	copy(block[:], data)
	block[len(data)] ^= 0x01
	block[rate-1] ^= 0x80
	absorb(&st, block[:])
	keccakF1600(&st)

	var out [32]byte
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], st[i])
	}
	return out
}

func absorb(st *[25]uint64, block []byte) {
	for i := 0; i < len(block)/8; i++ {
		st[i] ^= binary.LittleEndian.Uint64(block[i*8:])
	}
}

var roundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// rotation offsets and lane permutation (rho and pi), in pi order.
var (
	rotc = [24]int{1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44}
	piln = [24]int{10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1}
)

func keccakF1600(st *[25]uint64) {
	var bc [5]uint64
	for round := 0; round < 24; round++ {
		// theta
		for i := 0; i < 5; i++ {
			bc[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20]
		}
		for i := 0; i < 5; i++ {
			t := bc[(i+4)%5] ^ bits.RotateLeft64(bc[(i+1)%5], 1)
			for j := 0; j < 25; j += 5 {
				st[j+i] ^= t
			}
		}
		// rho and pi
		t := st[1]
		for i := 0; i < 24; i++ {
			j := piln[i]
			bc[0] = st[j]
			st[j] = bits.RotateLeft64(t, rotc[i])
			t = bc[0]
		}
		// chi
		for j := 0; j < 25; j += 5 {
			for i := 0; i < 5; i++ {
				bc[i] = st[j+i]
			}
			for i := 0; i < 5; i++ {
				st[j+i] ^= (^bc[(i+1)%5]) & bc[(i+2)%5]
			}
		}
		// iota
		st[0] ^= roundConstants[round]
	}
}
