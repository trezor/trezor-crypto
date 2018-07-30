/**
 * Copyright (c) 2017 Saleem Rashid
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 * OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#include "hasher.h"

void hasher_Init(Hasher *hasher, HasherType type) {
	hasher->type = type;

	switch (hasher->type) {
	case HASHER_SHA2:
	case HASHER_SHA2D:
		sha256_Init(&hasher->ctx.sha2);
		break;
	case HASHER_SHA3:
#if USE_KECCAK
	case HASHER_SHA3K:
#endif
		sha3_256_Init(&hasher->ctx.sha3);
		break;
	case HASHER_BLAKE:
	case HASHER_BLAKED:
		blake256_Init(&hasher->ctx.blake);
		break;
	case HASHER_GROESTLD_TRUNC:
		groestl512_Init(&hasher->ctx.groestl);
		break;
	case HASHER_OVERWINTER_PREVOUTS:
		blake2b_InitPersonal(&hasher->ctx.blake2b, 32, "ZcashPrevoutHash", 16);
		break;
	case HASHER_OVERWINTER_SEQUENCE:
		blake2b_InitPersonal(&hasher->ctx.blake2b, 32, "ZcashSequencHash", 16);
		break;
	case HASHER_OVERWINTER_OUTPUTS:
		blake2b_InitPersonal(&hasher->ctx.blake2b, 32, "ZcashOutputsHash", 16);
		break;
	case HASHER_OVERWINTER_PREIMAGE:
		blake2b_InitPersonal(&hasher->ctx.blake2b, 32, "ZcashSigHash\x19\x1b\xa8\x5b", 16);  // BRANCH_ID = 0x5ba81b19
		break;
	}
}

void hasher_Reset(Hasher *hasher) {
	hasher_Init(hasher, hasher->type);
}

void hasher_Update(Hasher *hasher, const uint8_t *data, size_t length) {
	switch (hasher->type) {
	case HASHER_SHA2:
	case HASHER_SHA2D:
		sha256_Update(&hasher->ctx.sha2, data, length);
		break;
	case HASHER_SHA3:
#if USE_KECCAK
	case HASHER_SHA3K:
#endif
		sha3_Update(&hasher->ctx.sha3, data, length);
		break;
	case HASHER_BLAKE:
	case HASHER_BLAKED:
		blake256_Update(&hasher->ctx.blake, data, length);
		break;
	case HASHER_GROESTLD_TRUNC:
		groestl512_Update(&hasher->ctx.groestl, data, length);
		break;
	case HASHER_OVERWINTER_PREVOUTS:
	case HASHER_OVERWINTER_SEQUENCE:
	case HASHER_OVERWINTER_OUTPUTS:
	case HASHER_OVERWINTER_PREIMAGE:
		blake2b_Update(&hasher->ctx.blake2b, data, length);
		break;
	}
}

void hasher_Final(Hasher *hasher, uint8_t hash[HASHER_DIGEST_LENGTH]) {
	switch (hasher->type) {
	case HASHER_SHA2:
		sha256_Final(&hasher->ctx.sha2, hash);
		break;
	case HASHER_SHA2D:
		sha256_Final(&hasher->ctx.sha2, hash);
		hasher_Raw(HASHER_SHA2, hash, HASHER_DIGEST_LENGTH, hash);
		break;
	case HASHER_SHA3:
		sha3_Final(&hasher->ctx.sha3, hash);
		break;
#if USE_KECCAK
	case HASHER_SHA3K:
		keccak_Final(&hasher->ctx.sha3, hash);
		break;
#endif
	case HASHER_BLAKE:
		blake256_Final(&hasher->ctx.blake, hash);
		break;
	case HASHER_BLAKED:
		blake256_Final(&hasher->ctx.blake, hash);
		hasher_Raw(HASHER_BLAKE, hash, HASHER_DIGEST_LENGTH, hash);
		break;
	case HASHER_GROESTLD_TRUNC:
		groestl512_DoubleTrunc(&hasher->ctx.groestl, hash);
		break;
	case HASHER_OVERWINTER_PREVOUTS:
	case HASHER_OVERWINTER_SEQUENCE:
	case HASHER_OVERWINTER_OUTPUTS:
	case HASHER_OVERWINTER_PREIMAGE:
		blake2b_Final(&hasher->ctx.blake2b, hash, 32);
		break;
	}
}

void hasher_Raw(HasherType type, const uint8_t *data, size_t length, uint8_t hash[HASHER_DIGEST_LENGTH]) {
	Hasher hasher;

	hasher_Init(&hasher, type);
	hasher_Update(&hasher, data, length);
	hasher_Final(&hasher, hash);
}
